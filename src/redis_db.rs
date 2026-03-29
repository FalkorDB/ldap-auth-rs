use async_trait::async_trait;
use chrono::Utc;
use deadpool_redis::{Config as PoolConfig, Pool, Runtime, redis::AsyncCommands};
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::db::{DbConnectionHealth, DbService};
use crate::error::{AppError, Result};
use crate::metrics;
use crate::models::{Group, GroupCreate, GroupUpdate, User, UserCreate, UserUpdate};
use crate::password::{hash_password, verify_password};

/// Redis-based implementation of the DbService trait
pub struct RedisDbService {
    primary_pool: Pool,
    replica_pool: Option<Pool>,
}

static RECONCILED_ORGS: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));

const METRICS_RECONCILE_INTERVAL_SECS: u64 = 60;

type RedisConnection = deadpool_redis::Connection;
type RedisReadFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

impl RedisDbService {
    /// Create a new RedisDbService from a Redis URL with retry logic
    #[allow(dead_code)]
    pub async fn new(redis_url: &str, retry: Option<u32>) -> Result<Self> {
        Self::new_with_replica(redis_url, None, retry).await
    }

    /// Create a new RedisDbService with an optional read-only replica URL.
    pub async fn new_with_replica(
        redis_url: &str,
        replica_url: Option<&str>,
        retry: Option<u32>,
    ) -> Result<Self> {
        let retry = retry.unwrap_or(10);
        Self::new_with_replica_and_retry(
            redis_url,
            replica_url,
            retry,
            tokio::time::Duration::from_secs(2),
        )
        .await
    }

    /// Create a new RedisDbService with configurable retry parameters
    #[allow(dead_code)]
    pub async fn new_with_retry(
        redis_url: &str,
        max_retries: u32,
        initial_delay: tokio::time::Duration,
    ) -> Result<Self> {
        Self::new_with_replica_and_retry(redis_url, None, max_retries, initial_delay).await
    }

    /// Create a new RedisDbService with replica-aware retry parameters.
    pub async fn new_with_replica_and_retry(
        redis_url: &str,
        replica_url: Option<&str>,
        max_retries: u32,
        initial_delay: tokio::time::Duration,
    ) -> Result<Self> {
        let primary_pool = Self::create_pool(redis_url)?;
        let replica_pool = match replica_url {
            Some(url) => Some(Self::create_pool(url)?),
            None => None,
        };

        // Retry connection with exponential backoff
        let mut retries = 0;
        let mut delay = initial_delay;

        loop {
            let primary_result = Self::test_connection(&primary_pool).await;
            let replica_result = match replica_pool.as_ref() {
                Some(pool) => Some(Self::test_connection(pool).await),
                None => None,
            };

            if primary_result.is_ok()
                || replica_result.as_ref().is_some_and(|result| result.is_ok())
            {
                if primary_result.is_ok() {
                    info!("Successfully connected to Redis primary");
                }

                match replica_result.as_ref() {
                    Some(Ok(_)) => info!("Successfully connected to Redis replica"),
                    Some(Err(err)) => warn!(
                        "Redis replica is configured but unavailable during startup: {}",
                        err
                    ),
                    None => {}
                }

                if primary_result.is_err()
                    && replica_result.as_ref().is_some_and(|result| result.is_ok())
                {
                    warn!("Starting in read-only degraded mode because Redis primary is offline");
                }

                let service = Self {
                    primary_pool,
                    replica_pool,
                };
                service.start_metrics_reconciler();
                return Ok(service);
            }

            retries += 1;
            let primary_error = primary_result
                .err()
                .map(|err| err.to_string())
                .unwrap_or_default();
            let replica_error = replica_result
                .and_then(|result| result.err())
                .map(|err| err.to_string());

            if retries >= max_retries {
                let mut message = format!(
                    "Failed to connect to Redis primary after {} attempts: {}",
                    max_retries, primary_error
                );
                if let Some(replica_error) = replica_error {
                    message.push_str(&format!("; replica also unavailable: {}", replica_error));
                }
                return Err(AppError::Database(message));
            }

            if let Some(replica_error) = replica_error {
                warn!(
                    "Redis primary and replica unavailable (attempt {}/{}): primary={}, replica={}. Retrying in {:?}...",
                    retries, max_retries, primary_error, replica_error, delay
                );
            } else {
                warn!(
                    "Redis primary unavailable (attempt {}/{}): {}. Retrying in {:?}...",
                    retries, max_retries, primary_error, delay
                );
            }

            tokio::time::sleep(delay).await;
            delay = std::cmp::min(delay * 2, tokio::time::Duration::from_secs(30));
        }
    }

    fn create_pool(redis_url: &str) -> Result<Pool> {
        let cfg = PoolConfig::from_url(redis_url);
        cfg.create_pool(Some(Runtime::Tokio1)).map_err(|err| {
            AppError::Database(format!(
                "Failed to create Redis pool for {}: {}",
                redis_url, err
            ))
        })
    }

    /// Test the Redis connection
    async fn test_connection(pool: &Pool) -> Result<()> {
        let mut conn = pool.get().await.map_err(|e| {
            AppError::Database(format!("Failed to get connection from pool: {}", e))
        })?;

        let _: String = deadpool_redis::redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::Database(format!("Failed to ping Redis: {}", e)))?;

        Ok(())
    }

    async fn get_primary_conn(&self) -> Result<RedisConnection> {
        self.primary_pool.get().await.map_err(AppError::from)
    }

    async fn get_replica_conn(&self) -> Result<RedisConnection> {
        let replica_pool = self
            .replica_pool
            .as_ref()
            .ok_or_else(|| AppError::Database("Redis replica is not configured".to_string()))?;

        replica_pool.get().await.map_err(AppError::from)
    }

    async fn get_read_conn_from_pools(
        primary_pool: &Pool,
        replica_pool: Option<&Pool>,
    ) -> Result<RedisConnection> {
        match primary_pool.get().await {
            Ok(conn) => Ok(conn),
            Err(primary_err) => {
                if let Some(replica_pool) = replica_pool {
                    warn!(
                        error = %primary_err,
                        "Primary Redis unavailable while acquiring read connection, trying replica"
                    );
                    match replica_pool.get().await {
                        Ok(conn) => Ok(conn),
                        Err(replica_err) => Err(AppError::Database(format!(
                            "Failed to get readable Redis connection; primary: {}, replica: {}",
                            primary_err, replica_err
                        ))),
                    }
                } else {
                    Err(AppError::from(primary_err))
                }
            }
        }
    }

    fn should_try_replica(error: &AppError) -> bool {
        matches!(
            error,
            AppError::Database(_) | AppError::Redis(_) | AppError::Pool(_)
        )
    }

    async fn with_read_fallback<T, F>(
        &self,
        operation_name: &'static str,
        operation: F,
    ) -> Result<T>
    where
        T: Send,
        F: for<'a> Fn(&'a mut RedisConnection) -> RedisReadFuture<'a, T> + Send + Sync,
    {
        match self.primary_pool.get().await {
            Ok(mut conn) => match operation(&mut conn).await {
                Ok(result) => Ok(result),
                Err(err) if self.replica_pool.is_some() && Self::should_try_replica(&err) => {
                    warn!(
                        operation = operation_name,
                        error = %err,
                        "Read against Redis primary failed, retrying against replica"
                    );
                    let mut replica_conn = self.get_replica_conn().await?;
                    operation(&mut replica_conn).await
                }
                Err(err) => Err(err),
            },
            Err(primary_err) => {
                if self.replica_pool.is_some() {
                    warn!(
                        operation = operation_name,
                        error = %primary_err,
                        "Primary Redis unavailable, using replica for read"
                    );
                    let mut replica_conn =
                        self.get_replica_conn().await.map_err(|replica_err| {
                            AppError::Database(format!(
                                "Failed to get readable Redis connection; primary: {}, replica: {}",
                                primary_err, replica_err
                            ))
                        })?;
                    operation(&mut replica_conn).await
                } else {
                    Err(AppError::from(primary_err))
                }
            }
        }
    }

    fn user_key(organization: &str, username: &str) -> String {
        format!("user:{}:{}", organization, username)
    }

    fn group_key(organization: &str, name: &str) -> String {
        format!("group:{}:{}", organization, name)
    }

    fn org_users_key(organization: &str) -> String {
        format!("org:{}:users", organization)
    }

    fn org_groups_key(organization: &str) -> String {
        format!("org:{}:groups", organization)
    }

    fn user_groups_key(organization: &str, username: &str) -> String {
        format!("user:{}:{}:groups", organization, username)
    }

    fn organizations_key() -> &'static str {
        "organizations"
    }

    async fn sync_organization_counts(
        conn: &mut deadpool_redis::Connection,
        organization: &str,
    ) -> Result<()> {
        let users_count: usize = conn.scard(Self::org_users_key(organization)).await?;
        let groups_count: usize = conn.scard(Self::org_groups_key(organization)).await?;

        metrics::set_users_count(organization, users_count as i64);
        metrics::set_groups_count(organization, groups_count as i64);
        Ok(())
    }

    async fn sync_total_organizations_count(conn: &mut deadpool_redis::Connection) -> Result<()> {
        let organizations_count: usize = conn.scard(Self::organizations_key()).await?;
        metrics::set_organizations_count(organizations_count as i64);
        Ok(())
    }

    async fn ensure_organization_registered(
        conn: &mut deadpool_redis::Connection,
        organization: &str,
    ) -> Result<()> {
        conn.sadd::<_, _, ()>(Self::organizations_key(), organization)
            .await?;
        Self::sync_total_organizations_count(conn).await
    }

    async fn cleanup_organization_if_empty(
        conn: &mut deadpool_redis::Connection,
        organization: &str,
    ) -> Result<()> {
        let users_count: usize = conn.scard(Self::org_users_key(organization)).await?;
        let groups_count: usize = conn.scard(Self::org_groups_key(organization)).await?;

        if users_count == 0 && groups_count == 0 {
            conn.srem::<_, _, ()>(Self::organizations_key(), organization)
                .await?;

            // Drop gauge label entries for deleted organizations to avoid unbounded cardinality.
            let _ = metrics::custom::USERS_COUNT.remove_label_values(&[organization]);
            let _ = metrics::custom::GROUPS_COUNT.remove_label_values(&[organization]);
        }

        Self::sync_total_organizations_count(conn).await
    }

    fn start_metrics_reconciler(&self) {
        let primary_pool = self.primary_pool.clone();
        let replica_pool = self.replica_pool.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::reconcile_metrics(&primary_pool, replica_pool.as_ref()).await {
                warn!("Initial metrics reconciliation failed: {}", e);
            }

            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
                METRICS_RECONCILE_INTERVAL_SECS,
            ));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;

            loop {
                interval.tick().await;
                if let Err(e) = Self::reconcile_metrics(&primary_pool, replica_pool.as_ref()).await
                {
                    warn!("Periodic metrics reconciliation failed: {}", e);
                }
            }
        });
    }

    async fn reconcile_metrics(primary_pool: &Pool, replica_pool: Option<&Pool>) -> Result<()> {
        let mut conn = Self::get_read_conn_from_pools(primary_pool, replica_pool).await?;
        let organizations: Vec<String> = conn.smembers(Self::organizations_key()).await?;

        for organization in &organizations {
            Self::sync_organization_counts(&mut conn, organization).await?;
        }
        Self::sync_total_organizations_count(&mut conn).await?;

        // Remove local label entries for organizations that no longer exist in Redis.
        let current: HashSet<String> = organizations.into_iter().collect();
        let mut reconciled = RECONCILED_ORGS.lock().await;
        for stale in reconciled.difference(&current) {
            let _ = metrics::custom::USERS_COUNT.remove_label_values(&[stale.as_str()]);
            let _ = metrics::custom::GROUPS_COUNT.remove_label_values(&[stale.as_str()]);
        }
        *reconciled = current;

        Ok(())
    }

    async fn get_user_with_conn(
        conn: &mut RedisConnection,
        organization: &str,
        username: &str,
    ) -> Result<User> {
        let key = Self::user_key(organization, username);
        let user_json: Option<String> = conn.get(&key).await?;

        match user_json {
            Some(json) => Ok(serde_json::from_str(&json)?),
            None => Err(AppError::NotFound(format!(
                "User {}/{} not found",
                organization, username
            ))),
        }
    }

    async fn list_users_with_conn(
        conn: &mut RedisConnection,
        organization: &str,
    ) -> Result<Vec<User>> {
        let usernames: Vec<String> = conn.smembers(Self::org_users_key(organization)).await?;

        let mut users = Vec::new();
        for username in usernames {
            match Self::get_user_with_conn(conn, organization, &username).await {
                Ok(user) => users.push(user),
                Err(AppError::NotFound(_)) => warn!(
                    "User {} listed in organization {} but not found in database",
                    username, organization
                ),
                Err(err) => return Err(err),
            }
        }

        Ok(users)
    }

    async fn get_group_with_conn(
        conn: &mut RedisConnection,
        organization: &str,
        name: &str,
    ) -> Result<Group> {
        let key = Self::group_key(organization, name);
        let group_json: Option<String> = conn.get(&key).await?;

        match group_json {
            Some(json) => Ok(serde_json::from_str(&json)?),
            None => Err(AppError::NotFound(format!(
                "Group {}/{} not found",
                organization, name
            ))),
        }
    }

    async fn list_groups_with_conn(
        conn: &mut RedisConnection,
        organization: &str,
    ) -> Result<Vec<Group>> {
        let group_names: Vec<String> = conn.smembers(Self::org_groups_key(organization)).await?;

        let mut groups = Vec::new();
        for name in group_names {
            match Self::get_group_with_conn(conn, organization, &name).await {
                Ok(group) => groups.push(group),
                Err(AppError::NotFound(_)) => warn!(
                    "Group {} listed in organization {} but not found in database",
                    name, organization
                ),
                Err(err) => return Err(err),
            }
        }

        Ok(groups)
    }

    async fn get_user_groups_with_conn(
        conn: &mut RedisConnection,
        organization: &str,
        username: &str,
    ) -> Result<Vec<Group>> {
        let group_names: Vec<String> = conn
            .smembers(Self::user_groups_key(organization, username))
            .await?;

        let mut groups = Vec::new();
        for name in group_names {
            match Self::get_group_with_conn(conn, organization, &name).await {
                Ok(group) => groups.push(group),
                Err(AppError::NotFound(_)) => warn!(
                    "Group {} listed for user {} in organization {} but not found in database",
                    name, username, organization
                ),
                Err(err) => return Err(err),
            }
        }

        Ok(groups)
    }
}

#[async_trait]
impl DbService for RedisDbService {
    async fn create_user(&self, user: UserCreate) -> Result<User> {
        info!(
            "Creating user: organization={}, username={}",
            user.organization, user.username
        );
        let mut conn = self.get_primary_conn().await?;
        let key = Self::user_key(&user.organization, &user.username);

        // Check if user already exists
        let exists: bool = conn.exists(&key).await?;
        if exists {
            return Err(AppError::AlreadyExists(format!(
                "User {}/{} already exists",
                user.organization, user.username
            )));
        }

        // Hash the password
        let password_hash = hash_password(&user.password)?;

        // Create user object
        let mut new_user = User::new(
            user.organization.clone(),
            user.username.clone(),
            password_hash,
        );
        new_user.email = user.email;
        new_user.full_name = user.full_name;

        // Serialize and store
        let user_json = serde_json::to_string(&new_user)?;
        conn.set::<_, _, ()>(&key, user_json).await?;

        // Add to organization's user list
        let org_users_key = Self::org_users_key(&user.organization);
        conn.sadd::<_, _, ()>(&org_users_key, &user.username)
            .await?;

        Self::ensure_organization_registered(&mut conn, &user.organization).await?;
        Self::sync_organization_counts(&mut conn, &user.organization).await?;

        metrics::record_user_operation(&user.organization, "create", true);

        info!(
            "Successfully created user: organization={}, username={}",
            new_user.organization, new_user.username
        );
        Ok(new_user)
    }

    async fn get_user(&self, organization: &str, username: &str) -> Result<User> {
        info!(
            "Getting user: organization={}, username={}",
            organization, username
        );
        let organization_owned = organization.to_string();
        let username_owned = username.to_string();
        self.with_read_fallback("get_user", move |conn| {
            let organization = organization_owned.clone();
            let username = username_owned.clone();
            Box::pin(async move { Self::get_user_with_conn(conn, &organization, &username).await })
        })
        .await
    }

    async fn update_user(
        &self,
        organization: &str,
        username: &str,
        update: UserUpdate,
    ) -> Result<User> {
        info!(
            "Updating user: organization={}, username={}, updating_password={}",
            organization,
            username,
            update.password.is_some()
        );
        let mut conn = self.get_primary_conn().await?;
        let key = Self::user_key(organization, username);

        // Get existing user from the primary for write consistency.
        let mut user = Self::get_user_with_conn(&mut conn, organization, username).await?;

        // Update fields
        if let Some(password) = update.password {
            user.password_hash = hash_password(&password)?;
        }
        if let Some(email) = update.email {
            user.email = Some(email);
        }
        if let Some(full_name) = update.full_name {
            user.full_name = Some(full_name);
        }
        user.updated_at = Utc::now();

        // Save updated user
        let user_json = serde_json::to_string(&user)?;
        conn.set::<_, _, ()>(&key, user_json).await?;

        metrics::record_user_operation(organization, "update", true);

        info!(
            "Successfully updated user: organization={}, username={}",
            user.organization, user.username
        );
        Ok(user)
    }

    async fn delete_user(&self, organization: &str, username: &str) -> Result<()> {
        info!(
            "Deleting user: organization={}, username={}",
            organization, username
        );
        let mut conn = self.get_primary_conn().await?;
        let key = Self::user_key(organization, username);

        // Check if user exists
        let exists: bool = conn.exists(&key).await?;
        if !exists {
            return Err(AppError::NotFound(format!(
                "User {}/{} not found",
                organization, username
            )));
        }

        // Get user's groups before deletion
        let user_groups_key = Self::user_groups_key(organization, username);
        let group_names: Vec<String> = conn.smembers(&user_groups_key).await?;

        // Remove user from all groups efficiently using the same connection
        for group_name in &group_names {
            let group_key = Self::group_key(organization, group_name);

            // Get group
            if let Ok(group_json) = conn.get::<_, String>(&group_key).await
                && let Ok(mut group) = serde_json::from_str::<crate::models::Group>(&group_json)
            {
                // Remove user from group
                if group.remove_member(username) {
                    let updated_json = serde_json::to_string(&group).map_err(|err| {
                        error!(
                            group_key = %group_key,
                            username = %username,
                            error = %err,
                            "Failed to serialize updated group after removing member"
                        );
                        AppError::Internal(format!(
                            "Failed to serialize updated group for key {} after removing user {}: {}",
                            group_key, username, err
                        ))
                    })?;

                    conn.set::<_, _, ()>(&group_key, updated_json)
                        .await
                        .map_err(|err| {
                            error!(
                                group_key = %group_key,
                                username = %username,
                                error = %err,
                                "Failed to persist updated group after removing member"
                            );
                            AppError::Database(format!(
                                "Failed to persist updated group for key {} after removing user {}: {}",
                                group_key, username, err
                            ))
                        })?;
                }
            }
        }

        // Delete user
        conn.del::<_, ()>(&key).await?;

        // Remove from organization's user list
        let org_users_key = Self::org_users_key(organization);
        conn.srem::<_, _, ()>(&org_users_key, username).await?;

        // Remove user's groups set
        conn.del::<_, ()>(&user_groups_key).await?;

        Self::sync_organization_counts(&mut conn, organization).await?;
        Self::cleanup_organization_if_empty(&mut conn, organization).await?;

        metrics::record_user_operation(organization, "delete", true);

        info!(
            "Successfully deleted user: organization={}, username={}",
            organization, username
        );
        Ok(())
    }

    async fn list_users(&self, organization: &str) -> Result<Vec<User>> {
        info!("Listing users: organization={}", organization);
        let organization_owned = organization.to_string();
        let users = self
            .with_read_fallback("list_users", move |conn| {
                let organization = organization_owned.clone();
                Box::pin(async move { Self::list_users_with_conn(conn, &organization).await })
            })
            .await?;

        info!(
            "Successfully listed {} users: organization={}",
            users.len(),
            organization
        );
        Ok(users)
    }

    async fn verify_user_password(
        &self,
        organization: &str,
        username: &str,
        password: &str,
    ) -> Result<bool> {
        info!(
            "Verifying user password: organization={}, username={}",
            organization, username
        );
        let organization_owned = organization.to_string();
        let username_owned = username.to_string();
        let user = self
            .with_read_fallback("verify_user_password", move |conn| {
                let organization = organization_owned.clone();
                let username = username_owned.clone();
                Box::pin(
                    async move { Self::get_user_with_conn(conn, &organization, &username).await },
                )
            })
            .await?;
        let result = verify_password(password, &user.password_hash)?;
        Ok(result)
    }

    async fn create_group(&self, group: GroupCreate) -> Result<Group> {
        info!(
            "Creating group: organization={}, name={}, description={:?}",
            group.organization, group.name, group.description
        );
        let mut conn = self.get_primary_conn().await?;
        let key = Self::group_key(&group.organization, &group.name);

        // Check if group already exists
        let exists: bool = conn.exists(&key).await?;
        if exists {
            return Err(AppError::AlreadyExists(format!(
                "Group {}/{} already exists",
                group.organization, group.name
            )));
        }

        // Create group object
        let mut new_group = Group::new(group.organization.clone(), group.name.clone());
        new_group.description = group.description;

        // Serialize and store
        let group_json = serde_json::to_string(&new_group)?;
        conn.set::<_, _, ()>(&key, group_json).await?;

        // Add to organization's group list
        let org_groups_key = Self::org_groups_key(&group.organization);
        conn.sadd::<_, _, ()>(&org_groups_key, &group.name).await?;

        Self::ensure_organization_registered(&mut conn, &group.organization).await?;
        Self::sync_organization_counts(&mut conn, &group.organization).await?;

        metrics::record_group_operation(&group.organization, "create", true);

        info!(
            "Successfully created group: organization={}, name={}",
            new_group.organization, new_group.name
        );
        Ok(new_group)
    }

    async fn get_group(&self, organization: &str, name: &str) -> Result<Group> {
        info!(
            "Getting group: organization={}, name={}",
            organization, name
        );
        let organization_owned = organization.to_string();
        let name_owned = name.to_string();
        self.with_read_fallback("get_group", move |conn| {
            let organization = organization_owned.clone();
            let name = name_owned.clone();
            Box::pin(async move { Self::get_group_with_conn(conn, &organization, &name).await })
        })
        .await
    }

    async fn update_group(
        &self,
        organization: &str,
        name: &str,
        update: GroupUpdate,
    ) -> Result<Group> {
        info!(
            "Updating group: organization={}, name={}, description={:?}",
            organization, name, update.description
        );
        let mut conn = self.get_primary_conn().await?;
        let key = Self::group_key(organization, name);

        // Get existing group from the primary for write consistency.
        let mut group = Self::get_group_with_conn(&mut conn, organization, name).await?;

        // Update fields
        if let Some(description) = update.description {
            group.description = Some(description);
        }
        group.updated_at = Utc::now();

        // Save updated group
        let group_json = serde_json::to_string(&group)?;
        conn.set::<_, _, ()>(&key, group_json).await?;

        info!(
            "Successfully updated group: organization={}, name={}",
            group.organization, group.name
        );
        Ok(group)
    }

    async fn delete_group(&self, organization: &str, name: &str) -> Result<()> {
        info!(
            "Deleting group: organization={}, name={}",
            organization, name
        );
        let mut conn = self.get_primary_conn().await?;
        let key = Self::group_key(organization, name);

        // Check if group exists
        let group = Self::get_group_with_conn(&mut conn, organization, name).await?;

        // Remove group from all users' group sets
        for username in &group.members {
            let user_groups_key = Self::user_groups_key(organization, username);
            let _: deadpool_redis::redis::RedisResult<i32> =
                conn.srem(&user_groups_key, name).await;
        }

        // Delete group
        conn.del::<_, ()>(&key).await?;

        // Remove from organization's group list
        let org_groups_key = Self::org_groups_key(organization);
        conn.srem::<_, _, ()>(&org_groups_key, name).await?;

        Self::sync_organization_counts(&mut conn, organization).await?;
        Self::cleanup_organization_if_empty(&mut conn, organization).await?;

        metrics::record_group_operation(organization, "delete", true);

        info!(
            "Successfully deleted group: organization={}, name={}",
            organization, name
        );
        Ok(())
    }

    async fn list_groups(&self, organization: &str) -> Result<Vec<Group>> {
        info!("Listing groups: organization={}", organization);
        let organization_owned = organization.to_string();
        self.with_read_fallback("list_groups", move |conn| {
            let organization = organization_owned.clone();
            Box::pin(async move { Self::list_groups_with_conn(conn, &organization).await })
        })
        .await
    }

    async fn add_user_to_group(
        &self,
        organization: &str,
        group_name: &str,
        username: &str,
    ) -> Result<Group> {
        info!(
            "Adding user to group: organization={}, group={}, username={}",
            organization, group_name, username
        );
        let mut conn = self.get_primary_conn().await?;

        // Verify user exists
        Self::get_user_with_conn(&mut conn, organization, username).await?;

        // Get group
        let mut group = Self::get_group_with_conn(&mut conn, organization, group_name).await?;

        // Add user to group
        if !group.add_member(username.to_string()) {
            return Err(AppError::InvalidInput(format!(
                "User {} is already a member of group {}",
                username, group_name
            )));
        }

        // Save updated group
        let group_key = Self::group_key(organization, group_name);
        let group_json = serde_json::to_string(&group)?;
        conn.set::<_, _, ()>(&group_key, group_json).await?;

        // Add group to user's groups set
        let user_groups_key = Self::user_groups_key(organization, username);
        conn.sadd::<_, _, ()>(&user_groups_key, group_name).await?;

        info!(
            "Successfully added user to group: organization={}, group={}, username={}",
            organization, group_name, username
        );
        Ok(group)
    }

    async fn remove_user_from_group(
        &self,
        organization: &str,
        group_name: &str,
        username: &str,
    ) -> Result<Group> {
        info!(
            "Removing user from group: organization={}, group={}, username={}",
            organization, group_name, username
        );
        let mut conn = self.get_primary_conn().await?;

        // Get group
        let mut group = Self::get_group_with_conn(&mut conn, organization, group_name).await?;

        // Remove user from group
        if !group.remove_member(username) {
            return Err(AppError::InvalidInput(format!(
                "User {} is not a member of group {}",
                username, group_name
            )));
        }

        // Save updated group
        let group_key = Self::group_key(organization, group_name);
        let group_json = serde_json::to_string(&group)?;
        conn.set::<_, _, ()>(&group_key, group_json).await?;

        // Remove group from user's groups set
        let user_groups_key = Self::user_groups_key(organization, username);
        conn.srem::<_, _, ()>(&user_groups_key, group_name).await?;

        info!(
            "Successfully removed user from group: organization={}, group={}, username={}",
            organization, group_name, username
        );
        Ok(group)
    }

    async fn get_user_groups(&self, organization: &str, username: &str) -> Result<Vec<Group>> {
        info!(
            "Getting user groups: organization={}, username={}",
            organization, username
        );
        let organization_owned = organization.to_string();
        let username_owned = username.to_string();
        let groups = self
            .with_read_fallback("get_user_groups", move |conn| {
                let organization = organization_owned.clone();
                let username = username_owned.clone();
                Box::pin(async move {
                    Self::get_user_groups_with_conn(conn, &organization, &username).await
                })
            })
            .await?;

        info!(
            "Successfully retrieved {} groups for user: organization={}, username={}",
            groups.len(),
            organization,
            username
        );
        Ok(groups)
    }

    async fn search_users(&self, organization: &str, filter: &str) -> Result<Vec<User>> {
        info!(
            "Searching users: organization={}, filter={}",
            organization, filter
        );
        let organization_owned = organization.to_string();
        let users = self
            .with_read_fallback("search_users", move |conn| {
                let organization = organization_owned.clone();
                Box::pin(async move { Self::list_users_with_conn(conn, &organization).await })
            })
            .await?;

        let filtered: Vec<User> = users
            .into_iter()
            .filter(|u| {
                u.username.contains(filter)
                    || u.email.as_ref().is_some_and(|e| e.contains(filter))
                    || u.full_name.as_ref().is_some_and(|n| n.contains(filter))
            })
            .collect();

        info!(
            "Search users completed: organization={}, filter={}, results={}",
            organization,
            filter,
            filtered.len()
        );
        Ok(filtered)
    }

    async fn search_groups(&self, organization: &str, filter: &str) -> Result<Vec<Group>> {
        info!(
            "Searching groups: organization={}, filter={}",
            organization, filter
        );
        let organization_owned = organization.to_string();
        let groups = self
            .with_read_fallback("search_groups", move |conn| {
                let organization = organization_owned.clone();
                Box::pin(async move { Self::list_groups_with_conn(conn, &organization).await })
            })
            .await?;

        let filtered: Vec<Group> = groups
            .into_iter()
            .filter(|g| {
                g.name.contains(filter)
                    || g.description.as_ref().is_some_and(|d| d.contains(filter))
            })
            .collect();

        info!(
            "Search groups completed: organization={}, filter={}, results={}",
            organization,
            filter,
            filtered.len()
        );
        Ok(filtered)
    }

    async fn health_check(&self) -> Result<bool> {
        info!("Performing database health check");
        let status = self.connection_status().await?;
        let is_healthy = status.can_read;
        info!("Database health check result: {}", is_healthy);
        Ok(is_healthy)
    }

    async fn connection_status(&self) -> Result<DbConnectionHealth> {
        let primary_available = Self::test_connection(&self.primary_pool).await.is_ok();
        let replica_available = match self.replica_pool.as_ref() {
            Some(pool) => Self::test_connection(pool).await.is_ok(),
            None => false,
        };

        Ok(DbConnectionHealth {
            can_read: primary_available || replica_available,
            can_write: primary_available,
            primary_available,
            replica_available,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        assert_eq!(RedisDbService::user_key("acme", "john"), "user:acme:john");
        assert_eq!(RedisDbService::group_key("acme", "devs"), "group:acme:devs");
        assert_eq!(RedisDbService::org_users_key("acme"), "org:acme:users");
        assert_eq!(RedisDbService::org_groups_key("acme"), "org:acme:groups");
    }
}
