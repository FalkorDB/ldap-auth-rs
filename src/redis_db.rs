use async_trait::async_trait;
use chrono::Utc;
use deadpool_redis::{Config as PoolConfig, Pool, Runtime, redis::AsyncCommands};
use once_cell::sync::Lazy;
use std::collections::HashSet;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::db::DbService;
use crate::error::{AppError, Result};
use crate::metrics;
use crate::models::{Group, GroupCreate, GroupUpdate, User, UserCreate, UserUpdate};
use crate::password::{hash_password, verify_password};

/// Redis-based implementation of the DbService trait
pub struct RedisDbService {
    pool: Pool,
}

static RECONCILED_ORGS: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));

const METRICS_RECONCILE_INTERVAL_SECS: u64 = 60;

impl RedisDbService {
    /// Create a new RedisDbService from a Redis URL with retry logic
    pub async fn new(redis_url: &str, retry: Option<u32>) -> Result<Self> {
        let retry = retry.unwrap_or(10);
        Self::new_with_retry(redis_url, retry, tokio::time::Duration::from_secs(2)).await
    }

    /// Create a new RedisDbService with configurable retry parameters
    pub async fn new_with_retry(
        redis_url: &str,
        max_retries: u32,
        initial_delay: tokio::time::Duration,
    ) -> Result<Self> {
        // Retry connection with exponential backoff
        let mut retries = 0;
        let mut delay = initial_delay;

        loop {
            // Recreate the pool on each attempt to force DNS re-resolution
            let cfg = PoolConfig::from_url(redis_url);
            let pool = match cfg.create_pool(Some(Runtime::Tokio1)) {
                Ok(pool) => pool,
                Err(e) => {
                    retries += 1;
                    if retries >= max_retries {
                        return Err(AppError::Database(format!(
                            "Failed to create Redis pool after {} attempts: {}",
                            max_retries, e
                        )));
                    }
                    warn!(
                        "Failed to create Redis pool (attempt {}/{}): {}. Retrying in {:?}...",
                        retries, max_retries, e, delay
                    );
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, tokio::time::Duration::from_secs(30));
                    continue;
                }
            };

            match Self::test_connection(&pool).await {
                Ok(_) => {
                    info!("Successfully connected to Redis");
                    let service = Self { pool: pool.clone() };
                    service.start_metrics_reconciler();
                    return Ok(service);
                }
                Err(e) => {
                    retries += 1;
                    if retries >= max_retries {
                        return Err(AppError::Database(format!(
                            "Failed to connect to Redis after {} attempts: {}",
                            max_retries, e
                        )));
                    }
                    warn!(
                        "Failed to connect to Redis (attempt {}/{}): {}. Retrying in {:?}...",
                        retries, max_retries, e, delay
                    );
                    tokio::time::sleep(delay).await;
                    // Exponential backoff with max 30 seconds
                    delay = std::cmp::min(delay * 2, tokio::time::Duration::from_secs(30));
                }
            }
        }
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

        // Sync operation counts as gauges from DB metadata if available, otherwise just use counts
        metrics::record_user_operation(organization, "total", users_count as i64);
        metrics::record_group_operation(organization, "total", groups_count as i64);
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
        let pool = self.pool.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::reconcile_metrics(&pool).await {
                warn!("Initial metrics reconciliation failed: {}", e);
            }

            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
                METRICS_RECONCILE_INTERVAL_SECS,
            ));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;

            loop {
                interval.tick().await;
                if let Err(e) = Self::reconcile_metrics(&pool).await {
                    warn!("Periodic metrics reconciliation failed: {}", e);
                }
            }
        });
    }

    async fn reconcile_metrics(pool: &Pool) -> Result<()> {
        let mut conn = pool.get().await?;
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
}

#[async_trait]
impl DbService for RedisDbService {
    async fn create_user(&self, user: UserCreate) -> Result<User> {
        info!(
            "Creating user: organization={}, username={}",
            user.organization, user.username
        );
        let mut conn = self.pool.get().await?;
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
        let mut conn = self.pool.get().await?;
        let key = Self::user_key(organization, username);

        let user_json: Option<String> = conn.get(&key).await?;
        match user_json {
            Some(json) => {
                let user: User = serde_json::from_str(&json)?;
                Ok(user)
            }
            None => Err(AppError::NotFound(format!(
                "User {}/{} not found",
                organization, username
            ))),
        }
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
        let mut conn = self.pool.get().await?;
        let key = Self::user_key(organization, username);

        // Get existing user
        let mut user = self.get_user(organization, username).await?;

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
        let mut conn = self.pool.get().await?;
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

        info!(
            "Successfully deleted user: organization={}, username={}",
            organization, username
        );
        Ok(())
    }

    async fn list_users(&self, organization: &str) -> Result<Vec<User>> {
        info!("Listing users: organization={}", organization);
        let mut conn = self.pool.get().await?;
        let org_users_key = Self::org_users_key(organization);

        let usernames: Vec<String> = conn.smembers(&org_users_key).await?;

        let mut users = Vec::new();
        for username in usernames {
            if let Ok(user) = self.get_user(organization, &username).await {
                users.push(user);
            } else {
                warn!(
                    "User {} listed in organization {} but not found in database",
                    username, organization
                );
            }
        }

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
        let user = self.get_user(organization, username).await?;
        let result = verify_password(password, &user.password_hash)?;
        Ok(result)
    }

    async fn create_group(&self, group: GroupCreate) -> Result<Group> {
        info!(
            "Creating group: organization={}, name={}, description={:?}",
            group.organization, group.name, group.description
        );
        let mut conn = self.pool.get().await?;
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
        let mut conn = self.pool.get().await?;
        let key = Self::group_key(organization, name);

        let group_json: Option<String> = conn.get(&key).await?;
        match group_json {
            Some(json) => {
                let group: Group = serde_json::from_str(&json)?;
                Ok(group)
            }
            None => Err(AppError::NotFound(format!(
                "Group {}/{} not found",
                organization, name
            ))),
        }
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
        let mut conn = self.pool.get().await?;
        let key = Self::group_key(organization, name);

        // Get existing group
        let mut group = self.get_group(organization, name).await?;

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
        let mut conn = self.pool.get().await?;
        let key = Self::group_key(organization, name);

        // Check if group exists
        let group = self.get_group(organization, name).await?;

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

        info!(
            "Successfully deleted group: organization={}, name={}",
            organization, name
        );
        Ok(())
    }

    async fn list_groups(&self, organization: &str) -> Result<Vec<Group>> {
        info!("Listing groups: organization={}", organization);
        let mut conn = self.pool.get().await?;
        let org_groups_key = Self::org_groups_key(organization);

        let group_names: Vec<String> = conn.smembers(&org_groups_key).await?;

        let mut groups = Vec::new();
        for name in group_names {
            if let Ok(group) = self.get_group(organization, &name).await {
                groups.push(group);
            }
        }

        Ok(groups)
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
        let mut conn = self.pool.get().await?;

        // Verify user exists
        self.get_user(organization, username).await?;

        // Get group
        let mut group = self.get_group(organization, group_name).await?;

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
        let mut conn = self.pool.get().await?;

        // Get group
        let mut group = self.get_group(organization, group_name).await?;

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
        let mut conn = self.pool.get().await?;
        let user_groups_key = Self::user_groups_key(organization, username);

        let group_names: Vec<String> = conn.smembers(&user_groups_key).await?;

        let mut groups = Vec::new();
        for name in group_names {
            if let Ok(group) = self.get_group(organization, &name).await {
                groups.push(group);
            }
        }

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
        // Simple implementation: list all users and filter by username or email
        let users = self.list_users(organization).await?;

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
        // Simple implementation: list all groups and filter by name or description
        let groups = self.list_groups(organization).await?;

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
        let mut conn = self.pool.get().await?;
        let result: deadpool_redis::redis::RedisResult<String> = deadpool_redis::redis::cmd("PING")
            .query_async(&mut conn)
            .await;
        let is_healthy = result.is_ok();
        info!("Database health check result: {}", is_healthy);
        Ok(is_healthy)
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
