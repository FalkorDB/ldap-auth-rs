use async_trait::async_trait;
use chrono::Utc;
use deadpool_redis::{Config as PoolConfig, Pool, Runtime};
use redis::AsyncCommands;
use tracing::{info, warn};

use crate::db::DbService;
use crate::error::{AppError, Result};
use crate::models::{Group, GroupCreate, GroupUpdate, User, UserCreate, UserUpdate};
use crate::password::{hash_password, verify_password};

/// Redis-based implementation of the DbService trait
pub struct RedisDbService {
    pool: Pool,
}

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
                    return Ok(Self { pool });
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

        let _: String = redis::cmd("PING")
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
}

#[async_trait]
impl DbService for RedisDbService {
    async fn create_user(&self, user: UserCreate) -> Result<User> {
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

        Ok(new_user)
    }

    async fn get_user(&self, organization: &str, username: &str) -> Result<User> {
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

        Ok(user)
    }

    async fn delete_user(&self, organization: &str, username: &str) -> Result<()> {
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

        // Remove from all groups
        let groups = self.get_user_groups(organization, username).await?;
        for group in groups {
            let _ = self
                .remove_user_from_group(organization, &group.name, username)
                .await;
        }

        // Delete user
        conn.del::<_, ()>(&key).await?;

        // Remove from organization's user list
        let org_users_key = Self::org_users_key(organization);
        conn.srem::<_, _, ()>(&org_users_key, username).await?;

        // Remove user's groups set
        let user_groups_key = Self::user_groups_key(organization, username);
        conn.del::<_, ()>(&user_groups_key).await?;

        Ok(())
    }

    async fn list_users(&self, organization: &str) -> Result<Vec<User>> {
        let mut conn = self.pool.get().await?;
        let org_users_key = Self::org_users_key(organization);

        let usernames: Vec<String> = conn.smembers(&org_users_key).await?;

        let mut users = Vec::new();
        for username in usernames {
            if let Ok(user) = self.get_user(organization, &username).await {
                users.push(user);
            }
        }

        Ok(users)
    }

    async fn verify_user_password(
        &self,
        organization: &str,
        username: &str,
        password: &str,
    ) -> Result<bool> {
        let user = self.get_user(organization, username).await?;
        verify_password(password, &user.password_hash)
    }

    async fn create_group(&self, group: GroupCreate) -> Result<Group> {
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

        Ok(new_group)
    }

    async fn get_group(&self, organization: &str, name: &str) -> Result<Group> {
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

        Ok(group)
    }

    async fn delete_group(&self, organization: &str, name: &str) -> Result<()> {
        let mut conn = self.pool.get().await?;
        let key = Self::group_key(organization, name);

        // Check if group exists
        let group = self.get_group(organization, name).await?;

        // Remove group from all users' group sets
        for username in &group.members {
            let user_groups_key = Self::user_groups_key(organization, username);
            let _: redis::RedisResult<i32> = conn.srem(&user_groups_key, name).await;
        }

        // Delete group
        conn.del::<_, ()>(&key).await?;

        // Remove from organization's group list
        let org_groups_key = Self::org_groups_key(organization);
        conn.srem::<_, _, ()>(&org_groups_key, name).await?;

        Ok(())
    }

    async fn list_groups(&self, organization: &str) -> Result<Vec<Group>> {
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

        Ok(group)
    }

    async fn remove_user_from_group(
        &self,
        organization: &str,
        group_name: &str,
        username: &str,
    ) -> Result<Group> {
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

        Ok(group)
    }

    async fn get_user_groups(&self, organization: &str, username: &str) -> Result<Vec<Group>> {
        let mut conn = self.pool.get().await?;
        let user_groups_key = Self::user_groups_key(organization, username);

        let group_names: Vec<String> = conn.smembers(&user_groups_key).await?;

        let mut groups = Vec::new();
        for name in group_names {
            if let Ok(group) = self.get_group(organization, &name).await {
                groups.push(group);
            }
        }

        Ok(groups)
    }

    async fn search_users(&self, organization: &str, filter: &str) -> Result<Vec<User>> {
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

        Ok(filtered)
    }

    async fn search_groups(&self, organization: &str, filter: &str) -> Result<Vec<Group>> {
        // Simple implementation: list all groups and filter by name or description
        let groups = self.list_groups(organization).await?;

        let filtered: Vec<Group> = groups
            .into_iter()
            .filter(|g| {
                g.name.contains(filter)
                    || g.description.as_ref().is_some_and(|d| d.contains(filter))
            })
            .collect();

        Ok(filtered)
    }

    async fn health_check(&self) -> Result<bool> {
        let mut conn = self.pool.get().await?;
        let result: redis::RedisResult<String> = redis::cmd("PING").query_async(&mut conn).await;
        Ok(result.is_ok())
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
