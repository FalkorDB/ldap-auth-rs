use async_trait::async_trait;
use crate::error::Result;
use crate::models::{User, Group, UserCreate, UserUpdate, GroupCreate, GroupUpdate};

/// Database service trait for abstracting storage operations
/// This allows for easy testing and switching between different storage backends
#[async_trait]
pub trait DbService: Send + Sync {
    // User operations
    
    /// Create a new user
    async fn create_user(&self, user: UserCreate) -> Result<User>;
    
    /// Get a user by organization and username
    async fn get_user(&self, organization: &str, username: &str) -> Result<User>;
    
    /// Update an existing user
    async fn update_user(&self, organization: &str, username: &str, update: UserUpdate) -> Result<User>;
    
    /// Delete a user
    async fn delete_user(&self, organization: &str, username: &str) -> Result<()>;
    
    /// List all users in an organization
    async fn list_users(&self, organization: &str) -> Result<Vec<User>>;
    
    /// Verify user credentials (for LDAP bind)
    async fn verify_user_password(&self, organization: &str, username: &str, password: &str) -> Result<bool>;
    
    // Group operations
    
    /// Create a new group
    async fn create_group(&self, group: GroupCreate) -> Result<Group>;
    
    /// Get a group by organization and name
    async fn get_group(&self, organization: &str, name: &str) -> Result<Group>;
    
    /// Update an existing group
    async fn update_group(&self, organization: &str, name: &str, update: GroupUpdate) -> Result<Group>;
    
    /// Delete a group
    async fn delete_group(&self, organization: &str, name: &str) -> Result<()>;
    
    /// List all groups in an organization
    async fn list_groups(&self, organization: &str) -> Result<Vec<Group>>;
    
    /// Add a user to a group
    async fn add_user_to_group(&self, organization: &str, group_name: &str, username: &str) -> Result<Group>;
    
    /// Remove a user from a group
    async fn remove_user_from_group(&self, organization: &str, group_name: &str, username: &str) -> Result<Group>;
    
    /// Get all groups a user belongs to
    async fn get_user_groups(&self, organization: &str, username: &str) -> Result<Vec<Group>>;
    
    // LDAP-specific operations
    
    /// Search for users matching a filter
    async fn search_users(&self, organization: &str, filter: &str) -> Result<Vec<User>>;
    
    /// Search for groups matching a filter
    async fn search_groups(&self, organization: &str, filter: &str) -> Result<Vec<Group>>;
    
    /// Health check for the database connection
    async fn health_check(&self) -> Result<bool>;
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use mockall::mock;

    mock! {
        pub DbService {}

        #[async_trait]
        impl DbService for DbService {
            async fn create_user(&self, user: UserCreate) -> Result<User>;
            async fn get_user(&self, organization: &str, username: &str) -> Result<User>;
            async fn update_user(&self, organization: &str, username: &str, update: UserUpdate) -> Result<User>;
            async fn delete_user(&self, organization: &str, username: &str) -> Result<()>;
            async fn list_users(&self, organization: &str) -> Result<Vec<User>>;
            async fn verify_user_password(&self, organization: &str, username: &str, password: &str) -> Result<bool>;
            async fn create_group(&self, group: GroupCreate) -> Result<Group>;
            async fn get_group(&self, organization: &str, name: &str) -> Result<Group>;
            async fn update_group(&self, organization: &str, name: &str, update: GroupUpdate) -> Result<Group>;
            async fn delete_group(&self, organization: &str, name: &str) -> Result<()>;
            async fn list_groups(&self, organization: &str) -> Result<Vec<Group>>;
            async fn add_user_to_group(&self, organization: &str, group_name: &str, username: &str) -> Result<Group>;
            async fn remove_user_from_group(&self, organization: &str, group_name: &str, username: &str) -> Result<Group>;
            async fn get_user_groups(&self, organization: &str, username: &str) -> Result<Vec<Group>>;
            async fn search_users(&self, organization: &str, filter: &str) -> Result<Vec<User>>;
            async fn search_groups(&self, organization: &str, filter: &str) -> Result<Vec<Group>>;
            async fn health_check(&self) -> Result<bool>;
        }
    }
}
