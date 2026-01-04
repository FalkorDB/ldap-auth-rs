use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub organization: String,
    pub username: String,
    // Note: This is stored in Redis but should be excluded from API responses
    pub password_hash: String,
    pub email: Option<String>,
    pub full_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// User response for API (excludes password_hash)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserResponse {
    pub organization: String,
    pub username: String,
    pub email: Option<String>,
    pub full_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            organization: user.organization,
            username: user.username,
            email: user.email,
            full_name: user.full_name,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCreate {
    pub organization: String,
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub full_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserUpdate {
    pub password: Option<String>,
    pub email: Option<String>,
    pub full_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Group {
    pub organization: String,
    pub name: String,
    pub description: Option<String>,
    pub members: Vec<String>, // usernames
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCreate {
    pub organization: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupUpdate {
    pub description: Option<String>,
}

impl User {
    pub fn new(org: String, username: String, password_hash: String) -> Self {
        let now = Utc::now();
        Self {
            organization: org,
            username,
            password_hash,
            email: None,
            full_name: None,
            created_at: now,
            updated_at: now,
        }
    }
    #[allow(dead_code)]
    pub fn to_dn(&self, base_dn: &str) -> String {
        format!("cn={},ou={},{}", self.username, self.organization, base_dn)
    }
}

impl Group {
    pub fn new(org: String, name: String) -> Self {
        let now = Utc::now();
        Self {
            organization: org,
            name,
            description: None,
            members: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    #[allow(dead_code)]
    pub fn to_dn(&self, base_dn: &str) -> String {
        format!(
            "cn={},ou=groups,ou={},{}",
            self.name, self.organization, base_dn
        )
    }

    pub fn add_member(&mut self, username: String) -> bool {
        if !self.members.contains(&username) {
            self.members.push(username);
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    pub fn remove_member(&mut self, username: &str) -> bool {
        if let Some(pos) = self.members.iter().position(|u| u == username) {
            self.members.remove(pos);
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let user = User::new(
            "acme".to_string(),
            "john".to_string(),
            "hashed_password".to_string(),
        );
        assert_eq!(user.organization, "acme");
        assert_eq!(user.username, "john");
        assert_eq!(user.password_hash, "hashed_password");
    }

    #[test]
    fn test_user_dn() {
        let user = User::new("acme".to_string(), "john".to_string(), "hash".to_string());
        let dn = user.to_dn("dc=example,dc=com");
        assert_eq!(dn, "cn=john,ou=acme,dc=example,dc=com");
    }

    #[test]
    fn test_group_add_member() {
        let mut group = Group::new("acme".to_string(), "developers".to_string());
        assert!(group.add_member("john".to_string()));
        assert_eq!(group.members.len(), 1);
        assert!(!group.add_member("john".to_string())); // duplicate
        assert_eq!(group.members.len(), 1);
    }

    #[test]
    fn test_group_remove_member() {
        let mut group = Group::new("acme".to_string(), "developers".to_string());
        group.add_member("john".to_string());
        assert!(group.remove_member("john"));
        assert_eq!(group.members.len(), 0);
        assert!(!group.remove_member("john")); // already removed
    }

    #[test]
    fn test_group_dn() {
        let group = Group::new("acme".to_string(), "developers".to_string());
        let dn = group.to_dn("dc=example,dc=com");
        assert_eq!(dn, "cn=developers,ou=groups,ou=acme,dc=example,dc=com");
    }
}
