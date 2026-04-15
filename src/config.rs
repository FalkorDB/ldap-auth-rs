use serde::Deserialize;
use std::env;

#[derive(Clone, Deserialize)]
pub struct Config {
    pub redis_host: String,
    pub redis_port: u16,
    pub redis_username: Option<String>,
    pub redis_password: Option<String>,
    pub redis_replica_host: Option<String>,
    pub redis_replica_port: Option<u16>,
    pub redis_replica_username: Option<String>,
    pub redis_replica_password: Option<String>,
    pub api_port: u16,
    pub ldap_port: u16,
    pub ldap_base_dn: String,
    pub ldap_search_bind_org: Option<String>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub enable_tls: bool,
}

impl Config {
    pub fn from_env() -> Self {
        let enable_tls = env::var("ENABLE_TLS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(false);

        Self {
            redis_host: env::var("REDIS_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            redis_port: env::var("REDIS_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(6379),
            redis_username: env::var("REDIS_USERNAME").ok(),
            redis_password: env::var("REDIS_PASSWORD").ok(),
            redis_replica_host: env::var("REDIS_REPLICA_HOST").ok(),
            redis_replica_port: env::var("REDIS_REPLICA_PORT")
                .ok()
                .and_then(|s| s.parse().ok()),
            redis_replica_username: env::var("REDIS_REPLICA_USERNAME").ok(),
            redis_replica_password: env::var("REDIS_REPLICA_PASSWORD").ok(),
            api_port: env::var("API_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8080),
            ldap_port: env::var("LDAP_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3389), // Non-privileged port
            ldap_base_dn: env::var("LDAP_BASE_DN")
                .unwrap_or_else(|_| "dc=example,dc=com".to_string()),
            ldap_search_bind_org: env::var("LDAP_SEARCH_BIND_ORG").ok(),
            tls_cert_path: env::var("TLS_CERT_PATH").ok(),
            tls_key_path: env::var("TLS_KEY_PATH").ok(),
            enable_tls,
        }
    }

    pub fn api_address(&self) -> String {
        format!("0.0.0.0:{}", self.api_port)
    }

    pub fn ldap_address(&self) -> String {
        format!("0.0.0.0:{}", self.ldap_port)
    }

    pub fn redis_url(&self) -> String {
        Self::build_redis_url(
            &self.redis_host,
            self.redis_port,
            self.redis_username.as_deref(),
            self.redis_password.as_deref(),
        )
    }

    pub fn redis_replica_url(&self) -> Option<String> {
        let host = self.redis_replica_host.as_deref()?;
        let port = self.redis_replica_port.unwrap_or(self.redis_port);
        let username = self
            .redis_replica_username
            .as_deref()
            .or(self.redis_username.as_deref());
        let password = self
            .redis_replica_password
            .as_deref()
            .or(self.redis_password.as_deref());

        Some(Self::build_redis_url(host, port, username, password))
    }

    fn build_redis_url(
        host: &str,
        port: u16,
        username: Option<&str>,
        password: Option<&str>,
    ) -> String {
        let mut url = "redis://".to_string();

        if let (Some(username), Some(password)) = (username, password) {
            // ACL authentication with username and password
            let encoded_password = urlencoding::encode(password);
            url.push_str(&format!("{}:{}@", username, encoded_password));
        } else if let Some(password) = password {
            // Password-only authentication (default user)
            let encoded_password = urlencoding::encode(password);
            url.push_str(&format!(":{}@", encoded_password));
        }
        url.push_str(&format!("{}:{}", host, port));
        url
    }

    /// Validate configuration at startup
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate Redis port range
        if self.redis_port == 0 {
            anyhow::bail!("REDIS_PORT cannot be 0");
        }

        if self.redis_replica_host.is_some() && self.redis_replica_port == Some(0) {
            anyhow::bail!("REDIS_REPLICA_PORT cannot be 0");
        }

        // Validate API port
        if self.api_port == 0 {
            anyhow::bail!("API_PORT cannot be 0");
        }

        // Validate LDAP port
        if self.ldap_port == 0 {
            anyhow::bail!("LDAP_PORT cannot be 0");
        }

        // Check TLS configuration is complete if enabled
        if self.enable_tls {
            if let Some(cert_path) = &self.tls_cert_path {
                if !std::path::Path::new(cert_path).exists() {
                    anyhow::bail!("TLS certificate file not found: {}", cert_path);
                }
            } else {
                anyhow::bail!("ENABLE_TLS is true but TLS_CERT_PATH is not set");
            }

            if let Some(key_path) = &self.tls_key_path {
                if !std::path::Path::new(key_path).exists() {
                    anyhow::bail!("TLS key file not found: {}", key_path);
                }
            } else {
                anyhow::bail!("ENABLE_TLS is true but TLS_KEY_PATH is not set");
            }
        }

        // Validate addresses are parseable
        self.api_address()
            .parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow::anyhow!("Invalid API_PORT {}: {}", self.api_port, e))?;

        self.ldap_address()
            .parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow::anyhow!("Invalid LDAP_PORT {}: {}", self.ldap_port, e))?;

        Ok(())
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("redis_host", &self.redis_host)
            .field("redis_port", &self.redis_port)
            .field("redis_username", &self.redis_username)
            .field(
                "redis_password",
                &self.redis_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field("redis_replica_host", &self.redis_replica_host)
            .field("redis_replica_port", &self.redis_replica_port)
            .field("redis_replica_username", &self.redis_replica_username)
            .field(
                "redis_replica_password",
                &self.redis_replica_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field("api_port", &self.api_port)
            .field("ldap_port", &self.ldap_port)
            .field("ldap_base_dn", &self.ldap_base_dn)
            .field("ldap_search_bind_org", &self.ldap_search_bind_org)
            .field("tls_cert_path", &self.tls_cert_path)
            .field("tls_key_path", &self.tls_key_path)
            .field("enable_tls", &self.enable_tls)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    fn base_config() -> Config {
        Config {
            redis_host: "primary.redis.local".to_string(),
            redis_port: 6379,
            redis_username: Some("primary-user".to_string()),
            redis_password: Some("primary-pass".to_string()),
            redis_replica_host: None,
            redis_replica_port: None,
            redis_replica_username: None,
            redis_replica_password: None,
            api_port: 8080,
            ldap_port: 3389,
            ldap_base_dn: "dc=example,dc=com".to_string(),
            ldap_search_bind_org: None,
            tls_cert_path: None,
            tls_key_path: None,
            enable_tls: false,
        }
    }

    #[test]
    fn test_replica_url_inherits_primary_auth() {
        let mut config = base_config();
        config.redis_replica_host = Some("replica.redis.local".to_string());

        assert_eq!(
            config.redis_replica_url().as_deref(),
            Some("redis://primary-user:primary-pass@replica.redis.local:6379")
        );
    }

    #[test]
    fn test_replica_url_overrides_primary_auth() {
        let mut config = base_config();
        config.redis_replica_host = Some("replica.redis.local".to_string());
        config.redis_replica_port = Some(6380);
        config.redis_replica_username = Some("replica-user".to_string());
        config.redis_replica_password = Some("replica-pass".to_string());

        assert_eq!(
            config.redis_replica_url().as_deref(),
            Some("redis://replica-user:replica-pass@replica.redis.local:6380")
        );
    }
}
