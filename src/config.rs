use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub redis_host: String,
    pub redis_port: u16,
    pub redis_username: Option<String>,
    pub redis_password: Option<String>,
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
        let mut url = "redis://".to_string();

        if let (Some(username), Some(password)) = (&self.redis_username, &self.redis_password) {
            url.push_str(&format!("{}:{}@", username, password));
        } else if let Some(username) = &self.redis_username {
            url.push_str(&format!("{}@", username));
        } else if let Some(password) = &self.redis_password {
            url.push_str(&format!(":{}@", password));
        }

        url.push_str(&format!("{}:{}", self.redis_host, self.redis_port));
        url
    }

    /// Validate configuration at startup
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate Redis port range
        if self.redis_port == 0 {
            anyhow::bail!("REDIS_PORT cannot be 0");
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
