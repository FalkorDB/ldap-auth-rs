use crate::error::{AppError, Result};
use argon2::{
    Argon2,
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
        rand_core::{OsRng, RngCore},
    },
};
use blake2::{Blake2bMac512, digest::Mac};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Upper bound on cached verifications, so memory stays bounded under churn.
const VERIFY_CACHE_MAX_ENTRIES: usize = 10_000;

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| AppError::Internal(format!("Invalid password hash: {}", e)))?;

    let argon2 = Argon2::default();
    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Hash a password on the blocking thread pool.
///
/// Argon2 is deliberately CPU-expensive; running it on the async worker threads
/// stalls every other task on that thread, including the tasks that read Redis
/// replies, which then hit the Redis response timeout.
pub async fn hash_password_blocking(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| AppError::Internal(format!("Password hashing task failed: {}", e)))?
}

/// Verify a password on the blocking thread pool. See [`hash_password_blocking`].
pub async fn verify_password_blocking(password: String, hash: String) -> Result<bool> {
    tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .map_err(|e| AppError::Internal(format!("Password verification task failed: {}", e)))?
}

struct VerifyCacheEntry {
    stored_hash: String,
    password_mac: Vec<u8>,
    expires_at: Instant,
}

/// Short-lived cache of successful password verifications.
///
/// Clients such as the FalkorDB LDAP module re-bind with the same service
/// credentials on every login, so without a cache each login pays for an extra
/// Argon2 verification. Entries are keyed by user and store a keyed BLAKE2b MAC
/// of the password (the key is random per process and never leaves memory)
/// together with the stored Argon2 hash, so a password change invalidates the
/// entry immediately. Only successes are cached; failures always run Argon2.
pub struct VerifyCache {
    ttl: Duration,
    mac_key: [u8; 32],
    entries: Mutex<HashMap<(String, String), VerifyCacheEntry>>,
}

impl VerifyCache {
    /// Create a cache. A zero `ttl` disables caching.
    pub fn new(ttl: Duration) -> Self {
        let mut mac_key = [0u8; 32];
        OsRng.fill_bytes(&mut mac_key);
        Self {
            ttl,
            mac_key,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn mac(&self) -> Blake2bMac512 {
        Blake2bMac512::new_from_slice(&self.mac_key).expect("32-byte key is valid for BLAKE2b")
    }

    fn password_mac(&self, password: &str) -> Vec<u8> {
        let mut mac = self.mac();
        mac.update(password.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// Returns true if this exact password was verified against this exact
    /// stored hash within the TTL.
    pub fn is_verified(
        &self,
        organization: &str,
        username: &str,
        password: &str,
        stored_hash: &str,
    ) -> bool {
        if self.ttl.is_zero() {
            return false;
        }
        let key = (organization.to_string(), username.to_string());
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = entries.get(&key) else {
            return false;
        };
        if entry.expires_at <= Instant::now() || entry.stored_hash != stored_hash {
            entries.remove(&key);
            return false;
        }
        let mut mac = self.mac();
        mac.update(password.as_bytes());
        // Constant-time comparison.
        mac.verify_slice(&entry.password_mac).is_ok()
    }

    /// Record a successful verification.
    pub fn record_success(
        &self,
        organization: &str,
        username: &str,
        password: &str,
        stored_hash: &str,
    ) {
        if self.ttl.is_zero() {
            return;
        }
        let entry = VerifyCacheEntry {
            stored_hash: stored_hash.to_string(),
            password_mac: self.password_mac(password),
            expires_at: Instant::now() + self.ttl,
        };
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= VERIFY_CACHE_MAX_ENTRIES {
            let now = Instant::now();
            entries.retain(|_, e| e.expires_at > now);
            if entries.len() >= VERIFY_CACHE_MAX_ENTRIES {
                entries.clear();
            }
        }
        entries.insert((organization.to_string(), username.to_string()), entry);
    }

    /// Drop any cached verification for a user.
    pub fn invalidate(&self, organization: &str, username: &str) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.remove(&(organization.to_string(), username.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_different_hashes() {
        let password = "same_password";
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();

        // Hashes should be different due to different salts
        assert_ne!(hash1, hash2);

        // But both should verify correctly
        assert!(verify_password(password, &hash1).unwrap());
        assert!(verify_password(password, &hash2).unwrap());
    }

    #[tokio::test]
    async fn test_blocking_variants() {
        let hash = hash_password_blocking("pw".to_string()).await.unwrap();
        assert!(
            verify_password_blocking("pw".to_string(), hash.clone())
                .await
                .unwrap()
        );
        assert!(
            !verify_password_blocking("nope".to_string(), hash)
                .await
                .unwrap()
        );
    }

    #[test]
    fn test_verify_cache_hit_and_miss() {
        let cache = VerifyCache::new(Duration::from_secs(60));
        assert!(!cache.is_verified("org", "user", "pw", "hash1"));

        cache.record_success("org", "user", "pw", "hash1");
        assert!(cache.is_verified("org", "user", "pw", "hash1"));

        // Wrong password, other user, or changed stored hash must miss.
        assert!(!cache.is_verified("org", "user", "other", "hash1"));
        assert!(!cache.is_verified("org", "other", "pw", "hash1"));
        assert!(!cache.is_verified("org", "user", "pw", "hash2"));
        // A stored-hash mismatch evicts the entry.
        assert!(!cache.is_verified("org", "user", "pw", "hash1"));
    }

    #[test]
    fn test_verify_cache_invalidate() {
        let cache = VerifyCache::new(Duration::from_secs(60));
        cache.record_success("org", "user", "pw", "hash1");
        cache.invalidate("org", "user");
        assert!(!cache.is_verified("org", "user", "pw", "hash1"));
    }

    #[test]
    fn test_verify_cache_expiry_and_disabled() {
        let cache = VerifyCache::new(Duration::from_millis(1));
        cache.record_success("org", "user", "pw", "hash1");
        std::thread::sleep(Duration::from_millis(5));
        assert!(!cache.is_verified("org", "user", "pw", "hash1"));

        let disabled = VerifyCache::new(Duration::ZERO);
        disabled.record_success("org", "user", "pw", "hash1");
        assert!(!disabled.is_verified("org", "user", "pw", "hash1"));
    }
}
