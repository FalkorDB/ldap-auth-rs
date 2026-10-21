use crate::error::{AppError, Result};
use argon2::{
    Argon2,
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
        rand_core::{OsRng, RngCore},
    },
};
use blake2::{Blake2bMac512, digest::Mac};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// Upper bound on cached verifications, so memory stays bounded under churn.
const VERIFY_CACHE_MAX_ENTRIES: usize = 10_000;

/// Limits concurrent Argon2 operations to the CPU budget. Each one uses ~19 MiB
/// and a full core, so an unbounded burst of binds would exhaust memory and
/// starve the threads that read Redis replies.
static HASHING_PERMITS: Lazy<Semaphore> = Lazy::new(|| {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    Semaphore::new(cpus)
});

async fn run_hashing<T, F>(task: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let _permit = HASHING_PERMITS
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Password hashing unavailable: {}", e)))?;
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|e| AppError::Internal(format!("Password hashing task failed: {}", e)))?
}

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
    run_hashing(move || hash_password(&password)).await
}

/// Verify a password on the blocking thread pool. See [`hash_password_blocking`].
pub async fn verify_password_blocking(password: String, hash: String) -> Result<bool> {
    run_hashing(move || verify_password(&password, &hash)).await
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
        let Some(expires_at) = Instant::now().checked_add(self.ttl) else {
            return;
        };
        let key = (organization.to_string(), username.to_string());
        let entry = VerifyCacheEntry {
            stored_hash: stored_hash.to_string(),
            password_mac: self.password_mac(password),
            expires_at,
        };
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= VERIFY_CACHE_MAX_ENTRIES && !entries.contains_key(&key) {
            let now = Instant::now();
            entries.retain(|_, e| e.expires_at > now);
            if entries.len() >= VERIFY_CACHE_MAX_ENTRIES {
                // Still full of live entries: evict the one closest to expiry.
                if let Some(victim) = entries
                    .iter()
                    .min_by_key(|(_, e)| e.expires_at)
                    .map(|(k, _)| k.clone())
                {
                    entries.remove(&victim);
                }
            }
        }
        entries.insert(key, entry);
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

    /// Random per-test secret, so no credential is hard-coded in the tests.
    fn secret() -> String {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[tokio::test]
    async fn test_blocking_variants() {
        let (pw, wrong) = (secret(), secret());
        let hash = hash_password_blocking(pw.clone()).await.unwrap();
        assert!(verify_password_blocking(pw, hash.clone()).await.unwrap());
        assert!(!verify_password_blocking(wrong, hash).await.unwrap());
    }

    #[test]
    fn test_verify_cache_hit_and_miss() {
        let cache = VerifyCache::new(Duration::from_secs(60));
        let (pw, other_pw, hash1, hash2) = (secret(), secret(), secret(), secret());
        assert!(!cache.is_verified("org", "user", &pw, &hash1));

        cache.record_success("org", "user", &pw, &hash1);
        assert!(cache.is_verified("org", "user", &pw, &hash1));

        // Wrong password, other user, or changed stored hash must miss.
        assert!(!cache.is_verified("org", "user", &other_pw, &hash1));
        assert!(!cache.is_verified("org", "other", &pw, &hash1));
        assert!(!cache.is_verified("org", "user", &pw, &hash2));
        // A stored-hash mismatch evicts the entry.
        assert!(!cache.is_verified("org", "user", &pw, &hash1));
    }

    #[test]
    fn test_verify_cache_invalidate() {
        let cache = VerifyCache::new(Duration::from_secs(60));
        let (pw, hash) = (secret(), secret());
        cache.record_success("org", "user", &pw, &hash);
        cache.invalidate("org", "user");
        assert!(!cache.is_verified("org", "user", &pw, &hash));
    }

    #[test]
    fn test_verify_cache_expiry_and_disabled() {
        let (pw, hash) = (secret(), secret());
        let cache = VerifyCache::new(Duration::from_millis(1));
        cache.record_success("org", "user", &pw, &hash);
        std::thread::sleep(Duration::from_millis(5));
        assert!(!cache.is_verified("org", "user", &pw, &hash));

        let disabled = VerifyCache::new(Duration::ZERO);
        disabled.record_success("org", "user", &pw, &hash);
        assert!(!disabled.is_verified("org", "user", &pw, &hash));
    }

    #[test]
    fn test_verify_cache_huge_ttl_does_not_panic() {
        let (pw, hash) = (secret(), secret());
        let cache = VerifyCache::new(Duration::MAX);
        cache.record_success("org", "user", &pw, &hash);
        assert!(!cache.is_verified("org", "user", &pw, &hash));
    }

    #[test]
    fn test_verify_cache_full_evicts_single_entry() {
        let cache = VerifyCache::new(Duration::from_secs(60));
        let (pw, hash) = (secret(), secret());
        for i in 0..VERIFY_CACHE_MAX_ENTRIES {
            cache.record_success("org", &format!("user{}", i), &pw, &hash);
        }
        cache.record_success("org", "newcomer", &pw, &hash);
        let len = cache.entries.lock().unwrap().len();
        assert_eq!(len, VERIFY_CACHE_MAX_ENTRIES);
        assert!(cache.is_verified("org", "newcomer", &pw, &hash));
        assert!(cache.is_verified("org", "user9999", &pw, &hash));
    }
}
