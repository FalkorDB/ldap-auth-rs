/// Redis-backed regression tests for the password verification cache:
/// a cached bind must not outlive a password change or user deletion.
use ldap_auth_rs::{
    db::DbService,
    error::AppError,
    metrics::custom::PASSWORD_VERIFY_CACHE,
    models::{UserCreate, UserUpdate},
    redis_db::{RedisDbService, RedisOptions},
};
use std::time::Duration;

async fn setup_cached_db() -> RedisDbService {
    let redis_url =
        std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6390/15".to_string());
    let options = RedisOptions {
        // Long enough that nothing expires during the test.
        verify_cache_ttl: Duration::from_secs(300),
        ..RedisOptions::default()
    };

    RedisDbService::new_with_options(&redis_url, None, Some(1), options)
        .await
        .expect("Failed to connect to Redis")
}

/// (hits, misses) recorded for an organization so far.
fn cache_counts(org: &str) -> (f64, f64) {
    (
        PASSWORD_VERIFY_CACHE.with_label_values(&[org, "hit"]).get(),
        PASSWORD_VERIFY_CACHE
            .with_label_values(&[org, "miss"])
            .get(),
    )
}

/// Random secret per test, so no credential is hard-coded.
fn secret() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[tokio::test]
async fn test_cached_bind_revoked_by_password_change_and_deletion() {
    let db = setup_cached_db().await;
    // Unique org so the process-global metric counters start at zero.
    let org_name = format!("verify-cache-org-{}", uuid::Uuid::new_v4());
    let org = org_name.as_str();
    let username = format!("user-{}", uuid::Uuid::new_v4());
    let (old_password, new_password) = (secret(), secret());

    db.create_user(UserCreate {
        organization: org.to_string(),
        username: username.clone(),
        password: old_password.clone(),
        email: None,
        full_name: None,
    })
    .await
    .expect("create user");

    // First bind runs Argon2; the second is served from the cache.
    assert!(
        db.verify_user_password(org, &username, &old_password)
            .await
            .unwrap()
    );
    assert_eq!(cache_counts(org), (0.0, 1.0));
    assert!(
        db.verify_user_password(org, &username, &old_password)
            .await
            .unwrap()
    );
    assert_eq!(cache_counts(org), (1.0, 1.0));

    // Change the password: the cached old password must stop working.
    db.update_user(
        org,
        &username,
        UserUpdate {
            password: Some(new_password.clone()),
            email: None,
            full_name: None,
        },
    )
    .await
    .expect("update password");

    assert!(
        !db.verify_user_password(org, &username, &old_password)
            .await
            .unwrap()
    );
    assert!(
        db.verify_user_password(org, &username, &new_password)
            .await
            .unwrap()
    );
    // Both went through Argon2: the stale cache entry was not used.
    assert_eq!(cache_counts(org), (1.0, 3.0));
    // Cached now.
    assert!(
        db.verify_user_password(org, &username, &new_password)
            .await
            .unwrap()
    );
    assert_eq!(cache_counts(org), (2.0, 3.0));

    // Delete the user: the cached new password must stop working.
    db.delete_user(org, &username).await.expect("delete user");

    let result = db.verify_user_password(org, &username, &new_password).await;
    assert!(
        matches!(result, Err(AppError::NotFound(_))),
        "bind after deletion should fail with NotFound, got {:?}",
        result.map_err(|e| e.to_string())
    );
}
