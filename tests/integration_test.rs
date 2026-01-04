use ldap_auth_rs::{
    api,
    db::DbService,
    redis_db::RedisDbService,
};
use reqwest::Client;
use serde_json::json;
use std::sync::Arc;

// Consistent token for all integration tests (must match auth_integration_test.rs)
const TEST_BEARER_TOKEN: &str = "test-bearer-token-12345";

async fn setup_test_db() -> Arc<dyn DbService> {
    let redis_url =
        std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    Arc::new(
        RedisDbService::new(&redis_url)
            .await
            .expect("Failed to connect to Redis"),
    )
}

#[tokio::test]
async fn test_api_user_crud() {
    // Set up authentication token
    // Token set via TEST_BEARER_TOKEN constant;
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);

    let db = setup_test_db().await;
    let app = api::create_router(db);

    // Start test server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = Client::new();
    let base_url = format!("http://{}", addr);

    // Create user
    let user_create = json!({
        "organization": "test-org",
        "username": "testuser",
        "password": "testpass123",
        "email": "test@example.com"
    });

    let response = client
        .post(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&user_create)
        .send()
        .await
        .expect("Failed to create user");

    assert_eq!(response.status(), 201);

    // Get user
    let response = client
        .get(format!("{}/api/users/test-org/testuser", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .expect("Failed to get user");

    assert_eq!(response.status(), 200);

    // Update user
    let user_update = json!({
        "email": "updated@example.com"
    });

    let response = client
        .put(format!("{}/api/users/test-org/testuser", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&user_update)
        .send()
        .await
        .expect("Failed to update user");

    assert_eq!(response.status(), 200);

    // Delete user
    let response = client
        .delete(format!("{}/api/users/test-org/testuser", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .expect("Failed to delete user");

    assert_eq!(response.status(), 204);
}

#[tokio::test]
async fn test_api_group_crud() {
    // Set up authentication token
    // Token set via TEST_BEARER_TOKEN constant;
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);

    let db = setup_test_db().await;
    let app = api::create_router(db.clone());

    // Start test server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = Client::new();
    let base_url = format!("http://{}", addr);

    // Create user first
    let user_create = json!({
        "organization": "test-org",
        "username": "groupuser",
        "password": "testpass123"
    });

    client
        .post(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&user_create)
        .send()
        .await
        .expect("Failed to create user");

    // Create group
    let group_create = json!({
        "organization": "test-org",
        "name": "testgroup",
        "description": "Test group"
    });

    let response = client
        .post(format!("{}/api/groups", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&group_create)
        .send()
        .await
        .expect("Failed to create group");

    assert_eq!(response.status(), 201);

    // Add member to group
    let add_member = json!({
        "username": "groupuser"
    });

    let response = client
        .post(format!(
            "{}/api/groups/test-org/testgroup/members",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&add_member)
        .send()
        .await
        .expect("Failed to add member");

    assert_eq!(response.status(), 200);

    // Get group
    let response = client
        .get(format!("{}/api/groups/test-org/testgroup", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .expect("Failed to get group");

    assert_eq!(response.status(), 200);

    // Remove member from group
    let response = client
        .delete(format!(
            "{}/api/groups/test-org/testgroup/members/groupuser",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .expect("Failed to remove member");

    assert_eq!(response.status(), 200);

    // Delete group
    let response = client
        .delete(format!("{}/api/groups/test-org/testgroup", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .expect("Failed to delete group");

    assert_eq!(response.status(), 204);

    // Cleanup user
    client
        .delete(format!("{}/api/users/test-org/groupuser", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .ok();
}

#[tokio::test]
async fn test_health_check() {
    let db = setup_test_db().await;
    let app = api::create_router(db);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = Client::new();
    let base_url = format!("http://{}", addr);

    let response = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .expect("Failed to check health");

    assert_eq!(response.status(), 200);
}
