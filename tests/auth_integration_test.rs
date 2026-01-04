use ldap_auth_rs::{
    api, db::DbService, models::UserCreate, redis_db::RedisDbService,
};
use std::sync::Arc;
use tokio::net::TcpListener;

// Consistent token for all auth tests
// Note: Bearer token is cached on first use, so all tests must use the same token
const TEST_BEARER_TOKEN: &str = "test-bearer-token-12345";

async fn setup_test_db() -> Arc<dyn DbService> {
    let redis_url = "redis://127.0.0.1:6379";
    Arc::new(
        RedisDbService::new(redis_url)
            .await
            .expect("Failed to connect to Redis"),
    ) as Arc<dyn DbService>
}

async fn start_test_server(db: Arc<dyn DbService>, port: u16) {
    let app = api::create_router(db);
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind test server");

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("Test server error");
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn test_api_health_check_no_auth() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let port = 18080;
    start_test_server(db.clone(), port).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/health", port))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn test_api_requires_auth() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let port = 18081;
    start_test_server(db.clone(), port).await;

    let client = reqwest::Client::new();
    
    // Try to access protected endpoint without token
    let response = client
        .get(format!("http://127.0.0.1:{}/api/users/testorg", port))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn test_api_with_invalid_token() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let port = 18082;
    start_test_server(db.clone(), port).await;

    let client = reqwest::Client::new();
    
    // Try with wrong token
    let response = client
        .get(format!("http://127.0.0.1:{}/api/users/testorg", port))
        .header("Authorization", "Bearer wrong-token")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn test_api_with_valid_token() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let port = 18083;
    start_test_server(db.clone(), port).await;

    let client = reqwest::Client::new();
    
    // Create a user first
    let user_create = UserCreate {
        organization: "testorg".to_string(),
        username: "testuser".to_string(),
        password: "testpass".to_string(),
        email: Some("test@example.com".to_string()),
        full_name: None,
    };

    let create_response = client
        .post(format!("http://127.0.0.1:{}/api/users", port))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&user_create)
        .send()
        .await
        .expect("Failed to create user");

    assert!(create_response.status().is_success());

    // Now list users with valid token
    let list_response = client
        .get(format!("http://127.0.0.1:{}/api/users/testorg", port))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(list_response.status(), 200);

    // Cleanup
    db.delete_user("testorg", "testuser").await.ok();
}

#[tokio::test]
async fn test_api_invalid_auth_format() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let port = 18084;
    start_test_server(db.clone(), port).await;

    let client = reqwest::Client::new();
    
    // Try with Basic auth instead of Bearer
    let response = client
        .get(format!("http://127.0.0.1:{}/api/users/testorg", port))
        .header("Authorization", "Basic dGVzdDp0ZXN0")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn test_all_protected_endpoints_require_auth() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let port = 18085;
    start_test_server(db.clone(), port).await;

    let client = reqwest::Client::new();
    
    let endpoints = vec![
        ("GET", format!("http://127.0.0.1:{}/api/users/testorg", port)),
        ("GET", format!("http://127.0.0.1:{}/api/users/testorg/testuser", port)),
        ("GET", format!("http://127.0.0.1:{}/api/groups/testorg", port)),
        ("GET", format!("http://127.0.0.1:{}/api/groups/testorg/testgroup", port)),
    ];

    for (method, url) in endpoints {
        let response = match method {
            "GET" => client.get(&url).send().await,
            _ => panic!("Unsupported method"),
        }.expect("Failed to send request");

        assert_eq!(
            response.status(),
            401,
            "Endpoint {} should require authentication",
            url
        );
    }
}
