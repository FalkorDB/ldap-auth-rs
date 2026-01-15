/// Comprehensive API route tests
/// Tests all API endpoints to ensure full coverage
use ldap_auth_rs::{api, db::DbService, redis_db::RedisDbService};
use reqwest::Client;
use serde_json::json;
use std::sync::Arc;

const TEST_BEARER_TOKEN: &str = "test-bearer-token-routes";

async fn setup_test_db() -> Arc<dyn DbService> {
    let redis_url =
        std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6390/15".to_string());

    Arc::new(
        RedisDbService::new(&redis_url, Some(1))
            .await
            .expect("Failed to connect to Redis"),
    )
}

async fn start_server(db: Arc<dyn DbService>) -> (String, tokio::task::JoinHandle<()>) {
    let app = api::create_router(db);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    (base_url, handle)
}

// User API Routes Tests

#[tokio::test]
async fn test_create_user_route() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    let user_data = json!({
        "organization": "test-org-create",
        "username": "newuser",
        "password": "password123",
        "email": "newuser@example.com",
        "full_name": "New User"
    });

    let response = client
        .post(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&user_data)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 201);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["username"], "newuser");
    assert_eq!(body["data"]["organization"], "test-org-create");
}

#[tokio::test]
async fn test_get_user_route() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    // Create user first
    let user_data = json!({
        "organization": "test-org-get",
        "username": "getuser",
        "password": "password123"
    });

    client
        .post(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&user_data)
        .send()
        .await
        .unwrap();

    // Get user
    let response = client
        .get(format!("{}/api/users/test-org-get/getuser", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .expect("Failed to get user");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["username"], "getuser");
}

#[tokio::test]
async fn test_get_user_not_found() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    let response = client
        .get(format!(
            "{}/api/users/nonexistent-org/nonexistent",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn test_update_user_route() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    // Create user
    let user_data = json!({
        "organization": "test-org-update",
        "username": "updateuser",
        "password": "password123",
        "email": "old@example.com"
    });

    client
        .post(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&user_data)
        .send()
        .await
        .unwrap();

    // Update user
    let update_data = json!({
        "email": "new@example.com",
        "full_name": "Updated Name"
    });

    let response = client
        .put(format!("{}/api/users/test-org-update/updateuser", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&update_data)
        .send()
        .await
        .expect("Failed to update user");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["email"], "new@example.com");
    assert_eq!(body["data"]["full_name"], "Updated Name");
}

#[tokio::test]
async fn test_delete_user_route() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    // Create user
    let user_data = json!({
        "organization": "test-org-delete",
        "username": "deleteuser",
        "password": "password123"
    });

    client
        .post(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&user_data)
        .send()
        .await
        .unwrap();

    // Delete user
    let response = client
        .delete(format!("{}/api/users/test-org-delete/deleteuser", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .expect("Failed to delete user");

    assert_eq!(response.status(), 204);

    // Verify user is deleted
    let response = client
        .get(format!("{}/api/users/test-org-delete/deleteuser", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn test_list_users_route() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    // Create multiple users
    for i in 1..=3 {
        let user_data = json!({
            "organization": "test-org-list",
            "username": format!("listuser{}", i),
            "password": "password123"
        });

        client
            .post(format!("{}/api/users", base_url))
            .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
            .json(&user_data)
            .send()
            .await
            .unwrap();
    }

    // List users
    let response = client
        .get(format!("{}/api/users/test-org-list", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .expect("Failed to list users");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert!(body["data"].is_array());
    assert!(body["data"].as_array().unwrap().len() >= 3);
}

#[tokio::test]
async fn test_get_user_groups_route() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    // Create user
    let user_data = json!({
        "organization": "test-org-usergroups",
        "username": "groupuser",
        "password": "password123"
    });

    client
        .post(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&user_data)
        .send()
        .await
        .unwrap();

    // Create groups and add user
    for i in 1..=2 {
        let group_data = json!({
            "organization": "test-org-usergroups",
            "name": format!("usergroup{}", i),
            "description": format!("User Group {}", i)
        });

        client
            .post(format!("{}/api/groups", base_url))
            .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
            .json(&group_data)
            .send()
            .await
            .unwrap();

        // Add user to group
        let add_member = json!({"username": "groupuser"});
        client
            .post(format!(
                "{}/api/groups/test-org-usergroups/usergroup{}/members",
                base_url, i
            ))
            .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
            .json(&add_member)
            .send()
            .await
            .unwrap();
    }

    // Get user's groups
    let response = client
        .get(format!(
            "{}/api/users/test-org-usergroups/groupuser/groups",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .expect("Failed to get user groups");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"].as_array().unwrap().len(), 2);
}

// Group API Routes Tests

#[tokio::test]
async fn test_create_group_route() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    let group_data = json!({
        "organization": "test-org-creategroup",
        "name": "newgroup",
        "description": "A new test group"
    });

    let response = client
        .post(format!("{}/api/groups", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&group_data)
        .send()
        .await
        .expect("Failed to create group");

    assert_eq!(response.status(), 201);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["name"], "newgroup");
    assert_eq!(body["data"]["description"], "A new test group");
}

#[tokio::test]
async fn test_get_group_route() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    // Create group
    let group_data = json!({
        "organization": "test-org-getgroup",
        "name": "getgroup",
        "description": "Test get group"
    });

    client
        .post(format!("{}/api/groups", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&group_data)
        .send()
        .await
        .unwrap();

    // Get group
    let response = client
        .get(format!(
            "{}/api/groups/test-org-getgroup/getgroup",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .expect("Failed to get group");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["name"], "getgroup");
}

#[tokio::test]
async fn test_update_group_route() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    // Create group
    let group_data = json!({
        "organization": "test-org-updategroup",
        "name": "updategroup",
        "description": "Old description"
    });

    client
        .post(format!("{}/api/groups", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&group_data)
        .send()
        .await
        .unwrap();

    // Update group
    let update_data = json!({
        "description": "Updated description"
    });

    let response = client
        .put(format!(
            "{}/api/groups/test-org-updategroup/updategroup",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&update_data)
        .send()
        .await
        .expect("Failed to update group");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["description"], "Updated description");
}

#[tokio::test]
async fn test_delete_group_route() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    // Create group
    let group_data = json!({
        "organization": "test-org-deletegroup",
        "name": "deletegroup",
        "description": "To be deleted"
    });

    client
        .post(format!("{}/api/groups", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&group_data)
        .send()
        .await
        .unwrap();

    // Delete group
    let response = client
        .delete(format!(
            "{}/api/groups/test-org-deletegroup/deletegroup",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .expect("Failed to delete group");

    assert_eq!(response.status(), 204);

    // Verify group is deleted
    let response = client
        .get(format!(
            "{}/api/groups/test-org-deletegroup/deletegroup",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn test_list_groups_route() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    // Create multiple groups
    for i in 1..=3 {
        let group_data = json!({
            "organization": "test-org-listgroups",
            "name": format!("listgroup{}", i),
            "description": format!("List Group {}", i)
        });

        client
            .post(format!("{}/api/groups", base_url))
            .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
            .json(&group_data)
            .send()
            .await
            .unwrap();
    }

    // List groups
    let response = client
        .get(format!("{}/api/groups/test-org-listgroups", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .expect("Failed to list groups");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert!(body["data"].is_array());
    assert!(body["data"].as_array().unwrap().len() >= 3);
}

#[tokio::test]
async fn test_add_member_to_group_route() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    // Create user and group
    let user_data = json!({
        "organization": "test-org-addmember",
        "username": "memberuser",
        "password": "password123"
    });
    client
        .post(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&user_data)
        .send()
        .await
        .unwrap();

    let group_data = json!({
        "organization": "test-org-addmember",
        "name": "membergroup",
        "description": "Member test group"
    });
    client
        .post(format!("{}/api/groups", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&group_data)
        .send()
        .await
        .unwrap();

    // Add member
    let add_member = json!({"username": "memberuser"});
    let response = client
        .post(format!(
            "{}/api/groups/test-org-addmember/membergroup/members",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&add_member)
        .send()
        .await
        .expect("Failed to add member");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert!(body["data"]["members"]
        .as_array()
        .unwrap()
        .contains(&json!("memberuser")));
}

#[tokio::test]
async fn test_remove_member_from_group_route() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    // Create user and group
    let user_data = json!({
        "organization": "test-org-removemember",
        "username": "removeuser",
        "password": "password123"
    });
    client
        .post(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&user_data)
        .send()
        .await
        .unwrap();

    let group_data = json!({
        "organization": "test-org-removemember",
        "name": "removegroup",
        "description": "Remove test group"
    });
    client
        .post(format!("{}/api/groups", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&group_data)
        .send()
        .await
        .unwrap();

    // Add member first
    let add_member = json!({"username": "removeuser"});
    client
        .post(format!(
            "{}/api/groups/test-org-removemember/removegroup/members",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&add_member)
        .send()
        .await
        .unwrap();

    // Remove member
    let response = client
        .delete(format!(
            "{}/api/groups/test-org-removemember/removegroup/members/removeuser",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .expect("Failed to remove member");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert!(!body["data"]["members"]
        .as_array()
        .unwrap()
        .contains(&json!("removeuser")));
}

// Test error cases

#[tokio::test]
async fn test_create_duplicate_user() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    let user_data = json!({
        "organization": "test-org-dup",
        "username": "dupuser",
        "password": "password123"
    });

    // Create first time - should succeed
    let response = client
        .post(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&user_data)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);

    // Create second time - should fail
    let response = client
        .post(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&user_data)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 409); // Conflict
}

#[tokio::test]
async fn test_create_duplicate_group() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    let group_data = json!({
        "organization": "test-org-dupgroup",
        "name": "dupgroup",
        "description": "Duplicate group"
    });

    // Create first time - should succeed
    let response = client
        .post(format!("{}/api/groups", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&group_data)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);

    // Create second time - should fail
    let response = client
        .post(format!("{}/api/groups", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&group_data)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 409); // Conflict
}

#[tokio::test]
async fn test_add_nonexistent_user_to_group() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    // Create group
    let group_data = json!({
        "organization": "test-org-nonexist",
        "name": "testgroup",
        "description": "Test group"
    });
    client
        .post(format!("{}/api/groups", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&group_data)
        .send()
        .await
        .unwrap();

    // Try to add nonexistent user
    let add_member = json!({"username": "nonexistentuser"});
    let response = client
        .post(format!(
            "{}/api/groups/test-org-nonexist/testgroup/members",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&add_member)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404); // Not found
}

#[tokio::test]
async fn test_delete_user_removes_from_groups() {
    std::env::set_var("API_BEARER_TOKEN", TEST_BEARER_TOKEN);
    let db = setup_test_db().await;
    let (base_url, _handle) = start_server(db).await;
    let client = Client::new();

    // Create user
    let user_data = json!({
        "organization": "test-org-cascade",
        "username": "cascadeuser",
        "password": "password123"
    });
    client
        .post(format!("{}/api/users", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&user_data)
        .send()
        .await
        .unwrap();

    // Create group and add user
    let group_data = json!({
        "organization": "test-org-cascade",
        "name": "cascadegroup",
        "description": "Cascade test"
    });
    client
        .post(format!("{}/api/groups", base_url))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&group_data)
        .send()
        .await
        .unwrap();

    let add_member = json!({"username": "cascadeuser"});
    client
        .post(format!(
            "{}/api/groups/test-org-cascade/cascadegroup/members",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .json(&add_member)
        .send()
        .await
        .unwrap();

    // Delete user
    client
        .delete(format!(
            "{}/api/users/test-org-cascade/cascadeuser",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .unwrap();

    // Verify user is removed from group
    let response = client
        .get(format!(
            "{}/api/groups/test-org-cascade/cascadegroup",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", TEST_BEARER_TOKEN))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["data"]["members"].as_array().unwrap().is_empty());
}
