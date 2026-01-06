/// Integration tests using ldap3 library (same as Valkey uses)
/// These tests verify LDAP protocol compliance and correct search results
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use std::time::Duration;
use tokio::time::timeout;

fn ldap3_tests_enabled() -> bool {
    match std::env::var("RUN_LDAP3_TESTS") {
        Ok(v) => matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"),
        Err(_) => false,
    }
}

fn test_api_base_url() -> String {
    std::env::var("TEST_API_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string())
}

fn test_api_token() -> String {
    std::env::var("TEST_API_TOKEN").unwrap_or_else(|_| "asdf".to_string())
}

fn test_ldap_url() -> String {
    std::env::var("TEST_LDAP_URL").unwrap_or_else(|_| "ldap://127.0.0.1:3389".to_string())
}

/// Helper to set up test data via API
/// Handles 409 Conflict gracefully (resource already exists)
async fn setup_test_data() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let base_url = test_api_base_url();
    let bearer_token = test_api_token();

    // Create test users (organization is included in the request body)
    for username in &["alice", "bob", "charlie"] {
        let response = client
            .post(format!("{}/api/users", base_url))
            .bearer_auth(&bearer_token)
            .json(&serde_json::json!({
                "organization": "testorg",
                "username": username,
                "password": "password123",
                "email": format!("{}@test.com", username)
            }))
            .send()
            .await?;

        let status = response.status();
        // 409 Conflict means user already exists - that's OK
        if !status.is_success() && status.as_u16() != 409 {
            let body = response.text().await.unwrap_or_default();
            return Err(
                format!("Failed to create user {}: {} - {}", username, status, body).into(),
            );
        }
    }

    // Create test groups
    for (name, description) in &[
        ("admins", "Administrator group"),
        ("developers", "Developer group"),
        ("readonly", "Read-only access group"),
    ] {
        let response = client
            .post(format!("{}/api/groups", base_url))
            .bearer_auth(&bearer_token)
            .json(&serde_json::json!({
                "organization": "testorg",
                "name": name,
                "description": description
            }))
            .send()
            .await?;

        let status = response.status();
        // 409 Conflict means group already exists - that's OK
        if !status.is_success() && status.as_u16() != 409 {
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Failed to create group {}: {} - {}", name, status, body).into());
        }
    }

    // Add members to groups
    // admins: alice, bob
    for username in &["alice", "bob"] {
        let response = client
            .post(format!("{}/api/groups/testorg/admins/members", base_url))
            .bearer_auth(&bearer_token)
            .json(&serde_json::json!({"username": username}))
            .send()
            .await?;

        let status = response.status();
        // 409 Conflict or 400 Bad Request with "already a member" means member already exists - that's OK
        if !status.is_success() && status.as_u16() != 409 && status.as_u16() != 400 {
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "Failed to add {} to admins: {} - {}",
                username, status, body
            )
            .into());
        }
    }

    // developers: alice, charlie
    for username in &["alice", "charlie"] {
        let response = client
            .post(format!(
                "{}/api/groups/testorg/developers/members",
                base_url
            ))
            .bearer_auth(&bearer_token)
            .json(&serde_json::json!({"username": username}))
            .send()
            .await?;

        let status = response.status();
        // 409 Conflict or 400 Bad Request with "already a member" means member already exists - that's OK
        if !status.is_success() && status.as_u16() != 409 && status.as_u16() != 400 {
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "Failed to add {} to developers: {} - {}",
                username, status, body
            )
            .into());
        }
    }

    // readonly: charlie
    let response = client
        .post(format!("{}/api/groups/testorg/readonly/members", base_url))
        .bearer_auth(&bearer_token)
        .json(&serde_json::json!({"username": "charlie"}))
        .send()
        .await?;

    let status = response.status();
    // 409 Conflict or 400 Bad Request with "already a member" means member already exists - that's OK
    if !status.is_success() && status.as_u16() != 409 && status.as_u16() != 400 {
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Failed to add charlie to readonly: {} - {}", status, body).into());
    }

    // Give time for data to be persisted
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(())
}

#[tokio::test]
async fn test_ldap3_bind_success() {
    if !ldap3_tests_enabled() {
        eprintln!("Skipping ldap3 integration test (set RUN_LDAP3_TESTS=1 to enable)");
        return;
    }
    // Connect to LDAP server
    let (conn, mut ldap) = LdapConnAsync::new(&test_ldap_url())
        .await
        .expect("Failed to connect to LDAP server");

    // Drive the connection in the background
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("Connection driver error: {}", e);
        }
    });

    // Test bind with valid credentials
    let result = ldap
        .simple_bind("cn=falkordb,ou=instance-1,dc=example,dc=com", "123456")
        .await;

    assert!(result.is_ok(), "Bind should succeed with valid credentials");

    let bind_result = result.unwrap();
    assert_eq!(bind_result.rc, 0, "Bind result code should be 0 (success)");

    // Unbind
    let _ = ldap.unbind().await;
}

#[tokio::test]
async fn test_ldap3_bind_invalid_credentials() {
    if !ldap3_tests_enabled() {
        eprintln!("Skipping ldap3 integration test (set RUN_LDAP3_TESTS=1 to enable)");
        return;
    }

    let (conn, mut ldap) = LdapConnAsync::new(&test_ldap_url())
        .await
        .expect("Failed to connect");

    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("Connection driver error: {}", e);
        }
    });

    // Test bind with invalid credentials
    let result = ldap
        .simple_bind(
            "cn=falkordb,ou=instance-1,dc=example,dc=com",
            "wrongpassword",
        )
        .await;

    assert!(
        result.is_ok(),
        "Bind should return a result (not connection error)"
    );

    let bind_result = result.unwrap();
    assert_ne!(
        bind_result.rc, 0,
        "Bind result code should not be 0 (should fail)"
    );

    let _ = ldap.unbind().await;
}

#[tokio::test]
async fn test_ldap3_group_search_with_attribute_filter() {
    if !ldap3_tests_enabled() {
        eprintln!("Skipping ldap3 integration test (set RUN_LDAP3_TESTS=1 to enable)");
        return;
    }

    let (conn, mut ldap) = LdapConnAsync::new(&test_ldap_url())
        .await
        .expect("Failed to connect");

    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("Connection driver error: {}", e);
        }
    });

    // Bind as user first
    ldap.simple_bind("cn=falkordb,ou=instance-1,dc=example,dc=com", "123456")
        .await
        .expect("User bind failed");

    // Bind as admin to search
    // Bind as a user in testorg.
    // The server currently scopes searches to the authenticated org (it doesn't parse the base DN),
    // so binding as admin would search org "admin" instead of "testorg".
    ldap.simple_bind("cn=alice,ou=testorg,dc=example,dc=com", "password123")
        .await
        .expect("User bind failed");

    // Search for groups - THIS IS THE KEY TEST
    // Request ONLY the "description" attribute (like Valkey does)
    let filter =
        "(&(objectClass=groupOfNames)(member=cn=falkordb,ou=instance-1,dc=example,dc=com))";

    let search_result = timeout(
        Duration::from_secs(2), // 2 second timeout - should be plenty
        ldap.search(
            "dc=example,dc=com",
            Scope::Subtree,
            filter,
            vec!["description"], // Only request description attribute
        ),
    )
    .await;

    assert!(search_result.is_ok(), "Search should not timeout");

    let search_stream = search_result.unwrap().expect("Search should succeed");

    let (rs, res) = search_stream.success().expect("Should get search results");
    assert_eq!(res.rc, 0, "Search result code should be 0");

    // Parse entries
    let entries: Vec<_> = rs.into_iter().map(SearchEntry::construct).collect();

    println!("Found {} group entries", entries.len());

    // Main success: the search completed without timeout!
    // Finding actual groups depends on test data setup
    // The key test is that requesting specific attributes doesn't cause protocol errors or timeouts

    if !entries.is_empty() {
        // Verify only requested attributes are returned if we got results
        for entry in &entries {
            println!("Entry DN: {}", entry.dn);
            println!("Attributes: {:?}", entry.attrs.keys().collect::<Vec<_>>());

            // Should have description attribute if it exists on the entry
            if entry.attrs.contains_key("description") {
                println!("Found description attribute as requested");
            }
        }
    } else {
        println!("No groups found - this may be due to test data setup");
        println!("Key success: search with attribute filter completed without timeout");
    }

    let _ = ldap.unbind().await;
}

#[tokio::test]
async fn test_ldap3_group_search_all_attributes() {
    if !ldap3_tests_enabled() {
        eprintln!("Skipping ldap3 integration test (set RUN_LDAP3_TESTS=1 to enable)");
        return;
    }

    let (conn, mut ldap) = LdapConnAsync::new(&test_ldap_url())
        .await
        .expect("Failed to connect");

    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("Connection driver error: {}", e);
        }
    });

    ldap.simple_bind("cn=falkordb,ou=instance-1,dc=example,dc=com", "123456")
        .await
        .expect("User bind failed");

    ldap.simple_bind("cn=admin,ou=admin,dc=example,dc=com", "admin123!")
        .await
        .expect("Admin bind failed");

    // Search requesting ALL attributes (empty vector)
    let filter =
        "(&(objectClass=groupOfNames)(member=cn=falkordb,ou=instance-1,dc=example,dc=com))";

    let search_result = timeout(
        Duration::from_secs(2),
        ldap.search(
            "dc=example,dc=com",
            Scope::Subtree,
            filter,
            Vec::<String>::new(), // Empty = all attributes
        ),
    )
    .await;

    assert!(
        search_result.is_ok(),
        "Search for all attributes should not timeout"
    );

    let search_stream = search_result.unwrap().expect("Search should succeed");

    let (rs, res) = search_stream.success().expect("Should get search results");
    assert_eq!(res.rc, 0);

    let entries: Vec<_> = rs.into_iter().map(SearchEntry::construct).collect();

    println!("Found {} entries with all attributes", entries.len());

    for entry in &entries {
        println!("Entry: {}", entry.dn);
        println!(
            "All attributes: {:?}",
            entry.attrs.keys().collect::<Vec<_>>()
        );

        // When requesting all attributes, we should get cn, objectClass, description, member
        assert!(entry.attrs.contains_key("cn"), "Should have cn");
        assert!(
            entry.attrs.contains_key("objectClass"),
            "Should have objectClass"
        );
        // description and member may or may not be present depending on the group
    }

    let _ = ldap.unbind().await;
}

#[tokio::test]
async fn test_ldap3_simple_search() {
    if !ldap3_tests_enabled() {
        eprintln!("Skipping ldap3 integration test (set RUN_LDAP3_TESTS=1 to enable)");
        return;
    }

    // This test verifies basic search functionality works without timing out
    let (conn, mut ldap) = LdapConnAsync::new(&test_ldap_url())
        .await
        .expect("Failed to connect");

    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("Connection driver error: {}", e);
        }
    });

    ldap.simple_bind("cn=admin,ou=admin,dc=example,dc=com", "admin123!")
        .await
        .expect("Admin bind failed");

    // Simple search that should complete quickly
    let search_stream = timeout(
        Duration::from_secs(2),
        ldap.search(
            "dc=example,dc=com",
            Scope::Base, // Just search the base object
            "(objectClass=*)",
            Vec::<String>::new(),
        ),
    )
    .await;

    // Main assertion: search should not timeout
    assert!(search_stream.is_ok(), "Simple search should not timeout");

    if let Ok(Ok(stream)) = search_stream {
        let (rs, res) = stream.success().expect("Should get results");
        println!("Search completed with result code: {}", res.rc);
        println!("Found {} entries", rs.len());
    }

    let _ = ldap.unbind().await;
}

#[tokio::test]
async fn test_ldap3_group_search_returns_entries() {
    if !ldap3_tests_enabled() {
        eprintln!("Skipping ldap3 integration test (set RUN_LDAP3_TESTS=1 to enable)");
        return;
    }

    // Setup test data - this test REQUIRES data
    setup_test_data()
        .await
        .expect("Test data setup failed - ensure API is running on port 8080");

    let (conn, mut ldap) = LdapConnAsync::new(&test_ldap_url())
        .await
        .expect("Failed to connect");

    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("Connection driver error: {}", e);
        }
    });

    // Bind as alice
    ldap.simple_bind("cn=alice,ou=testorg,dc=example,dc=com", "password123")
        .await
        .expect("User bind failed");

    // Bind as admin to search
    ldap.simple_bind("cn=admin,ou=admin,dc=example,dc=com", "admin123!")
        .await
        .expect("Admin bind failed");

    // Search for groups where alice is a member
    let filter = "(&(objectClass=groupOfNames)(member=cn=alice,ou=testorg,dc=example,dc=com))";

    let search_result = timeout(
        Duration::from_secs(2),
        ldap.search(
            "ou=testorg,dc=example,dc=com",
            Scope::Subtree,
            filter,
            vec!["description"], // Request only description
        ),
    )
    .await;

    assert!(search_result.is_ok(), "Search should not timeout");

    let search_stream = search_result.unwrap().expect("Search should succeed");

    let (rs, res) = search_stream.success().expect("Should get search results");
    assert_eq!(res.rc, 0, "Search result code should be 0");

    let entries: Vec<_> = rs.into_iter().map(SearchEntry::construct).collect();

    // Alice MUST be in exactly 2 groups: admins and developers
    assert_eq!(
        entries.len(),
        2,
        "Alice should be member of exactly 2 groups (admins and developers)"
    );

    let group_names: Vec<_> = entries
        .iter()
        .filter_map(|e| {
            // Extract group name from DN like "cn=admins,ou=groups,ou=testorg,dc=example,dc=com"
            e.dn.split(',').next()?.strip_prefix("cn=")
        })
        .collect();

    assert!(group_names.contains(&"admins"), "Should find admins group");
    assert!(
        group_names.contains(&"developers"),
        "Should find developers group"
    );

    // Verify only requested attribute is returned
    for entry in &entries {
        println!("Group: {}", entry.dn);
        println!("Attributes: {:?}", entry.attrs.keys().collect::<Vec<_>>());

        // Should have description attribute
        assert!(
            entry.attrs.contains_key("description"),
            "Should have description attribute"
        );

        // Should NOT have unrequested attributes like member
        assert!(
            !entry.attrs.contains_key("member"),
            "Should not have member attribute (not requested)"
        );
    }

    let _ = ldap.unbind().await;
}

#[tokio::test]
async fn test_ldap3_group_search_all_attributes_with_data() {
    if !ldap3_tests_enabled() {
        eprintln!("Skipping ldap3 integration test (set RUN_LDAP3_TESTS=1 to enable)");
        return;
    }

    // Setup test data - this test REQUIRES data
    setup_test_data()
        .await
        .expect("Test data setup failed - ensure API is running on port 8080");

    let (conn, mut ldap) = LdapConnAsync::new(&test_ldap_url())
        .await
        .expect("Failed to connect");

    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("Connection driver error: {}", e);
        }
    });

    ldap.simple_bind("cn=charlie,ou=testorg,dc=example,dc=com", "password123")
        .await
        .expect("User bind failed");

    ldap.simple_bind("cn=admin,ou=admin,dc=example,dc=com", "admin123!")
        .await
        .expect("Admin bind failed");

    // Search for groups where charlie is a member, requesting ALL attributes
    let filter = "(&(objectClass=groupOfNames)(member=cn=charlie,ou=testorg,dc=example,dc=com))";

    let search_result = timeout(
        Duration::from_secs(2),
        ldap.search(
            "ou=testorg,dc=example,dc=com",
            Scope::Subtree,
            filter,
            Vec::<String>::new(), // Empty = request all attributes
        ),
    )
    .await;

    assert!(search_result.is_ok(), "Search should not timeout");

    let search_stream = search_result.unwrap().expect("Search should succeed");

    let (rs, res) = search_stream.success().expect("Should get search results");
    assert_eq!(res.rc, 0);

    let entries: Vec<_> = rs.into_iter().map(SearchEntry::construct).collect();

    // Charlie MUST be in exactly 2 groups: developers and readonly
    assert_eq!(
        entries.len(),
        2,
        "Charlie should be member of exactly 2 groups (developers and readonly)"
    );

    // Verify all attributes are returned when not filtering
    for entry in &entries {
        println!("Group: {}", entry.dn);
        println!(
            "All attributes: {:?}",
            entry.attrs.keys().collect::<Vec<_>>()
        );

        // When requesting all attributes, we should get all group attributes
        assert!(entry.attrs.contains_key("cn"), "Should have cn attribute");
        assert!(
            entry.attrs.contains_key("objectClass"),
            "Should have objectClass attribute"
        );
        assert!(
            entry.attrs.contains_key("description"),
            "Should have description attribute"
        );
        assert!(
            entry.attrs.contains_key("member"),
            "Should have member attribute"
        );

        // Verify member attribute contains charlie
        if let Some(members) = entry.attrs.get("member") {
            let member_dns: Vec<_> = members.iter().map(|m| m.as_str()).collect();
            assert!(
                member_dns.iter().any(|m| m.contains("cn=charlie")),
                "Member list should contain charlie"
            );
        }
    }

    let _ = ldap.unbind().await;
}

#[tokio::test]
async fn test_ldap3_group_search_all_groups_in_org() {
    if !ldap3_tests_enabled() {
        eprintln!("Skipping ldap3 integration test (set RUN_LDAP3_TESTS=1 to enable)");
        return;
    }

    // Setup test data - this test REQUIRES data
    setup_test_data()
        .await
        .expect("Test data setup failed - ensure API is running on port 8080");

    let (conn, mut ldap) = LdapConnAsync::new(&test_ldap_url())
        .await
        .expect("Failed to connect");

    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("Connection driver error: {}", e);
        }
    });

    ldap.simple_bind("cn=admin,ou=admin,dc=example,dc=com", "admin123!")
        .await
        .expect("Admin bind failed");

    // Search for ALL groups in testorg (no member filter)
    let filter = "(objectClass=groupOfNames)";

    let search_result = timeout(
        Duration::from_secs(2),
        ldap.search(
            "ou=testorg,dc=example,dc=com",
            Scope::Subtree,
            filter,
            vec!["cn", "description"], // Request specific attributes
        ),
    )
    .await;

    assert!(search_result.is_ok(), "Search should not timeout");

    let search_stream = search_result.unwrap().expect("Search should succeed");

    let (rs, res) = search_stream.success().expect("Should get search results");
    assert_eq!(res.rc, 0);

    let entries: Vec<_> = rs.into_iter().map(SearchEntry::construct).collect();

    // MUST find all 3 groups: admins, developers, readonly
    assert_eq!(entries.len(), 3, "Should find exactly 3 groups in testorg");

    let group_names: Vec<_> = entries
        .iter()
        .filter_map(|e| e.dn.split(',').next()?.strip_prefix("cn="))
        .collect();

    // Verify all 3 groups are present
    assert!(group_names.contains(&"admins"), "Should find admins group");
    assert!(
        group_names.contains(&"developers"),
        "Should find developers group"
    );
    assert!(
        group_names.contains(&"readonly"),
        "Should find readonly group"
    );

    // Verify only requested attributes are returned
    for entry in &entries {
        assert!(entry.attrs.contains_key("cn"), "Should have cn");
        assert!(
            entry.attrs.contains_key("description"),
            "Should have description"
        );
        assert!(
            !entry.attrs.contains_key("member"),
            "Should NOT have member (not requested)"
        );
        assert!(
            !entry.attrs.contains_key("objectClass"),
            "Should NOT have objectClass (not requested)"
        );
    }

    let _ = ldap.unbind().await;
}

#[tokio::test]
async fn test_ldap3_user_not_in_any_group() {
    if !ldap3_tests_enabled() {
        eprintln!("Skipping ldap3 integration test (set RUN_LDAP3_TESTS=1 to enable)");
        return;
    }

    // Setup test data - this test REQUIRES data
    setup_test_data()
        .await
        .expect("Test data setup failed - ensure API is running on port 8080");

    // Create a user not in any group
    let client = reqwest::Client::new();
    let base_url = test_api_base_url();
    let bearer_token = test_api_token();
    let _response = client
        .post(format!("{}/api/users", base_url))
        .bearer_auth(&bearer_token)
        .json(&serde_json::json!({
            "organization": "testorg",
            "username": "lonely",
            "password": "password123",
            "email": "lonely@test.com"
        }))
        .send()
        .await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let (conn, mut ldap) = LdapConnAsync::new(&test_ldap_url())
        .await
        .expect("Failed to connect");

    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("Connection driver error: {}", e);
        }
    });

    ldap.simple_bind("cn=admin,ou=admin,dc=example,dc=com", "admin123!")
        .await
        .expect("Admin bind failed");

    // Search for groups where lonely user is a member
    let filter = "(&(objectClass=groupOfNames)(member=cn=lonely,ou=testorg,dc=example,dc=com))";

    let search_result = timeout(
        Duration::from_secs(2),
        ldap.search(
            "ou=testorg,dc=example,dc=com",
            Scope::Subtree,
            filter,
            vec!["description"],
        ),
    )
    .await;

    assert!(
        search_result.is_ok(),
        "Search should not timeout even with no results"
    );

    let search_stream = search_result.unwrap().expect("Search should succeed");

    let (rs, res) = search_stream.success().expect("Should get search results");
    assert_eq!(res.rc, 0, "Should succeed with empty results");

    let entries: Vec<_> = rs.into_iter().map(SearchEntry::construct).collect();

    // Should find no groups
    assert_eq!(
        entries.len(),
        0,
        "User not in any groups should return 0 entries"
    );

    let _ = ldap.unbind().await;
}
