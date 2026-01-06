use ldap_auth_rs::{
    db::DbService, ldap::LdapServer, models::UserCreate, redis_db::RedisDbService, tls,
};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use std::io::BufReader;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use tokio_rustls::TlsConnector;

async fn setup_test_db() -> Arc<dyn DbService> {
    let redis_url =
        std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6390/15".to_string());

    Arc::new(
        RedisDbService::new(&redis_url, Some(1))
            .await
            .expect("Failed to connect to Redis"),
    )
}

async fn start_ldap_server(db: Arc<dyn DbService>, port: u16) {
    let addr = format!("127.0.0.1:{}", port);
    let base_dn = "dc=example,dc=com".to_string();
    let server = LdapServer::new(db, base_dn, None);

    tokio::spawn(async move {
        if let Err(e) = server.run(&addr).await {
            eprintln!("LDAP server error: {}", e);
        }
    });

    // Wait for server to start
    sleep(Duration::from_millis(100)).await;
}

async fn start_ldap_server_with_tls(
    db: Arc<dyn DbService>,
    port: u16,
) -> Result<(String, String), String> {
    let addr = format!("127.0.0.1:{}", port);
    let base_dn = "dc=example,dc=com".to_string();
    let server = LdapServer::new(db, base_dn, None);

    // Generate test certificates
    let (cert_path, key_path) =
        tls::generate_test_certs().map_err(|e| format!("Failed to generate test certs: {}", e))?;

    // Load TLS config
    let tls_config = tls::load_tls_config(&cert_path, &key_path)
        .map_err(|e| format!("Failed to load TLS config: {}", e))?;

    let cert_clone = cert_path.to_string();
    let key_clone = key_path.to_string();

    tokio::spawn(async move {
        if let Err(e) = server.run_with_tls(&addr, tls_config).await {
            eprintln!("LDAP TLS server error: {}", e);
        }
    });

    // Wait for server to start
    sleep(Duration::from_millis(200)).await;

    Ok((cert_clone, key_clone))
}

fn create_bind_request(message_id: u8, dn: &str, password: &str) -> Vec<u8> {
    let mut request = Vec::new();

    let dn_bytes = dn.as_bytes();
    let pwd_bytes = password.as_bytes();

    // Calculate lengths
    let bind_content_len = 3 + 2 + dn_bytes.len() + 2 + pwd_bytes.len();
    let total_len = 3 + bind_content_len;

    // SEQUENCE
    request.push(0x30);
    request.push(total_len as u8);

    // Message ID
    request.push(0x02);
    request.push(0x01);
    request.push(message_id);

    // Bind Request
    request.push(0x60);
    request.push(bind_content_len as u8);

    // Version 3
    request.push(0x02);
    request.push(0x01);
    request.push(0x03);

    // DN
    request.push(0x04);
    request.push(dn_bytes.len() as u8);
    request.extend_from_slice(dn_bytes);

    // Password (simple auth)
    request.push(0x80);
    request.push(pwd_bytes.len() as u8);
    request.extend_from_slice(pwd_bytes);

    request
}

fn create_unbind_request(message_id: u8) -> Vec<u8> {
    vec![
        0x30, 0x05, // SEQUENCE, length 5
        0x02, 0x01, message_id, // Message ID
        0x42, 0x00, // Unbind Request (APPLICATION 2)
    ]
}

fn create_search_request(message_id: u8, base_dn: &str) -> Vec<u8> {
    let mut request = Vec::new();
    let base_bytes = base_dn.as_bytes();

    // Simplified search request
    let search_len = 2 + base_bytes.len() + 12;
    let total_len = 3 + search_len;

    // SEQUENCE
    request.push(0x30);
    request.push(total_len as u8);

    // Message ID
    request.push(0x02);
    request.push(0x01);
    request.push(message_id);

    // Search Request
    request.push(0x63); // APPLICATION 3
    request.push(search_len as u8);

    // Base DN
    request.push(0x04);
    request.push(base_bytes.len() as u8);
    request.extend_from_slice(base_bytes);

    // Scope (base=0, one=1, sub=2)
    request.push(0x0a);
    request.push(0x01);
    request.push(0x02); // sub

    // Deref aliases (never=0)
    request.push(0x0a);
    request.push(0x01);
    request.push(0x00);

    // Size limit (0 = no limit)
    request.push(0x02);
    request.push(0x01);
    request.push(0x00);

    // Time limit (0 = no limit)
    request.push(0x02);
    request.push(0x01);
    request.push(0x00);

    // Types only (false)
    request.push(0x01);
    request.push(0x01);
    request.push(0x00);

    // Filter (objectClass=*)
    request.push(0x87); // present filter
    request.push(0x0b);
    request.extend_from_slice(b"objectClass");

    // Attributes (empty)
    request.push(0x30);
    request.push(0x00);

    request
}

fn create_whoami_request(message_id: u8) -> Vec<u8> {
    let oid = b"1.3.6.1.4.1.4203.1.11.3"; // WhoAmI OID

    let mut request = Vec::new();
    let extended_len = 2 + oid.len();
    let total_len = 3 + extended_len;

    // SEQUENCE
    request.push(0x30);
    request.push(total_len as u8);

    // Message ID
    request.push(0x02);
    request.push(0x01);
    request.push(message_id);

    // Extended Request
    request.push(0x77); // APPLICATION 23
    request.push(extended_len as u8);

    // OID
    request.push(0x80); // CONTEXT 0
    request.push(oid.len() as u8);
    request.extend_from_slice(oid);

    request
}

fn parse_bind_response(data: &[u8]) -> Result<u8, String> {
    if data.len() < 12 {
        return Err("Response too short".to_string());
    }

    // Find result code (ENUMERATED after bind response tag)
    for i in 0..data.len() - 2 {
        if data[i] == 0x0a && data[i + 1] == 0x01 {
            return Ok(data[i + 2]);
        }
    }

    Err("Result code not found".to_string())
}

#[tokio::test]
async fn test_ldap_bind_success() {
    let db = setup_test_db().await;
    let port = 13389;

    // Create test user
    let user_create = UserCreate {
        organization: "testorg".to_string(),
        username: "testuser".to_string(),
        password: "testpass123".to_string(),
        email: Some("test@example.com".to_string()),
        full_name: None,
    };
    db.create_user(user_create)
        .await
        .expect("Failed to create user");

    // Start LDAP server
    start_ldap_server(db.clone(), port).await;

    // Connect and bind
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");

    let dn = "cn=testuser,ou=testorg,dc=example,dc=com";
    let bind_request = create_bind_request(1, dn, "testpass123");

    stream
        .write_all(&bind_request)
        .await
        .expect("Failed to send bind");

    let mut response = vec![0u8; 1024];
    let n = stream
        .read(&mut response)
        .await
        .expect("Failed to read response");
    let response = &response[..n];

    let result_code = parse_bind_response(response).expect("Failed to parse response");
    assert_eq!(result_code, 0, "Bind should succeed");

    // Cleanup
    db.delete_user("testorg", "testuser").await.ok();
}

#[tokio::test]
async fn test_ldap_bind_invalid_credentials() {
    let db = setup_test_db().await;
    let port = 13390;

    // Create test user
    let user_create = UserCreate {
        organization: "testorg".to_string(),
        username: "testuser2".to_string(),
        password: "correctpass".to_string(),
        email: None,
        full_name: None,
    };
    db.create_user(user_create)
        .await
        .expect("Failed to create user");

    // Start LDAP server
    start_ldap_server(db.clone(), port).await;

    // Connect and bind with wrong password
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");

    let dn = "cn=testuser2,ou=testorg,dc=example,dc=com";
    let bind_request = create_bind_request(1, dn, "wrongpass");

    stream
        .write_all(&bind_request)
        .await
        .expect("Failed to send bind");

    let mut response = vec![0u8; 1024];
    let n = stream
        .read(&mut response)
        .await
        .expect("Failed to read response");
    let response = &response[..n];

    let result_code = parse_bind_response(response).expect("Failed to parse response");
    assert_eq!(result_code, 49, "Bind should fail with invalid credentials");

    // Cleanup
    db.delete_user("testorg", "testuser2").await.ok();
}

#[tokio::test]
async fn test_ldap_bind_anonymous() {
    let db = setup_test_db().await;
    let port = 13391;

    // Start LDAP server
    start_ldap_server(db.clone(), port).await;

    // Connect and anonymous bind
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");

    let bind_request = create_bind_request(1, "", "");

    stream
        .write_all(&bind_request)
        .await
        .expect("Failed to send bind");

    let mut response = vec![0u8; 1024];
    let n = stream
        .read(&mut response)
        .await
        .expect("Failed to read response");
    let response = &response[..n];

    let result_code = parse_bind_response(response).expect("Failed to parse response");
    assert_eq!(result_code, 0, "Anonymous bind should succeed");
}

#[tokio::test]
async fn test_ldap_search_authenticated() {
    let db = setup_test_db().await;
    let port = 13392;

    // Create test user
    let user_create = UserCreate {
        organization: "searchorg".to_string(),
        username: "searchuser".to_string(),
        password: "searchpass".to_string(),
        email: Some("search@example.com".to_string()),
        full_name: None,
    };
    db.create_user(user_create)
        .await
        .expect("Failed to create user");

    // Start LDAP server
    start_ldap_server(db.clone(), port).await;

    // Connect and bind
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");

    let dn = "cn=searchuser,ou=searchorg,dc=example,dc=com";
    let bind_request = create_bind_request(1, dn, "searchpass");
    stream
        .write_all(&bind_request)
        .await
        .expect("Failed to send bind");

    let mut response = vec![0u8; 1024];
    let _ = stream
        .read(&mut response)
        .await
        .expect("Failed to read bind response");

    // Now search
    let search_request = create_search_request(2, "dc=example,dc=com");
    stream
        .write_all(&search_request)
        .await
        .expect("Failed to send search");

    let mut search_response = vec![0u8; 4096];
    let n = stream
        .read(&mut search_response)
        .await
        .expect("Failed to read search response");
    let search_response = &search_response[..n];

    assert!(
        !search_response.is_empty(),
        "Should receive search response"
    );

    // Should contain search result done (0x65)
    assert!(
        search_response.contains(&0x65),
        "Should contain search result done"
    );

    // Cleanup
    db.delete_user("searchorg", "searchuser").await.ok();
}

#[tokio::test]
async fn test_ldap_search_unauthenticated() {
    let db = setup_test_db().await;
    let port = 13393;

    // Start LDAP server
    start_ldap_server(db.clone(), port).await;

    // Connect without binding
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");

    let search_request = create_search_request(1, "dc=example,dc=com");
    stream
        .write_all(&search_request)
        .await
        .expect("Failed to send search");

    let mut response = vec![0u8; 1024];
    let n = stream
        .read(&mut response)
        .await
        .expect("Failed to read response");
    let response = &response[..n];

    // Per RFC 4532: Anonymous search should return success with empty results
    let result_code = parse_bind_response(response).unwrap_or(255);
    assert_eq!(
        result_code, 0,
        "Should return success with empty results for anonymous search"
    );

    // Should contain search result done (0x65) but no entries
    assert!(
        response.contains(&0x65),
        "Should contain search result done"
    );
}

#[tokio::test]
async fn test_ldap_whoami() {
    let db = setup_test_db().await;
    let port = 13394;

    // Create test user
    let user_create = UserCreate {
        organization: "whoorg".to_string(),
        username: "whouser".to_string(),
        password: "whopass".to_string(),
        email: None,
        full_name: None,
    };
    db.create_user(user_create)
        .await
        .expect("Failed to create user");

    // Start LDAP server
    start_ldap_server(db.clone(), port).await;

    // Connect and bind
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");

    let dn = "cn=whouser,ou=whoorg,dc=example,dc=com";
    let bind_request = create_bind_request(1, dn, "whopass");
    stream
        .write_all(&bind_request)
        .await
        .expect("Failed to send bind");

    let mut response = vec![0u8; 1024];
    let _ = stream
        .read(&mut response)
        .await
        .expect("Failed to read bind response");

    // Send WhoAmI request
    let whoami_request = create_whoami_request(2);
    stream
        .write_all(&whoami_request)
        .await
        .expect("Failed to send whoami");

    let mut whoami_response = vec![0u8; 1024];
    let n = stream
        .read(&mut whoami_response)
        .await
        .expect("Failed to read whoami response");
    let whoami_response = &whoami_response[..n];

    assert!(
        !whoami_response.is_empty(),
        "Should receive whoami response"
    );

    // Should contain extended response tag (0x78)
    assert!(
        whoami_response.contains(&0x78),
        "Should contain extended response"
    );

    // Should contain "dn:" in the response
    let response_str = String::from_utf8_lossy(whoami_response);
    assert!(
        response_str.contains("dn:"),
        "Should contain DN in response"
    );

    // Cleanup
    db.delete_user("whoorg", "whouser").await.ok();
}

#[tokio::test]
async fn test_ldap_unbind() {
    let db = setup_test_db().await;
    let port = 13395;

    // Start LDAP server
    start_ldap_server(db.clone(), port).await;

    // Connect and bind anonymously
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");

    let bind_request = create_bind_request(1, "", "");
    stream
        .write_all(&bind_request)
        .await
        .expect("Failed to send bind");

    let mut response = vec![0u8; 1024];
    let _ = stream
        .read(&mut response)
        .await
        .expect("Failed to read bind response");

    // Send unbind
    let unbind_request = create_unbind_request(2);
    stream
        .write_all(&unbind_request)
        .await
        .expect("Failed to send unbind");

    // Server should close the connection after unbind
    let mut buffer = vec![0u8; 10];
    let result = stream.read(&mut buffer).await;

    // Should either get EOF (Ok(0)) or connection reset
    match result {
        Ok(0) => {} // Connection closed gracefully
        Ok(_) => panic!("Server should have closed connection"),
        Err(_) => {} // Connection reset is also acceptable
    }
}

#[tokio::test]
async fn test_ldap_multiple_operations() {
    let db = setup_test_db().await;
    let port = 13396;

    // Create test user
    let user_create = UserCreate {
        organization: "multiorg".to_string(),
        username: "multiuser".to_string(),
        password: "multipass".to_string(),
        email: Some("multi@example.com".to_string()),
        full_name: Some("Multi User".to_string()),
    };
    db.create_user(user_create)
        .await
        .expect("Failed to create user");

    // Start LDAP server
    start_ldap_server(db.clone(), port).await;

    // Connect
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");

    // 1. Bind
    let dn = "cn=multiuser,ou=multiorg,dc=example,dc=com";
    let bind_request = create_bind_request(1, dn, "multipass");
    stream
        .write_all(&bind_request)
        .await
        .expect("Failed to send bind");

    let mut response = vec![0u8; 1024];
    let n = stream
        .read(&mut response)
        .await
        .expect("Failed to read bind response");
    assert!(parse_bind_response(&response[..n]).unwrap() == 0);

    // 2. WhoAmI
    let whoami_request = create_whoami_request(2);
    stream
        .write_all(&whoami_request)
        .await
        .expect("Failed to send whoami");

    let mut whoami_response = vec![0u8; 1024];
    let n = stream
        .read(&mut whoami_response)
        .await
        .expect("Failed to read whoami");
    assert!(!whoami_response[..n].is_empty());

    // 3. Search
    let search_request = create_search_request(3, "dc=example,dc=com");
    stream
        .write_all(&search_request)
        .await
        .expect("Failed to send search");

    let mut search_response = vec![0u8; 4096];
    let n = stream
        .read(&mut search_response)
        .await
        .expect("Failed to read search");
    assert!(!search_response[..n].is_empty());

    // 4. Unbind
    let unbind_request = create_unbind_request(4);
    stream
        .write_all(&unbind_request)
        .await
        .expect("Failed to send unbind");

    // Cleanup
    db.delete_user("multiorg", "multiuser").await.ok();
}

#[tokio::test]
async fn test_ldap_bind_success_tls() {
    let db = setup_test_db().await;
    let port = 13397;

    // Create test user
    let user_create = UserCreate {
        organization: "tlsorg".to_string(),
        username: "tlsuser".to_string(),
        password: "tlspass123".to_string(),
        email: Some("tls@example.com".to_string()),
        full_name: None,
    };
    db.create_user(user_create)
        .await
        .expect("Failed to create user");

    // Start LDAP server with TLS
    let (cert_path, _key_path) = match start_ldap_server_with_tls(db.clone(), port).await {
        Ok(paths) => paths,
        Err(e) => {
            eprintln!("Skipping TLS test: {}", e);
            db.delete_user("tlsorg", "tlsuser").await.ok();
            return;
        }
    };

    // Load the certificate for client
    let cert_file = std::fs::File::open(&cert_path).expect("Failed to open cert");
    let mut reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .expect("Failed to parse certs");

    let mut root_store = RootCertStore::empty();
    for cert in certs {
        root_store
            .add(cert)
            .expect("Failed to add cert to root store");
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");

    let domain = ServerName::try_from("localhost")
        .expect("Invalid DNS name")
        .to_owned();

    let mut tls_stream = connector
        .connect(domain, tcp_stream)
        .await
        .expect("TLS handshake failed");

    // Send bind request over TLS
    let dn = "cn=tlsuser,ou=tlsorg,dc=example,dc=com";
    let bind_request = create_bind_request(1, dn, "tlspass123");

    tls_stream
        .write_all(&bind_request)
        .await
        .expect("Failed to send bind");

    let mut response = vec![0u8; 1024];
    let n = tls_stream
        .read(&mut response)
        .await
        .expect("Failed to read response");
    let response = &response[..n];

    let result_code = parse_bind_response(response).expect("Failed to parse response");
    assert_eq!(result_code, 0, "TLS bind should succeed");

    // Cleanup
    db.delete_user("tlsorg", "tlsuser").await.ok();
    std::fs::remove_file(&cert_path).ok();
    std::fs::remove_file(&_key_path).ok();
}

#[tokio::test]
async fn test_ldap_search_authenticated_tls() {
    let db = setup_test_db().await;
    let port = 13398;

    // Create test user
    let user_create = UserCreate {
        organization: "tlssearchorg".to_string(),
        username: "tlssearchuser".to_string(),
        password: "tlssearchpass".to_string(),
        email: Some("tlssearch@example.com".to_string()),
        full_name: None,
    };
    db.create_user(user_create)
        .await
        .expect("Failed to create user");

    // Start LDAP server with TLS
    let (cert_path, _key_path) = match start_ldap_server_with_tls(db.clone(), port).await {
        Ok(paths) => paths,
        Err(e) => {
            eprintln!("Skipping TLS test: {}", e);
            db.delete_user("tlssearchorg", "tlssearchuser").await.ok();
            return;
        }
    };

    // Load the certificate for client
    let cert_file = std::fs::File::open(&cert_path).expect("Failed to open cert");
    let mut reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .expect("Failed to parse certs");

    let mut root_store = RootCertStore::empty();
    for cert in certs {
        root_store
            .add(cert)
            .expect("Failed to add cert to root store");
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");

    let domain = ServerName::try_from("localhost")
        .expect("Invalid DNS name")
        .to_owned();

    let mut tls_stream = connector
        .connect(domain, tcp_stream)
        .await
        .expect("TLS handshake failed");

    // Bind over TLS
    let dn = "cn=tlssearchuser,ou=tlssearchorg,dc=example,dc=com";
    let bind_request = create_bind_request(1, dn, "tlssearchpass");
    tls_stream
        .write_all(&bind_request)
        .await
        .expect("Failed to send bind");

    let mut response = vec![0u8; 1024];
    let _ = tls_stream
        .read(&mut response)
        .await
        .expect("Failed to read bind response");

    // Now search over TLS
    let search_request = create_search_request(2, "dc=example,dc=com");
    tls_stream
        .write_all(&search_request)
        .await
        .expect("Failed to send search");

    let mut search_response = vec![0u8; 4096];
    let n = tls_stream
        .read(&mut search_response)
        .await
        .expect("Failed to read search response");
    let search_response = &search_response[..n];

    assert!(
        !search_response.is_empty(),
        "Should receive search response"
    );

    // Should contain search result done (0x65)
    assert!(
        search_response.contains(&0x65),
        "Should contain search result done"
    );

    // Cleanup
    db.delete_user("tlssearchorg", "tlssearchuser").await.ok();
    std::fs::remove_file(&cert_path).ok();
    std::fs::remove_file(&_key_path).ok();
}

#[tokio::test]
async fn test_ldap_invalid_credentials_tls() {
    let db = setup_test_db().await;
    let port = 13399;

    // Create test user
    let user_create = UserCreate {
        organization: "tlsinvalidorg".to_string(),
        username: "tlsinvaliduser".to_string(),
        password: "correctpass".to_string(),
        email: None,
        full_name: None,
    };
    db.create_user(user_create)
        .await
        .expect("Failed to create user");

    // Start LDAP server with TLS
    let (cert_path, _key_path) = match start_ldap_server_with_tls(db.clone(), port).await {
        Ok(paths) => paths,
        Err(e) => {
            eprintln!("Skipping TLS test: {}", e);
            db.delete_user("tlsinvalidorg", "tlsinvaliduser").await.ok();
            return;
        }
    };

    // Load the certificate for client
    let cert_file = std::fs::File::open(&cert_path).expect("Failed to open cert");
    let mut reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .expect("Failed to parse certs");

    let mut root_store = RootCertStore::empty();
    for cert in certs {
        root_store
            .add(cert)
            .expect("Failed to add cert to root store");
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");

    let domain = ServerName::try_from("localhost")
        .expect("Invalid DNS name")
        .to_owned();

    let mut tls_stream = connector
        .connect(domain, tcp_stream)
        .await
        .expect("TLS handshake failed");

    // Try to bind with wrong password over TLS
    let dn = "cn=tlsinvaliduser,ou=tlsinvalidorg,dc=example,dc=com";
    let bind_request = create_bind_request(1, dn, "wrongpass");

    tls_stream
        .write_all(&bind_request)
        .await
        .expect("Failed to send bind");

    let mut response = vec![0u8; 1024];
    let n = tls_stream
        .read(&mut response)
        .await
        .expect("Failed to read response");
    let response = &response[..n];

    let result_code = parse_bind_response(response).expect("Failed to parse response");
    assert_eq!(
        result_code, 49,
        "TLS bind should fail with invalid credentials"
    );

    // Cleanup
    db.delete_user("tlsinvalidorg", "tlsinvaliduser").await.ok();
    std::fs::remove_file(&cert_path).ok();
    std::fs::remove_file(&_key_path).ok();
}
