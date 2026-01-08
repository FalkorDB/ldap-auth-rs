//! Simplified LDAP Server Implementation
//!
//! # RFC Compliance Status
//!
//! This is a simplified LDAP v3 server implementation with the following limitations:
//!
//! ## Implemented Operations (RFC 4511)
//! - **Bind Request/Response**: Simple authentication with username/password (Section 4.2)
//! - **Unbind Request**: Clean connection termination (Section 4.3)
//! - **Search Request/Response**: Basic user search with authorization checks (Section 4.5)
//! - **Extended Operations**: WhoAmI (RFC 4532) and StartTLS (RFC 4511 Section 4.14)
//!
//! ## Known Limitations
//!
//! ### 1. Search Request Parsing (RFC 4511 Section 4.5.1)
//! - **Base DN**: Not extracted from request, uses configured base_dn
//! - **Search Scope**: Not parsed (base, one-level, subtree ignored)
//! - **Filter**: Not parsed, returns all users in organization
//! - **Attributes**: Requested attributes are ignored, always returns cn and mail
//! - **Size/Time Limits**: Not enforced
//!
//! ### 2. DN Format Support
//! - Supports:
//!   - `cn=username,ou=organization,dc=...`
//!   - `cn=username,dc=domain,dc=tld` (uses first DC as organization)
//!   - Case-insensitive prefixes (cn/CN/Cn, ou/OU/Ou, dc/DC/Dc)
//! - Does NOT support:
//!   - Multiple OUs: `cn=user,ou=dept,ou=company,dc=...`
//!   - Alternative RDN types: `uid=user` or `mail=user@example.com`
//!   - Escaped characters in DN components
//!
//! ### 3. Extended Operations
//! - WhoAmI: Fully implemented per RFC 4532
//! - StartTLS: Returns unavailable (TLS should be enabled at server start)
//! - Other extended operations: Not supported
//!
//! ### 4. Unsupported Operations
//! - Modify, Add, Delete, ModifyDN, Compare operations
//! - SASL authentication (only simple bind supported)
//! - Referrals and continuations
//! - Controls (RFC 4511 Section 4.1.11)
//!
//! ### 5. Protocol Encoding
//! - Uses simplified BER/DER parsing
//! - For production use, consider a proper ASN.1/BER library like `ldap3` or `lber`
//!
//! ## Security Model
//! - Anonymous bind allowed but search returns empty results unless authorized
//! - `search_bind_org` configuration restricts search to specific organization
//! - TLS strongly recommended for production (use `run_with_tls`)
//!
//! ## TLS Connection Handling
//! - Gracefully handles improper TLS connection closures (missing `close_notify` alerts)
//! - Many LDAP clients/servers don't follow RFC-compliant TLS shutdown procedures
//! - Such closures are logged at debug level but don't trigger errors

use rustls::ServerConfig;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::db::DbService;
use crate::error::AppError;
use crate::error::Result;
use crate::ldap_lib::{
    create_bind_response, create_error_response, create_extended_response,
    create_group_search_entry_response, create_search_done_response, create_search_entry_response,
    create_whoami_response, LdapResultCode,
};

/// LDAP message types
#[derive(Debug)]
#[allow(dead_code)]
enum LdapOp {
    BindRequest = 0,
    BindResponse = 1,
    UnbindRequest = 2,
    SearchRequest = 3,
    SearchResultEntry = 4,
    SearchResultDone = 5,
    ModifyRequest = 6,
    ModifyResponse = 7,
    AddRequest = 8,
    AddResponse = 9,
    DelRequest = 10,
    DelResponse = 11,
    ModifyDNRequest = 12,
    ModifyDNResponse = 13,
    CompareRequest = 14,
    CompareResponse = 15,
    AbandonRequest = 16,
    ExtendedRequest = 23,
    ExtendedResponse = 24,
}

pub struct LdapServer {
    db: Arc<dyn DbService>,
    base_dn: String,
    search_bind_org: Option<String>,
}

impl LdapServer {
    pub fn new(db: Arc<dyn DbService>, base_dn: String, search_bind_org: Option<String>) -> Self {
        Self {
            db,
            base_dn,
            search_bind_org,
        }
    }

    /// Start the LDAP server
    pub async fn run(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await.map_err(|e| {
            crate::error::AppError::Internal(format!("Failed to bind LDAP server: {}", e))
        })?;

        info!("LDAP server listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    info!("New LDAP connection from {}", addr);
                    let db = self.db.clone();
                    let base_dn = self.base_dn.clone();
                    let search_bind_org = self.search_bind_org.clone();

                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_connection(socket, db, base_dn, search_bind_org).await
                        {
                            error!("Error handling LDAP connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept LDAP connection: {}", e);
                }
            }
        }
    }

    /// Start the LDAP server with TLS
    pub async fn run_with_tls(&self, addr: &str, tls_config: Arc<ServerConfig>) -> Result<()> {
        let listener = TcpListener::bind(addr).await.map_err(|e| {
            crate::error::AppError::Internal(format!("Failed to bind LDAP server: {}", e))
        })?;

        let acceptor = TlsAcceptor::from(tls_config);
        info!("LDAP server with TLS listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((socket, client_addr)) => {
                    debug!("New LDAP connection from {}", client_addr);
                    let acceptor = acceptor.clone();
                    let db = self.db.clone();
                    let base_dn = self.base_dn.clone();
                    let search_bind_org = self.search_bind_org.clone();

                    tokio::spawn(async move {
                        match acceptor.accept(socket).await {
                            Ok(tls_stream) => {
                                if let Err(e) =
                                    handle_tls_connection(tls_stream, db, base_dn, search_bind_org)
                                        .await
                                {
                                    error!("Error handling TLS LDAP connection: {}", e);
                                }
                            }
                            Err(e) => {
                                error!("TLS handshake failed: {}", e);
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept LDAP connection: {}", e);
                }
            }
        }
    }
}

async fn handle_connection(
    mut socket: TcpStream,
    db: Arc<dyn DbService>,
    base_dn: String,
    search_bind_org: Option<String>,
) -> Result<()> {
    // Enable TCP_NODELAY to send data immediately without buffering
    socket.set_nodelay(true).map_err(|e| {
        crate::error::AppError::Internal(format!("Failed to set TCP_NODELAY: {}", e))
    })?;

    let mut buffer = vec![0u8; 8192];
    let mut authenticated_user: Option<String> = None;
    let mut authenticated_org: Option<String> = None;

    loop {
        let n = socket.read(&mut buffer).await.map_err(|e| {
            crate::error::AppError::Internal(format!("Failed to read from socket: {}", e))
        })?;

        if n == 0 {
            debug!("Client disconnected");
            return Ok(());
        }

        let request = &buffer[..n];
        debug!("Received {} bytes", n);

        // Parse LDAP message (simplified)
        match parse_ldap_message(request) {
            Ok((message_id, op_type, payload)) => {
                debug!("Message ID: {}, Op: {:?}", message_id, op_type);

                match op_type {
                    0 => {
                        // Bind Request
                        let response = handle_bind_request(
                            message_id,
                            payload,
                            &db,
                            &base_dn,
                            &mut authenticated_user,
                            &mut authenticated_org,
                        )
                        .await;

                        socket.write_all(&response).await.map_err(|e| {
                            crate::error::AppError::Internal(format!(
                                "Failed to write response: {}",
                                e
                            ))
                        })?;
                        socket.flush().await.map_err(|e| {
                            crate::error::AppError::Internal(format!(
                                "Failed to flush socket: {}",
                                e
                            ))
                        })?;
                    }
                    2 => {
                        // Unbind Request
                        debug!("User unbound");
                        return Ok(());
                    }
                    3 => {
                        // Search Request - returns multiple messages
                        let messages = handle_search_request(
                            message_id,
                            payload,
                            &db,
                            &base_dn,
                            &authenticated_org,
                            &search_bind_org,
                        )
                        .await;

                        // Write each message separately
                        for (idx, message) in messages.iter().enumerate() {
                            debug!(
                                "Writing LDAP message {}/{}: {} bytes",
                                idx + 1,
                                messages.len(),
                                message.len()
                            );
                            socket.write_all(message).await.map_err(|e| {
                                crate::error::AppError::Internal(format!(
                                    "Failed to write search message: {}",
                                    e
                                ))
                            })?;
                            socket.flush().await.map_err(|e| {
                                crate::error::AppError::Internal(format!(
                                    "Failed to flush after search message: {}",
                                    e
                                ))
                            })?;
                        }
                    }
                    23 => {
                        // Extended Request (e.g., WhoAmI, StartTLS)
                        let response = handle_extended_request(
                            message_id,
                            payload,
                            &authenticated_user,
                            &authenticated_org,
                        )
                        .await;

                        socket.write_all(&response).await.map_err(|e| {
                            crate::error::AppError::Internal(format!(
                                "Failed to write response: {}",
                                e
                            ))
                        })?;
                        socket.flush().await.map_err(|e| {
                            crate::error::AppError::Internal(format!(
                                "Failed to flush socket: {}",
                                e
                            ))
                        })?;
                    }
                    _ => {
                        warn!("Unsupported LDAP operation: {}", op_type);
                        let response = create_error_response(
                            message_id,
                            1,
                            LdapResultCode::OperationsError as u8,
                        );
                        socket.write_all(&response).await.map_err(|e| {
                            crate::error::AppError::Internal(format!(
                                "Failed to write response: {}",
                                e
                            ))
                        })?;
                        socket.flush().await.map_err(|e| {
                            crate::error::AppError::Internal(format!(
                                "Failed to flush socket: {}",
                                e
                            ))
                        })?;
                    }
                }
            }
            Err(e) => {
                error!("Failed to parse LDAP message: {}", e);
                let error_response =
                    create_error_response(1, 1, LdapResultCode::ProtocolError as u8);
                socket.write_all(&error_response).await.map_err(|e| {
                    crate::error::AppError::Internal(format!("Failed to write error: {}", e))
                })?;
                socket.flush().await.map_err(|e| {
                    crate::error::AppError::Internal(format!("Failed to flush socket: {}", e))
                })?;
            }
        }
    }
}

/// Helper function to check if a TLS error is due to improper connection closure
/// Many LDAP clients/servers don't send close_notify alerts, which is not critical
fn is_benign_tls_closure_error(error: &std::io::Error) -> bool {
    let error_msg = error.to_string().to_lowercase();
    error_msg.contains("closenotify")
        || error_msg.contains("close_notify")
        || error_msg.contains("peer closed connection without sending tls close_notify")
        || error_msg.contains("unexpectedeof")
        || error_msg.contains("connection reset")
        || error_msg.contains("broken pipe")
}

async fn handle_tls_connection(
    mut socket: tokio_rustls::server::TlsStream<TcpStream>,
    db: Arc<dyn DbService>,
    base_dn: String,
    search_bind_org: Option<String>,
) -> Result<()> {
    // Enable TCP_NODELAY on the underlying stream
    socket.get_ref().0.set_nodelay(true).map_err(|e| {
        crate::error::AppError::Internal(format!("Failed to set TCP_NODELAY on TLS socket: {}", e))
    })?;

    let mut buffer = vec![0u8; 8192];
    let mut authenticated_user: Option<String> = None;
    let mut authenticated_org: Option<String> = None;

    loop {
        let n = match socket.read(&mut buffer).await {
            Ok(n) => n,
            Err(e) => {
                // Handle TLS close_notify gracefully - some LDAP clients don't send it
                if is_benign_tls_closure_error(&e) {
                    debug!("Client closed TLS connection (no close_notify): {}", e);
                    return Ok(());
                }
                return Err(crate::error::AppError::Internal(format!(
                    "Failed to read from TLS socket: {}",
                    e
                )));
            }
        };

        if n == 0 {
            debug!("Client disconnected");
            return Ok(());
        }

        let request = &buffer[..n];
        debug!("Received {} bytes over TLS", n);

        // Parse LDAP message (simplified)
        match parse_ldap_message(request) {
            Ok((message_id, op_type, payload)) => {
                debug!("Message ID: {}, Op: {:?}", message_id, op_type);

                match op_type {
                    0 => {
                        // Bind Request
                        let response = handle_bind_request(
                            message_id,
                            payload,
                            &db,
                            &base_dn,
                            &mut authenticated_user,
                            &mut authenticated_org,
                        )
                        .await;

                        if let Err(e) = socket.write_all(&response).await {
                            if is_benign_tls_closure_error(&e) {
                                debug!("Client disconnected during write");
                                return Ok(());
                            }
                            return Err(crate::error::AppError::Internal(format!(
                                "Failed to write TLS response: {}",
                                e
                            )));
                        }
                        if let Err(e) = socket.flush().await {
                            if is_benign_tls_closure_error(&e) {
                                debug!("Client disconnected during flush");
                                return Ok(());
                            }
                            return Err(crate::error::AppError::Internal(format!(
                                "Failed to flush TLS socket: {}",
                                e
                            )));
                        }
                    }
                    2 => {
                        // Unbind Request
                        debug!("User unbound");
                        return Ok(());
                    }
                    3 => {
                        // Search Request - returns multiple messages
                        let messages = handle_search_request(
                            message_id,
                            payload,
                            &db,
                            &base_dn,
                            &authenticated_org,
                            &search_bind_org,
                        )
                        .await;

                        // Write each message separately
                        for (idx, message) in messages.iter().enumerate() {
                            debug!(
                                "Writing TLS LDAP message {}/{}: {} bytes",
                                idx + 1,
                                messages.len(),
                                message.len()
                            );
                            if let Err(e) = socket.write_all(message).await {
                                if is_benign_tls_closure_error(&e) {
                                    debug!("Client disconnected during write");
                                    return Ok(());
                                }
                                return Err(crate::error::AppError::Internal(format!(
                                    "Failed to write TLS search message: {}",
                                    e
                                )));
                            }
                            if let Err(e) = socket.flush().await {
                                if is_benign_tls_closure_error(&e) {
                                    debug!("Client disconnected during flush");
                                    return Ok(());
                                }
                                return Err(crate::error::AppError::Internal(format!(
                                    "Failed to flush after TLS search message: {}",
                                    e
                                )));
                            }
                        }
                    }
                    23 => {
                        // Extended Request (e.g., WhoAmI, StartTLS)
                        let response = handle_extended_request(
                            message_id,
                            payload,
                            &authenticated_user,
                            &authenticated_org,
                        )
                        .await;

                        if let Err(e) = socket.write_all(&response).await {
                            if is_benign_tls_closure_error(&e) {
                                debug!("Client disconnected during write");
                                return Ok(());
                            }
                            return Err(crate::error::AppError::Internal(format!(
                                "Failed to write TLS response: {}",
                                e
                            )));
                        }
                        if let Err(e) = socket.flush().await {
                            if is_benign_tls_closure_error(&e) {
                                debug!("Client disconnected during flush");
                                return Ok(());
                            }
                            return Err(crate::error::AppError::Internal(format!(
                                "Failed to flush TLS socket: {}",
                                e
                            )));
                        }
                    }
                    _ => {
                        warn!("Unsupported LDAP operation: {}", op_type);
                        let response = create_error_response(
                            message_id,
                            1,
                            LdapResultCode::OperationsError as u8,
                        );
                        if let Err(e) = socket.write_all(&response).await {
                            if is_benign_tls_closure_error(&e) {
                                debug!("Client disconnected during write");
                                return Ok(());
                            }
                            return Err(crate::error::AppError::Internal(format!(
                                "Failed to write TLS response: {}",
                                e
                            )));
                        }
                        if let Err(e) = socket.flush().await {
                            if is_benign_tls_closure_error(&e) {
                                debug!("Client disconnected during flush");
                                return Ok(());
                            }
                            return Err(crate::error::AppError::Internal(format!(
                                "Failed to flush TLS socket: {}",
                                e
                            )));
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to parse LDAP message: {}", e);
                let error_response =
                    create_error_response(1, 1, LdapResultCode::ProtocolError as u8);
                if let Err(e) = socket.write_all(&error_response).await {
                    if is_benign_tls_closure_error(&e) {
                        debug!("Client disconnected during write");
                        return Ok(());
                    }
                    return Err(crate::error::AppError::Internal(format!(
                        "Failed to write TLS error: {}",
                        e
                    )));
                }
                if let Err(e) = socket.flush().await {
                    if is_benign_tls_closure_error(&e) {
                        debug!("Client disconnected during flush");
                        return Ok(());
                    }
                    return Err(crate::error::AppError::Internal(format!(
                        "Failed to flush TLS socket: {}",
                        e
                    )));
                }
            }
        }
    }
}

/// Parse a DN to extract organization and username
/// Supported formats:
/// - cn=username,ou=organization,dc=example,dc=com
/// - cn=username,dc=domain,dc=tld (uses first DC as organization)
///   Accepts both lowercase (cn=, ou=, dc=) and uppercase (CN=, OU=, DC=) prefixes
fn parse_dn(dn: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = dn.split(',').collect();
    if parts.len() < 2 {
        return None;
    }

    let mut username = None;
    let mut organization = None;
    let mut first_dc = None;

    for part in parts {
        let part = part.trim();
        let part_lower = part.to_lowercase();

        if let Some(stripped) = part_lower.strip_prefix("cn=") {
            // Extract the value from the original part to preserve case
            let value = &part[part.len() - stripped.len()..];
            username = Some(value.to_string());
        } else if let Some(stripped) = part_lower.strip_prefix("ou=") {
            if organization.is_none() {
                // Extract the value from the original part to preserve case
                let value = &part[part.len() - stripped.len()..];
                organization = Some(value.to_string());
            }
        } else if let Some(stripped) = part_lower.strip_prefix("dc=") {
            if first_dc.is_none() {
                // Extract the value from the original part to preserve case
                let value = &part[part.len() - stripped.len()..];
                first_dc = Some(value.to_string());
            }
        }
    }

    match (username, organization.or(first_dc)) {
        (Some(u), Some(o)) => Some((o, u)),
        _ => None,
    }
}

/// Parse bind request payload to extract DN and password
fn parse_bind_payload(payload: &[u8]) -> std::result::Result<(String, String), String> {
    if payload.len() < 7 {
        return Err("Bind payload too short".to_string());
    }

    let mut pos = 0;

    // Skip bind request tag (APPLICATION 0 = 0x60)
    if payload[pos] & 0xe0 != 0x60 {
        return Err(format!("Invalid bind request tag: {:#x}", payload[pos]));
    }
    pos += 1;

    // Parse and skip bind request length
    let len_byte = payload[pos];
    pos += 1;
    if len_byte & 0x80 != 0 {
        let num_octets = (len_byte & 0x7f) as usize;
        if pos + num_octets > payload.len() {
            return Err("Length octets exceed payload".to_string());
        }
        pos += num_octets;
    }

    // Parse version (INTEGER = 0x02)
    if pos >= payload.len() {
        return Err("Unexpected end of payload at version".to_string());
    }
    if payload[pos] != 0x02 {
        return Err(format!("Invalid version tag: {:#x}", payload[pos]));
    }
    pos += 1;

    if pos >= payload.len() {
        return Err("Unexpected end of payload at version length".to_string());
    }
    let version_len = payload[pos] as usize;
    pos += 1 + version_len; // Skip version value

    // Parse DN (OCTET STRING = 0x04)
    if pos >= payload.len() {
        return Err("Unexpected end of payload at DN tag".to_string());
    }
    if payload[pos] != 0x04 {
        return Err(format!("Invalid DN tag: {:#x}", payload[pos]));
    }
    pos += 1;

    if pos >= payload.len() {
        return Err("Unexpected end of payload at DN length".to_string());
    }
    let dn_len = payload[pos] as usize;
    pos += 1;

    if pos + dn_len > payload.len() {
        return Err(format!(
            "DN length {} exceeds remaining payload {}",
            dn_len,
            payload.len() - pos
        ));
    }

    let dn = if dn_len > 0 {
        String::from_utf8_lossy(&payload[pos..pos + dn_len]).to_string()
    } else {
        String::new()
    };
    pos += dn_len;

    // Parse password (CONTEXT 0 - simple auth = 0x80)
    if pos >= payload.len() {
        return Err("Unexpected end of payload at password tag".to_string());
    }
    if payload[pos] != 0x80 {
        return Err(format!(
            "Invalid password tag (expected 0x80): {:#x}",
            payload[pos]
        ));
    }
    pos += 1;

    if pos >= payload.len() {
        return Err("Unexpected end of payload at password length".to_string());
    }
    let pwd_len = payload[pos] as usize;
    pos += 1;

    if pos + pwd_len > payload.len() {
        return Err(format!(
            "Password length {} exceeds remaining payload {}",
            pwd_len,
            payload.len() - pos
        ));
    }

    let password = if pwd_len > 0 {
        String::from_utf8_lossy(&payload[pos..pos + pwd_len]).to_string()
    } else {
        String::new()
    };

    Ok((dn, password))
}

fn parse_ldap_message(data: &[u8]) -> std::result::Result<(u32, u8, &[u8]), String> {
    // Simplified BER/DER parser for LDAP messages
    // In production, use a proper ASN.1/BER library

    if data.len() < 5 {
        return Err("Message too short".to_string());
    }

    // Skip SEQUENCE tag and length
    let mut pos = 0;
    if data[pos] != 0x30 {
        return Err("Invalid SEQUENCE tag".to_string());
    }
    pos += 1;

    // Parse length
    let len_byte = data[pos];
    pos += 1;
    if len_byte & 0x80 != 0 {
        let num_octets = (len_byte & 0x7f) as usize;
        pos += num_octets;
    }

    // Parse message ID (INTEGER)
    if data[pos] != 0x02 {
        return Err("Invalid message ID tag".to_string());
    }
    pos += 1;
    let id_len = data[pos] as usize;
    pos += 1;

    let mut message_id = 0u32;
    for i in 0..id_len {
        message_id = (message_id << 8) | data[pos + i] as u32;
    }
    pos += id_len;

    // Parse operation type (APPLICATION tag)
    let op_type = data[pos] & 0x1f;

    // Return message ID, operation type, and remaining payload
    Ok((message_id, op_type, &data[pos..]))
}

async fn handle_bind_request(
    message_id: u32,
    payload: &[u8],
    db: &Arc<dyn DbService>,
    _base_dn: &str,
    authenticated_user: &mut Option<String>,
    authenticated_org: &mut Option<String>,
) -> Vec<u8> {
    debug!("Processing bind request");

    // Parse DN and password from payload
    let (dn, password) = match parse_bind_payload(payload) {
        Ok(creds) => creds,
        Err(e) => {
            warn!("Failed to parse bind payload: {}", e);
            return create_bind_response(message_id, LdapResultCode::ProtocolError as u8);
        }
    };

    debug!("Bind request for DN: {}", dn);

    // Handle anonymous bind (empty DN and password)
    if dn.is_empty() && password.is_empty() {
        debug!("Anonymous bind accepted");
        *authenticated_user = None;
        *authenticated_org = None;
        return create_bind_response(message_id, LdapResultCode::Success as u8);
    }

    // Parse DN to extract organization and username
    let (org, username) = match parse_dn(&dn) {
        Some(parsed) => parsed,
        None => {
            warn!("Invalid DN format: {}", dn);
            return create_bind_response(message_id, LdapResultCode::InvalidCredentials as u8);
        }
    };

    // Verify credentials with database
    match db.verify_user_password(&org, &username, &password).await {
        Ok(true) => {
            info!("User {}/{} authenticated successfully", org, username);
            *authenticated_user = Some(username);
            *authenticated_org = Some(org);
            create_bind_response(message_id, LdapResultCode::Success as u8)
        }
        Ok(false) => {
            warn!("Invalid credentials for {}/{}", org, username);
            *authenticated_user = None;
            *authenticated_org = None;
            create_bind_response(message_id, LdapResultCode::InvalidCredentials as u8)
        }
        Err(AppError::NotFound(_)) => {
            warn!(
                "Invalid credentials for {}/{} (user not found)",
                org, username
            );
            *authenticated_user = None;
            *authenticated_org = None;
            create_bind_response(message_id, LdapResultCode::InvalidCredentials as u8)
        }
        Err(e) => {
            error!("Error verifying credentials: {}", e);
            *authenticated_user = None;
            *authenticated_org = None;
            create_bind_response(message_id, LdapResultCode::OperationsError as u8)
        }
    }
}

async fn handle_search_request(
    message_id: u32,
    payload: &[u8],
    db: &Arc<dyn DbService>,
    base_dn: &str,
    authenticated_org: &Option<String>,
    search_bind_org: &Option<String>,
) -> Vec<Vec<u8>> {
    debug!(
        "Processing search request, payload length: {}",
        payload.len()
    );

    // Parse requested attributes
    let requested_attrs = parse_search_attributes(payload);
    debug!("Requested attributes from search: {:?}", requested_attrs);

    // Parse base DN (baseObject) from the SearchRequest payload. This lets callers
    // scope searches to a specific organization via `ou=<org>,...`.
    let base_object_dn = parse_search_base_dn(payload);
    let org_from_base_dn = base_object_dn.as_deref().and_then(extract_org_from_base_dn);
    debug!(
        "Search base DN: {:?}, org from base DN: {:?}",
        base_object_dn, org_from_base_dn
    );

    // Simple approach: search for group-related strings in the entire payload
    let payload_str = String::from_utf8_lossy(payload).to_lowercase();
    debug!("Payload string (lowercase): {}", payload_str);

    // Check if this is a group search
    let is_group_search = payload_str.contains("groupofnames")
        || payload_str.contains("groupofuniquenames")
        || payload_str.contains("posixgroup");

    // Check if searching for groups a specific user is member of
    // In LDAP BER encoding, the filter might have the pattern differently
    // Try multiple patterns: "member=cn=", "member" followed by "cn="
    // Extract both username and organization from the member DN
    let member_search = extract_member_info(&payload_str);
    debug!("Member search result: {:?}", member_search);

    // Per LDAP standards: if a search_bind_org is configured, only authenticated users
    // from that organization can search. If not configured, anonymous searches are allowed
    // but will return limited or no results (security by design).

    // If search_bind_org is configured, require authentication from that specific org
    if let Some(required_org) = search_bind_org {
        match authenticated_org {
            Some(org) if org == required_org => {
                // Authenticated with correct org - proceed with search
            }
            Some(org) => {
                warn!(
                    "Search attempted by organization '{}' but only '{}' is authorized",
                    org, required_org
                );
                return vec![create_error_response(
                    message_id,
                    5,
                    LdapResultCode::InsufficientAccessRights as u8,
                )];
            }
            None => {
                warn!("Search attempted without authentication (authentication required)");
                return vec![create_error_response(
                    message_id,
                    5,
                    LdapResultCode::InsufficientAccessRights as u8,
                )];
            }
        }
    }

    // If we reach here, either:
    // 1. search_bind_org is configured and user is authenticated with correct org, OR
    // 2. search_bind_org is NOT configured (anonymous search allowed)

    let org = match authenticated_org {
        Some(o) => o,
        None => {
            // Anonymous search: return empty results (no organization to search)
            debug!("Anonymous search - returning empty results");
            let done_response =
                create_search_done_response(message_id, LdapResultCode::Success as u8);
            return vec![done_response];
        }
    };

    // Prefer the organization inferred from the search base DN (if present),
    // otherwise fall back to the authenticated org.
    let search_org: &str = org_from_base_dn.as_deref().unwrap_or(org);

    let mut messages = Vec::new();

    // Handle group searches
    if is_group_search {
        debug!("Group search detected - querying groups from database");

        // If searching for groups a specific user is member of
        if let Some((member_org, username)) = member_search {
            debug!(
                "Searching for groups where user '{}' is a member in org '{}'",
                username, member_org
            );
            match db.get_user_groups(&member_org, &username).await {
                Ok(groups) => {
                    debug!("Found {} groups for user '{}'", groups.len(), username);
                    for group in groups {
                        let dn = group.to_dn(base_dn);
                        let entry_response = create_group_search_entry_response(
                            message_id,
                            &dn,
                            &group.name,
                            group.description.as_deref(),
                            &group.members,
                            requested_attrs.as_deref(),
                        );
                        info!(
                            "Group entry response - DN: '{}', size: {} bytes, first 20 bytes: {:02x?}",
                            dn,
                            entry_response.len(),
                            &entry_response[..std::cmp::min(20, entry_response.len())]
                        );
                        messages.push(entry_response);
                    }
                }
                Err(e) => {
                    warn!("Error searching user groups: {}", e);
                }
            }
        } else {
            // List all groups in the organization
            debug!("Listing all groups in organization '{}'", search_org);
            match db.list_groups(search_org).await {
                Ok(groups) => {
                    for group in groups {
                        let dn = group.to_dn(base_dn);
                        let entry_response = create_group_search_entry_response(
                            message_id,
                            &dn,
                            &group.name,
                            group.description.as_deref(),
                            &group.members,
                            requested_attrs.as_deref(),
                        );
                        messages.push(entry_response);
                    }
                }
                Err(e) => {
                    warn!("Error searching groups: {}", e);
                }
            }
        }
    } else {
        // Regular user search - return all users in the organization
        match db.list_users(search_org).await {
            Ok(users) => {
                for user in users {
                    let dn = format!("cn={},ou={},{}", user.username, search_org, base_dn);
                    let entry_response = create_search_entry_response(
                        message_id,
                        &dn,
                        &user.username,
                        user.email.as_deref(),
                    );
                    messages.push(entry_response);
                }
            }
            Err(e) => {
                warn!("Error searching users: {}", e);
            }
        }
    }

    // Add search result done as separate message
    let done_response = create_search_done_response(message_id, LdapResultCode::Success as u8);

    debug!(
        "Sending {} LDAP messages: {} entries + 1 done response",
        messages.len() + 1,
        messages.len()
    );

    messages.push(done_response);
    messages
}

fn parse_search_base_dn(payload: &[u8]) -> Option<String> {
    // SearchRequest ::= [APPLICATION 3] SEQUENCE {
    //   baseObject      LDAPDN,
    //   scope          ENUMERATED,
    //   derefAliases   ENUMERATED,
    //   sizeLimit      INTEGER (0 .. maxInt),
    //   timeLimit      INTEGER (0 .. maxInt),
    //   typesOnly      BOOLEAN,
    //   filter         Filter,
    //   attributes     AttributeSelection }
    //
    // The payload passed to this function is the contents of the SearchRequest
    // (i.e., after the application tag + length). The first element is the
    // baseObject LDAPDN which is encoded as an OCTET STRING.
    if payload.is_empty() {
        return None;
    }

    // Our simplified `parse_ldap_message` returns the payload starting at the
    // operation APPLICATION tag (e.g. SearchRequest = 0x63), not after it.
    // Strip the operation tag+length if present.
    let mut cursor: &[u8] = payload;
    if cursor.first() == Some(&0x63) {
        let (op_len, op_len_bytes) = parse_ber_length(cursor.get(1..)?)?;
        let start = 1 + op_len_bytes;
        let end = start.checked_add(op_len)?;
        cursor = cursor.get(start..end)?;
    }

    // Some callers may pass an inner SEQUENCE (0x30) wrapper.
    if cursor.first() == Some(&0x30) {
        let (seq_len, seq_len_bytes) = parse_ber_length(cursor.get(1..)?)?;
        let start = 1 + seq_len_bytes;
        let end = start.checked_add(seq_len)?;
        cursor = cursor.get(start..end)?;
    }

    if cursor.first() != Some(&0x04) {
        return None;
    }
    let (len, len_bytes) = parse_ber_length(cursor.get(1..)?)?;
    let start = 1 + len_bytes;
    let end = start.checked_add(len)?;
    let dn_bytes = cursor.get(start..end)?;
    String::from_utf8(dn_bytes.to_vec()).ok()
}

fn parse_ber_length(input: &[u8]) -> Option<(usize, usize)> {
    // Returns (length, bytes_consumed_from_input)
    let first = *input.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let num_bytes = (first & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 8 {
        return None;
    }
    if input.len() < 1 + num_bytes {
        return None;
    }
    let mut len: usize = 0;
    for b in &input[1..1 + num_bytes] {
        len = (len << 8) | (*b as usize);
    }
    Some((len, 1 + num_bytes))
}

fn extract_org_from_base_dn(base_dn: &str) -> Option<String> {
    // Supported org encodings in this service:
    // - ou=<org>,dc=...
    // - ou=groups,ou=<org>,dc=...
    let mut ous: Vec<String> = Vec::new();
    for part in base_dn.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("ou=") {
            ous.push(rest.trim().to_string());
            continue;
        }
        if let Some(rest) = part.strip_prefix("OU=") {
            ous.push(rest.trim().to_string());
            continue;
        }
        if let Some(rest) = part.strip_prefix("Ou=") {
            ous.push(rest.trim().to_string());
            continue;
        }
    }

    if ous.is_empty() {
        return None;
    }

    for (idx, ou) in ous.iter().enumerate() {
        if ou.eq_ignore_ascii_case("groups") {
            return ous.get(idx + 1).cloned();
        }
    }

    ous.first().cloned()
}

/// Parses the requested attributes from an LDAP SearchRequest payload
/// Returns a vector of attribute names, or None if all attributes should be returned
/// Per RFC 4511: empty list = all user attributes, "*" = all user attributes
fn parse_search_attributes(payload: &[u8]) -> Option<Vec<String>> {
    // SearchRequest structure (simplified parsing):
    // SEQUENCE -> baseObject, scope, derefAliases, sizeLimit, timeLimit, typesOnly, filter, attributes
    // We need to skip to the attributes SEQUENCE at the end

    let mut pos = 0;

    // Skip SEQUENCE tag and length for SearchRequest
    if pos >= payload.len() || payload[pos] != 0x63 {
        // APPLICATION 3
        return None;
    }
    pos += 1;

    // Skip length
    if pos >= payload.len() {
        return None;
    }
    let len = payload[pos];
    if len & 0x80 != 0 {
        let len_bytes = (len & 0x7f) as usize;
        pos += 1 + len_bytes;
    } else {
        pos += 1;
    }

    // For simplicity, search for the attributes SEQUENCE (0x30) near the end
    // The attributes list is the last element in SearchRequest
    // Look for pattern: SEQUENCE of OCTET STRINGs
    let mut attrs = Vec::new();

    // Scan backwards from end to find the last SEQUENCE
    let mut i = payload.len().saturating_sub(1);
    while i > pos {
        if payload[i] == 0x30 {
            // SEQUENCE tag
            // Try to parse attributes from here
            let mut attr_pos = i + 1;
            if attr_pos >= payload.len() {
                break;
            }

            // Skip SEQUENCE length
            let seq_len = payload[attr_pos] as usize;
            attr_pos += 1;

            // If sequence is empty, return None (all attributes)
            if seq_len == 0 {
                return None;
            }

            let seq_end = attr_pos + seq_len;
            if seq_end > payload.len() {
                i -= 1;
                continue;
            }

            // Parse OCTET STRINGs
            while attr_pos < seq_end && attr_pos < payload.len() {
                if payload[attr_pos] == 0x04 {
                    // OCTET STRING
                    attr_pos += 1;
                    if attr_pos >= payload.len() {
                        break;
                    }
                    let attr_len = payload[attr_pos] as usize;
                    attr_pos += 1;

                    if attr_pos + attr_len <= payload.len() {
                        let attr_name =
                            String::from_utf8_lossy(&payload[attr_pos..attr_pos + attr_len])
                                .to_string();
                        attrs.push(attr_name);
                        attr_pos += attr_len;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            if !attrs.is_empty() {
                debug!("Parsed requested attributes: {:?}", attrs);
                return Some(attrs);
            }
        }
        i -= 1;
    }

    // If we couldn't parse attributes, return None (all attributes)
    None
}

fn extract_member_info(payload_str: &str) -> Option<(String, String)> {
    // Extract username and organization from "member=cn=<username>,ou=<org>,..." pattern
    // Returns (organization, username)
    // Try different patterns as LDAP BER encoding might separate them

    // Pattern 1: Direct "member=cn=" (most common)
    if let Some(start) = payload_str.find("member=cn=") {
        let after_member = &payload_str[start + 10..]; // Skip "member=cn="
        if let Some(cn_end) = after_member.find(',') {
            let username = after_member[..cn_end].to_string();
            // Now look for ou= or dc= for organization
            let after_username = &after_member[cn_end + 1..];
            if let Some(org) = extract_org_from_dn(after_username) {
                debug!(
                    "Extracted from pattern 1: org='{}', username='{}'",
                    org, username
                );
                return Some((org, username));
            }
        }
    }

    // Pattern 2: "member" followed by "cn=" with possible separators
    // In BER encoding, attribute name and value might be separated
    if let Some(member_pos) = payload_str.find("member") {
        let after_member = &payload_str[member_pos + 6..]; // Skip "member"
        if let Some(cn_pos) = after_member.find("cn=") {
            let after_cn = &after_member[cn_pos + 3..]; // Skip "cn="
            if let Some(cn_end) = after_cn.find(',') {
                let username = after_cn[..cn_end].to_string();
                // Look for ou= or dc= for organization
                let after_username = &after_cn[cn_end + 1..];
                if let Some(org) = extract_org_from_dn(after_username) {
                    debug!(
                        "Extracted from pattern 2: org='{}', username='{}'",
                        org, username
                    );
                    return Some((org, username));
                }
            }
        }
    }

    debug!("Failed to extract member info from payload");
    None
}

fn extract_org_from_dn(dn_part: &str) -> Option<String> {
    // Extract organization from "ou=<org>,..." or "dc=<org>,..." pattern
    // Prefer ou= over dc=
    if let Some(ou_pos) = dn_part.find("ou=") {
        let after_ou = &dn_part[ou_pos + 3..]; // Skip "ou="
        if let Some(end) = after_ou.find(',') {
            return Some(after_ou[..end].to_string());
        } else {
            // No comma, take rest of string
            return Some(after_ou.to_string());
        }
    }

    // Fall back to first dc= if no ou=
    if let Some(dc_pos) = dn_part.find("dc=") {
        let after_dc = &dn_part[dc_pos + 3..]; // Skip "dc="
        if let Some(end) = after_dc.find(',') {
            return Some(after_dc[..end].to_string());
        } else {
            return Some(after_dc.to_string());
        }
    }

    None
}

async fn handle_extended_request(
    message_id: u32,
    payload: &[u8],
    authenticated_user: &Option<String>,
    authenticated_org: &Option<String>,
) -> Vec<u8> {
    debug!("Processing extended request");

    // Parse the OID from the extended request (RFC 4511 Section 4.12)
    // Extended request format: [APPLICATION 23] { requestName [0] LDAPOID, requestValue [1] OCTET STRING OPTIONAL }
    let oid = match parse_extended_request_oid(payload) {
        Ok(oid) => oid,
        Err(e) => {
            warn!("Failed to parse extended request OID: {}", e);
            return create_extended_response(
                message_id,
                LdapResultCode::ProtocolError as u8,
                None,
                None,
            );
        }
    };

    debug!("Extended request OID: {}", oid);

    match oid.as_str() {
        // WhoAmI - RFC 4532
        "1.3.6.1.4.1.4203.1.11.3" => {
            // Per RFC 4532: return authorization identity for authenticated users,
            // or empty string for anonymous/unauthenticated users (NOT an error)
            if let (Some(user), Some(org)) = (authenticated_user, authenticated_org) {
                let dn = format!("cn={},ou={}", user, org);
                create_whoami_response(message_id, &dn)
            } else {
                // Anonymous/unauthenticated: return empty authorization identity
                create_whoami_response(message_id, "")
            }
        }
        // StartTLS - RFC 4511 Section 4.14
        "1.3.6.1.4.1.1466.20037" => {
            // StartTLS is not supported when TLS is already enabled
            // Clients should connect to the TLS port directly
            warn!("StartTLS requested but server requires TLS from start");
            create_extended_response(
                message_id,
                LdapResultCode::Unavailable as u8,
                Some("1.3.6.1.4.1.1466.20037"),
                None,
            )
        }
        // Unknown extended operation
        _ => {
            warn!("Unsupported extended operation: {}", oid);
            create_extended_response(
                message_id,
                LdapResultCode::UnwillingToPerform as u8,
                None,
                None,
            )
        }
    }
}

/// Parse the OID from an extended request payload
fn parse_extended_request_oid(payload: &[u8]) -> std::result::Result<String, String> {
    if payload.is_empty() {
        return Err("Empty extended request payload".to_string());
    }

    let mut pos = 0;

    // Skip extended request tag (APPLICATION 23 = 0x77)
    if payload[pos] & 0xf0 != 0x70 {
        return Err(format!("Invalid extended request tag: {:#x}", payload[pos]));
    }
    pos += 1;

    // Skip extended request length
    if pos >= payload.len() {
        return Err("Unexpected end at length".to_string());
    }
    let len_byte = payload[pos];
    pos += 1;
    if len_byte & 0x80 != 0 {
        let num_octets = (len_byte & 0x7f) as usize;
        if pos + num_octets > payload.len() {
            return Err("Length octets exceed payload".to_string());
        }
        pos += num_octets;
    }

    // Parse OID (CONTEXT 0 = 0x80)
    if pos >= payload.len() {
        return Err("Unexpected end at OID tag".to_string());
    }
    if payload[pos] != 0x80 {
        return Err(format!("Invalid OID tag: {:#x}", payload[pos]));
    }
    pos += 1;

    // Parse OID length
    if pos >= payload.len() {
        return Err("Unexpected end at OID length".to_string());
    }
    let oid_len = payload[pos] as usize;
    pos += 1;

    if pos + oid_len > payload.len() {
        return Err("OID length exceeds payload".to_string());
    }

    // Extract OID string
    let oid = String::from_utf8_lossy(&payload[pos..pos + oid_len]).to_string();
    Ok(oid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::mock::MockDbService;
    use crate::models::User;
    use chrono::Utc;

    #[test]
    fn test_parse_ldap_message() {
        // Simple test message: SEQUENCE { messageID: 1, bindRequest: ... }
        let message = vec![
            0x30, 0x0c, // SEQUENCE, length 12
            0x02, 0x01, 0x01, // INTEGER 1 (message ID)
            0x60, 0x07, // APPLICATION 0 (bind request), length 7
            0x02, 0x01, 0x03, // version 3
            0x04, 0x00, // empty DN
            0x80, 0x00, // empty password
        ];

        let result = parse_ldap_message(&message);
        assert!(result.is_ok());

        let (message_id, op_type, _) = result.unwrap();
        assert_eq!(message_id, 1);
        assert_eq!(op_type, 0); // bind request
    }

    #[test]
    fn test_parse_ldap_message_invalid() {
        let short_message = vec![0x30, 0x01];
        assert!(parse_ldap_message(&short_message).is_err());

        let invalid_tag = vec![0x31, 0x0c, 0x02, 0x01, 0x01];
        assert!(parse_ldap_message(&invalid_tag).is_err());
    }

    #[test]
    fn test_parse_dn_valid() {
        let dn = "cn=john,ou=acme,dc=example,dc=com";
        let result = parse_dn(dn);
        assert!(result.is_some());

        let (org, username) = result.unwrap();
        assert_eq!(org, "acme");
        assert_eq!(username, "john");

        // Test uppercase prefixes
        let dn_upper = "CN=john,OU=acme,DC=example,DC=com";
        let result_upper = parse_dn(dn_upper);
        assert!(result_upper.is_some());

        let (org_upper, username_upper) = result_upper.unwrap();
        assert_eq!(org_upper, "acme");
        assert_eq!(username_upper, "john");

        // Test mixed case
        let dn_mixed = "Cn=jane,Ou=widgets,dc=example,dc=com";
        let result_mixed = parse_dn(dn_mixed);
        assert!(result_mixed.is_some());

        let (org_mixed, username_mixed) = result_mixed.unwrap();
        assert_eq!(org_mixed, "widgets");
        assert_eq!(username_mixed, "jane");

        // Test DN without OU (uses first DC as organization)
        let dn_no_ou = "cn=falkordb,DC=falkordb,DC=cloud";
        let result_no_ou = parse_dn(dn_no_ou);
        assert!(result_no_ou.is_some());

        let (org_no_ou, username_no_ou) = result_no_ou.unwrap();
        assert_eq!(org_no_ou, "falkordb");
        assert_eq!(username_no_ou, "falkordb");
    }

    #[test]
    fn test_parse_dn_invalid() {
        // Missing username (no cn)
        assert!(parse_dn("ou=acme,dc=example,dc=com").is_none());

        // Too short
        assert!(parse_dn("cn=john").is_none());

        // Empty
        assert!(parse_dn("").is_none());
    }

    #[test]
    fn test_parse_bind_payload() {
        // Valid bind request payload
        // "cn=john,ou=acme" = 15 characters
        let payload = vec![
            0x60, 0x1c, // APPLICATION 0, length 28
            0x02, 0x01, 0x03, // version 3
            0x04, 0x0f, // DN length 15
            b'c', b'n', b'=', b'j', b'o', b'h', b'n', b',', b'o', b'u', b'=', b'a', b'c', b'm',
            b'e', 0x80, 0x08, // password length 8
            b'p', b'a', b's', b's', b'w', b'o', b'r', b'd',
        ];

        let result = parse_bind_payload(&payload);
        if let Err(ref e) = result {
            eprintln!("Parse error: {}", e);
        }
        assert!(result.is_ok());

        let (dn, password) = result.unwrap();
        assert_eq!(dn, "cn=john,ou=acme");
        assert_eq!(password, "password");
    }

    #[test]
    fn test_parse_bind_payload_anonymous() {
        // Anonymous bind (empty DN and password)
        let payload = vec![
            0x60, 0x07, // APPLICATION 0
            0x02, 0x01, 0x03, // version 3
            0x04, 0x00, // empty DN
            0x80, 0x00, // empty password
        ];

        let result = parse_bind_payload(&payload);
        assert!(result.is_ok());

        let (dn, password) = result.unwrap();
        assert_eq!(dn, "");
        assert_eq!(password, "");
    }

    #[test]
    fn test_parse_bind_payload_invalid() {
        // Too short
        let short = vec![0x60, 0x01];
        assert!(parse_bind_payload(&short).is_err());

        // Invalid version tag
        let invalid = vec![0x60, 0x07, 0x03, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00];
        assert!(parse_bind_payload(&invalid).is_err());
    }

    #[test]
    fn test_create_bind_response() {
        let response = create_bind_response(1, LdapResultCode::Success as u8);
        assert!(!response.is_empty());
        assert_eq!(response[0], 0x30); // SEQUENCE
        assert_eq!(response[2], 0x02); // INTEGER tag
        assert_eq!(response[4], 1); // message ID
        assert_eq!(response[5], 0x61); // Bind Response tag
    }

    #[test]
    fn test_create_bind_response_invalid_credentials() {
        let response = create_bind_response(2, LdapResultCode::InvalidCredentials as u8);
        assert!(!response.is_empty());
        assert_eq!(response[0], 0x30); // SEQUENCE
        assert_eq!(response[4], 2); // message ID
                                    // Result code should be 49 (invalid credentials)
        let result_code_pos = 9;
        assert_eq!(response[result_code_pos], 49);
    }

    #[test]
    fn test_create_search_done_response() {
        let response = create_search_done_response(3, LdapResultCode::Success as u8);
        assert!(!response.is_empty());
        assert_eq!(response[0], 0x30); // SEQUENCE
        assert_eq!(response[4], 3); // message ID
        assert_eq!(response[5], 0x65); // Search Result Done tag
    }

    #[test]
    fn test_create_whoami_response() {
        let dn = "cn=john,ou=acme";
        let response = create_whoami_response(4, dn);
        assert!(!response.is_empty());
        assert_eq!(response[0], 0x30); // SEQUENCE
        assert_eq!(response[4], 4); // message ID
        assert_eq!(response[5], 0x78); // Extended Response tag
    }

    #[test]
    fn test_create_error_response() {
        let response = create_error_response(5, 1, LdapResultCode::ProtocolError as u8);
        assert!(!response.is_empty());
        assert_eq!(response[0], 0x30); // SEQUENCE
        assert_eq!(response[4], 5); // message ID
                                    // Result code should be 2 (protocol error)
        let result_code_pos = 9;
        assert_eq!(response[result_code_pos], 2);
    }

    #[test]
    fn test_create_search_entry_response() {
        let dn = "cn=john,ou=acme,dc=example,dc=com";
        let cn = "john";
        let mail = Some("john@acme.com");

        let response = create_search_entry_response(1, dn, cn, mail);
        assert!(!response.is_empty());
        assert_eq!(response[0], 0x30); // SEQUENCE

        // Check that the DN is included
        let response_str = String::from_utf8_lossy(&response);
        assert!(response_str.contains("john"));
    }

    #[test]
    fn test_create_search_entry_response_no_email() {
        let dn = "cn=jane,ou=acme,dc=example,dc=com";
        let cn = "jane";

        let response = create_search_entry_response(1, dn, cn, None);
        assert!(!response.is_empty());
        assert_eq!(response[0], 0x30); // SEQUENCE
    }

    #[tokio::test]
    async fn test_handle_bind_request_success() {
        let mut mock_db = MockDbService::new();
        mock_db
            .expect_verify_user_password()
            .with(
                mockall::predicate::eq("acme"),
                mockall::predicate::eq("john"),
                mockall::predicate::eq("password123"),
            )
            .times(1)
            .returning(|_, _, _| Ok(true));

        let db = Arc::new(mock_db) as Arc<dyn DbService>;
        let base_dn = "dc=example,dc=com";
        let mut auth_user = None;
        let mut auth_org = None;

        // Create bind request payload
        // DN: "cn=john,ou=acme,dc=example,dc=com" = 33 bytes
        // Password: "password123" = 11 bytes
        // Total: 2 (APPLICATION tag + length) + 3 (version) + 2 (DN tag + length) + 33 (DN) + 2 (password tag + length) + 11 (password) = 53 bytes
        // So APPLICATION length is 51 (53 - 2)
        let payload = vec![
            0x60, 0x33, // APPLICATION 0, length 51
            0x02, 0x01, 0x03, // version 3
            0x04, 0x21, // DN OCTET STRING, length 33
            b'c', b'n', b'=', b'j', b'o', b'h', b'n', b',', b'o', b'u', b'=', b'a', b'c', b'm',
            b'e', b',', b'd', b'c', b'=', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b',', b'd',
            b'c', b'=', b'c', b'o', b'm', 0x80,
            0x0b, // password (context-specific [0]), length 11
            b'p', b'a', b's', b's', b'w', b'o', b'r', b'd', b'1', b'2', b'3',
        ];

        let response =
            handle_bind_request(1, &payload, &db, base_dn, &mut auth_user, &mut auth_org).await;

        assert!(!response.is_empty());
        assert_eq!(auth_user, Some("john".to_string()));
        assert_eq!(auth_org, Some("acme".to_string()));

        // Check for success result code (0)
        let result_code_pos = 9;
        assert_eq!(response[result_code_pos], 0);
    }

    #[tokio::test]
    async fn test_handle_bind_request_invalid_credentials() {
        let mut mock_db = MockDbService::new();
        mock_db
            .expect_verify_user_password()
            .with(
                mockall::predicate::eq("acme"),
                mockall::predicate::eq("john"),
                mockall::predicate::eq("wrongpass"),
            )
            .times(1)
            .returning(|_, _, _| Ok(false));

        let db = Arc::new(mock_db) as Arc<dyn DbService>;
        let base_dn = "dc=example,dc=com";
        let mut auth_user = None;
        let mut auth_org = None;

        // DN: "cn=john,ou=acme,dc=example,dc=com" = 33 bytes
        // Password: "wrongpass" = 9 bytes
        // Total: 2 + 3 + 2 + 33 + 2 + 9 = 51, so APPLICATION length is 49
        let payload = vec![
            0x60, 0x31, // APPLICATION 0, length 49
            0x02, 0x01, 0x03, // version 3
            0x04, 0x21, // DN OCTET STRING, length 33
            b'c', b'n', b'=', b'j', b'o', b'h', b'n', b',', b'o', b'u', b'=', b'a', b'c', b'm',
            b'e', b',', b'd', b'c', b'=', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b',', b'd',
            b'c', b'=', b'c', b'o', b'm', 0x80,
            0x09, // password (context-specific [0]), length 9
            b'w', b'r', b'o', b'n', b'g', b'p', b'a', b's', b's',
        ];

        let response =
            handle_bind_request(1, &payload, &db, base_dn, &mut auth_user, &mut auth_org).await;

        assert!(!response.is_empty());
        assert_eq!(auth_user, None);
        assert_eq!(auth_org, None);

        // Check for invalid credentials result code (49)
        let result_code_pos = 9;
        assert_eq!(response[result_code_pos], 49);
    }

    #[tokio::test]
    async fn test_handle_bind_request_anonymous() {
        let mock_db = MockDbService::new();
        let db = Arc::new(mock_db) as Arc<dyn DbService>;
        let base_dn = "dc=example,dc=com";
        let mut auth_user = Some("previous".to_string());
        let mut auth_org = Some("previous".to_string());

        // Anonymous bind payload
        let payload = vec![0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00];

        let response =
            handle_bind_request(1, &payload, &db, base_dn, &mut auth_user, &mut auth_org).await;

        assert!(!response.is_empty());
        assert_eq!(auth_user, None);
        assert_eq!(auth_org, None);

        // Check for success result code
        let result_code_pos = 9;
        assert_eq!(response[result_code_pos], 0);
    }

    #[tokio::test]
    async fn test_handle_search_request() {
        let mut mock_db = MockDbService::new();

        let now = Utc::now();
        let test_users = vec![
            User {
                organization: "acme".to_string(),
                username: "john".to_string(),
                password_hash: "hash".to_string(),
                email: Some("john@acme.com".to_string()),
                full_name: Some("John Doe".to_string()),
                created_at: now,
                updated_at: now,
            },
            User {
                organization: "acme".to_string(),
                username: "jane".to_string(),
                password_hash: "hash".to_string(),
                email: Some("jane@acme.com".to_string()),
                full_name: Some("Jane Doe".to_string()),
                created_at: now,
                updated_at: now,
            },
        ];

        mock_db
            .expect_list_users()
            .with(mockall::predicate::eq("acme"))
            .times(1)
            .returning(move |_| Ok(test_users.clone()));

        let db = Arc::new(mock_db) as Arc<dyn DbService>;
        let base_dn = "dc=example,dc=com";
        let auth_org = Some("acme".to_string());
        let search_bind_org = None; // No restriction in this test

        let payload = vec![]; // Simplified - normally would contain search params

        let messages =
            handle_search_request(1, &payload, &db, base_dn, &auth_org, &search_bind_org).await;

        assert!(
            !messages.is_empty(),
            "Should return at least search done message"
        );

        // Messages should contain search entries and a search done message
        // Last message should be search done
        assert!(
            messages.last().is_some(),
            "Should have at least done message"
        );
    }

    #[tokio::test]
    async fn test_handle_search_request_unauthenticated() {
        let mock_db = MockDbService::new();
        let db = Arc::new(mock_db) as Arc<dyn DbService>;
        let base_dn = "dc=example,dc=com";
        let auth_org = None;
        let search_bind_org = None;

        let payload = vec![];

        let messages =
            handle_search_request(1, &payload, &db, base_dn, &auth_org, &search_bind_org).await;

        assert!(!messages.is_empty());
        // Per RFC 4532: Anonymous search should return empty results (success), not error
        assert_eq!(messages.len(), 1, "Should have single done message");
        let result_code_pos = 9;
        assert_eq!(messages[0][result_code_pos], 0); // Success with empty results
    }

    #[tokio::test]
    async fn test_handle_search_request_wrong_organization() {
        let mock_db = MockDbService::new();
        let db = Arc::new(mock_db) as Arc<dyn DbService>;
        let base_dn = "dc=example,dc=com";
        let auth_org = Some("acme".to_string()); // User is from "acme"
        let search_bind_org = Some("allowed_org".to_string()); // But only "allowed_org" can search

        let payload = vec![];

        let messages =
            handle_search_request(1, &payload, &db, base_dn, &auth_org, &search_bind_org).await;

        assert!(!messages.is_empty());
        // Should return error response for insufficient access rights
        assert_eq!(messages.len(), 1, "Should have single error message");
        let result_code_pos = 9;
        assert_eq!(messages[0][result_code_pos], 50); // Insufficient access rights
    }

    #[test]
    fn test_extract_member_info_pattern1() {
        // Pattern 1: Direct "member=cn=username,ou=org,..."
        let payload =
            "(&(objectclass=groupofnames)(member=cn=testuser,ou=testorg,dc=example,dc=com))";
        let result = extract_member_info(payload);
        assert_eq!(
            result,
            Some(("testorg".to_string(), "testuser".to_string()))
        );
    }

    #[test]
    fn test_extract_member_info_pattern2() {
        // Pattern 2: "member" followed by "cn=" with separators (BER encoding)
        // Simulating BER-encoded payload where attribute and value are separated
        let payload = "(&(objectclass=groupofnames)(member\x00\x04cn=falkordb,ou=instance-1,dc=falkordb,dc=cloud))";
        let result = extract_member_info(payload);
        assert_eq!(
            result,
            Some(("instance-1".to_string(), "falkordb".to_string()))
        );
    }

    #[test]
    fn test_extract_member_info_no_match() {
        // No member filter present
        let payload = "(&(objectclass=groupofnames)(cn=testgroup))";
        let result = extract_member_info(payload);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_member_info_different_case() {
        // Test case sensitivity - in handle_search_request, payload is lowercased before extraction
        // So simulate what the function receives
        let payload = "(&(objectclass=groupofnames)(member=cn=username,ou=org,dc=example,dc=com))";
        let result = extract_member_info(payload);
        assert_eq!(result, Some(("org".to_string(), "username".to_string())));
    }

    #[test]
    fn test_extract_member_info_no_comma() {
        // Member filter without comma after username (invalid format)
        let payload = "(&(objectclass=groupofnames)(member=cn=testuser))";
        let result = extract_member_info(payload);
        // Should return None since there's no org info
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_member_info_dc_only() {
        // Test with dc= only (no ou=) - should use first dc as org
        let payload = "(&(objectclass=groupofnames)(member=cn=user,dc=example,dc=com))";
        let result = extract_member_info(payload);
        assert_eq!(result, Some(("example".to_string(), "user".to_string())));
    }

    #[tokio::test]
    async fn test_handle_search_request_group_member_filter() {
        use crate::models::Group;
        use chrono::Utc;

        let mut mock_db = MockDbService::new();
        let now = Utc::now();

        let test_groups = vec![Group {
            organization: "testorg".to_string(),
            name: "developers".to_string(),
            description: Some("Dev team".to_string()),
            members: vec!["testuser".to_string(), "alice".to_string()],
            created_at: now,
            updated_at: now,
        }];

        mock_db
            .expect_get_user_groups()
            .with(
                mockall::predicate::eq("testorg"),
                mockall::predicate::eq("testuser"),
            )
            .times(1)
            .returning(move |_, _| Ok(test_groups.clone()));

        let db = Arc::new(mock_db) as Arc<dyn DbService>;
        let base_dn = "dc=example,dc=com";
        let auth_org = Some("testorg".to_string());
        let search_bind_org = None;

        // Simulate LDAP filter with member search
        let payload =
            b"(&(objectclass=groupofnames)(member=cn=testuser,ou=testorg,dc=example,dc=com))";

        let messages =
            handle_search_request(1, payload, &db, base_dn, &auth_org, &search_bind_org).await;

        assert!(!messages.is_empty());
        // Should contain the group name "developers" in one of the messages
        let all_messages = messages
            .iter()
            .map(|m| String::from_utf8_lossy(m).to_string())
            .collect::<Vec<_>>()
            .join("");
        assert!(all_messages.contains("developers"));
    }

    #[tokio::test]
    async fn test_handle_search_request_all_groups() {
        use crate::models::Group;
        use chrono::Utc;

        let mut mock_db = MockDbService::new();
        let now = Utc::now();

        let test_groups = vec![
            Group {
                organization: "testorg".to_string(),
                name: "admins".to_string(),
                description: Some("Admin group".to_string()),
                members: vec!["admin".to_string()],
                created_at: now,
                updated_at: now,
            },
            Group {
                organization: "testorg".to_string(),
                name: "users".to_string(),
                description: None,
                members: vec!["user1".to_string(), "user2".to_string()],
                created_at: now,
                updated_at: now,
            },
        ];

        mock_db
            .expect_list_groups()
            .with(mockall::predicate::eq("testorg"))
            .times(1)
            .returning(move |_| Ok(test_groups.clone()));

        let db = Arc::new(mock_db) as Arc<dyn DbService>;
        let base_dn = "dc=example,dc=com";
        let auth_org = Some("testorg".to_string());
        let search_bind_org = None;

        // Simulate LDAP filter for all groups (no member filter)
        let payload = b"(objectclass=groupofnames)";

        let messages =
            handle_search_request(1, payload, &db, base_dn, &auth_org, &search_bind_org).await;

        assert!(!messages.is_empty());
        // Should contain both group names in the messages
        let all_messages = messages
            .iter()
            .map(|m| String::from_utf8_lossy(m).to_string())
            .collect::<Vec<_>>()
            .join("");
        assert!(all_messages.contains("admins"));
        assert!(all_messages.contains("users"));
    }

    #[tokio::test]
    async fn test_handle_search_request_authorized_organization() {
        let mut mock_db = MockDbService::new();

        let now = Utc::now();
        let test_users = vec![User {
            organization: "allowed_org".to_string(),
            username: "search_user".to_string(),
            password_hash: "hash".to_string(),
            email: Some("search@allowed.com".to_string()),
            full_name: Some("Search User".to_string()),
            created_at: now,
            updated_at: now,
        }];

        mock_db
            .expect_list_users()
            .with(mockall::predicate::eq("allowed_org"))
            .times(1)
            .returning(move |_| Ok(test_users.clone()));

        let db = Arc::new(mock_db) as Arc<dyn DbService>;
        let base_dn = "dc=example,dc=com";
        let auth_org = Some("allowed_org".to_string()); // User is from "allowed_org"
        let search_bind_org = Some("allowed_org".to_string()); // Only "allowed_org" can search

        let payload = vec![];

        let messages =
            handle_search_request(1, &payload, &db, base_dn, &auth_org, &search_bind_org).await;

        assert!(!messages.is_empty());
        // Should successfully return search results
        let all_messages = messages
            .iter()
            .map(|m| String::from_utf8_lossy(m).to_string())
            .collect::<Vec<_>>()
            .join("");
        assert!(
            all_messages.contains("search_user")
                || messages.iter().map(|m| m.len()).sum::<usize>() > 100
        );
    }

    #[tokio::test]
    async fn test_handle_extended_request_whoami() {
        let auth_user = Some("john".to_string());
        let auth_org = Some("acme".to_string());

        // Proper WhoAmI extended request payload with OID 1.3.6.1.4.1.4203.1.11.3
        let whoami_oid = b"1.3.6.1.4.1.4203.1.11.3";
        let payload = vec![
            0x77,
            (whoami_oid.len() + 2) as u8, // Extended request tag and length
            0x80,
            whoami_oid.len() as u8, // OID tag (CONTEXT 0) and length
        ];
        let mut full_payload = payload;
        full_payload.extend_from_slice(whoami_oid);

        let response = handle_extended_request(1, &full_payload, &auth_user, &auth_org).await;

        assert!(!response.is_empty());
        assert_eq!(response[5], 0x78); // Extended Response tag

        // Should contain the DN in the response value
        let response_str = String::from_utf8_lossy(&response);
        assert!(response_str.contains("dn:cn=john,ou=acme"));
    }

    #[tokio::test]
    async fn test_handle_extended_request_unauthenticated() {
        let auth_user = None;
        let auth_org = None;

        // Proper WhoAmI extended request payload with OID 1.3.6.1.4.1.4203.1.11.3
        let whoami_oid = b"1.3.6.1.4.1.4203.1.11.3";
        let payload = vec![
            0x77,
            (whoami_oid.len() + 2) as u8, // Extended request tag and length
            0x80,
            whoami_oid.len() as u8, // OID tag (CONTEXT 0) and length
        ];
        let mut full_payload = payload;
        full_payload.extend_from_slice(whoami_oid);

        let response = handle_extended_request(1, &full_payload, &auth_user, &auth_org).await;

        assert!(!response.is_empty());
        // Per RFC 4532: Anonymous should return success with empty authorization identity (no response value)
        let result_code_pos = 9;
        assert_eq!(response[result_code_pos], 0); // Success
                                                  // Response should NOT contain "dn:" for anonymous - response value should be absent
        let response_str = String::from_utf8_lossy(&response);
        assert!(!response_str.contains("dn:"));
    }
}
