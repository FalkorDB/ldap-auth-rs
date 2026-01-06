//! Low-level LDAP Protocol Functions
//!
//! This module contains BER encoding/decoding and LDAP message construction
//! functions. These are the building blocks for the LDAP protocol implementation.
//!
//! # BER Encoding
//! BER (Basic Encoding Rules) is used to encode LDAP messages. Key points:
//! - Tags identify data types (SEQUENCE=0x30, INTEGER=0x02, OCTET STRING=0x04, etc.)
//! - Lengths can be short form (1 byte for lengths < 128) or long form (multi-byte)
//! - Values follow the tag and length
//!
//! # LDAP Result Codes
//! Common LDAP result codes used in responses:
//! - 0: success
//! - 1: operations error
//! - 2: protocol error
//! - 7: auth method not supported
//! - 49: invalid credentials
//! - 53: unwilling to perform

use tracing::debug;

/// LDAP Result Codes (RFC 4511 Appendix A)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LdapResultCode {
    Success = 0,
    OperationsError = 1,
    ProtocolError = 2,
    InsufficientAccessRights = 50,
    InvalidCredentials = 49,
    Unavailable = 52,
    UnwillingToPerform = 53,
}

/// Encodes length in BER format
///
/// # BER Length Encoding Rules
/// - Short form (0-127): Single byte with the length value
/// - Long form (128+): First byte = 0x80 + number of length bytes, followed by length bytes
///
/// # Examples
/// ```
/// use ldap_auth_rs::ldap_lib::encode_ber_length;
///
/// assert_eq!(encode_ber_length(10), vec![0x0a]);        // Short form
/// assert_eq!(encode_ber_length(200), vec![0x81, 0xc8]); // Long form (1 byte)
/// assert_eq!(encode_ber_length(300), vec![0x82, 0x01, 0x2c]); // Long form (2 bytes)
/// ```
pub fn encode_ber_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else if len < 65536 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

/// Encodes a message ID as BER INTEGER
///
/// Message IDs can be larger than 255, so this handles multi-byte encoding.
///
/// # Format
/// Returns: tag (0x02) + length + value bytes
fn encode_message_id(message_id: u32) -> Vec<u8> {
    let value_bytes = if message_id <= 0xFF {
        vec![message_id as u8]
    } else if message_id <= 0xFFFF {
        vec![(message_id >> 8) as u8, message_id as u8]
    } else {
        vec![
            (message_id >> 16) as u8,
            (message_id >> 8) as u8,
            message_id as u8,
        ]
    };

    let mut result = vec![0x02]; // INTEGER tag
    result.push(value_bytes.len() as u8);
    result.extend_from_slice(&value_bytes);
    result
}

/// Creates an LDAP Bind Response (RFC 4511 Section 4.2.2)
///
/// # Structure
/// ```text
/// BindResponse ::= [APPLICATION 1] SEQUENCE {
///     COMPONENTS OF LDAPResult,
///     serverSaslCreds    [7] OCTET STRING OPTIONAL
/// }
/// ```
///
/// # Arguments
/// * `message_id` - The message ID from the bind request
/// * `result_code` - LDAP result code (0 = success, 49 = invalid credentials)
///
/// # Examples
/// ```
/// use ldap_auth_rs::ldap_lib::{create_bind_response, LdapResultCode};
///
/// let success = create_bind_response(1, LdapResultCode::Success as u8);
/// let failure = create_bind_response(2, LdapResultCode::InvalidCredentials as u8);
/// ```
pub fn create_bind_response(message_id: u32, result_code: u8) -> Vec<u8> {
    let mut response = Vec::new();

    let message_id_bytes = encode_message_id(message_id);

    // BindResponse content: tag(1) + length(1) + content(7)
    let total_len = message_id_bytes.len() + 9;

    // SEQUENCE
    response.push(0x30);
    response.extend_from_slice(&encode_ber_length(total_len));

    // Message ID
    response.extend_from_slice(&message_id_bytes);

    // Bind Response (APPLICATION 1)
    response.push(0x61);
    response.push(0x07);

    // Result code (ENUMERATED)
    response.push(0x0a);
    response.push(0x01);
    response.push(result_code);

    // Matched DN (empty OCTET STRING)
    response.push(0x04);
    response.push(0x00);

    // Diagnostic message (empty OCTET STRING)
    response.push(0x04);
    response.push(0x00);

    debug!(
        "Created bind response: message_id={}, result_code={}, size={} bytes",
        message_id,
        result_code,
        response.len()
    );

    response
}

fn encode_octet_string(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + value.len());
    out.push(0x04);
    out.extend_from_slice(&encode_ber_length(value.len()));
    out.extend_from_slice(value);
    out
}

fn encode_partial_attribute(attr_type: &str, values: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();

    // type: OCTET STRING
    content.extend_from_slice(&encode_octet_string(attr_type.as_bytes()));

    // vals: SET OF OCTET STRING
    let mut set_content = Vec::new();
    for value in values {
        set_content.extend_from_slice(&encode_octet_string(value));
    }

    content.push(0x31); // SET
    content.extend_from_slice(&encode_ber_length(set_content.len()));
    content.extend_from_slice(&set_content);

    // PartialAttribute ::= SEQUENCE { type, vals }
    let mut out = Vec::new();
    out.push(0x30); // SEQUENCE
    out.extend_from_slice(&encode_ber_length(content.len()));
    out.extend_from_slice(&content);
    out
}

/// Creates an LDAP Search Entry Response (RFC 4511 Section 4.5.2)
///
/// Returns a search result entry for a user with cn and mail attributes.
///
/// # Arguments
/// * `message_id` - The message ID from the search request
/// * `dn` - Distinguished Name of the entry
/// * `cn` - Common name (username)
/// * `email` - Email address (optional)
///
/// # Structure
/// ```text
/// SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
///     objectName      LDAPDN,
///     attributes      PartialAttributeList
/// }
/// ```
pub fn create_search_entry_response(
    message_id: u32,
    dn: &str,
    cn: &str,
    email: Option<&str>,
) -> Vec<u8> {
    let mut response = Vec::new();

    // Build attributes
    let mut attrs = Vec::new();

    // cn attribute
    attrs.extend_from_slice(&encode_partial_attribute("cn", &[cn.as_bytes().to_vec()]));

    // mail attribute (if provided)
    if let Some(mail) = email {
        attrs.extend_from_slice(&encode_partial_attribute(
            "mail",
            &[mail.as_bytes().to_vec()],
        ));
    }

    let dn_bytes = dn.as_bytes();
    let message_id_bytes = encode_message_id(message_id);

    // Calculate entry_len (DN + Attributes)
    let dn_len_bytes = encode_ber_length(dn_bytes.len());
    let attrs_len_bytes = encode_ber_length(attrs.len());
    let entry_len =
        1 + dn_len_bytes.len() + dn_bytes.len() + 1 + attrs_len_bytes.len() + attrs.len();

    // Calculate total_len (entire message content)
    let entry_len_bytes = encode_ber_length(entry_len);
    let total_len = message_id_bytes.len() + 1 + entry_len_bytes.len() + entry_len;

    // SEQUENCE
    response.push(0x30);
    response.extend_from_slice(&encode_ber_length(total_len));

    // Message ID
    response.extend_from_slice(&message_id_bytes);

    // Search Result Entry (APPLICATION 4)
    response.push(0x64);
    response.extend_from_slice(&entry_len_bytes);

    // DN
    response.push(0x04);
    response.extend_from_slice(&dn_len_bytes);
    response.extend_from_slice(dn_bytes);

    // Attributes
    response.push(0x30);
    response.extend_from_slice(&attrs_len_bytes);
    response.extend_from_slice(&attrs);

    debug!(
        "Created search entry: message_id={}, dn='{}', size={} bytes",
        message_id,
        dn,
        response.len()
    );

    response
}

/// Creates an LDAP Search Entry Response for a group (RFC 4519)
///
/// Returns a search result entry for a groupOfNames with cn, objectClass,
/// description, and member attributes.
///
/// # Arguments
/// * `message_id` - The message ID from the search request
/// * `dn` - Distinguished Name of the group
/// * `cn` - Common name (group name)
/// * `description` - Group description (optional)
/// * `members` - List of member usernames
/// * `requested_attrs` - Optional list of requested attributes (None = all attributes)
pub fn create_group_search_entry_response(
    message_id: u32,
    dn: &str,
    cn: &str,
    description: Option<&str>,
    members: &[String],
    requested_attrs: Option<&[String]>,
) -> Vec<u8> {
    let mut response = Vec::new();

    // Helper to check if attribute should be included
    let should_include = |attr_name: &str| -> bool {
        match requested_attrs {
            None => true, // No filter, include all
            Some(attrs) => {
                // Empty list = all attributes (RFC 4511)
                attrs.is_empty()
                    || attrs
                        .iter()
                        .any(|a| a.eq_ignore_ascii_case(attr_name) || a == "*")
            }
        }
    };

    // Build attributes for groupOfNames
    let mut attrs = Vec::new();

    // cn attribute (always included if requested or if all attrs requested)
    if should_include("cn") {
        attrs.extend_from_slice(&encode_partial_attribute("cn", &[cn.as_bytes().to_vec()]));
    }

    // objectClass attribute (groupOfNames)
    if should_include("objectClass") {
        attrs.extend_from_slice(&encode_partial_attribute(
            "objectClass",
            &[b"groupOfNames".to_vec()],
        ));
    }

    // description attribute (if present)
    if let Some(desc) = description {
        if should_include("description") {
            attrs.extend_from_slice(&encode_partial_attribute(
                "description",
                &[desc.as_bytes().to_vec()],
            ));
        }
    }

    // member attributes (one for each member)
    if should_include("member") {
        let member_values: Vec<Vec<u8>> = members
            .iter()
            .map(|member| format!("cn={}", member).into_bytes())
            .collect();
        if !member_values.is_empty() {
            attrs.extend_from_slice(&encode_partial_attribute("member", &member_values));
        }
    }

    let dn_bytes = dn.as_bytes();
    let message_id_bytes = encode_message_id(message_id);

    // Calculate entry_len (DN + Attributes) with proper BER length encoding
    let dn_len_bytes = encode_ber_length(dn_bytes.len());
    let attrs_len_bytes = encode_ber_length(attrs.len());
    let entry_len =
        1 + dn_len_bytes.len() + dn_bytes.len() + 1 + attrs_len_bytes.len() + attrs.len();

    // Calculate total_len (entire message content)
    let entry_len_bytes = encode_ber_length(entry_len);
    // message_id: already includes tag+len+value
    // search_entry: tag(1) + length(entry_len_bytes.len()) + value(entry_len)
    let total_len = message_id_bytes.len() + 1 + entry_len_bytes.len() + entry_len;

    // SEQUENCE
    response.push(0x30);
    response.extend_from_slice(&encode_ber_length(total_len));

    // Message ID (already includes tag + length + value)
    response.extend_from_slice(&message_id_bytes);

    // Search Result Entry (APPLICATION 4)
    response.push(0x64);
    response.extend_from_slice(&entry_len_bytes);

    // DN
    response.push(0x04);
    response.extend_from_slice(&dn_len_bytes);
    response.extend_from_slice(dn_bytes);

    // Attributes
    response.push(0x30);
    response.extend_from_slice(&attrs_len_bytes);
    response.extend_from_slice(&attrs);

    debug!(
        "Created group search entry: message_id={}, dn='{}', members={}, attrs_len={}, size={} bytes, requested_attrs={:?}",
        message_id,
        dn,
        members.len(),
        attrs.len(),
        response.len(),
        requested_attrs,
    );

    response
}

/// Creates an LDAP Search Result Done Response (RFC 4511 Section 4.5.2)
///
/// Indicates the end of search results.
///
/// # Structure
/// ```text
/// SearchResultDone ::= [APPLICATION 5] LDAPResult
/// ```
///
/// # Arguments
/// * `message_id` - The message ID from the search request
/// * `result_code` - LDAP result code (typically 0 for success)
pub fn create_search_done_response(message_id: u32, result_code: u8) -> Vec<u8> {
    let mut response = Vec::new();

    let message_id_bytes = encode_message_id(message_id);

    // total_len = message_id (already includes tag+len+value) + SearchResultDone (tag + len + content)
    //           = message_id_bytes.len() + (1 + 1 + 7)
    let total_len = message_id_bytes.len() + 9;

    // SEQUENCE
    response.push(0x30);
    response.extend_from_slice(&encode_ber_length(total_len));

    // Message ID (already includes tag + length + value)
    response.extend_from_slice(&message_id_bytes);

    // Search Result Done (APPLICATION 5)
    response.push(0x65);
    response.push(0x07);

    // Result code (ENUMERATED)
    response.push(0x0a);
    response.push(0x01);
    response.push(result_code);

    // Matched DN (empty OCTET STRING)
    response.push(0x04);
    response.push(0x00);

    // Diagnostic message (empty OCTET STRING)
    response.push(0x04);
    response.push(0x00);

    debug!(
        "Created search done: message_id={}, result_code={}, size={} bytes",
        message_id,
        result_code,
        response.len()
    );

    response
}

/// Creates an LDAP WhoAmI Extended Response (RFC 4532)
///
/// Returns the authorization identity of the bound user.
///
/// # Arguments
/// * `message_id` - The message ID from the extended request
/// * `dn` - The bound DN (empty string for anonymous)
pub fn create_whoami_response(message_id: u32, dn: &str) -> Vec<u8> {
    // Authorization identity (empty for anonymous, "dn:<dn>" for authenticated)
    let authz_id = if dn.is_empty() {
        Vec::new()
    } else {
        format!("dn:{}", dn).into_bytes()
    };

    // Use create_extended_response with WhoAmI OID and response value
    create_extended_response(
        message_id,
        LdapResultCode::Success as u8,
        Some("1.3.6.1.4.1.4203.1.11.3"), // WhoAmI OID
        if authz_id.is_empty() {
            None
        } else {
            Some(&authz_id)
        },
    )
}

/// Creates a generic LDAP Extended Response (RFC 4511 Section 4.12)
///
/// Used for extended operations like StartTLS.
///
/// # Arguments
/// * `message_id` - The message ID from the extended request
/// * `result_code` - LDAP result code
/// * `response_name` - OID of the response (optional)
/// * `response_value` - Response value bytes (optional)
pub fn create_extended_response(
    message_id: u32,
    result_code: u8,
    response_name: Option<&str>,
    response_value: Option<&[u8]>,
) -> Vec<u8> {
    let mut response = Vec::new();

    let message_id_bytes = encode_message_id(message_id);

    // Extended response structure
    let response_name_bytes = response_name
        .map(|name| {
            let name_bytes = name.as_bytes();
            let mut result = vec![0x8a]; // CONTEXT-SPECIFIC [10]
            result.extend_from_slice(&encode_ber_length(name_bytes.len()));
            result.extend_from_slice(name_bytes);
            result
        })
        .unwrap_or_default();

    let response_value_bytes = response_value
        .map(|value| {
            let mut result = vec![0x8b]; // CONTEXT-SPECIFIC [11]
            result.extend_from_slice(&encode_ber_length(value.len()));
            result.extend_from_slice(value);
            result
        })
        .unwrap_or_default();

    let extended_len = 7 + response_name_bytes.len() + response_value_bytes.len();
    let total_len = message_id_bytes.len() + 2 + extended_len;

    // SEQUENCE
    response.push(0x30);
    response.extend_from_slice(&encode_ber_length(total_len));

    // Message ID
    response.extend_from_slice(&message_id_bytes);

    // Extended Response (APPLICATION 24)
    response.push(0x78);
    response.extend_from_slice(&encode_ber_length(extended_len));

    // Result code
    response.push(0x0a);
    response.push(0x01);
    response.push(result_code);

    // Matched DN (empty)
    response.push(0x04);
    response.push(0x00);

    // Diagnostic message (empty)
    response.push(0x04);
    response.push(0x00);

    // Response name (optional)
    if !response_name_bytes.is_empty() {
        response.extend_from_slice(&response_name_bytes);
    }

    // Response value (optional)
    if !response_value_bytes.is_empty() {
        response.extend_from_slice(&response_value_bytes);
    }

    debug!(
        "Created extended response: message_id={}, result_code={}, size={} bytes",
        message_id,
        result_code,
        response.len()
    );

    response
}

/// Creates a generic LDAP error response
///
/// Can be used for any operation type with a result code.
///
/// # Arguments
/// * `message_id` - The message ID from the request
/// * `op_type` - Operation type tag (e.g., 0x61 for bind, 0x65 for search done)
/// * `result_code` - LDAP result code indicating the error
pub fn create_error_response(message_id: u32, op_type: u8, result_code: u8) -> Vec<u8> {
    let mut response = Vec::new();

    let message_id_bytes = encode_message_id(message_id);
    let total_len = message_id_bytes.len() + 9;

    // SEQUENCE
    response.push(0x30);
    response.extend_from_slice(&encode_ber_length(total_len));

    // Message ID
    response.extend_from_slice(&message_id_bytes);

    // Operation response
    response.push(op_type);
    response.push(0x07);

    // Result code
    response.push(0x0a);
    response.push(0x01);
    response.push(result_code);

    // Matched DN (empty)
    response.push(0x04);
    response.push(0x00);

    // Diagnostic message (empty)
    response.push(0x04);
    response.push(0x00);

    debug!(
        "Created error response: message_id={}, op_type=0x{:02x}, result_code={}, size={} bytes",
        message_id,
        op_type,
        result_code,
        response.len()
    );

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_ber_length_short_form() {
        // Short form: 0-127 bytes
        assert_eq!(encode_ber_length(0), vec![0x00]);
        assert_eq!(encode_ber_length(1), vec![0x01]);
        assert_eq!(encode_ber_length(127), vec![0x7f]);
    }

    #[test]
    fn test_encode_ber_length_long_form_1_byte() {
        // Long form with 1 length byte: 128-255
        assert_eq!(encode_ber_length(128), vec![0x81, 0x80]);
        assert_eq!(encode_ber_length(200), vec![0x81, 0xc8]);
        assert_eq!(encode_ber_length(255), vec![0x81, 0xff]);
    }

    #[test]
    fn test_encode_ber_length_long_form_2_bytes() {
        // Long form with 2 length bytes: 256-65535
        assert_eq!(encode_ber_length(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(encode_ber_length(300), vec![0x82, 0x01, 0x2c]);
        assert_eq!(encode_ber_length(65535), vec![0x82, 0xff, 0xff]);
    }

    #[test]
    fn test_encode_ber_length_long_form_3_bytes() {
        // Long form with 3 length bytes: 65536+
        assert_eq!(encode_ber_length(65536), vec![0x83, 0x01, 0x00, 0x00]);
        assert_eq!(encode_ber_length(100000), vec![0x83, 0x01, 0x86, 0xa0]);
    }

    #[test]
    fn test_encode_message_id_single_byte() {
        let encoded = encode_message_id(1);
        assert_eq!(encoded, vec![0x02, 0x01, 0x01]); // INTEGER tag, length 1, value 1
    }

    #[test]
    fn test_encode_message_id_two_bytes() {
        let encoded = encode_message_id(256);
        assert_eq!(encoded, vec![0x02, 0x02, 0x01, 0x00]); // INTEGER tag, length 2, value 256
    }

    #[test]
    fn test_encode_message_id_three_bytes() {
        let encoded = encode_message_id(65536);
        assert_eq!(encoded, vec![0x02, 0x03, 0x01, 0x00, 0x00]); // INTEGER tag, length 3, value 65536
    }

    #[test]
    fn test_create_bind_response_success() {
        let response = create_bind_response(1, LdapResultCode::Success as u8);

        // Check structure
        assert_eq!(response[0], 0x30); // SEQUENCE
        assert_eq!(response[2], 0x02); // INTEGER tag for message ID
        assert_eq!(response[3], 0x01); // Length of message ID
        assert_eq!(response[4], 0x01); // Message ID value
        assert_eq!(response[5], 0x61); // BindResponse tag (APPLICATION 1)
        assert_eq!(response[6], 0x07); // Length
        assert_eq!(response[7], 0x0a); // ENUMERATED tag
        assert_eq!(response[8], 0x01); // Length
        assert_eq!(response[9], 0x00); // Result code: success
    }

    #[test]
    fn test_create_bind_response_invalid_credentials() {
        let response = create_bind_response(2, LdapResultCode::InvalidCredentials as u8);

        // Check result code
        assert_eq!(response[9], 49); // Result code: invalid credentials
    }

    #[test]
    fn test_create_bind_response_large_message_id() {
        let response = create_bind_response(300, LdapResultCode::Success as u8);

        // Check structure with 2-byte message ID
        assert_eq!(response[0], 0x30); // SEQUENCE
        assert_eq!(response[2], 0x02); // INTEGER tag
        assert_eq!(response[3], 0x02); // Length of message ID (2 bytes)
        assert_eq!(response[4], 0x01); // Message ID high byte
        assert_eq!(response[5], 0x2c); // Message ID low byte (300 = 0x012c)
    }

    #[test]
    fn test_create_search_entry_response_with_email() {
        let response = create_search_entry_response(
            1,
            "cn=testuser,ou=testorg,dc=example,dc=com",
            "testuser",
            Some("test@example.com"),
        );

        // Verify it's a valid LDAP message
        assert_eq!(response[0], 0x30); // SEQUENCE
        assert!(response.len() > 50); // Should have reasonable size

        // Verify message ID
        assert_eq!(response[2], 0x02); // INTEGER tag
        assert_eq!(response[3], 0x01); // Length
        assert_eq!(response[4], 0x01); // Message ID value

        // Verify SearchResultEntry tag
        assert_eq!(response[5], 0x64); // APPLICATION 4
    }

    #[test]
    fn test_create_search_entry_response_without_email() {
        let response = create_search_entry_response(
            2,
            "cn=testuser,ou=testorg,dc=example,dc=com",
            "testuser",
            None,
        );

        // Should be smaller without email attribute
        let with_email = create_search_entry_response(
            2,
            "cn=testuser,ou=testorg,dc=example,dc=com",
            "testuser",
            Some("test@example.com"),
        );

        assert!(response.len() < with_email.len());
    }

    #[test]
    fn test_create_group_search_entry_response() {
        let members = vec!["user1".to_string(), "user2".to_string()];
        let response = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test Group Description"),
            &members,
            None, // All attributes
        );

        // Verify structure
        assert_eq!(response[0], 0x30); // SEQUENCE
        assert!(response.len() > 100); // Should be substantial with members

        // Response should contain the message ID somewhere (encoded)
        // The exact position varies with BER length encoding
        assert!(response.contains(&0x02)); // Contains INTEGER tag
        assert!(response.contains(&0x64)); // Contains SearchResultEntry tag
    }

    #[test]
    fn test_production_group_response() {
        // Based on previous tests:
        // "ping only" + username = 165 bytes (1 over)
        // "Ping only ACL" + empty member = 161 bytes (3 under)

        // Test combinations to find exact 164:
        let r1_members = vec!["falkordb".to_string()];
        let r1 = create_group_search_entry_response(
            7,
            "cn=pingOnly,ou=groups,ou=instance-1,dc=example,dc=com",
            "pingOnly",
            Some("Ping only"), // "Ping only" instead of "Ping only ACL"
            &r1_members,
            None,
        );
        println!("'Ping only' + username: {} bytes", r1.len());

        let r2_members = vec!["falkordb".to_string()];
        let r2 = create_group_search_entry_response(
            7,
            "cn=pingOnly,ou=groups,ou=instance-1,dc=example,dc=com",
            "pingOnly",
            Some("ping ACL"), // Different variation
            &r2_members,
            None,
        );
        println!("'ping ACL' + username: {} bytes", r2.len());

        let r3_members = vec!["fal".to_string()];
        let r3 = create_group_search_entry_response(
            7,
            "cn=pingOnly,ou=groups,ou=instance-1,dc=example,dc=com",
            "pingOnly",
            Some("Ping only ACL"),
            &r3_members, // Shorter username?
            None,
        );
        println!("'Ping only ACL' + 'fal': {} bytes", r3.len());

        // Check for 164
        for (i, resp) in [&r1, &r2, &r3].iter().enumerate() {
            if resp.len() == 164 {
                println!("\n*** Test {} is EXACTLY 164 bytes! ***", i + 1);
                println!("Header: {:02x?}", &resp[..10]);
            }
        }
    }

    #[test]
    fn test_create_search_done_response() {
        let response = create_search_done_response(1, LdapResultCode::Success as u8);

        assert_eq!(response[0], 0x30); // SEQUENCE
        assert_eq!(response[2], 0x02); // INTEGER tag for message ID
        assert_eq!(response[3], 0x01); // Length
        assert_eq!(response[4], 0x01); // Message ID
        assert_eq!(response[5], 0x65); // SearchResultDone tag (APPLICATION 5)
        assert_eq!(response[6], 0x07); // Length
        assert_eq!(response[7], 0x0a); // ENUMERATED tag
        assert_eq!(response[9], 0x00); // Result code: success
    }

    #[test]
    fn test_create_whoami_response_authenticated() {
        let response = create_whoami_response(1, "cn=admin,ou=testorg,dc=example,dc=com");

        // Should include authorization identity
        assert_eq!(response[0], 0x30); // SEQUENCE
        assert!(response.len() > 20); // Should contain "dn:cn=admin..."

        // Verify Extended Response tag
        let msg_id_end = 5; // After SEQUENCE header and message ID
        assert_eq!(response[msg_id_end], 0x78); // APPLICATION 24
    }

    #[test]
    fn test_create_whoami_response_anonymous() {
        let response = create_whoami_response(1, "");

        // Should be smaller for anonymous (no response value)
        let authenticated = create_whoami_response(1, "cn=admin,ou=testorg,dc=example,dc=com");
        assert!(response.len() < authenticated.len());
    }

    #[test]
    fn test_create_extended_response_with_name() {
        let response = create_extended_response(
            1,
            LdapResultCode::Success as u8,
            Some("1.3.6.1.4.1.4203.1.11.3"),
            None,
        );

        // Verify structure
        assert_eq!(response[0], 0x30); // SEQUENCE
        assert!(response.len() > 20); // Should contain OID
    }

    #[test]
    fn test_create_extended_response_without_name() {
        let response = create_extended_response(1, LdapResultCode::Unavailable as u8, None, None);

        // Should be smaller without response name
        let with_name = create_extended_response(
            1,
            LdapResultCode::Success as u8,
            Some("1.3.6.1.4.1.4203.1.11.3"),
            None,
        );
        assert!(response.len() < with_name.len());
    }

    #[test]
    fn test_create_error_response() {
        let response = create_error_response(
            1,
            0x61, // BindResponse
            LdapResultCode::InvalidCredentials as u8,
        );

        // Verify structure
        assert_eq!(response[0], 0x30); // SEQUENCE
        assert_eq!(response[5], 0x61); // Operation type
        assert_eq!(response[9], 49); // Result code: invalid credentials
    }

    #[test]
    fn test_search_entry_response_length_calculation() {
        // Test that the BER length encoding is correct for various sizes
        let short_dn = "cn=a,ou=b,dc=c";
        let long_dn = "cn=verylongusername,ou=verylongorganization,dc=example,dc=com";

        let short_response = create_search_entry_response(1, short_dn, "a", None);
        let long_response = create_search_entry_response(1, long_dn, "verylongusername", None);

        // Longer DN should result in longer response
        assert!(long_response.len() > short_response.len());

        // Both should have valid SEQUENCE headers
        assert_eq!(short_response[0], 0x30);
        assert_eq!(long_response[0], 0x30);
    }

    #[test]
    fn test_group_search_entry_many_members() {
        // Test with many members to ensure BER encoding handles larger sizes
        let members: Vec<String> = (0..50).map(|i| format!("user{}", i)).collect();

        let response = create_group_search_entry_response(
            1,
            "cn=largegroup,ou=groups,ou=testorg,dc=example,dc=com",
            "largegroup",
            Some("A group with many members"),
            &members,
            None,
        );

        // Should be a substantial message
        assert!(response.len() > 500);

        // Should have proper SEQUENCE header
        assert_eq!(response[0], 0x30);

        // Length should be encoded properly (likely multi-byte)
        if response.len() > 127 {
            assert_eq!(response[1] & 0x80, 0x80); // Long form length indicator
        }
    }

    #[test]
    fn test_group_search_with_description_only() {
        // Test requesting only description attribute (like Valkey does)
        let members = vec!["user1".to_string()];
        let response = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            Some(&["description".to_string()]),
        );

        // Response should be smaller than with all attributes
        let all_attrs_response = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            None,
        );

        assert!(
            response.len() < all_attrs_response.len(),
            "Filtered response ({} bytes) should be smaller than all attributes ({} bytes)",
            response.len(),
            all_attrs_response.len()
        );

        // Should still have valid LDAP message structure
        assert_eq!(response[0], 0x30); // SEQUENCE
        assert_eq!(response[2], 0x02); // INTEGER tag for message ID

        println!(
            "Description only: {} bytes vs All attributes: {} bytes",
            response.len(),
            all_attrs_response.len()
        );
    }

    #[test]
    fn test_group_search_with_multiple_attrs() {
        // Test requesting multiple specific attributes
        let members = vec!["user1".to_string()];
        let response = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            Some(&["cn".to_string(), "description".to_string()]),
        );

        let all_attrs = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            None,
        );

        // Should be smaller than all attributes but larger than just description
        assert!(response.len() < all_attrs.len());

        let desc_only = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            Some(&["description".to_string()]),
        );

        assert!(
            response.len() > desc_only.len(),
            "Response with cn+description should be larger than description only"
        );
    }

    #[test]
    fn test_group_search_with_wildcard() {
        // Test requesting all attributes with "*"
        let members = vec!["user1".to_string()];
        let response_wildcard = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            Some(&["*".to_string()]),
        );

        let response_none = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            None,
        );

        // Wildcard should return same as None (all attributes)
        assert_eq!(
            response_wildcard.len(),
            response_none.len(),
            "Wildcard should return all attributes like None"
        );
    }

    #[test]
    fn test_group_search_with_nonexistent_attr() {
        // Test requesting an attribute that doesn't exist
        let members = vec!["user1".to_string()];
        let response = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            Some(&["nonexistent".to_string()]),
        );

        // Should return minimal response with just DN (no matching attributes)
        // Response will be smaller than even description-only
        let desc_response = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            Some(&["description".to_string()]),
        );

        assert!(
            response.len() < desc_response.len(),
            "Response with non-existent attribute should be smaller"
        );

        // But should still be a valid LDAP message
        assert_eq!(response[0], 0x30); // SEQUENCE
    }

    #[test]
    fn test_group_search_empty_attrs_list() {
        // Test with empty attributes list (should return all per RFC 4511)
        let members = vec!["user1".to_string()];
        let response_empty = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            Some(&[]),
        );

        let response_none = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            None,
        );

        // Empty list should return all attributes like None
        assert_eq!(
            response_empty.len(),
            response_none.len(),
            "Empty attributes list should return all attributes"
        );
    }

    #[test]
    fn test_group_search_case_insensitive_attrs() {
        // Test that attribute matching is case-insensitive
        let members = vec!["user1".to_string()];

        let response_lower = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            Some(&["description".to_string()]),
        );

        let response_upper = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            Some(&["DESCRIPTION".to_string()]),
        );

        let response_mixed = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            Some(&["Description".to_string()]),
        );

        // All should return the same result (case-insensitive)
        assert_eq!(
            response_lower.len(),
            response_upper.len(),
            "Case should not matter for attribute names"
        );
        assert_eq!(
            response_lower.len(),
            response_mixed.len(),
            "Case should not matter for attribute names"
        );
    }

    #[test]
    fn test_group_search_member_filtering() {
        // Test that member attribute can be filtered out
        let members = vec!["user1".to_string(), "user2".to_string()];

        let with_members = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            Some(&[
                "cn".to_string(),
                "objectClass".to_string(),
                "description".to_string(),
                "member".to_string(),
            ]),
        );

        let without_members = create_group_search_entry_response(
            1,
            "cn=testgroup,ou=groups,ou=testorg,dc=example,dc=com",
            "testgroup",
            Some("Test description"),
            &members,
            Some(&[
                "cn".to_string(),
                "objectClass".to_string(),
                "description".to_string(),
            ]),
        );

        // Response without member should be smaller
        assert!(
            without_members.len() < with_members.len(),
            "Response without member attributes should be smaller"
        );

        println!(
            "With members: {} bytes, Without members: {} bytes, Difference: {} bytes",
            with_members.len(),
            without_members.len(),
            with_members.len() - without_members.len()
        );
    }
}
