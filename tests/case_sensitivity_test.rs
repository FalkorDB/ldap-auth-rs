/// Tests for case sensitivity preservation in LDAP DN parsing and member info extraction
///
/// This test suite ensures that:
/// 1. LDAP keywords (cn=, ou=, dc=, member=) are matched case-insensitively
/// 2. Usernames, organization names, and group names preserve their original case
/// 3. Mixed case values in LDAP filters are correctly extracted
use ldap_auth_rs::ldap::{extract_member_info, extract_org_from_dn, parse_dn};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dn_preserves_username_case() {
        // Test that parse_dn preserves the case of the username
        let dn = "cn=pingOnly,ou=instance-a2pzrd3w9,dc=falkordb,dc=cloud";
        let result = parse_dn(dn);

        assert!(result.is_some());
        let (org, username) = result.unwrap();
        assert_eq!(username, "pingOnly", "Username case should be preserved");
        assert_eq!(
            org, "instance-a2pzrd3w9",
            "Organization case should be preserved"
        );
    }

    #[test]
    fn test_parse_dn_with_uppercase_keywords() {
        // Test that LDAP keywords are matched case-insensitively
        let dn = "CN=TestUser,OU=MyOrg,DC=example,DC=com";
        let result = parse_dn(dn);

        assert!(result.is_some());
        let (org, username) = result.unwrap();
        assert_eq!(
            username, "TestUser",
            "Username case should be preserved with uppercase keywords"
        );
        assert_eq!(
            org, "MyOrg",
            "Organization case should be preserved with uppercase keywords"
        );
    }

    #[test]
    fn test_parse_dn_with_mixed_case_keywords() {
        // Test with mixed case keywords
        let dn = "Cn=MyUser,Ou=TestOrg,Dc=domain,Dc=tld";
        let result = parse_dn(dn);

        assert!(result.is_some());
        let (org, username) = result.unwrap();
        assert_eq!(username, "MyUser", "Username case should be preserved");
        assert_eq!(org, "TestOrg", "Organization case should be preserved");
    }

    #[test]
    fn test_parse_dn_dc_as_org() {
        // Test using DC as organization when OU is not present
        let dn = "cn=user123,dc=MyCompany,dc=com";
        let result = parse_dn(dn);

        assert!(result.is_some());
        let (org, username) = result.unwrap();
        assert_eq!(username, "user123");
        assert_eq!(
            org, "MyCompany",
            "First DC should be used as org with case preserved"
        );
    }

    #[test]
    fn test_extract_member_info_preserves_case() {
        // Test that extract_member_info preserves username and org case
        let payload = "(&(objectClass=groupOfNames)(member=cn=pingOnly,ou=instance-a2pzrd3w9,dc=falkordb,dc=cloud))";
        let payload_lower = payload.to_lowercase();

        let result = extract_member_info(payload, &payload_lower);

        assert!(result.is_some());
        let (org, username) = result.unwrap();
        assert_eq!(
            username, "pingOnly",
            "Username case should be preserved in member filter"
        );
        assert_eq!(
            org, "instance-a2pzrd3w9",
            "Organization case should be preserved in member filter"
        );
    }

    #[test]
    fn test_extract_member_info_with_camel_case() {
        // Test various mixed case usernames
        let test_cases = vec![
            ("cn=JohnDoe", "JohnDoe"),
            ("cn=johnDoe", "johnDoe"),
            ("cn=JOHNDOE", "JOHNDOE"),
            ("cn=john_Doe", "john_Doe"),
            ("cn=John-Doe", "John-Doe"),
        ];

        for (cn_part, expected_username) in test_cases {
            let payload = format!("(member={},ou=TestOrg,dc=test,dc=com)", cn_part);
            let payload_lower = payload.to_lowercase();

            let result = extract_member_info(&payload, &payload_lower);

            assert!(result.is_some(), "Failed to extract for {}", cn_part);
            let (_, username) = result.unwrap();
            assert_eq!(
                username, expected_username,
                "Username case not preserved for {}",
                cn_part
            );
        }
    }

    #[test]
    fn test_extract_member_info_with_uppercase_ldap_keywords() {
        // Test that LDAP keywords can be in any case but values are preserved
        let payload = "(&(objectClass=groupOfNames)(MEMBER=CN=TestUser,OU=MyOrg,DC=test,DC=com))";
        let payload_lower = payload.to_lowercase();

        let result = extract_member_info(payload, &payload_lower);

        assert!(result.is_some());
        let (org, username) = result.unwrap();
        assert_eq!(
            username, "TestUser",
            "Username case should be preserved even with uppercase keywords"
        );
        assert_eq!(
            org, "MyOrg",
            "Organization case should be preserved even with uppercase keywords"
        );
    }

    #[test]
    fn test_extract_member_info_pattern_2() {
        // Test pattern 2 (member followed by cn= with possible separators)
        // Simulating BER encoding where there might be null bytes or separators
        let payload = "member\x00cn=CaseSensitiveUser,ou=OrgName,dc=test";
        let payload_lower = payload.to_lowercase();

        let result = extract_member_info(payload, &payload_lower);

        assert!(result.is_some());
        let (org, username) = result.unwrap();
        assert_eq!(
            username, "CaseSensitiveUser",
            "Pattern 2 should preserve username case"
        );
        assert_eq!(org, "OrgName", "Pattern 2 should preserve org case");
    }

    #[test]
    fn test_extract_org_from_dn_preserves_case() {
        // Test that extract_org_from_dn preserves organization name case
        let test_cases = vec![
            ("ou=MyOrganization,dc=test,dc=com", Some("MyOrganization")),
            ("ou=testORG,dc=example,dc=com", Some("testORG")),
            ("ou=Test-Org_123,dc=test", Some("Test-Org_123")),
            ("dc=MyCompany,dc=com", Some("MyCompany")),
        ];

        for (dn_part, expected) in test_cases {
            let result = extract_org_from_dn(dn_part);
            assert_eq!(
                result.as_deref(),
                expected,
                "Failed to preserve case for: {}",
                dn_part
            );
        }
    }

    #[test]
    fn test_extract_org_from_dn_uppercase_keywords() {
        // Test with uppercase LDAP keywords
        let dn_part = "OU=TestOrg,DC=domain,DC=com";
        let result = extract_org_from_dn(dn_part);

        assert_eq!(
            result.as_deref(),
            Some("TestOrg"),
            "Should extract org with uppercase keywords"
        );
    }

    #[test]
    fn test_extract_org_from_dn_mixed_case_keywords() {
        // Test with mixed case LDAP keywords
        let dn_part = "Ou=MixedCaseOrg,Dc=test,Dc=com";
        let result = extract_org_from_dn(dn_part);

        assert_eq!(
            result.as_deref(),
            Some("MixedCaseOrg"),
            "Should extract org with mixed case keywords"
        );
    }

    #[test]
    fn test_real_world_ldap_filter_with_mixed_case() {
        // Test a real-world LDAP filter similar to what Grafana might send
        let payload = r#"(&(objectClass=groupOfNames)(member=cn=AdminUser,ou=Production-Env,dc=mycompany,dc=cloud))"#;
        let payload_lower = payload.to_lowercase();

        let result = extract_member_info(payload, &payload_lower);

        assert!(
            result.is_some(),
            "Should extract member info from real-world filter"
        );
        let (org, username) = result.unwrap();
        assert_eq!(
            username, "AdminUser",
            "Real-world filter should preserve admin username case"
        );
        assert_eq!(
            org, "Production-Env",
            "Real-world filter should preserve environment name case"
        );
    }

    #[test]
    fn test_ldap_keywords_are_case_insensitive() {
        // Verify that different cases of LDAP keywords all work
        let test_cases = vec![
            "cn=user,ou=org,dc=test",
            "CN=user,OU=org,DC=test",
            "Cn=user,Ou=org,Dc=test",
            "cN=user,oU=org,dC=test",
        ];

        for dn in test_cases {
            let result = parse_dn(dn);
            assert!(
                result.is_some(),
                "Should parse DN with various keyword cases: {}",
                dn
            );
            let (org, username) = result.unwrap();
            assert_eq!(username, "user");
            // org could be "org" or "test" depending on whether ou= or dc= is used
            assert!(org == "org" || org == "test");
        }
    }

    #[test]
    fn test_special_characters_in_names() {
        // Test that special characters commonly used in usernames/orgs are preserved
        let dn = "cn=user.name+test,ou=org-123_abc,dc=test";
        let result = parse_dn(dn);

        assert!(result.is_some());
        let (org, username) = result.unwrap();
        assert_eq!(
            username, "user.name+test",
            "Should preserve special characters in username"
        );
        assert_eq!(
            org, "org-123_abc",
            "Should preserve special characters in org"
        );
    }

    #[test]
    fn test_extract_member_info_no_match() {
        // Test that function returns None when pattern doesn't match
        let payload = "(&(objectClass=user)(uid=testuser))";
        let payload_lower = payload.to_lowercase();

        let result = extract_member_info(payload, &payload_lower);

        assert!(
            result.is_none(),
            "Should return None when member pattern not found"
        );
    }

    #[test]
    fn test_parse_dn_invalid_format() {
        // Test invalid DN formats
        let invalid_dns = vec![
            "invalid", "cn=user", // Missing org component
            "ou=org",  // Missing user component
            "",
        ];

        for dn in invalid_dns {
            let result = parse_dn(dn);
            assert!(
                result.is_none(),
                "Should return None for invalid DN: {}",
                dn
            );
        }
    }

    #[test]
    fn test_comparison_lowercase_vs_original() {
        // Demonstrate the bug that was fixed: lowercasing changes the username
        let original = "pingOnly";
        let lowercased = original.to_lowercase();

        assert_ne!(original, lowercased, "Lowercasing changes the username");
        assert_eq!(lowercased, "pingonly");

        // This demonstrates why we need to preserve case in the payload
        let dn = format!("cn={},ou=org,dc=test", original);
        let result = parse_dn(&dn);

        assert!(result.is_some());
        let (_, username) = result.unwrap();
        assert_eq!(username, original, "parse_dn must preserve original case");
    }
}
