# LDAP Compliance Testing

This document describes the LDAP compliance tests and how to run them.

## Overview

The LDAP compliance test suite (`tests/ldap_compliance_test.sh`) validates that the LDAP server implementation follows LDAP RFCs and works correctly with standard LDAP clients.

## Test Coverage

The test suite covers:

### 1. Bind Operations
- **Anonymous Bind**: Verifies anonymous bind is accepted (RFC 4513)
- **Simple Bind with Valid Credentials**: Tests successful authentication
- **Simple Bind with Invalid Credentials**: Ensures proper rejection of bad credentials
- **DN Format Variations**: Tests different DN formats:
  - Standard: `cn=username,ou=org,dc=example,dc=com`
  - Uppercase: `CN=username,OU=org,DC=example,DC=com`
  - Without OU: `cn=username,dc=org,dc=com`

### 2. Search Operations
- **Anonymous Search**: Verifies RFC 4532 compliance (returns empty results, not error)
- **Authenticated Search**: Tests search with valid credentials
- **Search Scopes**: Tests base, one-level, and subtree scopes
- **Multiple Searches**: Validates connection persistence

### 3. Extended Operations
- **WhoAmI (Anonymous)**: Tests RFC 4532 - should return empty string for anonymous
- **WhoAmI (Authenticated)**: Tests RFC 4532 - should return authorization identity

### 4. Protocol Compliance
- **Large Message IDs**: Ensures proper encoding of message IDs > 255
- **Response Encoding**: Validates BER/DER encoding is correct (no decoding errors)

## Prerequisites

### Required Tools
- `ldapsearch` - LDAP search utility
- `ldapwhoami` - LDAP WhoAmI utility (optional but recommended)

Install on different platforms:

**Ubuntu/Debian:**
```bash
sudo apt-get install ldap-utils
```

**macOS:**
```bash
brew install openldap
```

**RHEL/CentOS/Fedora:**
```bash
sudo dnf install openldap-clients
```

### Running Server
The LDAP server must be running and accessible. You'll also need:
- Redis running for backend storage
- Test users created in the database

## Running Tests

### Local Testing

1. **Start Redis:**
```bash
docker run -d -p 6379:6379 redis:latest
```

2. **Start LDAP Server:**
```bash
cargo run --release
```

3. **Create Test Users:**
```bash
# Create test organization and user
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin" \
  -d '{
    "organization": "testorg",
    "username": "testuser",
    "password": "testpass123",
    "email": "test@example.com"
  }'

# Create admin user for search tests
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin" \
  -d '{
    "organization": "admin",
    "username": "admin",
    "password": "admin123",
    "email": "admin@example.com"
  }'
```

4. **Run Compliance Tests:**
```bash
./tests/ldap_compliance_test.sh
```

### Custom Configuration

You can customize test parameters using environment variables:

```bash
LDAP_HOST=localhost \
LDAP_PORT=3389 \
BASE_DN="dc=example,dc=com" \
TEST_ORG="myorg" \
TEST_USER="myuser" \
TEST_PASSWORD="mypass" \
./tests/ldap_compliance_test.sh
```

### CI/CD Testing

The tests are automatically run in CI/CD pipeline (GitHub Actions):
- Server is started with test configuration
- Test users are created automatically
- All compliance tests are executed
- Results are reported in the job output

## Test Output

The test script provides colored output:
- 🟡 **Yellow**: Test name
- 🟢 **Green**: Test passed
- 🔴 **Red**: Test failed

Example output:
```
================================
LDAP Compliance Test Suite
================================
LDAP URL: ldap://localhost:3389
Base DN:  dc=example,dc=com

[TEST] Anonymous Bind
[PASS] Anonymous bind succeeded

[TEST] Simple Bind with Valid Credentials
[PASS] Bind with valid credentials succeeded

...

================================
Test Summary
================================
Total:  15
Passed: 15
Failed: 0

All tests passed!
```

## Troubleshooting

### Connection Refused
If tests fail with "Connection refused":
- Verify LDAP server is running: `netstat -an | grep 3389`
- Check server logs for errors
- Ensure correct host/port configuration

### Authentication Failures
If bind tests fail:
- Verify test users exist in the database
- Check credentials match what was created
- Review server logs for authentication errors

### Decoding Errors
If you see "Decoding error (-4)":
- This indicates BER/DER encoding issues
- Check message ID encoding (must handle values > 255)
- Verify response length fields are correct
- Review recent code changes to response builders

### Empty Search Results
If authenticated searches return no results:
- Verify `LDAP_SEARCH_BIND_ORG` configuration
- Check user is in the correct organization
- Review search base DN matches test configuration

## RFC Compliance

This test suite validates compliance with:

- **RFC 4510**: LDAP Technical Specification Road Map
- **RFC 4511**: LDAP Protocol (v3)
- **RFC 4513**: LDAP Authentication Methods (Simple Bind)
- **RFC 4532**: LDAP WhoAmI Operation

## Known Limitations

See the main [ARCHITECTURE.md](../docs/ARCHITECTURE.md) for detailed information about LDAP implementation limitations. Key limitations tested:

✅ **Tested & Working:**
- Simple bind authentication
- Anonymous bind
- Basic search operations
- WhoAmI extended operation
- Case-insensitive DN components
- DN format variations (with/without OU)

⚠️ **Limited Testing:**
- Search filters (not parsed, returns all users)
- Search scope (accepted but not enforced)
- Large result sets (pagination not implemented)

## Adding New Tests

To add a new compliance test:

1. Create a new test function in `ldap_compliance_test.sh`:
```bash
test_my_new_feature() {
    print_test "My New Feature"
    
    # Your test logic here
    if test_passes; then
        print_pass "Feature works correctly"
    else
        print_fail "Feature failed"
    fi
}
```

2. Call it from the `main()` function:
```bash
main() {
    # ... existing tests ...
    test_my_new_feature
    # ... more tests ...
    print_summary
}
```

3. Update this README with the new test coverage

## References

- [RFC 4511 - LDAP Protocol](https://tools.ietf.org/html/rfc4511)
- [RFC 4532 - WhoAmI Operation](https://tools.ietf.org/html/rfc4532)
- [OpenLDAP ldapsearch Documentation](https://www.openldap.org/software/man.cgi?query=ldapsearch)
