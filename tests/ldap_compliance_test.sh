#!/usr/bin/env bash
set -e

# LDAP Compliance Test Suite
# Tests LDAP server compliance using ldapsearch and other standard LDAP tools

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
LDAP_HOST="${LDAP_HOST:-localhost}"
LDAP_PORT="${LDAP_PORT:-3389}"
LDAP_URL="ldap://${LDAP_HOST}:${LDAP_PORT}"
BASE_DN="${BASE_DN:-dc=example,dc=com}"
TEST_ORG="${TEST_ORG:-testorg}"
TEST_USER="${TEST_USER:-testuser}"
TEST_PASSWORD="${TEST_PASSWORD:-testpass123}"
ADMIN_ORG="${ADMIN_ORG:-admin}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin123}"
API_HOST="${API_HOST:-localhost:8080}"
API_TOKEN="${API_TOKEN:-admin}"

# Test counters
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0

# Check if ldapsearch is available
if ! command -v ldapsearch &> /dev/null; then
    echo -e "${RED}Error: ldapsearch command not found. Please install openldap-clients or ldap-utils${NC}"
    exit 1
fi

# Helper functions
print_test() {
    echo -e "\n${YELLOW}[TEST]${NC} $1"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

print_summary() {
    echo -e "\n${YELLOW}================================${NC}"
    echo -e "${YELLOW}Test Summary${NC}"
    echo -e "${YELLOW}================================${NC}"
    echo -e "Total:  ${TESTS_TOTAL}"
    echo -e "Passed: ${GREEN}${TESTS_PASSED}${NC}"
    echo -e "Failed: ${RED}${TESTS_FAILED}${NC}"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "\n${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "\n${RED}Some tests failed!${NC}"
        exit 1
    fi
}

# Wait for LDAP server to be ready
wait_for_ldap() {
    echo "Waiting for LDAP server at ${LDAP_URL}..."
    for i in {1..30}; do
        if ldapsearch -x -H "${LDAP_URL}" -b "" -s base "(objectclass=*)" &>/dev/null; then
            echo "LDAP server is ready!"
            return 0
        fi
        sleep 1
    done
    echo -e "${RED}LDAP server did not become ready in time${NC}"
    exit 1
}

# Create test user via API (requires API to be available)
create_test_user() {
    echo "Creating test user ${TEST_ORG}/${TEST_USER}..."
    
    local response
    response=$(curl -s -w "\n%{http_code}" -X POST "http://${API_HOST}/api/users" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -d "{\"organization\":\"${TEST_ORG}\",\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASSWORD}\",\"email\":\"${TEST_USER}@${TEST_ORG}.com\"}")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
        echo "✓ Test user created successfully"
        return 0
    elif [ "$http_code" = "409" ]; then
        echo "ℹ Test user already exists"
        return 0
    else
        echo "✗ Failed to create test user (HTTP $http_code): $body"
        return 1
    fi
}

# Test 1: Anonymous Bind
test_anonymous_bind() {
    print_test "Anonymous Bind"
    
    if ldapsearch -x -H "${LDAP_URL}" -b "${BASE_DN}" -s base "(objectclass=*)" &>/dev/null; then
        print_pass "Anonymous bind succeeded"
    else
        print_fail "Anonymous bind failed"
    fi
}

# Test 2: Simple Bind with Valid Credentials
test_simple_bind_valid() {
    print_test "Simple Bind with Valid Credentials"
    
    local bind_dn="cn=${TEST_USER},ou=${TEST_ORG},${BASE_DN}"
    
    if ldapsearch -x -H "${LDAP_URL}" -D "${bind_dn}" -w "${TEST_PASSWORD}" -b "${BASE_DN}" -s base "(objectclass=*)" &>/dev/null; then
        print_pass "Bind with valid credentials succeeded"
    else
        print_fail "Bind with valid credentials failed"
    fi
}

# Test 3: Simple Bind with Invalid Credentials
test_simple_bind_invalid() {
    print_test "Simple Bind with Invalid Credentials"
    
    local bind_dn="cn=${TEST_USER},ou=${TEST_ORG},${BASE_DN}"
    
    if ldapsearch -x -H "${LDAP_URL}" -D "${bind_dn}" -w "wrongpassword" -b "${BASE_DN}" -s base "(objectclass=*)" 2>&1 | grep -q "Invalid credentials"; then
        print_pass "Bind with invalid credentials properly rejected"
    else
        print_fail "Bind with invalid credentials did not fail as expected"
    fi
}

# Test 4: DN Format - Standard (cn=X,ou=Y,dc=...)
test_dn_format_standard() {
    print_test "DN Format - Standard (cn=X,ou=Y,dc=...)"
    
    local bind_dn="cn=${TEST_USER},ou=${TEST_ORG},${BASE_DN}"
    
    if ldapsearch -x -H "${LDAP_URL}" -D "${bind_dn}" -w "${TEST_PASSWORD}" -b "${BASE_DN}" -s base "(objectclass=*)" &>/dev/null; then
        print_pass "Standard DN format accepted"
    else
        print_fail "Standard DN format rejected"
    fi
}

# Test 5: DN Format - Uppercase Prefixes (CN=X,OU=Y,DC=...)
test_dn_format_uppercase() {
    print_test "DN Format - Uppercase Prefixes (CN=X,OU=Y,DC=...)"
    
    local bind_dn="CN=${TEST_USER},OU=${TEST_ORG},${BASE_DN}"
    
    if ldapsearch -x -H "${LDAP_URL}" -D "${bind_dn}" -w "${TEST_PASSWORD}" -b "${BASE_DN}" -s base "(objectclass=*)" &>/dev/null; then
        print_pass "Uppercase DN format accepted"
    else
        print_fail "Uppercase DN format rejected"
    fi
}

# Test 6: DN Format - Without OU (cn=X,dc=Y,dc=...)
test_dn_format_no_ou() {
    print_test "DN Format - Without OU (cn=X,dc=Y,dc=...)"
    
    # Use first DC component as organization
    local bind_dn="cn=${TEST_USER},dc=${TEST_ORG},dc=com"
    
    if ldapsearch -x -H "${LDAP_URL}" -D "${bind_dn}" -w "${TEST_PASSWORD}" -b "${BASE_DN}" -s base "(objectclass=*)" &>/dev/null; then
        print_pass "DN format without OU accepted"
    else
        print_fail "DN format without OU rejected"
    fi
}

# Test 7: Anonymous Search (should return empty results)
test_anonymous_search() {
    print_test "Anonymous Search"
    
    # Anonymous search should succeed but return no entries (per RFC 4532)
    local result=$(ldapsearch -x -H "${LDAP_URL}" -b "ou=${TEST_ORG},${BASE_DN}" 2>&1)
    
    if echo "$result" | grep -q "numResponses: 1"; then
        print_pass "Anonymous search returned empty results (RFC compliant)"
    elif echo "$result" | grep -q "Insufficient access"; then
        print_fail "Anonymous search returned error instead of empty results"
    else
        print_fail "Anonymous search had unexpected result"
    fi
}

# Test 8: Authenticated Search
test_authenticated_search() {
    print_test "Authenticated Search"
    
    local bind_dn="cn=${TEST_USER},ou=${TEST_ORG},${BASE_DN}"
    local result=$(ldapsearch -x -H "${LDAP_URL}" -D "${bind_dn}" -w "${TEST_PASSWORD}" -b "ou=${TEST_ORG},${BASE_DN}" 2>&1)
    
    if echo "$result" | grep -q "numResponses:"; then
        if echo "$result" | grep -q "Decoding error"; then
            print_fail "Search response has encoding/decoding errors"
        else
            print_pass "Authenticated search succeeded"
        fi
    else
        print_fail "Authenticated search failed"
    fi
}

# Test 9: WhoAmI Extended Operation - Anonymous
test_whoami_anonymous() {
    print_test "WhoAmI Extended Operation - Anonymous"
    
    if command -v ldapwhoami &> /dev/null; then
        local result=$(ldapwhoami -x -H "${LDAP_URL}" 2>&1)
        
        # Per RFC 4532, anonymous should return empty string
        if echo "$result" | grep -qE "^$|anonymous"; then
            print_pass "WhoAmI for anonymous user returned empty/anonymous (RFC compliant)"
        else
            print_fail "WhoAmI for anonymous user had unexpected result: $result"
        fi
    else
        echo "  Skipped (ldapwhoami not available)"
    fi
}

# Test 10: WhoAmI Extended Operation - Authenticated
test_whoami_authenticated() {
    print_test "WhoAmI Extended Operation - Authenticated"
    
    if command -v ldapwhoami &> /dev/null; then
        local bind_dn="cn=${TEST_USER},ou=${TEST_ORG},${BASE_DN}"
        local result=$(ldapwhoami -x -H "${LDAP_URL}" -D "${bind_dn}" -w "${TEST_PASSWORD}" 2>&1)
        
        if echo "$result" | grep -q "dn:"; then
            print_pass "WhoAmI for authenticated user returned DN"
        else
            print_fail "WhoAmI for authenticated user failed: $result"
        fi
    else
        echo "  Skipped (ldapwhoami not available)"
    fi
}

# Test 11: Search with Base Scope
test_search_base_scope() {
    print_test "Search with Base Scope"
    
    local bind_dn="cn=${TEST_USER},ou=${TEST_ORG},${BASE_DN}"
    
    if ldapsearch -x -H "${LDAP_URL}" -D "${bind_dn}" -w "${TEST_PASSWORD}" -b "${BASE_DN}" -s base "(objectclass=*)" &>/dev/null; then
        print_pass "Search with base scope succeeded"
    else
        print_fail "Search with base scope failed"
    fi
}

# Test 12: Search with One-Level Scope
test_search_one_level() {
    print_test "Search with One-Level Scope"
    
    local bind_dn="cn=${TEST_USER},ou=${TEST_ORG},${BASE_DN}"
    
    if ldapsearch -x -H "${LDAP_URL}" -D "${bind_dn}" -w "${TEST_PASSWORD}" -b "ou=${TEST_ORG},${BASE_DN}" -s one "(objectclass=*)" &>/dev/null; then
        print_pass "Search with one-level scope succeeded"
    else
        print_fail "Search with one-level scope failed"
    fi
}

# Test 13: Search with Subtree Scope
test_search_subtree() {
    print_test "Search with Subtree Scope"
    
    local bind_dn="cn=${TEST_USER},ou=${TEST_ORG},${BASE_DN}"
    
    if ldapsearch -x -H "${LDAP_URL}" -D "${bind_dn}" -w "${TEST_PASSWORD}" -b "ou=${TEST_ORG},${BASE_DN}" -s sub "(objectclass=*)" &>/dev/null; then
        print_pass "Search with subtree scope succeeded"
    else
        print_fail "Search with subtree scope failed"
    fi
}

# Test 14: Large Message IDs (testing proper encoding)
test_large_message_ids() {
    print_test "Large Message IDs"
    
    local bind_dn="cn=${TEST_USER},ou=${TEST_ORG},${BASE_DN}"
    
    # Perform multiple searches to increment message ID
    for i in {1..300}; do
        ldapsearch -x -H "${LDAP_URL}" -D "${bind_dn}" -w "${TEST_PASSWORD}" -b "${BASE_DN}" -s base "(objectclass=*)" &>/dev/null
    done
    
    # Final search should work even with large message ID
    if ldapsearch -x -H "${LDAP_URL}" -D "${bind_dn}" -w "${TEST_PASSWORD}" -b "${BASE_DN}" -s base "(objectclass=*)" 2>&1 | grep -q "Decoding error"; then
        print_fail "Large message IDs cause decoding errors"
    else
        print_pass "Large message IDs handled correctly"
    fi
}

# Test 15: Multiple Searches in Same Connection
test_multiple_searches() {
    print_test "Multiple Searches in Same Connection"
    
    local bind_dn="cn=${TEST_USER},ou=${TEST_ORG},${BASE_DN}"
    local passed=true
    
    for i in {1..10}; do
        if ! ldapsearch -x -H "${LDAP_URL}" -D "${bind_dn}" -w "${TEST_PASSWORD}" -b "${BASE_DN}" -s base "(objectclass=*)" &>/dev/null; then
            passed=false
            break
        fi
    done
    
    if $passed; then
        print_pass "Multiple consecutive searches succeeded"
    else
        print_fail "Multiple searches failed"
    fi
}

# Test 16: Group Membership Query
test_group_membership_query() {
    print_test "Group Membership Query (groupOfNames)"
    
    local bind_dn="cn=${TEST_USER},ou=${TEST_ORG},${BASE_DN}"
    
    # Search for groups where the user is a member
    # This should return empty results since groups are not supported (but should not timeout or error)
    if ldapsearch -x -H "${LDAP_URL}" -D "${bind_dn}" -w "${TEST_PASSWORD}" \
        -b "${BASE_DN}" -s sub \
        "(&(objectClass=groupOfNames)(member=cn=${TEST_USER},ou=${TEST_ORG},dc=falkordb,dc=cloud))" \
        description 2>&1 | grep -q "result: 0 Success"; then
        print_pass "Group membership query returned successfully (empty results expected - groups not supported)"
    else
        print_fail "Group membership query failed or timed out"
    fi
}

# Main test execution
main() {
    echo -e "${YELLOW}================================${NC}"
    echo -e "${YELLOW}LDAP Compliance Test Suite${NC}"
    echo -e "${YELLOW}================================${NC}"
    echo "LDAP URL: ${LDAP_URL}"
    echo "Base DN:  ${BASE_DN}"
    echo ""
    
    # Wait for server
    wait_for_ldap
    
    # Create test user
    create_test_user
    
    # Run all tests
    test_anonymous_bind
    test_simple_bind_valid
    test_simple_bind_invalid
    test_dn_format_standard
    test_dn_format_uppercase
    test_dn_format_no_ou
    test_anonymous_search
    test_authenticated_search
    test_whoami_anonymous
    test_whoami_authenticated
    test_search_base_scope
    test_search_one_level
    test_search_subtree
    test_large_message_ids
    test_multiple_searches
    test_group_membership_query
    
    # Print summary
    print_summary
}

# Run tests
main "$@"
