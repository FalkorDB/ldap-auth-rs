#!/usr/bin/env bash
# CLI Sanity Tests
# Tests basic functionality of the ldap-auth-cli tool

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Determine if we're testing the binary directly or via Docker
CLI_CMD="${CLI_CMD:-cargo run --quiet --bin ldap-auth-cli --}"

echo "Testing CLI tool with command: $CLI_CMD"
echo "========================================"
echo ""

# Helper function to run a test
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_exit_code="${3:-0}"
    local should_contain="${4:-}"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -n "Test $TESTS_RUN: $test_name ... "
    
    # Run the command and capture output
    set +e
    output=$($command 2>&1)
    exit_code=$?
    set -e
    
    # Check exit code
    if [ "$exit_code" -ne "$expected_exit_code" ]; then
        echo -e "${RED}FAILED${NC}"
        echo "  Expected exit code: $expected_exit_code"
        echo "  Got exit code: $exit_code"
        echo "  Output: $output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
    
    # Check if output contains expected string (if provided)
    if [ -n "$should_contain" ]; then
        if ! echo "$output" | grep -q "$should_contain"; then
            echo -e "${RED}FAILED${NC}"
            echo "  Expected output to contain: $should_contain"
            echo "  Got: $output"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            return 1
        fi
    fi
    
    echo -e "${GREEN}PASSED${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    return 0
}

# Test 1: Help flag
run_test "CLI shows help" \
    "$CLI_CMD --help" \
    0 \
    "CLI tool for interacting with the LDAP Auth Service API"

# Test 2: User subcommand help
run_test "User command shows help" \
    "$CLI_CMD user --help" \
    0 \
    "User management"

# Test 3: Group subcommand help
run_test "Group command shows help" \
    "$CLI_CMD group --help" \
    0 \
    "Group management"

# Test 4: Health command help
run_test "Health command shows help" \
    "$CLI_CMD health --help" \
    0 \
    "Health check"

# Test 5: User create help
run_test "User create shows help" \
    "$CLI_CMD user create --help" \
    0 \
    "Create a new user"

# Test 6: Group add-member help
run_test "Group add-member shows help" \
    "$CLI_CMD group add-member --help" \
    0 \
    "Add a member to a group"

# Test 7: Missing required token should fail
run_test "User list without token fails" \
    "$CLI_CMD user list --org test" \
    1 \
    "Token required for this operation"

# Test 8: Invalid API URL format is accepted (fails later on connection)
run_test "Health with unreachable URL" \
    "$CLI_CMD --url http://localhost:1 health" \
    1 \
    ""

# Test 9: User create with missing arguments
run_test "User create without required args fails" \
    "$CLI_CMD user create --org test" \
    2 \
    ""

# Test 10: Environment variable support
export LDAP_AUTH_URL="http://test.example.com"
run_test "CLI respects LDAP_AUTH_URL env var" \
    "$CLI_CMD health" \
    1 \
    ""
unset LDAP_AUTH_URL

echo ""
echo "========================================"
echo "Test Results:"
echo "========================================"
echo -e "Total tests: $TESTS_RUN"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
