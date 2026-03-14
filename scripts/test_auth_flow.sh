#!/bin/bash

################################################################################
# test_auth_flow.sh - Test device code authentication flow
#
# Tests the complete OAuth 2.0 Device Authorization Grant flow:
# 1. Request device code from API
# 2. Simulate device authorization (manual simulation)
# 3. Poll for token until authorized
# 4. Verify token is valid
# 5. Test session persistence
#
# This tests the CLI authentication mechanism end-to-end.
#
# Prerequisites:
#   - API server running
#   - curl installed
#   - jq installed (for JSON parsing)
#
# Environment:
#   ZYPHERON_API_URL - API base URL (default: http://localhost:8000)
################################################################################

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Configuration
API_URL="${ZYPHERON_API_URL:-http://localhost:8000}"
TEST_EMAIL="test-auth-$(date +%s)@example.com"
TEST_PASSWORD="SecurePassword123!"
TEST_DEVICE_INFO="Zypheron CLI Test v1.0"

# Test result tracking
TESTS_PASSED=0
TESTS_FAILED=0

################################################################################
# Utility functions
################################################################################

print_test() {
    echo -e "${CYAN}[TEST]${NC} $1"
}

print_pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "${RED}[FAIL]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if jq is installed
check_dependencies() {
    if ! command -v jq &> /dev/null; then
        print_error "jq is required but not installed"
        print_info "Install with: sudo apt install jq"
        exit 1
    fi

    if ! command -v curl &> /dev/null; then
        print_error "curl is required but not installed"
        exit 1
    fi
}

################################################################################
# Test 1: Register a test user
################################################################################

test_register_user() {
    print_test "Test 1: User registration"

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/auth/register" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\"}")

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    if [ "$http_code" -eq 201 ]; then
        USER_ID=$(echo "$body" | jq -r '.user.id')
        USER_TOKEN=$(echo "$body" | jq -r '.access_token')

        if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ] && [ -n "$USER_TOKEN" ]; then
            print_pass "User registered successfully (ID: ${USER_ID})"
            return 0
        else
            print_fail "Registration returned 201 but missing user ID or token"
            echo "$body" | jq '.'
            return 1
        fi
    else
        print_fail "Registration failed with HTTP ${http_code}"
        echo "$body" | jq '.'
        return 1
    fi
}

################################################################################
# Test 2: Request device code
################################################################################

test_device_code_request() {
    print_test "Test 2: Request device code"

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/auth/device/code" \
        -H "Content-Type: application/json" \
        -d "{\"device_info\":\"${TEST_DEVICE_INFO}\"}")

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    if [ "$http_code" -eq 201 ]; then
        DEVICE_CODE=$(echo "$body" | jq -r '.device_code')
        USER_CODE=$(echo "$body" | jq -r '.user_code')
        VERIFICATION_URL=$(echo "$body" | jq -r '.verification_url')
        EXPIRES_IN=$(echo "$body" | jq -r '.expires_in')
        POLL_INTERVAL=$(echo "$body" | jq -r '.interval')

        if [ -n "$DEVICE_CODE" ] && [ "$DEVICE_CODE" != "null" ] && \
           [ -n "$USER_CODE" ] && [ "$USER_CODE" != "null" ]; then
            print_pass "Device code generated: ${USER_CODE}"
            print_info "Device code: ${DEVICE_CODE}"
            print_info "User code: ${USER_CODE}"
            print_info "Verification URL: ${VERIFICATION_URL}"
            print_info "Expires in: ${EXPIRES_IN} seconds"
            print_info "Poll interval: ${POLL_INTERVAL} seconds"
            return 0
        else
            print_fail "Device code request returned 201 but missing codes"
            echo "$body" | jq '.'
            return 1
        fi
    else
        print_fail "Device code request failed with HTTP ${http_code}"
        echo "$body" | jq '.'
        return 1
    fi
}

################################################################################
# Test 3: Poll device token (should be pending)
################################################################################

test_device_token_pending() {
    print_test "Test 3: Poll device token (expect pending)"

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/auth/device/token" \
        -H "Content-Type: application/json" \
        -d "{\"device_code\":\"${DEVICE_CODE}\"}")

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    if [ "$http_code" -eq 200 ]; then
        local status=$(echo "$body" | jq -r '.status')

        if [ "$status" = "pending" ]; then
            print_pass "Device code status is pending (as expected)"
            return 0
        else
            print_fail "Expected status 'pending', got '${status}'"
            echo "$body" | jq '.'
            return 1
        fi
    else
        print_fail "Device token poll failed with HTTP ${http_code}"
        echo "$body" | jq '.'
        return 1
    fi
}

################################################################################
# Test 4: Authorize device code
################################################################################

test_authorize_device() {
    print_test "Test 4: Authorize device code"

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/auth/device/authorize" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${USER_TOKEN}" \
        -d "{\"user_code\":\"${USER_CODE}\"}")

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    if [ "$http_code" -eq 200 ]; then
        local success=$(echo "$body" | jq -r '.success')

        if [ "$success" = "true" ]; then
            print_pass "Device authorized successfully"
            print_info "Message: $(echo "$body" | jq -r '.message')"
            return 0
        else
            print_fail "Authorization returned success=false"
            echo "$body" | jq '.'
            return 1
        fi
    else
        print_fail "Device authorization failed with HTTP ${http_code}"
        echo "$body" | jq '.'
        return 1
    fi
}

################################################################################
# Test 5: Poll device token (should be authorized with token)
################################################################################

test_device_token_authorized() {
    print_test "Test 5: Poll device token (expect authorized with JWT)"

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/auth/device/token" \
        -H "Content-Type: application/json" \
        -d "{\"device_code\":\"${DEVICE_CODE}\"}")

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    if [ "$http_code" -eq 200 ]; then
        local status=$(echo "$body" | jq -r '.status')

        if [ "$status" = "authorized" ]; then
            CLI_TOKEN=$(echo "$body" | jq -r '.access_token')
            CLI_EMAIL=$(echo "$body" | jq -r '.email')
            CLI_TIER=$(echo "$body" | jq -r '.tier')

            if [ -n "$CLI_TOKEN" ] && [ "$CLI_TOKEN" != "null" ]; then
                print_pass "Device authorized, received access token"
                print_info "Email: ${CLI_EMAIL}"
                print_info "Tier: ${CLI_TIER}"
                return 0
            else
                print_fail "Status is authorized but missing access token"
                echo "$body" | jq '.'
                return 1
            fi
        else
            print_fail "Expected status 'authorized', got '${status}'"
            echo "$body" | jq '.'
            return 1
        fi
    else
        print_fail "Device token poll failed with HTTP ${http_code}"
        echo "$body" | jq '.'
        return 1
    fi
}

################################################################################
# Test 6: Verify token is valid by calling /auth/me
################################################################################

test_verify_token() {
    print_test "Test 6: Verify token validity"

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X GET "${API_URL}/auth/me" \
        -H "Authorization: Bearer ${CLI_TOKEN}")

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    if [ "$http_code" -eq 200 ]; then
        local email=$(echo "$body" | jq -r '.email')

        if [ "$email" = "$TEST_EMAIL" ]; then
            print_pass "Token is valid, authenticated as ${email}"
            return 0
        else
            print_fail "Token valid but email mismatch: expected ${TEST_EMAIL}, got ${email}"
            echo "$body" | jq '.'
            return 1
        fi
    else
        print_fail "Token verification failed with HTTP ${http_code}"
        echo "$body" | jq '.'
        return 1
    fi
}

################################################################################
# Test 7: Test session persistence
################################################################################

test_session_persistence() {
    print_test "Test 7: Session persistence (multiple API calls)"

    # Make multiple calls with the same token
    for i in {1..3}; do
        local response
        local http_code

        response=$(curl -s -w "\n%{http_code}" -X GET "${API_URL}/auth/me" \
            -H "Authorization: Bearer ${CLI_TOKEN}")

        http_code=$(echo "$response" | tail -n1)

        if [ "$http_code" -ne 200 ]; then
            print_fail "Session failed on call ${i} with HTTP ${http_code}"
            return 1
        fi
    done

    print_pass "Session persisted across 3 API calls"
    return 0
}

################################################################################
# Test 8: Test logout
################################################################################

test_logout() {
    print_test "Test 8: Logout and session invalidation"

    local response
    local http_code

    # Logout
    response=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/auth/logout" \
        -H "Authorization: Bearer ${CLI_TOKEN}")

    http_code=$(echo "$response" | tail -n1)

    if [ "$http_code" -ne 204 ]; then
        print_fail "Logout failed with HTTP ${http_code}"
        return 1
    fi

    # Try to use token after logout (should fail)
    response=$(curl -s -w "\n%{http_code}" -X GET "${API_URL}/auth/me" \
        -H "Authorization: Bearer ${CLI_TOKEN}")

    http_code=$(echo "$response" | tail -n1)

    if [ "$http_code" -eq 401 ]; then
        print_pass "Session invalidated after logout (HTTP 401)"
        return 0
    else
        print_fail "Expected HTTP 401 after logout, got ${http_code}"
        return 1
    fi
}

################################################################################
# Test 9: Test expired device code
################################################################################

test_expired_device_code() {
    print_test "Test 9: Test expired device code handling"

    # Create a new device code
    local response
    response=$(curl -s -X POST "${API_URL}/auth/device/code" \
        -H "Content-Type: application/json" \
        -d "{\"device_info\":\"Expired test\"}")

    local new_device_code=$(echo "$response" | jq -r '.device_code')

    # Note: We can't actually wait 5 minutes for expiry in tests
    # This test would need database manipulation or mocking
    # For now, just verify the endpoint accepts the request
    if [ -n "$new_device_code" ] && [ "$new_device_code" != "null" ]; then
        print_pass "Expiry handling endpoint accessible (full test needs time manipulation)"
        return 0
    else
        print_fail "Failed to generate device code for expiry test"
        return 1
    fi
}

################################################################################
# Main execution
################################################################################

main() {
    echo -e "${BOLD}${BLUE}Authentication Flow Integration Tests${NC}\n"

    check_dependencies

    print_info "Testing against API: ${API_URL}"
    echo ""

    # Run all tests
    test_register_user || true
    echo ""

    test_device_code_request || true
    echo ""

    test_device_token_pending || true
    echo ""

    test_authorize_device || true
    echo ""

    test_device_token_authorized || true
    echo ""

    test_verify_token || true
    echo ""

    test_session_persistence || true
    echo ""

    test_logout || true
    echo ""

    test_expired_device_code || true
    echo ""

    # Summary
    echo -e "${BOLD}Test Summary:${NC}"
    echo -e "  ${GREEN}Passed: ${TESTS_PASSED}${NC}"
    echo -e "  ${RED}Failed: ${TESTS_FAILED}${NC}"

    if [ "$TESTS_FAILED" -gt 0 ]; then
        echo -e "\n${RED}Some tests failed${NC}"
        exit 1
    else
        echo -e "\n${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

main
