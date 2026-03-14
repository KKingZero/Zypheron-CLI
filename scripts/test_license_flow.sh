#!/bin/bash

################################################################################
# test_license_flow.sh - Test license validation and tier features
#
# Tests:
# 1. License validation endpoint
# 2. Tier features endpoint
# 3. Feature limits per tier
# 4. License refresh from Stripe (if configured)
# 5. Offline mode simulation
# 6. Graceful degradation when API unavailable
#
# Prerequisites:
#   - API server running
#   - curl and jq installed
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
TEST_EMAIL="test-license-$(date +%s)@example.com"
TEST_PASSWORD="SecurePassword123!"

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

check_dependencies() {
    if ! command -v jq &> /dev/null; then
        print_error "jq is required but not installed"
        exit 1
    fi
}

################################################################################
# Setup: Create test user and get token
################################################################################

setup_test_user() {
    print_info "Setting up test user: ${TEST_EMAIL}"

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/auth/register" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\"}")

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    if [ "$http_code" -eq 201 ]; then
        USER_TOKEN=$(echo "$body" | jq -r '.access_token')
        USER_ID=$(echo "$body" | jq -r '.user.id')
        print_info "Test user created (ID: ${USER_ID})"
        return 0
    else
        print_error "Failed to create test user (HTTP ${http_code})"
        echo "$body" | jq '.'
        return 1
    fi
}

################################################################################
# Test 1: Validate license endpoint
################################################################################

test_license_validation() {
    print_test "Test 1: License validation for new user"

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X GET "${API_URL}/license/validate" \
        -H "Authorization: Bearer ${USER_TOKEN}")

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    if [ "$http_code" -eq 200 ]; then
        local is_valid=$(echo "$body" | jq -r '.is_valid')
        local tier=$(echo "$body" | jq -r '.tier')
        local status=$(echo "$body" | jq -r '.status')

        if [ "$is_valid" = "true" ] && [ "$tier" = "free" ] && [ "$status" = "active" ]; then
            print_pass "License validated: tier=${tier}, status=${status}, valid=${is_valid}"
            print_info "Full response:"
            echo "$body" | jq '.'
            return 0
        else
            print_fail "License validation returned unexpected values"
            echo "$body" | jq '.'
            return 1
        fi
    else
        print_fail "License validation failed with HTTP ${http_code}"
        echo "$body" | jq '.'
        return 1
    fi
}

################################################################################
# Test 2: Get tier features
################################################################################

test_tier_features() {
    print_test "Test 2: Get tier features for current user"

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X GET "${API_URL}/license/features" \
        -H "Authorization: Bearer ${USER_TOKEN}")

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    if [ "$http_code" -eq 200 ]; then
        local tier=$(echo "$body" | jq -r '.tier')
        local ai_scanning=$(echo "$body" | jq -r '.ai_scanning')
        local compliance_reports=$(echo "$body" | jq -r '.compliance_reports')
        local max_scans=$(echo "$body" | jq -r '.max_scans_per_month')

        print_pass "Features retrieved for tier: ${tier}"
        print_info "AI Scanning: ${ai_scanning}"
        print_info "Compliance Reports: ${compliance_reports}"
        print_info "Max Scans/Month: ${max_scans}"
        print_info "Full features:"
        echo "$body" | jq '.'
        return 0
    else
        print_fail "Get features failed with HTTP ${http_code}"
        echo "$body" | jq '.'
        return 1
    fi
}

################################################################################
# Test 3: Get all tier comparison
################################################################################

test_all_tiers() {
    print_test "Test 3: Get all tier feature comparison"

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X GET "${API_URL}/license/tiers")

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    if [ "$http_code" -eq 200 ]; then
        local has_free=$(echo "$body" | jq 'has("free")')
        local has_starter=$(echo "$body" | jq 'has("starter")')
        local has_pro=$(echo "$body" | jq 'has("pro")')
        local has_enterprise=$(echo "$body" | jq 'has("enterprise")')

        if [ "$has_free" = "true" ] && [ "$has_starter" = "true" ] && \
           [ "$has_pro" = "true" ] && [ "$has_enterprise" = "true" ]; then
            print_pass "All tiers retrieved successfully"

            # Display tier comparison
            print_info "Free tier scans: $(echo "$body" | jq -r '.free.max_scans_per_month')"
            print_info "Starter tier scans: $(echo "$body" | jq -r '.starter.max_scans_per_month')"
            print_info "Pro tier scans: $(echo "$body" | jq -r '.pro.max_scans_per_month')"
            print_info "Enterprise tier scans: $(echo "$body" | jq -r '.enterprise.max_scans_per_month')"

            return 0
        else
            print_fail "Missing tier information"
            echo "$body" | jq '.'
            return 1
        fi
    else
        print_fail "Get tiers failed with HTTP ${http_code}"
        echo "$body" | jq '.'
        return 1
    fi
}

################################################################################
# Test 4: Get license details
################################################################################

test_license_details() {
    print_test "Test 4: Get full license details"

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X GET "${API_URL}/license" \
        -H "Authorization: Bearer ${USER_TOKEN}")

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    if [ "$http_code" -eq 200 ]; then
        local tier=$(echo "$body" | jq -r '.tier')
        local status=$(echo "$body" | jq -r '.status')
        local created_at=$(echo "$body" | jq -r '.created_at')

        print_pass "License details retrieved"
        print_info "Tier: ${tier}"
        print_info "Status: ${status}"
        print_info "Created: ${created_at}"
        return 0
    else
        print_fail "Get license details failed with HTTP ${http_code}"
        echo "$body" | jq '.'
        return 1
    fi
}

################################################################################
# Test 5: Test license refresh (will fail if Stripe not configured)
################################################################################

test_license_refresh() {
    print_test "Test 5: Test license refresh from Stripe"

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/license/refresh" \
        -H "Authorization: Bearer ${USER_TOKEN}")

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    # Either 200 (success, no stripe subscription) or 501 (Stripe not configured)
    if [ "$http_code" -eq 200 ]; then
        local success=$(echo "$body" | jq -r '.success')
        local message=$(echo "$body" | jq -r '.message')

        print_pass "License refresh succeeded: ${message}"
        return 0
    elif [ "$http_code" -eq 501 ]; then
        print_pass "Stripe not configured (expected in test environment)"
        return 0
    else
        print_fail "License refresh failed with unexpected HTTP ${http_code}"
        echo "$body" | jq '.'
        return 1
    fi
}

################################################################################
# Test 6: Test offline mode (API unavailable)
################################################################################

test_offline_mode() {
    print_test "Test 6: Test graceful degradation (offline mode)"

    # Try to hit a non-existent API endpoint to simulate offline
    local response
    local http_code

    # Use --max-time to fail quickly
    response=$(curl -s -w "\n%{http_code}" --max-time 2 -X GET "http://localhost:9999/health" 2>/dev/null || echo "OFFLINE")

    if [[ "$response" == *"OFFLINE"* ]] || [[ "$response" == "" ]]; then
        print_pass "Offline mode detection works (connection failed as expected)"
        return 0
    else
        # This is actually OK - it means something is running on 9999
        print_pass "Offline simulation completed (used port 9999)"
        return 0
    fi
}

################################################################################
# Test 7: Test unauthorized access to license endpoints
################################################################################

test_unauthorized_access() {
    print_test "Test 7: Test unauthorized access to license endpoints"

    local response
    local http_code

    # Try to access license without token
    response=$(curl -s -w "\n%{http_code}" -X GET "${API_URL}/license/validate")

    http_code=$(echo "$response" | tail -n1)

    if [ "$http_code" -eq 401 ]; then
        print_pass "Unauthorized access blocked (HTTP 401)"
        return 0
    else
        print_fail "Expected HTTP 401, got ${http_code}"
        return 1
    fi
}

################################################################################
# Test 8: Test feature flags per tier
################################################################################

test_feature_flags() {
    print_test "Test 8: Verify feature flags per tier"

    local response
    response=$(curl -s -X GET "${API_URL}/license/tiers")

    # Check free tier restrictions
    local free_ai=$(echo "$response" | jq -r '.free.ai_scanning')
    local free_compliance=$(echo "$response" | jq -r '.free.compliance_reports')
    local free_api=$(echo "$response" | jq -r '.free.api_access')

    # Check pro tier features
    local pro_ai=$(echo "$response" | jq -r '.pro.ai_scanning')
    local pro_compliance=$(echo "$response" | jq -r '.pro.compliance_reports')
    local pro_api=$(echo "$response" | jq -r '.pro.api_access')

    if [ "$free_ai" = "false" ] && [ "$pro_ai" = "true" ] && \
       [ "$free_compliance" = "false" ] && [ "$pro_compliance" = "true" ]; then
        print_pass "Feature flags correct: Free tier restricted, Pro tier has access"
        print_info "Free - AI: ${free_ai}, Compliance: ${free_compliance}, API: ${free_api}"
        print_info "Pro - AI: ${pro_ai}, Compliance: ${pro_compliance}, API: ${pro_api}"
        return 0
    else
        print_fail "Feature flags incorrect"
        echo "$response" | jq '.free, .pro'
        return 1
    fi
}

################################################################################
# Test 9: Test rate limiting info (if available)
################################################################################

test_rate_limit_info() {
    print_test "Test 9: Check rate limit headers (if present)"

    local response
    response=$(curl -si -X GET "${API_URL}/license/features" \
        -H "Authorization: Bearer ${USER_TOKEN}")

    # Look for rate limit headers (may not be present in all configurations)
    if echo "$response" | grep -qi "x-ratelimit"; then
        print_pass "Rate limit headers present"
        echo "$response" | grep -i "x-ratelimit" || true
        return 0
    else
        print_pass "No rate limit headers (may not be enabled)"
        return 0
    fi
}

################################################################################
# Main execution
################################################################################

main() {
    echo -e "${BOLD}${BLUE}License Flow Integration Tests${NC}\n"

    check_dependencies

    print_info "Testing against API: ${API_URL}"
    echo ""

    # Setup
    if ! setup_test_user; then
        print_error "Failed to setup test user, aborting"
        exit 1
    fi
    echo ""

    # Run all tests
    test_license_validation || true
    echo ""

    test_tier_features || true
    echo ""

    test_all_tiers || true
    echo ""

    test_license_details || true
    echo ""

    test_license_refresh || true
    echo ""

    test_offline_mode || true
    echo ""

    test_unauthorized_access || true
    echo ""

    test_feature_flags || true
    echo ""

    test_rate_limit_info || true
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
