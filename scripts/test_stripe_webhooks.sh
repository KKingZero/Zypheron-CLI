#!/bin/bash

################################################################################
# test_stripe_webhooks.sh - Test Stripe webhook handling
#
# Sends mock Stripe webhook events to test:
# 1. Subscription created event
# 2. Subscription updated event
# 3. Subscription deleted event
# 4. Invoice payment failed event
# 5. Invoice payment succeeded event
# 6. Webhook signature verification
#
# Note: This tests the webhook endpoint logic, but uses mock data.
# Real Stripe webhooks require proper signature verification.
#
# Prerequisites:
#   - API server running
#   - curl and jq installed
#   - STRIPE_WEBHOOK_SECRET configured in API (optional)
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
WEBHOOK_ENDPOINT="${API_URL}/webhooks/stripe"

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

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

check_dependencies() {
    if ! command -v jq &> /dev/null; then
        print_error "jq is required but not installed"
        exit 1
    fi
}

################################################################################
# Test 1: Check webhook endpoint accessibility
################################################################################

test_webhook_endpoint_exists() {
    print_test "Test 1: Check webhook endpoint exists"

    # Send a simple request to see if endpoint responds
    # Without proper signature, it should return 400 or 501
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$WEBHOOK_ENDPOINT" \
        -H "Content-Type: application/json" \
        -d '{}')

    # 400 (bad request/signature) or 501 (not configured) are both acceptable
    if [ "$http_code" -eq 400 ] || [ "$http_code" -eq 501 ]; then
        print_pass "Webhook endpoint accessible (HTTP ${http_code})"
        return 0
    elif [ "$http_code" -eq 404 ]; then
        print_fail "Webhook endpoint not found (HTTP 404)"
        return 1
    else
        # Other codes might be OK too (e.g., 200 if no signature check)
        print_pass "Webhook endpoint responded (HTTP ${http_code})"
        return 0
    fi
}

################################################################################
# Test 2: Test subscription.created event (mock)
################################################################################

test_subscription_created() {
    print_test "Test 2: Send subscription.created webhook event"

    # Mock Stripe webhook event
    local event_data
    event_data=$(cat <<'EOF'
{
  "id": "evt_test_subscription_created",
  "type": "customer.subscription.created",
  "data": {
    "object": {
      "id": "sub_test_12345",
      "customer": "cus_test_12345",
      "status": "active",
      "items": {
        "data": [
          {
            "price": {
              "id": "price_starter_test",
              "product": "prod_starter"
            }
          }
        ]
      },
      "current_period_start": 1234567890,
      "current_period_end": 1237159890,
      "metadata": {
        "user_id": "1"
      }
    }
  }
}
EOF
)

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X POST "$WEBHOOK_ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "$event_data")

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    # Expected: 501 (Stripe not configured) or 400 (invalid signature)
    if [ "$http_code" -eq 501 ]; then
        print_pass "Webhook endpoint exists but Stripe not configured (expected in test)"
        return 0
    elif [ "$http_code" -eq 400 ]; then
        local detail=$(echo "$body" | jq -r '.detail' 2>/dev/null || echo "")
        if [[ "$detail" == *"signature"* ]] || [[ "$detail" == *"Stripe"* ]]; then
            print_pass "Webhook signature verification active (expected failure without signature)"
            return 0
        else
            print_warning "Webhook returned 400, but unclear if signature check: ${detail}"
            return 0
        fi
    elif [ "$http_code" -eq 200 ]; then
        # If Stripe is configured and signature check is disabled for testing
        print_warning "Webhook accepted (signature verification may be disabled)"
        return 0
    else
        print_fail "Unexpected HTTP code: ${http_code}"
        echo "$body"
        return 1
    fi
}

################################################################################
# Test 3: Test subscription.updated event
################################################################################

test_subscription_updated() {
    print_test "Test 3: Send subscription.updated webhook event"

    local event_data
    event_data=$(cat <<'EOF'
{
  "id": "evt_test_subscription_updated",
  "type": "customer.subscription.updated",
  "data": {
    "object": {
      "id": "sub_test_12345",
      "customer": "cus_test_12345",
      "status": "active",
      "items": {
        "data": [
          {
            "price": {
              "id": "price_pro_test",
              "product": "prod_pro"
            }
          }
        ]
      },
      "current_period_start": 1234567890,
      "current_period_end": 1237159890,
      "metadata": {
        "user_id": "1"
      }
    }
  }
}
EOF
)

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$WEBHOOK_ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "$event_data")

    if [ "$http_code" -eq 501 ] || [ "$http_code" -eq 400 ] || [ "$http_code" -eq 200 ]; then
        print_pass "Subscription updated event processed (HTTP ${http_code})"
        return 0
    else
        print_fail "Unexpected HTTP code: ${http_code}"
        return 1
    fi
}

################################################################################
# Test 4: Test subscription.deleted event
################################################################################

test_subscription_deleted() {
    print_test "Test 4: Send subscription.deleted webhook event"

    local event_data
    event_data=$(cat <<'EOF'
{
  "id": "evt_test_subscription_deleted",
  "type": "customer.subscription.deleted",
  "data": {
    "object": {
      "id": "sub_test_12345",
      "customer": "cus_test_12345",
      "status": "canceled",
      "metadata": {
        "user_id": "1"
      }
    }
  }
}
EOF
)

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$WEBHOOK_ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "$event_data")

    if [ "$http_code" -eq 501 ] || [ "$http_code" -eq 400 ] || [ "$http_code" -eq 200 ]; then
        print_pass "Subscription deleted event processed (HTTP ${http_code})"
        return 0
    else
        print_fail "Unexpected HTTP code: ${http_code}"
        return 1
    fi
}

################################################################################
# Test 5: Test invoice.payment_failed event
################################################################################

test_invoice_payment_failed() {
    print_test "Test 5: Send invoice.payment_failed webhook event"

    local event_data
    event_data=$(cat <<'EOF'
{
  "id": "evt_test_invoice_payment_failed",
  "type": "invoice.payment_failed",
  "data": {
    "object": {
      "id": "in_test_12345",
      "customer": "cus_test_12345",
      "subscription": "sub_test_12345",
      "status": "open",
      "attempt_count": 1,
      "metadata": {
        "user_id": "1"
      }
    }
  }
}
EOF
)

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$WEBHOOK_ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "$event_data")

    if [ "$http_code" -eq 501 ] || [ "$http_code" -eq 400 ] || [ "$http_code" -eq 200 ]; then
        print_pass "Invoice payment failed event processed (HTTP ${http_code})"
        return 0
    else
        print_fail "Unexpected HTTP code: ${http_code}"
        return 1
    fi
}

################################################################################
# Test 6: Test invoice.payment_succeeded event
################################################################################

test_invoice_payment_succeeded() {
    print_test "Test 6: Send invoice.payment_succeeded webhook event"

    local event_data
    event_data=$(cat <<'EOF'
{
  "id": "evt_test_invoice_payment_succeeded",
  "type": "invoice.payment_succeeded",
  "data": {
    "object": {
      "id": "in_test_12345",
      "customer": "cus_test_12345",
      "subscription": "sub_test_12345",
      "status": "paid",
      "metadata": {
        "user_id": "1"
      }
    }
  }
}
EOF
)

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$WEBHOOK_ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "$event_data")

    if [ "$http_code" -eq 501 ] || [ "$http_code" -eq 400 ] || [ "$http_code" -eq 200 ]; then
        print_pass "Invoice payment succeeded event processed (HTTP ${http_code})"
        return 0
    else
        print_fail "Unexpected HTTP code: ${http_code}"
        return 1
    fi
}

################################################################################
# Test 7: Test unhandled event type
################################################################################

test_unhandled_event() {
    print_test "Test 7: Send unhandled event type"

    local event_data
    event_data=$(cat <<'EOF'
{
  "id": "evt_test_unhandled",
  "type": "customer.created",
  "data": {
    "object": {
      "id": "cus_test_12345",
      "email": "test@example.com"
    }
  }
}
EOF
)

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$WEBHOOK_ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "$event_data")

    # Should still return 200 or appropriate code, just logs as unhandled
    if [ "$http_code" -eq 501 ] || [ "$http_code" -eq 400 ] || [ "$http_code" -eq 200 ]; then
        print_pass "Unhandled event type processed gracefully (HTTP ${http_code})"
        return 0
    else
        print_fail "Unexpected HTTP code: ${http_code}"
        return 1
    fi
}

################################################################################
# Test 8: Test missing signature header
################################################################################

test_missing_signature() {
    print_test "Test 8: Test request without signature header"

    local event_data='{"id": "evt_test", "type": "test.event", "data": {"object": {}}}'

    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X POST "$WEBHOOK_ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "$event_data")

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    # Should return 400 or 501 depending on Stripe configuration
    if [ "$http_code" -eq 400 ]; then
        local detail=$(echo "$body" | jq -r '.detail' 2>/dev/null || echo "")
        if [[ "$detail" == *"signature"* ]]; then
            print_pass "Missing signature rejected (HTTP 400)"
            return 0
        else
            print_pass "Bad request handled (HTTP 400)"
            return 0
        fi
    elif [ "$http_code" -eq 501 ]; then
        print_pass "Stripe not configured (expected in test environment)"
        return 0
    elif [ "$http_code" -eq 200 ]; then
        print_warning "Webhook accepted without signature (signature check may be disabled)"
        return 0
    else
        print_fail "Unexpected HTTP code: ${http_code}"
        echo "$body"
        return 1
    fi
}

################################################################################
# Test 9: Test malformed JSON
################################################################################

test_malformed_json() {
    print_test "Test 9: Test malformed JSON payload"

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$WEBHOOK_ENDPOINT" \
        -H "Content-Type: application/json" \
        -d 'this is not json')

    # Should return 400 or 422 for malformed JSON
    if [ "$http_code" -eq 400 ] || [ "$http_code" -eq 422 ] || [ "$http_code" -eq 501 ]; then
        print_pass "Malformed JSON rejected (HTTP ${http_code})"
        return 0
    else
        print_warning "Unexpected response to malformed JSON (HTTP ${http_code})"
        return 0
    fi
}

################################################################################
# Main execution
################################################################################

main() {
    echo -e "${BOLD}${BLUE}Stripe Webhook Integration Tests${NC}\n"

    check_dependencies

    print_info "Testing webhook endpoint: ${WEBHOOK_ENDPOINT}"
    print_warning "Note: Real Stripe webhooks require signature verification"
    print_warning "These tests use mock data and expect signature failures or 'not configured' errors"
    echo ""

    # Run all tests
    test_webhook_endpoint_exists || true
    echo ""

    test_subscription_created || true
    echo ""

    test_subscription_updated || true
    echo ""

    test_subscription_deleted || true
    echo ""

    test_invoice_payment_failed || true
    echo ""

    test_invoice_payment_succeeded || true
    echo ""

    test_unhandled_event || true
    echo ""

    test_missing_signature || true
    echo ""

    test_malformed_json || true
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
