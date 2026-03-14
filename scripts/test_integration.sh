#!/bin/bash

################################################################################
# test_integration.sh - Master integration test script for Zypheron
#
# This script orchestrates all integration tests by:
# - Starting the API server in the background
# - Running all test suites sequentially
# - Cleaning up processes on exit
# - Reporting comprehensive pass/fail status
#
# Usage:
#   ./scripts/test_integration.sh [--skip-api]
#
# Options:
#   --skip-api    Skip starting the API server (use if already running)
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed
################################################################################

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Project paths - using absolute paths for reliability
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_DIR="${PROJECT_ROOT}/zypheron-api"
CLI_DIR="${PROJECT_ROOT}/zypheron-go"
SCRIPTS_DIR="${PROJECT_ROOT}/scripts"

# API server configuration
API_PID=""
API_HOST="localhost"
API_PORT="8000"
API_URL="http://${API_HOST}:${API_PORT}"
SKIP_API_START=false

# Test results tracking
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
declare -a FAILED_TESTS

################################################################################
# Utility functions
################################################################################

print_header() {
    echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}\n"
}

print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_test_result() {
    local test_name="$1"
    local exit_code="$2"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [ "$exit_code" -eq 0 ]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "${GREEN}✓${NC} ${test_name} ${GREEN}PASSED${NC}"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        FAILED_TESTS+=("${test_name}")
        echo -e "${RED}✗${NC} ${test_name} ${RED}FAILED${NC}"
    fi
}

################################################################################
# Cleanup handler - ensures API server is stopped on exit
################################################################################

cleanup() {
    local exit_code=$?

    if [ "$SKIP_API_START" = false ] && [ -n "$API_PID" ]; then
        print_info "Stopping API server (PID: ${API_PID})..."
        kill "$API_PID" 2>/dev/null || true
        wait "$API_PID" 2>/dev/null || true
        print_success "API server stopped"
    fi

    # Print final summary
    print_header "INTEGRATION TEST SUMMARY"

    echo -e "${BOLD}Tests Run:${NC}    ${TESTS_RUN}"
    echo -e "${GREEN}${BOLD}Tests Passed:${NC} ${TESTS_PASSED}"

    if [ "$TESTS_FAILED" -gt 0 ]; then
        echo -e "${RED}${BOLD}Tests Failed:${NC} ${TESTS_FAILED}"
        echo -e "\n${RED}Failed tests:${NC}"
        for test in "${FAILED_TESTS[@]}"; do
            echo -e "  ${RED}✗${NC} ${test}"
        done
        echo ""
        exit 1
    else
        echo -e "\n${GREEN}${BOLD}🎉 All integration tests passed!${NC}\n"
        exit 0
    fi
}

trap cleanup EXIT INT TERM

################################################################################
# Parse command line arguments
################################################################################

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-api)
            SKIP_API_START=true
            shift
            ;;
        -h|--help)
            grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

################################################################################
# Start API server
################################################################################

start_api_server() {
    print_info "Starting API server at ${API_URL}..."

    # Check if API directory exists
    if [ ! -d "$API_DIR" ]; then
        print_error "API directory not found: ${API_DIR}"
        exit 1
    fi

    cd "$API_DIR"

    # Check if virtual environment exists
    if [ ! -d ".venv" ]; then
        print_error "Virtual environment not found in ${API_DIR}/.venv"
        print_info "Run: cd ${API_DIR} && python -m venv .venv && source .venv/bin/activate && pip install -e ."
        exit 1
    fi

    # Start API server in background
    source .venv/bin/activate
    python -m uvicorn app.main:app --host "$API_HOST" --port "$API_PORT" --log-level warning > /tmp/zypheron-api-test.log 2>&1 &
    API_PID=$!

    print_info "API server started with PID: ${API_PID}"
    print_info "API logs: /tmp/zypheron-api-test.log"

    # Wait for API to be ready
    print_info "Waiting for API to be ready..."
    local retries=30
    local count=0

    while [ $count -lt $retries ]; do
        if curl -s "${API_URL}/health" > /dev/null 2>&1; then
            print_success "API server is ready"
            return 0
        fi

        # Check if process is still running
        if ! kill -0 "$API_PID" 2>/dev/null; then
            print_error "API server process died"
            print_error "Check logs at: /tmp/zypheron-api-test.log"
            cat /tmp/zypheron-api-test.log
            exit 1
        fi

        count=$((count + 1))
        sleep 1
    done

    print_error "API server failed to start within 30 seconds"
    print_error "Check logs at: /tmp/zypheron-api-test.log"
    cat /tmp/zypheron-api-test.log
    exit 1
}

################################################################################
# Run test suites
################################################################################

run_test_suite() {
    local test_name="$1"
    local test_script="$2"

    print_header "Running: ${test_name}"

    if [ ! -f "$test_script" ]; then
        print_error "Test script not found: ${test_script}"
        print_test_result "$test_name" 1
        return 1
    fi

    # Make script executable
    chmod +x "$test_script"

    # Run test script and capture exit code
    set +e
    "$test_script"
    local exit_code=$?
    set -e

    print_test_result "$test_name" "$exit_code"
    return "$exit_code"
}

################################################################################
# Main execution
################################################################################

main() {
    print_header "ZYPHERON INTEGRATION TEST SUITE"

    print_info "Project root: ${PROJECT_ROOT}"
    print_info "API directory: ${API_DIR}"
    print_info "CLI directory: ${CLI_DIR}"
    print_info "Scripts directory: ${SCRIPTS_DIR}"

    # Start API server unless skipped
    if [ "$SKIP_API_START" = false ]; then
        start_api_server
    else
        print_warning "Skipping API server startup (--skip-api flag)"
        print_info "Assuming API is already running at ${API_URL}"

        # Verify API is accessible
        if ! curl -s "${API_URL}/health" > /dev/null 2>&1; then
            print_error "API server is not accessible at ${API_URL}"
            print_error "Either start the API or remove --skip-api flag"
            exit 1
        fi
        print_success "API server is accessible"
    fi

    # Export API URL for test scripts
    export ZYPHERON_API_URL="$API_URL"

    # Run all test suites
    echo ""
    run_test_suite "Authentication Flow Tests" "${SCRIPTS_DIR}/test_auth_flow.sh" || true

    echo ""
    run_test_suite "License Flow Tests" "${SCRIPTS_DIR}/test_license_flow.sh" || true

    echo ""
    run_test_suite "Stripe Webhook Tests" "${SCRIPTS_DIR}/test_stripe_webhooks.sh" || true

    echo ""
    run_test_suite "Compliance Tests" "${SCRIPTS_DIR}/test_compliance.sh" || true

    # Final summary is printed by cleanup() trap
}

# Run main function
main
