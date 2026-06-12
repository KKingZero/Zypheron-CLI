#!/bin/bash

################################################################################
# run_all_tests.sh - Master test runner for entire Zypheron project
#
# Runs comprehensive test suite including:
# 1. Python unit tests (pytest) for API
# 2. Python unit tests (pytest) for AI runtime
# 3. Go unit tests (go test) for CLI
# 4. Integration tests (auth, license, webhooks, compliance)
# 4. Code coverage reporting
# 5. Summary output with detailed results
#
# This is the main entry point for CI/CD and local testing.
#
# Usage:
#   ./scripts/run_all_tests.sh [OPTIONS]
#
# Options:
#   --skip-unit          Skip unit tests (Python and Go)
#   --skip-integration   Skip integration tests
#   --skip-coverage      Skip coverage report generation
#   --fast               Skip coverage and verbose output
#   --ci                 CI mode (exit on first failure, no color)
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more test suites failed
################################################################################

set -euo pipefail

# Color codes (disabled in CI mode)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

# Project paths
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_DIR="${PROJECT_ROOT}/zypheron-api"
AI_DIR="${PROJECT_ROOT}/zypheron-ai"
CLI_DIR="${PROJECT_ROOT}/zypheron-go"
SCRIPTS_DIR="${PROJECT_ROOT}/scripts"

# Test options
SKIP_UNIT=false
SKIP_INTEGRATION=false
SKIP_COVERAGE=false
CI_MODE=false
FAST_MODE=false

# Results tracking
declare -a TEST_SUITES
declare -a TEST_RESULTS
declare -a TEST_DURATIONS
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

################################################################################
# Utility functions
################################################################################

print_header() {
    if [ "$CI_MODE" = false ]; then
        echo -e "\n${BOLD}${MAGENTA}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BOLD}${MAGENTA}║  $1${NC}"
        echo -e "${BOLD}${MAGENTA}╚═══════════════════════════════════════════════════════════════╝${NC}\n"
    else
        echo ""
        echo "================================================================================"
        echo "  $1"
        echo "================================================================================"
        echo ""
    fi
}

print_section() {
    if [ "$CI_MODE" = false ]; then
        echo -e "\n${BOLD}${BLUE}▶ $1${NC}\n"
    else
        echo ""
        echo ">>> $1"
        echo ""
    fi
}

print_info() {
    if [ "$CI_MODE" = false ]; then
        echo -e "${CYAN}[INFO]${NC} $1"
    else
        echo "[INFO] $1"
    fi
}

print_success() {
    if [ "$CI_MODE" = false ]; then
        echo -e "${GREEN}[SUCCESS]${NC} $1"
    else
        echo "[SUCCESS] $1"
    fi
}

print_warning() {
    if [ "$CI_MODE" = false ]; then
        echo -e "${YELLOW}[WARNING]${NC} $1"
    else
        echo "[WARNING] $1"
    fi
}

print_error() {
    if [ "$CI_MODE" = false ]; then
        echo -e "${RED}[ERROR]${NC} $1"
    else
        echo "[ERROR] $1"
    fi
}

################################################################################
# Parse command line arguments
################################################################################

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-unit)
                SKIP_UNIT=true
                shift
                ;;
            --skip-integration)
                SKIP_INTEGRATION=true
                shift
                ;;
            --skip-coverage)
                SKIP_COVERAGE=true
                shift
                ;;
            --fast)
                FAST_MODE=true
                SKIP_COVERAGE=true
                shift
                ;;
            --ci)
                CI_MODE=true
                # Disable colors in CI mode
                RED=''
                GREEN=''
                YELLOW=''
                BLUE=''
                CYAN=''
                MAGENTA=''
                NC=''
                BOLD=''
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
}

################################################################################
# Record test suite results
################################################################################

record_test_result() {
    local suite_name="$1"
    local exit_code="$2"
    local duration="$3"

    TEST_SUITES+=("$suite_name")
    TEST_RESULTS+=("$exit_code")
    TEST_DURATIONS+=("$duration")

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ "$exit_code" -eq 0 ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))

        # In CI mode, fail fast
        if [ "$CI_MODE" = true ]; then
            print_error "Test suite failed: ${suite_name}"
            print_error "Failing fast in CI mode"
            exit 1
        fi
    fi
}

################################################################################
# Python unit tests (API)
################################################################################

setup_args() {
    if [ "$CI_MODE" = true ]; then
        echo "--allow-online"
    fi
}

run_api_python_tests() {
    print_section "Running Python Unit Tests (API)"

    if [ ! -d "$API_DIR" ]; then
        print_warning "API directory not found: ${API_DIR}"
        record_test_result "Python Tests" 1 "0s"
        return 1
    fi

    cd "$API_DIR"

    # Check for virtual environment
    if [ ! -d ".venv" ]; then
        print_warning "Virtual environment not found in ${API_DIR}/.venv"
        print_info "Attempting locked test environment setup..."
        if ! "${SCRIPTS_DIR}/setup_api_test_env.sh" $(setup_args); then
            print_error "Offline setup failed. Provide zypheron-api/wheelhouse or run ${SCRIPTS_DIR}/setup_api_test_env.sh --allow-online"
            record_test_result "Python Tests" 1 "0s"
            return 1
        fi
    fi

    source .venv/bin/activate

    # Check if pytest is installed
    if ! python -m pytest --version &> /dev/null; then
        print_warning "pytest not installed in the API virtualenv"
        print_info "Rebuilding test environment from requirements.lock..."
        if ! "${SCRIPTS_DIR}/setup_api_test_env.sh" $(setup_args); then
            print_error "Failed to provision locked API test environment"
            record_test_result "Python Tests" 1 "0s"
            return 1
        fi
        source .venv/bin/activate
    fi
    export ENVIRONMENT="${ENVIRONMENT:-development}"
    export DATABASE_TYPE="${DATABASE_TYPE:-sqlite}"
    export DATABASE_URL="${DATABASE_URL:-sqlite+aiosqlite:///./zypheron_test.db}"
    export REDIS_ENABLED="${REDIS_ENABLED:-false}"
    export ENABLE_RATE_LIMITING="${ENABLE_RATE_LIMITING:-false}"
    export JWT_SECRET_KEY="${JWT_SECRET_KEY:-test-secret-key-for-ci-tests-only-32chars-minimum}"

    # Run tests
    local start_time=$(date +%s)
    local pytest_args="-v"
    local api_test_scope="${API_TEST_SCOPE:-oss-rc}"
    local api_test_targets="tests/"

    if [ "$api_test_scope" = "oss-rc" ]; then
        api_test_targets="tests/test_ai_providers.py tests/test_cache.py tests/test_load_balancer.py tests/test_ollama_provider.py tests/test_security_remediation.py tests/test_token_reservation_race_condition.py tests/test_token_tracking.py"
    elif [ "$api_test_scope" != "full" ]; then
        print_error "Unknown API_TEST_SCOPE=${api_test_scope}; expected oss-rc or full"
        record_test_result "API Python Tests" 1 "0s"
        cd "$PROJECT_ROOT"
        return 1
    fi

    print_info "API test scope: ${api_test_scope}"

    if [ "$SKIP_COVERAGE" = false ] && [ "$FAST_MODE" = false ]; then
        pytest_args="${pytest_args} --cov=app --cov-report=term --cov-report=html:htmlcov"
    fi

    set +e
    python -m pytest $pytest_args $api_test_targets
    local exit_code=$?
    set -e

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    if [ "$exit_code" -eq 0 ]; then
        print_success "API Python tests passed (${duration}s)"
    else
        print_error "API Python tests failed (${duration}s)"
    fi

    if [ "$SKIP_COVERAGE" = false ] && [ "$FAST_MODE" = false ]; then
        print_info "Coverage report: ${API_DIR}/htmlcov/index.html"
    fi

    record_test_result "API Python Tests" "$exit_code" "${duration}s"
    cd "$PROJECT_ROOT"
    return "$exit_code"
}

################################################################################
# Python unit tests (AI)
################################################################################

run_ai_python_tests() {
    print_section "Running Python Unit Tests (AI Runtime)"

    if [ ! -d "$AI_DIR" ]; then
        print_warning "AI directory not found: ${AI_DIR}"
        record_test_result "AI Python Tests" 1 "0s"
        return 1
    fi

    cd "$AI_DIR"

    if [ ! -d ".venv" ]; then
        print_warning "Virtual environment not found in ${AI_DIR}/.venv"
        print_info "Attempting locked AI test environment setup..."
        if ! "${SCRIPTS_DIR}/setup_ai_test_env.sh" $(setup_args); then
            print_error "Offline setup failed. Provide zypheron-ai/wheelhouse or run ${SCRIPTS_DIR}/setup_ai_test_env.sh --allow-online"
            record_test_result "AI Python Tests" 1 "0s"
            return 1
        fi
    fi

    source .venv/bin/activate

    if ! python -m pytest --version &> /dev/null; then
        print_warning "pytest not installed in the AI virtualenv"
        print_info "Rebuilding AI test environment from requirements.lock..."
        if ! "${SCRIPTS_DIR}/setup_ai_test_env.sh" $(setup_args); then
            print_error "Failed to provision locked AI test environment"
            record_test_result "AI Python Tests" 1 "0s"
            return 1
        fi
        source .venv/bin/activate
    fi

    export ZYPHERON_STATE_DIR="${ZYPHERON_STATE_DIR:-${AI_DIR}/.pytest-state}"

    local start_time=$(date +%s)
    local pytest_args="-v"

    if [ "$SKIP_COVERAGE" = false ] && [ "$FAST_MODE" = false ]; then
        pytest_args="${pytest_args} --cov=core --cov=providers --cov=analysis --cov=ml --cov=agents --cov-report=term --cov-report=html:htmlcov"
    fi

    set +e
    python -m pytest $pytest_args tests/
    local exit_code=$?
    set -e

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    if [ "$exit_code" -eq 0 ]; then
        print_success "AI Python tests passed (${duration}s)"
    else
        print_error "AI Python tests failed (${duration}s)"
    fi

    if [ "$SKIP_COVERAGE" = false ] && [ "$FAST_MODE" = false ]; then
        print_info "Coverage report: ${AI_DIR}/htmlcov/index.html"
    fi

    record_test_result "AI Python Tests" "$exit_code" "${duration}s"
    cd "$PROJECT_ROOT"
    return "$exit_code"
}

################################################################################
# Go unit tests (CLI)
################################################################################

run_go_tests() {
    print_section "Running Go Unit Tests (CLI)"

    if [ ! -d "$CLI_DIR" ]; then
        print_warning "CLI directory not found: ${CLI_DIR}"
        record_test_result "Go Tests" 1 "0s"
        return 1
    fi

    cd "$CLI_DIR"

    # Check if go.mod exists
    if [ ! -f "go.mod" ]; then
        print_error "go.mod not found in ${CLI_DIR}"
        record_test_result "Go Tests" 1 "0s"
        return 1
    fi

    # Run tests
    local start_time=$(date +%s)
    local go_tmp="${CLI_DIR}/.gotmp"
    local go_cache="${CLI_DIR}/.gocache"
    local ccache_dir="${CLI_DIR}/.ccache"
    mkdir -p "$go_tmp"
    mkdir -p "$go_cache"
    mkdir -p "$ccache_dir"
    export GOTMPDIR="$go_tmp"
    export GOCACHE="$go_cache"
    export CCACHE_DIR="$ccache_dir"

    local go_test_args="-v ./..."

    if [ "$SKIP_COVERAGE" = false ] && [ "$FAST_MODE" = false ]; then
        go_test_args="-v -coverprofile=coverage.out -covermode=atomic ./..."
    fi

    set +e
    go test $go_test_args
    local exit_code=$?
    set -e

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    if [ "$exit_code" -eq 0 ]; then
        print_success "Go tests passed (${duration}s)"

        if [ "$SKIP_COVERAGE" = false ] && [ "$FAST_MODE" = false ] && [ -f "coverage.out" ]; then
            # Generate HTML coverage report
            go tool cover -html=coverage.out -o coverage.html
            print_info "Coverage report: ${CLI_DIR}/coverage.html"

            # Show coverage summary
            go tool cover -func=coverage.out | tail -n 1
        fi
    else
        print_error "Go tests failed (${duration}s)"
    fi

    record_test_result "Go Tests" "$exit_code" "${duration}s"
    cd "$PROJECT_ROOT"
    return "$exit_code"
}

################################################################################
# Integration tests
################################################################################

run_integration_tests() {
    print_section "Running Integration Tests"

    # Check if test_integration.sh exists
    if [ ! -f "${SCRIPTS_DIR}/test_integration.sh" ]; then
        print_error "Integration test script not found: ${SCRIPTS_DIR}/test_integration.sh"
        record_test_result "Integration Tests" 1 "0s"
        return 1
    fi

    chmod +x "${SCRIPTS_DIR}/test_integration.sh"

    # Run integration tests
    local start_time=$(date +%s)

    set +e
    "${SCRIPTS_DIR}/test_integration.sh"
    local exit_code=$?
    set -e

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    if [ "$exit_code" -eq 0 ]; then
        print_success "Integration tests passed (${duration}s)"
    else
        print_error "Integration tests failed (${duration}s)"
    fi

    record_test_result "Integration Tests" "$exit_code" "${duration}s"
    return "$exit_code"
}

################################################################################
# Generate final report
################################################################################

generate_report() {
    print_header "TEST SUMMARY"

    echo -e "${BOLD}Total Test Suites:${NC} ${TOTAL_TESTS}"
    echo -e "${GREEN}${BOLD}Passed:${NC} ${PASSED_TESTS}"
    echo -e "${RED}${BOLD}Failed:${NC} ${FAILED_TESTS}"
    echo ""

    echo -e "${BOLD}Detailed Results:${NC}"
    for i in "${!TEST_SUITES[@]}"; do
        local suite="${TEST_SUITES[$i]}"
        local result="${TEST_RESULTS[$i]}"
        local duration="${TEST_DURATIONS[$i]}"

        if [ "$result" -eq 0 ]; then
            echo -e "  ${GREEN}✓${NC} ${suite} ${GREEN}PASSED${NC} (${duration})"
        else
            echo -e "  ${RED}✗${NC} ${suite} ${RED}FAILED${NC} (${duration})"
        fi
    done

    echo ""

    # Summary files
    if [ "$SKIP_COVERAGE" = false ] && [ "$FAST_MODE" = false ]; then
        echo -e "${BOLD}Coverage Reports:${NC}"
        if [ -f "${API_DIR}/htmlcov/index.html" ]; then
            echo -e "  ${CYAN}Python:${NC} ${API_DIR}/htmlcov/index.html"
        fi
        if [ -f "${CLI_DIR}/coverage.html" ]; then
            echo -e "  ${CYAN}Go:${NC} ${CLI_DIR}/coverage.html"
        fi
        echo ""
    fi

    # Final verdict
    if [ "$FAILED_TESTS" -eq 0 ]; then
        echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}${BOLD}║                                                               ║${NC}"
        echo -e "${GREEN}${BOLD}║  🎉 ALL TESTS PASSED! 🎉                                     ║${NC}"
        echo -e "${GREEN}${BOLD}║                                                               ║${NC}"
        echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
        return 0
    else
        echo -e "${RED}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}${BOLD}║                                                               ║${NC}"
        echo -e "${RED}${BOLD}║  ❌ SOME TESTS FAILED                                         ║${NC}"
        echo -e "${RED}${BOLD}║                                                               ║${NC}"
        echo -e "${RED}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
        return 1
    fi
}

################################################################################
# Main execution
################################################################################

main() {
    parse_args "$@"

    print_header "ZYPHERON COMPREHENSIVE TEST SUITE"

    print_info "Project root: ${PROJECT_ROOT}"
    print_info "API directory: ${API_DIR}"
    print_info "AI directory: ${AI_DIR}"
    print_info "CLI directory: ${CLI_DIR}"
    echo ""

    # Display test configuration
    print_info "Test Configuration:"
    print_info "  Unit Tests: $([ "$SKIP_UNIT" = true ] && echo "SKIP" || echo "RUN")"
    print_info "  Integration Tests: $([ "$SKIP_INTEGRATION" = true ] && echo "SKIP" || echo "RUN")"
    print_info "  Coverage Reports: $([ "$SKIP_COVERAGE" = true ] && echo "SKIP" || echo "GENERATE")"
    print_info "  CI Mode: $([ "$CI_MODE" = true ] && echo "YES" || echo "NO")"
    echo ""

    # Record start time
    local overall_start=$(date +%s)

    # Run test suites
    if [ "$SKIP_UNIT" = false ]; then
        run_api_python_tests || true
        echo ""
        run_ai_python_tests || true
        echo ""
        run_go_tests || true
        echo ""
    else
        print_warning "Skipping unit tests (--skip-unit flag)"
        echo ""
    fi

    if [ "$SKIP_INTEGRATION" = false ]; then
        if [ "$CI_MODE" = true ]; then
            export ZYPHERON_ALLOW_ONLINE_SETUP=true
        fi
        run_integration_tests || true
        echo ""
    else
        print_warning "Skipping integration tests (--skip-integration flag)"
        echo ""
    fi

    # Calculate total time
    local overall_end=$(date +%s)
    local total_duration=$((overall_end - overall_start))
    print_info "Total test time: ${total_duration}s"
    echo ""

    # Generate final report
    if generate_report; then
        exit 0
    else
        exit 1
    fi
}

main "$@"
