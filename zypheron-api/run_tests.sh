#!/bin/bash
# Zypheron API Test Runner
# Quick script to run tests with common configurations

set -e

echo "🧪 Zypheron API Test Suite"
echo "=========================="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if virtual environment is activated
if [ -z "$VIRTUAL_ENV" ]; then
    echo -e "${YELLOW}⚠️  Warning: No virtual environment detected${NC}"
    echo "Consider activating venv first: source .venv/bin/activate"
    echo ""
fi

# Parse command line arguments
MODE="${1:-all}"

case $MODE in
    "all"|"")
        echo -e "${BLUE}Running all tests...${NC}"
        pytest -v
        ;;
    "fast")
        echo -e "${BLUE}Running tests (fast mode, no coverage)...${NC}"
        pytest -v -x
        ;;
    "coverage")
        echo -e "${BLUE}Running tests with coverage report...${NC}"
        pytest --cov=app --cov-report=html --cov-report=term-missing --cov-fail-under=70
        echo ""
        echo -e "${GREEN}✅ Coverage report generated: htmlcov/index.html${NC}"
        ;;
    "device")
        echo -e "${BLUE}Running device authentication tests...${NC}"
        pytest tests/test_device_auth.py -v
        ;;
    "stripe")
        echo -e "${BLUE}Running Stripe webhook tests...${NC}"
        pytest tests/test_stripe_webhooks.py -v
        ;;
    "license")
        echo -e "${BLUE}Running license management tests...${NC}"
        pytest tests/test_license.py -v
        ;;
    "auth")
        echo -e "${BLUE}Running authentication tests...${NC}"
        pytest tests/test_auth.py -v
        ;;
    "compliance")
        echo -e "${BLUE}Running compliance tests (includes skipped)...${NC}"
        pytest tests/test_compliance.py -v
        ;;
    "count")
        echo -e "${BLUE}Test count by file:${NC}"
        echo ""
        for file in tests/test_*.py; do
            count=$(grep -c "async def test_" "$file" || echo "0")
            echo "  $(basename $file): $count tests"
        done
        echo ""
        total=$(find tests -name "test_*.py" -exec grep -h "async def test_" {} \; | wc -l)
        echo -e "${GREEN}Total: $total tests${NC}"
        ;;
    "watch")
        echo -e "${BLUE}Running tests in watch mode...${NC}"
        if ! command -v pytest-watch &> /dev/null; then
            echo "Installing pytest-watch..."
            pip install pytest-watch
        fi
        ptw -- -v
        ;;
    "parallel")
        echo -e "${BLUE}Running tests in parallel...${NC}"
        if ! command -v pytest-xdist &> /dev/null; then
            echo "Installing pytest-xdist..."
            pip install pytest-xdist
        fi
        pytest -n auto -v
        ;;
    "help"|"-h"|"--help")
        echo "Usage: ./run_tests.sh [MODE]"
        echo ""
        echo "Modes:"
        echo "  all         - Run all tests (default)"
        echo "  fast        - Run tests without coverage, stop on first failure"
        echo "  coverage    - Run tests with coverage report"
        echo "  device      - Run device authentication tests only"
        echo "  stripe      - Run Stripe webhook tests only"
        echo "  license     - Run license management tests only"
        echo "  auth        - Run authentication tests only"
        echo "  compliance  - Run compliance tests (includes skipped)"
        echo "  count       - Count tests by file"
        echo "  watch       - Run tests in watch mode (auto-rerun on changes)"
        echo "  parallel    - Run tests in parallel (faster)"
        echo "  help        - Show this help message"
        echo ""
        echo "Examples:"
        echo "  ./run_tests.sh                 # Run all tests"
        echo "  ./run_tests.sh coverage        # Run with coverage"
        echo "  ./run_tests.sh device          # Run device auth tests"
        echo "  ./run_tests.sh parallel        # Run tests in parallel"
        ;;
    *)
        echo -e "${YELLOW}Unknown mode: $MODE${NC}"
        echo "Run './run_tests.sh help' for usage information"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}✅ Done!${NC}"
