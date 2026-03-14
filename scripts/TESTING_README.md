# Zypheron Integration Test Suite

Comprehensive end-to-end integration testing for the Zypheron API and CLI.

## Overview

This test suite validates the complete Zypheron platform including:

- **Authentication Flow**: Device code OAuth 2.0, token polling, session management
- **License Management**: Tier validation, feature flags, Stripe integration
- **Webhook Processing**: Stripe subscription lifecycle events
- **Compliance Framework**: SOC2, PCI-DSS control loading and reporting
- **Unit Tests**: Python (API) and Go (CLI) test coverage

## Quick Start

```bash
# Run all tests (unit + integration)
./scripts/run_all_tests.sh

# Run only integration tests
./scripts/test_integration.sh

# Run specific test suite
./scripts/test_auth_flow.sh
./scripts/test_license_flow.sh
./scripts/test_stripe_webhooks.sh
./scripts/test_compliance.sh
```

## Prerequisites

### Required Tools

```bash
# Ubuntu/Debian
sudo apt install curl jq

# macOS
brew install curl jq
```

### API Setup

The API server must be running for integration tests:

```bash
cd zypheron-api
python -m venv .venv
source .venv/bin/activate
pip install -e .
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Or let the test scripts start it automatically (see `test_integration.sh`).

### Environment Variables

```bash
# Optional: Override API URL
export ZYPHERON_API_URL="http://localhost:8000"

# Optional: Specify CLI binary location
export ZYPHERON_CLI="./zypheron-go/zypheron"
```

## Test Scripts

### 1. Master Test Runner (`run_all_tests.sh`)

Runs complete test suite with coverage reports.

```bash
./scripts/run_all_tests.sh [OPTIONS]
```

**Options:**
- `--skip-unit`: Skip Python and Go unit tests
- `--skip-integration`: Skip integration tests
- `--skip-coverage`: Skip coverage report generation
- `--fast`: Fast mode (skip coverage, minimal output)
- `--ci`: CI mode (exit on first failure, no color)

**Examples:**

```bash
# Full test suite with coverage
./scripts/run_all_tests.sh

# Fast run for local development
./scripts/run_all_tests.sh --fast

# Integration tests only
./scripts/run_all_tests.sh --skip-unit

# CI pipeline
./scripts/run_all_tests.sh --ci
```

**Output:**
- Python coverage: `zypheron-api/htmlcov/index.html`
- Go coverage: `zypheron-go/coverage.html`
- Test summary with pass/fail counts and timing

### 2. Integration Test Orchestrator (`test_integration.sh`)

Master integration test script that:
- Starts API server in background
- Runs all integration test suites
- Cleans up processes on exit
- Reports comprehensive results

```bash
./scripts/test_integration.sh [--skip-api]
```

**Options:**
- `--skip-api`: Use existing API server (don't start new one)

**What it tests:**
- API server startup and health check
- Authentication flow end-to-end
- License validation and features
- Stripe webhook handling
- Compliance framework loading

**Example:**

```bash
# Automatic API startup
./scripts/test_integration.sh

# Use already running API
./scripts/test_integration.sh --skip-api
```

### 3. Authentication Flow Tests (`test_auth_flow.sh`)

Tests the complete OAuth 2.0 Device Authorization Grant flow.

```bash
./scripts/test_auth_flow.sh
```

**Test Coverage:**

1. **User Registration**: Create new user account
2. **Device Code Request**: CLI requests device code
3. **Pending Status**: Verify polling returns pending before authorization
4. **Device Authorization**: Web app authorizes device
5. **Token Receipt**: CLI receives JWT token after authorization
6. **Token Validation**: Verify token works with `/auth/me`
7. **Session Persistence**: Multiple API calls with same token
8. **Logout**: Session invalidation
9. **Expired Codes**: Handling of expired device codes

**Example Output:**

```
[TEST] Test 1: User registration
[PASS] User registered successfully (ID: 42)

[TEST] Test 2: Request device code
[PASS] Device code generated: ABCD-1234
[INFO] Verification URL: http://localhost:3000/device?code=ABCD-1234
[INFO] Expires in: 300 seconds

[TEST] Test 3: Poll device token (expect pending)
[PASS] Device code status is pending (as expected)

...

Test Summary:
  Passed: 9
  Failed: 0

All tests passed!
```

### 4. License Flow Tests (`test_license_flow.sh`)

Validates license tiers, features, and Stripe integration.

```bash
./scripts/test_license_flow.sh
```

**Test Coverage:**

1. **License Validation**: Check default free license for new user
2. **Tier Features**: Retrieve feature flags for current tier
3. **All Tiers Comparison**: Get feature matrix for pricing page
4. **License Details**: Full license metadata
5. **Stripe Refresh**: Sync with Stripe subscription (if configured)
6. **Offline Mode**: Graceful degradation when API unavailable
7. **Unauthorized Access**: Security checks for protected endpoints
8. **Feature Flags**: Verify tier restrictions (free vs paid)
9. **Rate Limit Headers**: Check for rate limiting information

**Example Output:**

```
[TEST] Test 2: Get tier features for current user
[PASS] Features retrieved for tier: free
[INFO] AI Scanning: false
[INFO] Compliance Reports: false
[INFO] Max Scans/Month: 10

[TEST] Test 8: Verify feature flags per tier
[PASS] Feature flags correct: Free tier restricted, Pro tier has access
[INFO] Free - AI: false, Compliance: false, API: false
[INFO] Pro - AI: true, Compliance: true, API: true
```

### 5. Stripe Webhook Tests (`test_stripe_webhooks.sh`)

Sends mock Stripe webhook events to test handler logic.

```bash
./scripts/test_stripe_webhooks.sh
```

**Test Coverage:**

1. **Endpoint Accessibility**: Webhook endpoint responds
2. **Subscription Created**: Handle new subscription event
3. **Subscription Updated**: Handle upgrade/downgrade events
4. **Subscription Deleted**: Handle cancellation
5. **Payment Failed**: Handle failed payment with grace period
6. **Payment Succeeded**: Clear past_due status
7. **Unhandled Events**: Gracefully ignore unknown event types
8. **Missing Signature**: Reject requests without Stripe signature
9. **Malformed JSON**: Handle invalid payloads

**Note:** Tests expect signature verification failures (expected) or "Stripe not configured" responses since we're using mock data without proper signatures.

**Example Output:**

```
[TEST] Test 1: Check webhook endpoint exists
[PASS] Webhook endpoint accessible (HTTP 501)

[TEST] Test 2: Send subscription.created webhook event
[PASS] Webhook endpoint exists but Stripe not configured (expected in test)

[WARN] Note: Real Stripe webhooks require signature verification
[WARN] These tests use mock data and expect signature failures
```

### 6. Compliance Tests (`test_compliance.sh`)

Tests compliance framework loading and report generation.

```bash
./scripts/test_compliance.sh
```

**Test Coverage:**

1. **CLI Version Check**: Verify CLI is executable
2. **Compliance Commands**: Check if compliance features exist
3. **SOC2 Framework**: Load SOC2 controls
4. **PCI-DSS Framework**: Load PCI-DSS controls
5. **Report Formats**: JSON, HTML, PDF output
6. **Control Validation**: Detect security issues in test code
7. **Compliance Scoring**: Calculate compliance score/grade
8. **Framework Metadata**: List available frameworks
9. **Config Loading**: YAML configuration file support

**Note:** Many compliance features are planned for Phase 2/3, so warnings for unimplemented features are expected and normal.

**Example Output:**

```
[TEST] Test 1: Check CLI version and help
[PASS] CLI executable and responsive

[TEST] Test 3: Test SOC2 framework loading
[WARN] SOC2 compliance not yet implemented (expected for Phase 2)

[INFO] Note: Many compliance features are expected in Phase 2/3
[INFO] Warnings for unimplemented features are normal
```

## Understanding Test Results

### Exit Codes

- `0`: All tests passed
- `1`: One or more tests failed

### Color Output

- **Green** ✓: Test passed
- **Red** ✗: Test failed
- **Yellow**: Warning (expected for unimplemented features)
- **Blue**: Information
- **Cyan**: Test description

### Common Issues

#### 1. API Server Not Running

```
[ERROR] API server is not accessible at http://localhost:8000
```

**Solution:** Start the API server or use `--skip-api` flag with an already running server.

```bash
cd zypheron-api
source .venv/bin/activate
python -m uvicorn app.main:app
```

#### 2. Missing Dependencies

```
[ERROR] jq is required but not installed
```

**Solution:** Install required tools:

```bash
sudo apt install curl jq  # Ubuntu/Debian
brew install curl jq      # macOS
```

#### 3. Virtual Environment Missing

```
[ERROR] Virtual environment not found in zypheron-api/.venv
```

**Solution:** Set up the Python environment:

```bash
cd zypheron-api
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

#### 4. CLI Binary Not Found

```
[FAIL] Zypheron CLI not found. Build it first with: make build
```

**Solution:** Build the Go CLI:

```bash
cd zypheron-go
make build
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Install dependencies
        run: sudo apt install -y curl jq

      - name: Run all tests
        run: ./scripts/run_all_tests.sh --ci

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./zypheron-api/htmlcov/coverage.xml,./zypheron-go/coverage.out
```

### GitLab CI Example

```yaml
stages:
  - test

integration_tests:
  stage: test
  image: ubuntu:22.04

  before_script:
    - apt update && apt install -y curl jq python3 python3-pip golang-go

  script:
    - ./scripts/run_all_tests.sh --ci

  artifacts:
    paths:
      - zypheron-api/htmlcov/
      - zypheron-go/coverage.html
    reports:
      coverage_report:
        coverage_format: cobertura
        path: zypheron-api/htmlcov/coverage.xml
```

## Advanced Usage

### Running Individual Test Functions

You can modify test scripts to run only specific tests:

```bash
# In test_auth_flow.sh, comment out tests you don't want:
# test_register_user || true
# test_device_code_request || true
test_device_token_authorized || true  # Only run this one
```

### Custom API URL

```bash
export ZYPHERON_API_URL="https://staging-api.zypheron.com"
./scripts/test_integration.sh
```

### Debugging Failed Tests

Enable verbose curl output:

```bash
# Add to test scripts temporarily
curl -v ...  # instead of curl -s ...
```

View API logs:

```bash
tail -f /tmp/zypheron-api-test.log
```

### Testing Against Production

**Warning:** Never run integration tests against production! They create test users and modify data.

For production smoke tests, create separate read-only validation scripts.

## Test Data Cleanup

Test scripts create temporary data:

- **Users**: `test-auth-*@example.com`, `test-license-*@example.com`
- **Device codes**: Automatically expire after 5 minutes
- **Sessions**: Invalidated after logout
- **Temporary files**: `/tmp/zypheron-*` (cleaned by scripts)

For database cleanup:

```bash
# SQLite (dev)
sqlite3 zypheron-api/zypheron.db "DELETE FROM users WHERE email LIKE 'test-%@example.com';"

# PostgreSQL (production)
psql -d zypheron -c "DELETE FROM users WHERE email LIKE 'test-%@example.com';"
```

## Contributing

When adding new features, add corresponding integration tests:

1. Create test function in appropriate script
2. Use consistent naming: `test_<feature_name>()`
3. Add pass/fail tracking: `print_pass` / `print_fail`
4. Update this README with test coverage details

## Troubleshooting

### Tests Hang or Timeout

- Check if API server is stuck (kill and restart)
- Verify network connectivity
- Check for port conflicts (8000 already in use)

### Inconsistent Results

- Clean database between runs
- Check for leftover processes: `ps aux | grep zypheron`
- Verify environment variables are set correctly

### Performance Issues

- Use `--fast` mode for quick iterations
- Skip unit tests during integration development: `--skip-unit`
- Run specific test scripts instead of full suite

## Support

For issues or questions:

1. Check logs: `/tmp/zypheron-api-test.log`
2. Review test script output carefully
3. Verify prerequisites are installed
4. Check API server status: `curl http://localhost:8000/health`

## License

Same license as Zypheron project (see main LICENSE file).
