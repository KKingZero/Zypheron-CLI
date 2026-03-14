# Zypheron Testing Quick Reference

Fast reference for common test commands and workflows.

## One-Command Testing

```bash
# Run everything
./scripts/run_all_tests.sh

# Fast local development
./scripts/run_all_tests.sh --fast

# CI pipeline
./scripts/run_all_tests.sh --ci
```

## Individual Test Suites

```bash
# Integration tests (master orchestrator)
./scripts/test_integration.sh

# Auth flow only
./scripts/test_auth_flow.sh

# License/tier features
./scripts/test_license_flow.sh

# Stripe webhooks
./scripts/test_stripe_webhooks.sh

# Compliance framework
./scripts/test_compliance.sh
```

## Unit Tests Only

```bash
# Python tests (API)
cd zypheron-api
source .venv/bin/activate
pytest -v

# Python with coverage
pytest -v --cov=app --cov-report=html

# Go tests (CLI)
cd zypheron-go
go test -v ./...

# Go with coverage
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Common Flags

```bash
--skip-api          # Use existing API server
--skip-unit         # Skip Python/Go unit tests
--skip-integration  # Skip integration tests
--skip-coverage     # Skip coverage reports
--fast              # Fast mode (no coverage)
--ci                # CI mode (fail fast, no color)
```

## Environment Setup

```bash
# API setup
cd zypheron-api
python -m venv .venv
source .venv/bin/activate
pip install -e .
python -m uvicorn app.main:app

# CLI build
cd zypheron-go
make build

# Install test tools
sudo apt install curl jq  # Ubuntu
brew install curl jq      # macOS
```

## Debugging

```bash
# View API logs
tail -f /tmp/zypheron-api-test.log

# Check API health
curl http://localhost:8000/health | jq

# Test specific endpoint
curl -X POST http://localhost:8000/auth/device/code \
  -H "Content-Type: application/json" \
  -d '{"device_info":"test"}' | jq

# Run single test function (edit script)
# Comment out other tests, run only:
test_specific_feature || true
```

## Coverage Reports

```bash
# Python coverage
open zypheron-api/htmlcov/index.html

# Go coverage
open zypheron-go/coverage.html
```

## Cleanup

```bash
# Kill stuck API server
pkill -f "uvicorn app.main:app"

# Remove test database
rm zypheron-api/zypheron.db

# Clean temp files
rm -rf /tmp/zypheron-*

# Remove test users (SQLite)
sqlite3 zypheron-api/zypheron.db \
  "DELETE FROM users WHERE email LIKE 'test-%@example.com';"
```

## Exit Codes

- `0` = All tests passed ✓
- `1` = Some tests failed ✗

## Quick Checks

```bash
# Is API running?
curl -s http://localhost:8000/health || echo "API down"

# Is CLI built?
[ -f zypheron-go/zypheron ] && echo "CLI ready" || echo "Build CLI"

# Are dependencies installed?
command -v jq && command -v curl && echo "Dependencies OK"
```

## Test Workflow Examples

### Pre-Commit Check

```bash
./scripts/run_all_tests.sh --fast
```

### Pre-Push Check

```bash
./scripts/run_all_tests.sh
```

### CI Pipeline

```bash
./scripts/run_all_tests.sh --ci
```

### Feature Development

```bash
# Start API in one terminal
cd zypheron-api
source .venv/bin/activate
python -m uvicorn app.main:app --reload

# Run tests in another terminal
./scripts/test_auth_flow.sh  # or whichever suite
```

### Integration Only (API Already Running)

```bash
./scripts/test_integration.sh --skip-api
```

## Common Errors & Solutions

| Error | Solution |
|-------|----------|
| `jq: command not found` | `sudo apt install jq` |
| `API not accessible` | Start API server |
| `.venv not found` | `python -m venv .venv` |
| `CLI not found` | `cd zypheron-go && make build` |
| `Tests hang` | Kill API, restart tests |
| `Port 8000 in use` | `lsof -ti:8000 \| xargs kill` |

## Test Result Interpretation

```bash
[PASS]  # ✓ Test succeeded
[FAIL]  # ✗ Test failed (needs fixing)
[WARN]  # ⚠ Expected for unimplemented features
[INFO]  # ℹ Informational message
```

## Performance Benchmarks

Expected test times (approximate):

- Auth flow: ~5-10 seconds
- License flow: ~5-10 seconds
- Webhook tests: ~5 seconds
- Compliance: ~10-15 seconds
- Python unit: ~10-30 seconds
- Go unit: ~5-15 seconds
- **Full suite**: ~1-2 minutes (without coverage)
- **Full suite + coverage**: ~2-4 minutes

## Files Generated

```
zypheron-api/
  htmlcov/              # Python coverage HTML
  .coverage             # Python coverage data
  zypheron.db           # SQLite database

zypheron-go/
  coverage.out          # Go coverage data
  coverage.html         # Go coverage HTML

/tmp/
  zypheron-api-test.log         # API server logs
  zypheron-compliance-test-*/   # Compliance test artifacts
```

## Quick Test Validation

After changes, run minimal validation:

```bash
# 1. Lint and format
cd zypheron-api && black . && mypy .
cd zypheron-go && go fmt ./... && go vet ./...

# 2. Quick unit tests
cd zypheron-api && pytest tests/
cd zypheron-go && go test ./...

# 3. Fast integration check
./scripts/run_all_tests.sh --fast
```

## Custom Test Runs

```bash
# Only auth tests
ZYPHERON_API_URL=http://localhost:8000 ./scripts/test_auth_flow.sh

# Only license tests
./scripts/test_license_flow.sh

# Skip specific suites (edit test_integration.sh)
# Comment out unwanted run_test_suite calls
```

## Integration with IDE

### VSCode

```json
// .vscode/tasks.json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Run All Tests",
      "type": "shell",
      "command": "./scripts/run_all_tests.sh --fast",
      "problemMatcher": []
    }
  ]
}
```

### PyCharm

Run configurations:
- Script: `scripts/run_all_tests.sh`
- Arguments: `--fast`

## Continuous Testing

```bash
# Watch mode for Python tests
cd zypheron-api
pytest-watch

# Watch mode for Go tests
cd zypheron-go
go install github.com/cespare/reflex@latest
reflex -r '\.go$' -- go test ./...
```

---

**Remember:** Integration tests modify the database. Use a test database, not production!
