# Testing Guide - Zypheron API

Complete guide for running and writing tests for the Zypheron API.

## Quick Start

```bash
# 1. Install dependencies
cd zypheron-api
pip install -e ".[dev]"

# 2. Run all tests
pytest

# 3. Run with coverage
pytest --cov=app --cov-report=html

# 4. Use the test runner script
./run_tests.sh coverage
```

## Test Suite Overview

### Statistics
- **Total Tests**: 70
- **Active Tests**: 59 (11 compliance tests are skipped placeholders)
- **Test Files**: 5
- **Average Runtime**: <5 seconds

### Test Files
1. **test_auth.py** (18 tests) - User authentication and session management
2. **test_device_auth.py** (16 tests) - OAuth 2.0 device authorization flow
3. **test_license.py** (15 tests) - License and subscription management
4. **test_stripe_webhooks.py** (10 tests) - Stripe payment webhooks
5. **test_compliance.py** (11 tests) - Compliance features (placeholder)

## Running Tests

### Using pytest directly

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_device_auth.py

# Run specific test class
pytest tests/test_device_auth.py::TestDeviceCodeCreation

# Run specific test
pytest tests/test_device_auth.py::TestDeviceCodeCreation::test_request_device_code_success

# Run tests matching pattern
pytest -k "device_code"
pytest -k "stripe"

# Stop on first failure
pytest -x

# Run last failed tests
pytest --lf

# Show local variables on failure
pytest -l

# Run with coverage
pytest --cov=app --cov-report=html --cov-report=term-missing
```

### Using the test runner script

```bash
# Make executable (first time only)
chmod +x run_tests.sh

# Run all tests
./run_tests.sh

# Run with coverage
./run_tests.sh coverage

# Run specific test suite
./run_tests.sh device
./run_tests.sh stripe
./run_tests.sh license
./run_tests.sh auth

# Run in parallel (faster)
./run_tests.sh parallel

# Watch mode (auto-rerun on changes)
./run_tests.sh watch

# Count tests
./run_tests.sh count

# Show help
./run_tests.sh help
```

### Using pytest-xdist for parallel execution

```bash
# Install if not already installed
pip install pytest-xdist

# Run tests in parallel (auto-detect CPUs)
pytest -n auto

# Run on specific number of CPUs
pytest -n 4
```

## Test Structure

### conftest.py
Central configuration file with shared fixtures:

**Database Fixtures:**
- `test_db` - In-memory SQLite database
- `override_get_db` - Override FastAPI database dependency

**Client Fixtures:**
- `client` - Async HTTP client for API testing

**User Fixtures:**
- `test_user` - Basic test user
- `test_user_with_license` - User with free license
- `test_paid_user` - User with pro subscription

**Auth Fixtures:**
- `auth_token` - JWT token
- `auth_headers` - Authorization headers
- `paid_user_headers` - Headers for paid user

**Stripe Mocks:**
- `mock_stripe_customer` - Mock customer object
- `mock_stripe_subscription` - Mock subscription data
- `mock_stripe_checkout_session` - Mock checkout session
- `mock_stripe_client` - Complete Stripe API mocks

**Device Code Fixtures:**
- `test_device_code` - Pending device code
- `expired_device_code` - Expired device code

### Test Organization

Each test file follows this structure:

```python
"""Module docstring describing what's tested."""

import statements

class TestFeatureGroup:
    """Test class for related tests."""

    async def test_happy_path(self, client, fixtures):
        """Test successful operation."""
        # Arrange
        test_data = {...}

        # Act
        response = await client.post("/endpoint", json=test_data)

        # Assert
        assert response.status_code == 200

    async def test_error_case(self, client):
        """Test error handling."""
        # Test implementation
```

## Writing New Tests

### Best Practices

1. **Use descriptive names**: Test names should clearly describe what they test
2. **Follow AAA pattern**: Arrange, Act, Assert
3. **Use appropriate fixtures**: Leverage existing fixtures instead of duplicating setup
4. **Mock external services**: Always mock Stripe, external APIs, etc.
5. **Test edge cases**: Include error cases and boundary conditions
6. **Keep tests isolated**: Each test should be independent
7. **Use async/await**: All tests calling async code must be async

### Example Test

```python
async def test_user_registration_success(
    client: AsyncClient,
    test_db: AsyncSession,
):
    """Test successful user registration creates account and license."""
    # Arrange
    user_data = {
        "email": "newuser@example.com",
        "password": "SecurePass123!",
    }

    # Act
    response = await client.post("/auth/register", json=user_data)

    # Assert
    assert response.status_code == 201
    data = response.json()
    assert data["user"]["email"] == user_data["email"]
    assert data["access_token"] is not None

    # Verify in database
    stmt = select(User).where(User.email == user_data["email"])
    result = await test_db.execute(stmt)
    user = result.scalar_one_or_none()
    assert user is not None
```

### Testing Authenticated Endpoints

```python
async def test_protected_endpoint(
    client: AsyncClient,
    auth_headers: dict[str, str],
):
    """Test endpoint requiring authentication."""
    response = await client.get(
        "/protected/endpoint",
        headers=auth_headers,  # Use fixture for auth
    )

    assert response.status_code == 200
```

### Mocking Stripe

```python
async def test_stripe_integration(
    client: AsyncClient,
    auth_headers: dict[str, str],
    mock_stripe_client,  # Use Stripe mock fixture
    mocker,
):
    """Test Stripe checkout creation."""
    # Mock settings
    mocker.patch("app.routers.license.settings.stripe_secret_key", "sk_test")

    response = await client.post(
        "/license/upgrade/pro",
        params={"success_url": "https://...", "cancel_url": "https://..."},
        headers=auth_headers,
    )

    assert response.status_code == 200
    # Verify Stripe was called
    mock_stripe_client["checkout_create"].assert_called_once()
```

## Coverage Reports

### Generate HTML Coverage Report

```bash
# Run tests with coverage
pytest --cov=app --cov-report=html --cov-report=term-missing

# Open report in browser
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```

### Coverage Goals

- **Routers**: 90%+ (core business logic)
- **Services**: 85%+ (external integrations)
- **Models**: 80%+ (ORM models)
- **Core utilities**: 95%+ (auth, security)

### Check Coverage Thresholds

```bash
# Fail if coverage below 70%
pytest --cov=app --cov-fail-under=70

# Show missing lines
pytest --cov=app --cov-report=term-missing
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

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

      - name: Install dependencies
        run: |
          cd zypheron-api
          pip install -e ".[dev]"

      - name: Run tests with coverage
        run: |
          cd zypheron-api
          pytest --cov=app --cov-report=xml --cov-report=term

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./zypheron-api/coverage.xml
```

## Troubleshooting

### Common Issues

#### Tests hanging or timing out
```
Symptom: Tests don't complete
Solution: Check for missing 'await' on async operations
```

#### Import errors
```
Symptom: Cannot import app modules
Solution: Install dev dependencies: pip install -e ".[dev]"
```

#### Database errors
```
Symptom: Database locked or constraint violations
Solution: Each test gets fresh database; check test isolation
```

#### Fixture not found
```
Symptom: fixture 'X' not found
Solution: Ensure fixture is in conftest.py and name matches
```

#### Async warnings
```
Symptom: RuntimeWarning about coroutines
Solution: Add 'await' before async function calls
```

### Debug Mode

```bash
# Show print statements
pytest -s

# Show local variables on failure
pytest -l

# Enter debugger on failure
pytest --pdb

# Increase verbosity
pytest -vv
```

### Performance Issues

```bash
# Profile test execution time
pytest --durations=10

# Show slowest tests
pytest --durations=0

# Run in parallel for speed
pytest -n auto
```

## Test Data Management

### Using Fixtures for Test Data

```python
@pytest.fixture
async def test_data(test_db: AsyncSession):
    """Create reusable test data."""
    user = User(email="test@example.com", tier="free")
    test_db.add(user)
    await test_db.commit()
    await test_db.refresh(user)
    return user
```

### Cleaning Up Test Data

Tests automatically clean up because each test gets a fresh database. If you need manual cleanup:

```python
async def test_with_cleanup(test_db: AsyncSession):
    """Test with explicit cleanup."""
    # Create test data
    user = User(email="temp@example.com")
    test_db.add(user)
    await test_db.commit()

    try:
        # Test logic here
        pass
    finally:
        # Cleanup (usually not needed with test_db fixture)
        await test_db.delete(user)
        await test_db.commit()
```

## Advanced Topics

### Parametrized Tests

```python
@pytest.mark.parametrize("tier,expected_limit", [
    ("free", 0),
    ("starter", 1_000_000),
    ("pro", 3_000_000),
    ("enterprise", 15_000_000),
])
async def test_token_limits_by_tier(tier, expected_limit):
    """Test token limits for each tier."""
    features = get_tier_features(tier)
    assert features["token_limit"] == expected_limit
```

### Testing Exceptions

```python
async def test_invalid_input_raises_error(client):
    """Test that invalid input raises proper error."""
    response = await client.post("/endpoint", json={"invalid": "data"})
    assert response.status_code == 422  # Validation error
```

### Markers

```python
# Skip test
@pytest.mark.skip(reason="Feature not implemented")
async def test_future_feature():
    pass

# Skip if condition
@pytest.mark.skipif(sys.platform == "win32", reason="Unix only")
async def test_unix_feature():
    pass

# Mark as slow test
@pytest.mark.slow
async def test_slow_operation():
    pass

# Run only slow tests
# pytest -m slow

# Skip slow tests
# pytest -m "not slow"
```

## Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [pytest-asyncio](https://pytest-asyncio.readthedocs.io/)
- [HTTPX Testing](https://www.python-httpx.org/async/)
- [FastAPI Testing](https://fastapi.tiangolo.com/tutorial/testing/)
- [Test Coverage Guide](https://coverage.readthedocs.io/)

## Summary

The Zypheron API test suite provides:
- ✅ Comprehensive coverage (70 tests)
- ✅ Fast execution (<5 seconds)
- ✅ Production-ready quality
- ✅ CI/CD ready
- ✅ Well-documented
- ✅ Easy to extend

For questions or issues, refer to the test files themselves - they serve as documentation through examples.
