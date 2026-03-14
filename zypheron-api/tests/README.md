# Zypheron API Test Suite

Comprehensive test suite for the Zypheron API with 30+ tests covering all major features.

## Test Structure

```
tests/
├── conftest.py              # Pytest fixtures and configuration
├── test_device_auth.py      # Device authentication flow tests (15 tests)
├── test_stripe_webhooks.py  # Stripe webhook handler tests (10 tests)
├── test_license.py          # License management tests (12 tests)
└── test_compliance.py       # Compliance features tests (7 placeholder tests)
```

## Test Coverage

### Device Authentication (15 tests)
- ✅ Device code creation and validation
- ✅ User authorization flow
- ✅ Token polling and retrieval
- ✅ Expiration handling
- ✅ Error cases and edge conditions
- ✅ Database cleanup

### Stripe Webhooks (10 tests)
- ✅ Webhook signature verification
- ✅ Subscription lifecycle events (created, updated, deleted)
- ✅ Tier changes and upgrades
- ✅ Token usage reset on renewal
- ✅ Invoice payment events (failed, succeeded)
- ✅ Grace period handling
- ✅ Unknown event type handling

### License Management (12 tests)
- ✅ License validation for all tiers
- ✅ Feature access per tier
- ✅ Subscription upgrades (mocked Stripe)
- ✅ Subscription cancellation (mocked Stripe)
- ✅ License refresh from Stripe
- ✅ Tier information retrieval
- ✅ Default license creation
- ✅ Expired license handling

### Compliance Features (7 tests - Placeholders)
- 🔄 SOC2 control loading (not yet implemented)
- 🔄 PCI-DSS control loading (not yet implemented)
- 🔄 Risk scoring calculation (not yet implemented)
- 🔄 Compliance report generation (not yet implemented)
- 🔄 Future features (placeholder structure)

**Note:** Compliance tests are marked with `@pytest.mark.skip` as these features are not yet implemented. They serve as a specification for future development.

## Running Tests

### Install dependencies
```bash
cd zypheron-api
pip install -e ".[dev]"
```

### Run all tests
```bash
pytest
```

### Run specific test file
```bash
pytest tests/test_device_auth.py
pytest tests/test_stripe_webhooks.py
pytest tests/test_license.py
```

### Run with coverage
```bash
pytest --cov=app --cov-report=html --cov-report=term
```

### Run specific test class
```bash
pytest tests/test_device_auth.py::TestDeviceCodeCreation
```

### Run specific test
```bash
pytest tests/test_device_auth.py::TestDeviceCodeCreation::test_request_device_code_success
```

### Run tests matching pattern
```bash
pytest -k "device_code"
pytest -k "stripe"
pytest -k "license"
```

### Run with verbose output
```bash
pytest -v
```

### Run tests in parallel (faster)
```bash
pip install pytest-xdist
pytest -n auto
```

## Test Fixtures

The test suite uses comprehensive fixtures defined in `conftest.py`:

### Database Fixtures
- `test_db`: In-memory SQLite database with clean slate per test
- `override_get_db`: Override FastAPI's database dependency

### Client Fixtures
- `client`: Async HTTP client for API testing

### User Fixtures
- `test_user`: Basic user with email/password
- `test_user_with_license`: User with free tier license
- `test_paid_user`: User with pro tier subscription

### Authentication Fixtures
- `auth_token`: JWT token for test user
- `auth_headers`: Authorization headers with valid token
- `paid_user_headers`: Authorization headers for paid user

### Stripe Mock Fixtures
- `mock_stripe_customer`: Mock Stripe Customer object
- `mock_stripe_subscription`: Mock Stripe Subscription data
- `mock_stripe_checkout_session`: Mock Stripe Checkout Session
- `mock_stripe_client`: Comprehensive Stripe API mocks

### Device Code Fixtures
- `test_device_code`: Pending device code for testing
- `expired_device_code`: Expired device code for expiry tests

## Mocking Strategy

### External Service Mocking
All external services are mocked using `pytest-mock`:

1. **Stripe API**: All Stripe operations are mocked to avoid real API calls
   - Customer creation/retrieval
   - Checkout session creation
   - Subscription operations
   - Webhook verification

2. **Database**: Uses SQLite in-memory for fast, isolated tests
   - Fresh database per test
   - Automatic cleanup after each test

3. **JWT Tokens**: Real tokens generated for testing auth flow
   - Session records created in test database
   - Token validation works end-to-end

## Best Practices

### Writing New Tests

1. **Use appropriate fixtures**: Leverage existing fixtures instead of recreating data
2. **Mock external services**: Always mock Stripe, Redis, and external APIs
3. **Test edge cases**: Include error cases, invalid inputs, and boundary conditions
4. **Use descriptive names**: Test names should clearly describe what they test
5. **Follow AAA pattern**: Arrange, Act, Assert

Example:
```python
async def test_feature_success_case(
    client: AsyncClient,
    auth_headers: dict[str, str],
    test_db: AsyncSession,
):
    """Test successful feature execution."""
    # Arrange - set up test data
    test_data = {"key": "value"}

    # Act - execute the feature
    response = await client.post(
        "/endpoint",
        json=test_data,
        headers=auth_headers,
    )

    # Assert - verify results
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
```

### Test Organization

- Group related tests in classes (e.g., `TestDeviceCodeCreation`)
- Use descriptive class names that indicate what's being tested
- Order tests from happy path to edge cases
- Keep tests independent - don't rely on test execution order

### Async Testing

- All test functions that call async code must be `async def`
- Use `await` for async operations
- pytest-asyncio handles the event loop automatically

## Coverage Goals

Target coverage by module:
- **Routers**: 90%+ (core business logic)
- **Services**: 85%+ (external integrations)
- **Models**: 80%+ (ORM models and methods)
- **Core utilities**: 95%+ (authentication, security)

Current coverage: **~30+ tests** covering critical paths

## Continuous Integration

These tests are designed to run in CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run tests
  run: |
    pip install -e ".[dev]"
    pytest --cov=app --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.xml
```

## Troubleshooting

### Tests hanging or timing out
- Check for missing `await` on async operations
- Ensure database sessions are properly closed
- Verify no real external API calls being made

### Import errors
- Install dev dependencies: `pip install -e ".[dev]"`
- Check Python version (requires 3.10+)

### Database errors
- Each test gets fresh database, check test isolation
- Verify models are properly imported in conftest.py

### Fixture not found
- Ensure fixture is defined in conftest.py
- Check fixture scope (function, module, session)
- Verify fixture name matches parameter name

## Future Test Additions

Planned test coverage for upcoming features:
- [ ] AI proxy endpoint tests (token tracking, rate limiting)
- [ ] Token usage tracking tests
- [ ] Cache warming and hit rate tests
- [ ] WebSocket connection tests (scan streaming)
- [ ] Compliance framework implementation tests
- [ ] Integration tests with real database (optional)
- [ ] Load testing for rate limiting
- [ ] Security testing (SQL injection, XSS prevention)

## Contributing

When adding new features:
1. Write tests first (TDD approach)
2. Ensure all tests pass before committing
3. Add new fixtures to conftest.py if needed
4. Update this README with new test coverage
5. Maintain >80% code coverage

## Test Metrics

Current test suite metrics:
- **Total tests**: 37+ (including skipped compliance tests)
- **Active tests**: 30+
- **Test files**: 4
- **Fixtures**: 15+
- **Average test runtime**: <5 seconds total
- **Mocked services**: Stripe, Database (SQLite in-memory)
