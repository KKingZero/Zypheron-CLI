# Testing Guide

This guide explains how to run tests, write new tests, and maintain test coverage for Zypheron.

## Table of Contents

- [Overview](#overview)
- [Go Tests](#go-tests)
- [Python Tests](#python-tests)
- [Integration Tests](#integration-tests)
- [Coverage Requirements](#coverage-requirements)
- [Writing New Tests](#writing-new-tests)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)

## Overview

Zypheron uses a comprehensive testing strategy:

- **Unit Tests**: Test individual functions and modules in isolation
- **Integration Tests**: Test interactions between components
- **Security Tests**: Validate input sanitization and injection prevention
- **Coverage Target**: Minimum 50% code coverage

## Go Tests

### Running Go Tests

```bash
# Navigate to Go project
cd zypheron-go

# Run all tests
make test

# Run tests with verbose output
go test -v ./...

# Run tests for specific package
go test -v ./internal/validation

# Run specific test
go test -v -run TestValidateToolName ./internal/validation

# Generate HTML coverage report
make coverage-html
```

### Test Structure

```
zypheron-go/
├── internal/
│   ├── validation/
│   │   ├── validator.go
│   │   └── validator_test.go       # Validation tests
│   ├── storage/
│   │   ├── scan_storage.go
│   │   └── scan_storage_test.go    # Storage tests
│   └── aibridge/
│       ├── bridge.go
│       └── bridge_test.go           # IPC tests
└── pkg/
    └── types/
        ├── scan.go
        └── scan_test.go             # Type tests
```

### Key Test Files

#### `validator_test.go`
- Tests input validation functions
- Verifies injection prevention
- Tests target, port, and tool name validation

#### `scan_storage_test.go`
- Tests scan persistence
- Verifies JSON serialization
- Tests scan listing and retrieval

### Running with Coverage

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...

# View coverage summary
go tool cover -func=coverage.out

# Generate HTML report
go tool cover -html=coverage.out -o coverage.html

# Open in browser (Linux)
xdg-open coverage.html
```

## Python Tests

### Running Python Tests

```bash
# Navigate to Python project
cd zypheron-ai

# Install test dependencies
pip install -e ".[test]"

# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html --cov-report=term-missing

# Run specific test file
pytest tests/test_secure_config.py

# Run specific test
pytest tests/test_server.py::TestIPCServer::test_handle_health -v

# Run with markers
pytest -m unit          # Only unit tests
pytest -m integration   # Only integration tests
```

### Test Structure

```
zypheron-ai/
├── tests/
│   ├── __init__.py
│   ├── test_secure_config.py    # Keyring storage tests
│   ├── test_server.py           # IPC server tests
│   ├── test_providers.py        # AI provider tests
│   └── integration/
│       └── test_ipc.py          # Integration tests
├── pytest.ini                   # Pytest configuration
└── setup.py                     # Test dependencies
```

### Key Test Files

#### `test_secure_config.py`
- Tests keyring integration
- Verifies API key storage/retrieval
- Tests migration from .env files

#### `test_server.py`
- Tests IPC server functionality
- Verifies authentication
- Tests request handling

### Pytest Configuration

The `pytest.ini` file configures:

```ini
[pytest]
# Minimum coverage requirement
addopts = --cov-fail-under=50

# Test discovery
python_files = test_*.py
python_classes = Test*
python_functions = test_*

# Markers for categorization
markers =
    unit: Unit tests
    integration: Integration tests
    slow: Slow running tests
```

## Integration Tests

Integration tests verify interactions between components:

### Go-Python IPC Test

```bash
# Start Python AI engine in background
cd zypheron-ai
python -m core.server &

# Run Go integration tests
cd ../zypheron-go
go test -v ./tests/integration/...
```

### End-to-End Scan Test

```bash
# Full scan workflow test
pytest tests/integration/test_scan_workflow.py
```

## Coverage Requirements

### Minimum Coverage

- **Go**: 50% overall coverage
- **Python**: 50% overall coverage
- **Critical Modules**: 70%+ coverage
  - Input validation
  - Security functions
  - API key storage

### Checking Coverage

```bash
# Go coverage
cd zypheron-go
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | grep total

# Python coverage
cd zypheron-ai
pytest --cov=. --cov-report=term-missing
```

### Coverage Reports

- **HTML Reports**: Interactive coverage browser
  - Go: `coverage.html`
  - Python: `htmlcov/index.html`
- **Terminal Reports**: Summary with missing lines
- **XML Reports**: For CI/CD integration

## Writing New Tests

### Go Test Template

```go
package mypackage

import (
    "testing"
)

func TestMyFunction(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {"valid input", "test", "expected", false},
        {"invalid input", "", "", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := MyFunction(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("MyFunction() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if got != tt.want {
                t.Errorf("MyFunction() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Python Test Template

```python
import pytest
from unittest.mock import Mock, patch

class TestMyClass:
    """Test MyClass functionality"""
    
    @pytest.fixture
    def my_instance(self):
        """Create test instance"""
        return MyClass(config="test")
    
    def test_my_method(self, my_instance):
        """Test my_method with valid input"""
        result = my_instance.my_method("input")
        assert result == "expected"
    
    def test_my_method_error(self, my_instance):
        """Test my_method error handling"""
        with pytest.raises(ValueError):
            my_instance.my_method(None)
    
    @patch('mymodule.external_function')
    def test_with_mock(self, mock_external, my_instance):
        """Test with mocked dependencies"""
        mock_external.return_value = "mocked"
        result = my_instance.method_using_external()
        assert result == "mocked"
```

### Testing Best Practices

1. **Test One Thing**: Each test should verify a single behavior
2. **Descriptive Names**: Use clear, descriptive test names
3. **Arrange-Act-Assert**: Structure tests clearly:
   ```python
   # Arrange
   input_data = "test"
   # Act
   result = function(input_data)
   # Assert
   assert result == expected
   ```
4. **Test Edge Cases**: Include boundary conditions, empty inputs, invalid data
5. **Use Fixtures**: Reuse test setup code
6. **Mock External Dependencies**: Don't rely on external services in tests

## CI/CD Integration

### GitHub Actions

Tests run automatically on:
- Every push to main/develop branches
- Every pull request
- Weekly security scans

### Workflows

1. **Go Tests** (`.github/workflows/go-tests.yml`)
   - Runs on Ubuntu with Go 1.21
   - Executes `make test`
   - Uploads coverage to Codecov

2. **Python Tests** (`.github/workflows/python-tests.yml`)
   - Runs on Python 3.9, 3.10, 3.11
   - Executes `pytest` with coverage
   - Uploads coverage to Codecov

3. **Security Scan** (`.github/workflows/security.yml`)
   - Gosec for Go code
   - Bandit for Python code
   - Dependency vulnerability checks

### Local CI Simulation

```bash
# Install act (GitHub Actions local runner)
# https://github.com/nektos/act

# Run Go tests locally
act -j test -W .github/workflows/go-tests.yml

# Run Python tests locally
act -j test -W .github/workflows/python-tests.yml
```

## Troubleshooting

### Common Issues

#### Go Tests Fail to Import

```bash
# Ensure go.mod is up to date
cd zypheron-go
go mod tidy

# Clear module cache
go clean -modcache
```

#### Python Tests Can't Find Modules

```bash
# Install package in editable mode
cd zypheron-ai
pip install -e .

# Or add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

#### Coverage Too Low

```bash
# Identify untested code
go tool cover -func=coverage.out | grep -v 100.0%

# Python detailed report
pytest --cov=. --cov-report=term-missing
```

#### Tests Timeout

```bash
# Increase timeout (Go)
go test -timeout 30s ./...

# Mark slow tests (Python)
@pytest.mark.slow
def test_long_operation():
    ...

# Skip slow tests
pytest -m "not slow"
```

### Getting Help

- **Documentation**: Check function docstrings and comments
- **Examples**: Look at existing tests in the same package
- **CI Logs**: Review GitHub Actions logs for failures
- **Coverage**: Use coverage reports to find untested code

## Test Maintenance

### Regular Tasks

- **Update Tests**: When adding new features
- **Review Coverage**: Weekly coverage checks
- **Dependency Updates**: Monthly test dependency updates
- **Performance**: Profile slow tests and optimize

### Pre-Commit Checklist

- [ ] All tests pass locally
- [ ] New code has tests
- [ ] Coverage meets minimum (50%)
- [ ] No security warnings
- [ ] Tests are deterministic (no flakiness)

---

**Questions?** Open an issue or check existing tests for examples.

