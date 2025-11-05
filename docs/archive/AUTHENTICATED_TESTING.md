# 🔐 Authenticated Testing Guide

## Overview

Zypheron's authenticated testing capabilities allow you to test vulnerabilities that require user login, including IDOR, privilege escalation, and broken authorization.

## Quick Start

### 1. Basic Authenticated Scan

```bash
# Using test account (auto-created and cleaned up)
zypheron auth-scan https://example.com --test-account --role user

# Using existing credentials
zypheron auth-scan https://example.com \
  --auth-type form \
  --username testuser \
  --password testpass123
```

### 2. Specific Vulnerability Tests

```bash
# Test only IDOR
zypheron auth-scan https://example.com --scan-type idor --test-account

# Test privilege escalation
zypheron auth-scan https://example.com --scan-type privesc --test-account --role admin

# Full authenticated assessment
zypheron auth-scan https://example.com --scan-type full --test-account
```

## Authentication Types Supported

### Form-Based Authentication (Default)
```bash
zypheron auth-scan https://example.com \
  --auth-type form \
  --username admin \
  --password secure123
```

### HTTP Basic Authentication
```bash
zypheron auth-scan https://api.example.com \
  --auth-type basic \
  --username apiuser \
  --password apipass
```

### Bearer Token Authentication
```bash
zypheron auth-scan https://api.example.com \
  --auth-type bearer \
  --auth-token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### API Key Authentication
```bash
zypheron auth-scan https://api.example.com \
  --auth-type apikey \
  --auth-token your-api-key-here
```

### OAuth 2.0
```bash
zypheron auth-scan https://example.com \
  --auth-type oauth2 \
  --username user@example.com \
  --password pass123
```

### Cookie-Based (Import existing session)
```bash
zypheron auth-scan https://example.com \
  --auth-type cookie \
  --session-file ./my-session.json
```

## Vulnerabilities Tested

### 1. IDOR (Insecure Direct Object References)

**What it tests:**
- Accessing other users' data by changing object IDs
- Unauthorized resource access

**Example findings:**
```
[!] IDOR Vulnerability Found
    Endpoint: /api/users/123/profile
    Issue: User can access ID 124 by changing parameter
    Severity: HIGH
    Impact: Unauthorized access to other users' data
```

### 2. Privilege Escalation (Vertical)

**What it tests:**
- Low privilege user accessing admin functions
- Missing role-based access controls

**Example findings:**
```
[!] Privilege Escalation Found
    Endpoint: /admin/users/delete
    Issue: Regular user can access admin endpoint
    Severity: CRITICAL
    Impact: User can perform administrative actions
```

### 3. Horizontal Privilege Escalation

**What it tests:**
- User A accessing User B's data
- Missing ownership validation

### 4. Session Security

**What it tests:**
- Session fixation vulnerabilities
- Insufficient session timeout
- Session token in URL
- Weak session token generation

## Test Account Management

### Auto-Created Test Accounts

```bash
# Create test account for specific role
zypheron auth-scan https://example.com \
  --test-account \
  --role user

# Accounts are automatically cleaned up after testing
```

### Manual Account Management (Python API)

```python
from auth.test_accounts import TestAccountManager

manager = TestAccountManager()

# Create account
account = manager.create_account(
    target_url="https://example.com",
    role="user",
    lifetime_hours=24,
    auto_cleanup=True
)

print(f"Username: {account.username}")
print(f"Password: {account.password}")

# Use account...

# Cleanup when done
manager.delete_account(account.account_id)
```

## Session Management

### Save and Reuse Sessions

```bash
# Save session for reuse
zypheron auth-scan https://example.com \
  --username user \
  --password pass \
  --session-file ./session.json

# Reuse saved session
zypheron auth-scan https://example.com \
  --session-file ./session.json \
  --scan-type idor
```

### Python API

```python
from auth.session_manager import SessionManager
from auth.auth_providers import FormAuthProvider

manager = SessionManager()
provider = FormAuthProvider("https://example.com")

# Authenticate
result = await provider.authenticate("user", "pass")

# Create session
if result.success:
    session = manager.create_session(
        session_id=result.session_id,
        target_url="https://example.com",
        auth_type="form",
        username="user"
    )
    
    manager.update_session(
        result.session_id,
        cookies=result.cookies,
        headers=result.headers
    )
    
    # Use session for testing
    req_session = manager.create_requests_session(session.session_id)
    response = req_session.get("https://example.com/profile")
```

## Advanced Usage

### Multi-Role Testing

```python
from analysis.authenticated_scanner import AuthenticatedScanner

scanner = AuthenticatedScanner(session_manager)

# Test with different roles
admin_vulns = await scanner.test_privilege_escalation(
    low_priv_session_id="user_session",
    high_priv_session_id="admin_session",
    admin_urls=[
        "/admin/users",
        "/admin/settings",
        "/admin/reports"
    ]
)

print(f"Found {len(admin_vulns)} privilege escalation issues")
```

### IDOR Comprehensive Testing

```python
# Test all user endpoints for IDOR
user_endpoints = [
    "/api/users/123/profile",
    "/api/users/123/settings",
    "/api/users/123/orders",
    "/api/documents/456"
]

idor_vulns = await scanner.test_idor(
    session_id="authenticated_session",
    test_urls=user_endpoints
)
```

## Best Practices

### 1. Use Test Accounts
- Always use dedicated test accounts
- Never use production user credentials
- Enable auto-cleanup

### 2. Scope Definition
- Clearly define in-scope targets
- Exclude production systems
- Document authorization

### 3. Session Management
- Monitor session health
- Handle expiration gracefully
- Clean up after testing

### 4. Evidence Collection
- Save all findings
- Capture HTTP requests/responses
- Screenshot evidence where applicable

## Output Example

```
╔═══════════════════════════════════════════╗
║  AUTHENTICATED SCAN RESULTS              ║
╚═══════════════════════════════════════════╝

Authenticated Scan Configuration:
────────────────────────────────────────────
  Target:      https://example.com
  Auth Type:   form
  Account:     Test account (auto-created)
  Scan Type:   full
────────────────────────────────────────────

[*] Creating test account...
[+] Test account created: test_user_1730400000

[*] Authenticating...
[+] Authenticated successfully (session: a7f3c9d1...)

[*] Running authenticated vulnerability tests...

  → Testing IDOR vulnerabilities...
  [!] Found 3 IDOR vulnerabilities

  → Testing privilege escalation...
  [✓] No privilege escalation found

  → Testing session security...
  [✓] Session security tests completed

╔═══════════════════════════════════════════╗
║  AUTHENTICATED SCAN RESULTS              ║
╚═══════════════════════════════════════════╝

Total Vulnerabilities: 3

Critical: 0
High: 3
Medium: 0

[*] Cleaning up test account...
[+] Test account cleaned up
[+] Results saved to: auth-scan-results.json
```

## Troubleshooting

### Authentication Fails

```bash
# Enable debug mode
zypheron auth-scan https://example.com --username user --password pass --debug

# Check session health
zypheron sessions list
zypheron sessions test <session-id>
```

### Test Account Creation Fails

Most likely the application doesn't have a registration API. You'll need to:
1. Manually create test accounts
2. Use existing credentials
3. Register a creation callback (Python API)

```python
from auth.test_accounts import TestAccountManager

manager = TestAccountManager()

# Register callback for account creation
def create_account_callback(username, password, email, role):
    # Your custom account creation logic
    # Call your app's registration API
    return True

manager.register_creation_callback(
    target_pattern="example.com",
    callback=create_account_callback
)
```

## Security Considerations

### Credential Storage
- All credentials stored in system keyring
- Passwords never written to disk in plain text
- Session files have 0600 permissions

### Authorization
- Always obtain written authorization
- Test only authorized targets
- Document all testing activities

### Data Protection
- Test accounts isolated from production
- No real user data accessed
- Auto-cleanup prevents account accumulation

## Integration with Other Features

### Combined with Compliance Reporting

```bash
# Run authenticated scan
zypheron auth-scan https://example.com --test-account -o results.json

# Generate compliance report from results
zypheron compliance --framework pci-dss --scan-results results.json
```

### Combined with Exploit Verification

```python
# Find IDOR
idor_vulns = await scanner.test_idor(...)

# Verify exploit safely
from verification import ExploitVerifier, VerificationMode

verifier = ExploitVerifier()
for vuln in idor_vulns:
    result = await verifier.verify_exploit(
        target=vuln.url,
        vulnerability=vuln.title,
        mode=VerificationMode.READ_ONLY
    )
```

---

**For more information, see:**
- `ENTERPRISE_FEATURES.md` - Complete enterprise guide
- `API_TESTING_GUIDE.md` - API security testing
- `SECRETS_SCANNING.md` - Finding hardcoded secrets

