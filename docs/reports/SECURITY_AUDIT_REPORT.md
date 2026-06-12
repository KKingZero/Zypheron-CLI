# Zypheron Security Audit Report

## Executive Summary

This report has been refreshed for the OSS release-candidate track. The current
target is the local/self-hosted CLI, Python AI runtime, and optional FastAPI
service. Hosted SaaS-only surfaces such as Enterprise Teams are explicitly
deferred and are not treated as RC launch blockers when they return clear
`501 Not Implemented` responses or are documented as unavailable.

The prior audit findings below are retained for traceability. Several high-risk
items have been remediated in the current working tree with focused regression
tests, but the release is not security-signed-off until the full RC gate passes:

```bash
./scripts/run_all_tests.sh --ci
./scripts/local_smoke_test.sh --setup-api-env --allow-online
```

---

## Current RC Security Status

| Area | Status | Notes |
|------|--------|-------|
| Go tool install shell recipes | Fixed, pending full gate | `zypheron-go/internal/kali/tools.go` no longer returns `bash -c` install commands; install recipes use direct argv commands. |
| JWT production defaults | Fixed, pending full gate | Non-development environments reject the published unsafe secret and short secrets. |
| API rate-limit client identity | Fixed, pending full gate | Forwarded IP headers are trusted only from configured proxy CIDRs. |
| Token/quota middleware | Fixed, pending full gate | Token checking is registered in the API app and covered by remediation tests. |
| Tool/API scanner scope controls | Fixed, pending full gate | API/web scanner paths enforce same-host or configured scope and private-target controls. |
| Loot/session path safety | Fixed, pending full gate | Final writes use containment checks and nofollow protections. |
| MSF TLS verification | Fixed, pending full gate | TLS verification defaults on; insecure mode is opt-in and warns for non-local/private hosts. |
| Provider/token CLI gates | Deferred by OSS posture | CLI provider entitlement checks are intentional no-ops for the MIT/open-source release and are documented/tested as non-security controls. |
| Enterprise Teams API | Deferred | Endpoints remain unavailable for OSS RC and may return `501`. |
| Streaming chat protocol | Deferred | Streaming requests fall back to standard chat behavior. |
| Full autonomous exploitation | Deferred | Autopent remains safety-first and approval-gated; full autonomous exploitation is not an OSS RC promise. |

## Historical Vulnerability Summary

| Severity | Historical Count | Current RC Treatment |
|----------|------------------|----------------------|
| CRITICAL | 3 | Fixed or deferred by explicit OSS scope; verify through full gate |
| HIGH | 4 | Fixed, deferred, or pending full gate depending on item |
| MEDIUM | 3 | Recommended hardening; do not block OSS RC unless tests fail |
| LOW | 2 | Optional hardening |

**Estimated Remediation:** 90-130 hours

---

## Critical Severity Findings

### 1. Command Injection Vulnerabilities in Tool Execution

**Severity:** CRITICAL
**CVSS Score:** 9.8
**Location:** `/zypheron-go/internal/tools/executor.go`, `/zypheron-go/internal/kali/tools.go`

**Description:**
While the code uses `exec.Command()` with separate arguments (preventing basic shell injection), the tool installation commands in `kali/tools.go` lines 164-176 use `bash -c` with shell interpolation, creating command injection vectors.

**Vulnerable Code:**
```go
"nuclei": {"bash", []string{"-c", "command -v go >/dev/null 2>&1 && go install..."}}
```

**Impact:**
- Arbitrary code execution as the user running Zypheron
- Potential privilege escalation if sudo is used
- Full system compromise

**Recommendation:**
1. Remove all `bash -c` constructs from installation commands
2. Use direct `exec.Command()` calls with properly separated arguments
3. Implement additional runtime validation before any exec calls

---

### 2. Weak JWT Secret in Default Configuration

**Severity:** CRITICAL
**CVSS Score:** 9.1
**Location:** `/zypheron-api/app/core/config.py:58`

**Description:**
The default JWT secret key is hardcoded as `"dev-secret-UNSAFE-FOR-PRODUCTION"`.

**Impact:**
- Complete authentication bypass
- Ability to impersonate any user
- Unauthorized access to all API endpoints

**Recommendation:**
1. Remove default value entirely - require JWT_SECRET_KEY to be set
2. Fail fast on startup if JWT_SECRET_KEY is missing
3. Implement key rotation mechanism

---

### 3. IPC Authentication Token Stored in Plaintext

**Severity:** HIGH (borderline CRITICAL)
**CVSS Score:** 8.1
**Location:** `/zypheron-ai/core/server.py:49-78`, `/zypheron-go/internal/aibridge/bridge.go:188-202`

**Description:**
The IPC authentication token between Go CLI and Python backend is stored in plaintext at `~/.zypheron/ipc.token` with 0600 permissions.

**Impact:**
- Unauthorized access to AI engine functionality
- Bypass of licensing restrictions

**Recommendation:**
1. Implement token encryption at rest using OS keyring
2. Add token rotation mechanism
3. Use memory-locked pages for token storage in Go

---

## High Severity Findings

### 4. Missing Input Validation on Custom Arguments

**Severity:** HIGH
**CVSS Score:** 7.8
**Location:** `/zypheron-go/internal/tools/executor.go:73-83`

**Description:**
The `Args` field in `ExecutionOptions` accepts arbitrary arguments without validation.

**Recommendation:**
1. Implement argument validation and sanitization
2. Use allowlist for permitted arguments per tool
3. Reject arguments containing shell metacharacters

---

### 5. API Key Validation Only on Format, Not Authenticity

**Severity:** HIGH
**CVSS Score:** 7.5
**Location:** `/zypheron-ai/core/secure_config.py:69-147`

**Description:**
API keys are validated only by regex pattern matching, not by actual verification with the provider.

**Recommendation:**
1. Add optional API key verification during storage
2. Implement periodic key health checks
3. Add provider-specific permission verification

---

### 6. Unix Socket Ownership Validation Race Condition

**Severity:** HIGH
**CVSS Score:** 7.0
**Location:** `/zypheron-ai/core/secure_socket.py:170-219`

**Description:**
TOCTOU (Time-of-Check-Time-of-Use) race condition between socket ownership validation and connection.

**Recommendation:**
1. Use file descriptor passing instead of path-based connection
2. Implement atomic socket creation and connection
3. Use abstract namespace sockets (Linux)

---

### 7. Session Tokens Never Expire (Default Configuration)

**Severity:** HIGH
**CVSS Score:** 6.8
**Location:** `/zypheron-api/app/core/config.py:62`

**Description:**
JWT tokens are configured with 0 expiration by default.

**Recommendation:**
1. Set reasonable default expiration (24 hours)
2. Implement refresh token mechanism
3. Add forced re-authentication for sensitive operations

---

## Medium Severity Findings

### 8. Insufficient Rate Limiting on Device Code Generation

**Severity:** MEDIUM
**CVSS Score:** 6.5
**Location:** `/zypheron-api/app/routers/auth.py:396-472`

**Recommendation:**
1. Add strict rate limiting (3 requests per hour per IP)
2. Increase user code entropy
3. Add CAPTCHA for device code generation

---

### 9. Verbose Error Messages Leak System Information

**Severity:** MEDIUM
**CVSS Score:** 5.3
**Location:** Multiple locations

**Recommendation:**
1. Implement error sanitization layer
2. Log detailed errors server-side only
3. Return generic errors to users

---

### 10. No Integrity Verification for AI Model Responses

**Severity:** MEDIUM
**CVSS Score:** 5.5
**Location:** `/zypheron-ai/core/server.py:216-242`

**Recommendation:**
1. Implement response signing for critical operations
2. Add response validation against expected schemas
3. Implement provider certificate pinning

---

## Low Severity Findings

### 11. Permissive CORS Configuration

**Severity:** LOW
**CVSS Score:** 4.3

**Recommendation:**
1. Review and restrict CORS origins
2. Never use `*` in production

---

### 12. Missing Security Headers

**Severity:** LOW
**CVSS Score:** 3.7

**Recommendation:**
1. Implement comprehensive security headers middleware
2. Add Content Security Policy
3. Enable HSTS for production

---

## Positive Security Controls Identified

1. **Input Validation Framework:** Comprehensive validation in `validation/validator.go`
2. **Tool Allowlisting:** Strict allowlist for security tools
3. **API Key Encryption:** Uses OS keyring for secure storage
4. **IPC Socket Security:** Ownership validation and restrictive permissions
5. **SQL Injection Protection:** Uses parameterized queries (SQLAlchemy ORM)
6. **Password Hashing:** bcrypt implementation
7. **Context-based Timeouts:** Prevents resource exhaustion
8. **Audit Logging:** Present in configuration

---

## Dependency Vulnerability Analysis

### Python Dependencies
- **anthropic>=0.34.0** - Check for known CVEs
- **openai>=1.42.0** - Verify latest security patches
- **cryptography>=42.0.0** - Good, recent version
- **aiohttp>=3.9.5** - Known vulnerabilities in older versions

### Go Dependencies
- **golang.org/x/net v0.47.0** - Check for HTTP/2 vulnerabilities
- **github.com/chromedp/chromedp v0.14.2** - Browser automation risks

**Recommendation:** Run `pip-audit` and `govulncheck` regularly

---

## Immediate Action Items

1. **Remove `bash -c` from tool installation** (Day 1)
2. **Enforce JWT_SECRET_KEY requirement** (Day 1)
3. **Implement IPC token encryption** (Week 1)
4. **Add argument validation to tool executor** (Week 1)
5. **Enable JWT token expiration with refresh tokens** (Week 2)
6. **Implement comprehensive rate limiting** (Week 2)
7. **Run full dependency vulnerability scan** (Ongoing)

---

## Compliance Considerations

- **OWASP Top 10 2021:** Addresses A01 (Broken Access Control), A02 (Cryptographic Failures), A03 (Injection)
- **CWE-77:** Command Injection vulnerabilities present
- **CWE-798:** Hardcoded credentials in default configuration
- **PCI-DSS:** If handling regulated financial data, additional controls would be required
- **GDPR:** User data handling requires privacy controls

---

*Audit conducted: 2025-12-30*
*Auditor: Claude Opus 4.5 (Security Analysis Mode)*
*Project: Zypheron AI-Powered Penetration Testing CLI*
