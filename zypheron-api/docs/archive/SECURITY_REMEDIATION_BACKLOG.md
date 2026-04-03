# Security Remediation Backlog

**Generated:** 2026-01-03
**Last Updated:** 2026-01-11
**Review Type:** Comprehensive Security Code Review
**Status:** Major security fixes complete, remaining items documented below

---

## ✅ FIXED - HIGH Priority Issues

### AUTH-H1: Timing Attack in OAuth State Validation ✅ FIXED
- **Location:** `app/routers/auth.py:519`
- **Issue:** String comparison using `!=` is vulnerable to timing attacks
- **Fix Applied:** Uses `secrets.compare_digest()` for constant-time comparison
- **Fixed Date:** 2026-01-11

### AUTH-H2: Email Enumeration Vulnerability ✅ FIXED
- **Location:** `app/routers/auth.py`
- **Issue:** Different error messages reveal whether email exists
- **Fix Applied:** Returns generic messages for all authentication flows
- **Fixed Date:** 2026-01-11

### AUTH-H3: Missing Account Lockout Protection ✅ FIXED
- **Location:** `app/routers/auth.py`, `app/models/user.py`
- **Issue:** No rate limiting or lockout after failed login attempts
- **Fix Applied:** Added `failed_login_attempts`, `locked_until`, `is_locked()` method, `MAX_FAILED_ATTEMPTS`
- **Fixed Date:** 2026-01-11

### AUTH-H4: Session Fixation Vulnerability ✅ FIXED
- **Location:** `app/routers/auth.py`
- **Issue:** No session limit per user, old sessions not invalidated
- **Fix Applied:** Added `SESSION_LIMITS` dict, `enforce_session_limit()` to limit active sessions per tier
- **Fixed Date:** 2026-01-11

### CRYPTO-H1: Weak Encryption Algorithm (AES-128) ✅ FIXED
- **Location:** `app/core/encryption.py`
- **Issue:** Fernet uses AES-128-CBC, should use AES-256-GCM
- **Fix Applied:** Upgraded to AES-256-GCM with dual-read migration (supports both GCM and legacy Fernet)
- **Format:** `gcm:v{version}:{nonce_b64}:{ciphertext_b64}`
- **Config:** `BYOK_ENCRYPTION_KEY_GCM_V1` through V5 for key rotation
- **Fixed Date:** 2026-01-11

### PROXY-H1: License Bypass via Provider Auto-Selection ✅ FIXED
- **Location:** `app/routers/ai_proxy.py:883-907`
- **Issue:** Provider selected before license check
- **Fix Applied:** Filters available providers by tier BEFORE auto-selection. Free tier can ONLY use Ollama.
- **Fixed Date:** 2026-01-11

### PROXY-H3: Missing Transaction Rollback on Token Failure ✅ FIXED
- **Location:** `app/routers/ai_proxy.py`
- **Issue:** API response sent before token deduction confirmed
- **Fix Applied:** Implemented `TokenReservationService` - reserves tokens BEFORE API call, finalizes/releases after
- **Fixed Date:** 2026-01-11

### TOKEN-H1: Integer Overflow in Token Counts ✅ FIXED
- **Location:** `app/services/token_sync.py:64-66, 163-179`
- **Issue:** No maximum bound on token counts
- **Fix Applied:** Added `MAX_TOKENS_PER_REQUEST = 10,000,000` with validation in `calculate_normalized_tokens()`
- **Fixed Date:** 2026-01-11

### TOKEN-H2: Redis Key Injection Vulnerability ✅ FIXED
- **Location:** `app/services/token_sync.py:75-95`
- **Issue:** user_id interpolated into Redis keys without validation
- **Fix Applied:** Added `validate_user_id()` function - validates positive integer within 32-bit range
- **Fixed Date:** 2026-01-11

---

## 🔴 REMAINING - HIGH Priority Issues (Fix Within 1 Week)

### PROXY-H2: BYOK Key Exposure via Error Messages
- **Location:** `app/routers/ai_proxy.py:401-411`
- **Issue:** Decryption errors confirm BYOK key exists
- **Fix:** Return generic error, treat as "no key found"

### PROXY-H4: Redis Pipeline Execution Not Validated
- **Location:** `app/routers/ai_proxy.py:271-286`
- **Issue:** Pipeline results not checked for failures
- **Fix:** Validate all pipeline command results

### DEVICE-H1: N+1 Query in Device Limit Check
- **Location:** `app/routers/devices.py:92-99`
- **Issue:** Fetches all devices when only count needed
- **Fix:** Use `SELECT COUNT(*)` for limit check

### TEAMS-H1: Missing License Expiration Check
- **Location:** `app/routers/teams.py:54-73`
- **Issue:** Enterprise check doesn't validate license.is_valid()
- **Fix:** Check license status and valid_until date

---

## MEDIUM Priority Issues (Fix Within 1 Month)

### Information Disclosure

| ID | Location | Issue |
|----|----------|-------|
| INFO-M1 | `auth.py:159-162` | Encryption errors leak crypto details |
| INFO-M2 | `byok.py:56-60` | Provider API status codes exposed |
| INFO-M3 | `devices.py:121-132` | Device hostnames in error responses |
| INFO-M4 | `rate_limiter.py:160-186` | Timing attack on user tier detection |

### Input Validation

| ID | Location | Issue |
|----|----------|-------|
| INPUT-M1 | `ai_proxy.py:933-934` | No maximum message size validation |
| INPUT-M2 | `ai_proxy.py:616-635` | Cache poisoning via unvalidated params |
| INPUT-M3 | `byok.py:26-31` | API key max length too permissive (500) |
| INPUT-M4 | `tokens.py:174-179` | Pagination overflow possible |
| INPUT-M5 | `device.py:18-23` | Weak device UUID validation |

### Code Quality

| ID | Location | Issue |
|----|----------|-------|
| CODE-M1 | `ai_proxy.py:57-58` | Global mutable state |
| CODE-M2 | `ai_proxy.py:784-972` | Function too long (188 lines) |
| CODE-M3 | `rate_limiter.py` vs `ai_proxy.py` | Inconsistent fail-open/closed |
| CODE-M4 | `token_sync.py:563-600` | Missing type hints |

### Missing Features

| ID | Location | Issue |
|----|----------|-------|
| FEAT-M1 | All routers | No request ID correlation |
| FEAT-M2 | `main.py` | CORS configuration not documented |
| FEAT-M3 | All routers | Missing audit logging |
| FEAT-M4 | `auth.py:589-605` | Expired session cleanup not scheduled |

### Database

| ID | Location | Issue |
|----|----------|-------|
| DB-M1 | `devices.py` | Missing composite index on (user_id, is_active) |
| DB-M2 | `token_sync.py:204-214` | Missing transaction handling |
| DB-M3 | `token_sync.py:633-645` | Inefficient historical usage query |

### Rate Limiting

| ID | Location | Issue |
|----|----------|-------|
| RATE-M1 | `ai_proxy.py:276-277` | Weak randomness in rate limit keys |
| RATE-M2 | `ai_proxy.py:1258-1262` | Stream token counting uses 50/50 estimation |
| RATE-M3 | `devices.py:325-364` | Ping endpoint has no rate limit |

---

## LOW Priority Issues (Technical Debt)

### Code Quality
- `load_balancer.py:346-463` - Duplicate logic, violates DRY
- `token_sync.py` - Magic numbers for cost multipliers
- `device.py:136-162` - Duplicate validation logic
- `teams.py` - Integer IDs allow enumeration (should use UUID)

### API Design
- `devices.py:367` - RESTful convention violated on `/limit` path
- `teams.py` - Redundant status_code in decorator AND exception
- `devices.py:165` - Missing pagination on list endpoint
- Multiple files - Inconsistent error response formats

### Performance
- `rate_limiter.py:198-207` - Database query on every request (N+1)
- `ai_proxy.py:280-281` - ZREMRANGEBYSCORE on every request
- `base.py:154-158` - Conservative connection pool limits

### Documentation
- Missing CORS headers documentation
- No audit logging setup guide
- Device limits defined in multiple places

---

## Compliance Mapping

### OWASP Top 10 (2021)
| Finding | OWASP Category |
|---------|---------------|
| Plaintext tokens | A02:2021 - Cryptographic Failures |
| OAuth state issues | A01:2021 - Broken Access Control |
| Email enumeration | A01:2021 - Broken Access Control |
| No lockout | A07:2021 - Identification and Authentication Failures |
| Error leakage | A05:2021 - Security Misconfiguration |

### CWE References
- CWE-256: Plaintext Storage of a Password
- CWE-208: Observable Timing Discrepancy
- CWE-320: Key Management Errors
- CWE-347: Improper Verification of Cryptographic Signature
- CWE-918: Server-Side Request Forgery (SSRF)

---

## Testing Recommendations

### Security Tests to Add
```python
# Test concurrent token deduction
async def test_concurrent_quota_bypass():
    """Verify quota can't be bypassed via concurrent requests."""

# Test rate limit bypass
async def test_concurrent_rate_limit_bypass():
    """Verify rate limits hold under concurrent load."""

# Test device registration race
async def test_concurrent_device_registration():
    """Verify device limits can't be bypassed."""

# Test SSRF protection
async def test_ollama_ssrf_blocked():
    """Verify internal URLs are blocked for Ollama."""

# Test encryption key rotation
async def test_key_rotation_decryption():
    """Verify old keys can still decrypt after rotation."""
```

### Penetration Testing Focus
1. Concurrent request attacks on quota/rate limits
2. OAuth CSRF bypass attempts
3. SSRF via Ollama URL parameter
4. Timing attacks on authentication
5. Error message information extraction

---

## Remediation Tracking

| Issue ID | Status | Fixed Date |
|----------|--------|------------|
| AUTH-H1 | ✅ Fixed | 2026-01-11 |
| AUTH-H2 | ✅ Fixed | 2026-01-11 |
| AUTH-H3 | ✅ Fixed | 2026-01-11 |
| AUTH-H4 | ✅ Fixed | 2026-01-11 |
| CRYPTO-H1 | ✅ Fixed | 2026-01-11 |
| PROXY-H1 | ✅ Fixed | 2026-01-11 |
| PROXY-H2 | 🔴 TODO | - |
| PROXY-H3 | ✅ Fixed | 2026-01-11 |
| PROXY-H4 | 🔴 TODO | - |
| TOKEN-H1 | ✅ Fixed | 2026-01-11 |
| TOKEN-H2 | ✅ Fixed | 2026-01-11 |
| DEVICE-H1 | 🔴 TODO | - |
| TEAMS-H1 | 🔴 TODO | - |

**Summary:** 9/13 HIGH priority issues fixed (69%)

---

**Next Review:** After remaining HIGH priority fixes deployed
**Contact:** Security Team
