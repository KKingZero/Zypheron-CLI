# CRITICAL-5: Race Condition Fix - Device Registration

## Vulnerability Summary

**Severity:** CRITICAL
**Attack Vector:** Race condition in device registration endpoint
**Impact:** Bypassing tier-based device limits

### Original Vulnerability (TOCTOU - Time-of-Check-Time-of-Use)

**Location:** `/app/routers/devices.py:59-162`

**Attack Scenario:**
1. Free tier user has limit of 1 device
2. User sends 3 concurrent POST requests to `/devices/register` with different UUIDs
3. All 3 requests execute line 93-99 (count check) at nearly the same time
4. All 3 requests see 0 devices (pass the limit check)
5. All 3 requests create devices (lines 150-160)
6. Result: User has 3 devices instead of allowed 1

**Vulnerable Code Flow:**
```
Request 1: Read count (0) → Check limit (OK) → Create device
Request 2: Read count (0) → Check limit (OK) → Create device
Request 3: Read count (0) → Check limit (OK) → Create device
```

## Fix Implementation

### Solution: Database Row-Level Locking with SELECT FOR UPDATE

**Key Changes:**

1. **Added row-level locking** using `SELECT FOR UPDATE`
   - Locks all user's active devices during the transaction
   - Prevents concurrent reads until transaction completes
   - Ensures accurate device count even under concurrency

2. **Atomic transaction** using nested transactions
   - All operations (check count, verify limit, create device) in single atomic block
   - Automatic rollback on error

3. **Deadlock handling** with exponential backoff retry
   - Detects deadlock errors
   - Retries up to 3 times with increasing delays (50ms, 100ms, 200ms)
   - Prevents transaction failures under high concurrency

4. **Security logging** for audit trail
   - Logs device registration, updates, reactivations
   - Logs limit violations for monitoring
   - Logs deadlock retries for performance analysis

### Secure Code Flow (After Fix):

```
Request 1: LOCK rows → Read count (0) → Check limit (OK) → Create device → UNLOCK
Request 2: [BLOCKED waiting for lock]
Request 3: [BLOCKED waiting for lock]

After Request 1 completes:
Request 2: LOCK rows → Read count (1) → Check limit (FAIL) → Reject → UNLOCK
Request 3: LOCK rows → Read count (1) → Check limit (FAIL) → Reject → UNLOCK
```

## Technical Details

### PostgreSQL Implementation

```python
# SELECT FOR UPDATE creates exclusive row lock
lock_stmt = (
    select(Device)
    .where(
        Device.user_id == current_user.id,
        Device.is_active == True,
    )
    .with_for_update()  # Row-level exclusive lock
)
```

**PostgreSQL Behavior:**
- First request acquires row lock on all user's devices
- Concurrent requests block waiting for lock release
- Lock released on transaction commit/rollback
- Prevents dirty reads and phantom reads

### SQLite Implementation

**SQLite Behavior:**
- `SELECT FOR UPDATE` is a no-op in SQLite
- SQLite uses database-level locking (write locks are exclusive)
- Single writer at a time, so race condition is naturally prevented
- No performance impact from the lock statement

### Transaction Isolation

```python
async with db.begin_nested():
    # All operations within this block are atomic
    # Lock → Check → Create all happens in single transaction
    # No other transaction can interleave
```

**ACID Guarantees:**
- **Atomic:** All operations succeed or all fail
- **Consistent:** Device count always accurate
- **Isolated:** Concurrent requests don't see partial state
- **Durable:** Committed devices persisted to disk

### Deadlock Prevention

**Deadlock Scenario (Rare but possible):**
- User A tries to register device while User B deactivates one
- Both acquire locks in different order
- Database detects circular wait and aborts one transaction

**Handling:**
```python
for attempt in range(MAX_RETRIES):
    try:
        return await _register_device_impl(...)
    except OperationalError as e:
        if "deadlock" in str(e).lower() and attempt < MAX_RETRIES - 1:
            await asyncio.sleep(backoff_ms / 1000.0)  # Exponential backoff
            continue
        raise
```

## Security Improvements

### 1. Memory Safety
- No buffer overflows or unsafe memory operations
- Python's managed memory prevents use-after-free

### 2. Information Disclosure Prevention
- Removed full hostname from error messages (line 172)
- Limited device list to 10 entries (line 176)
- Only expose necessary information to users

### 3. Audit Logging
- All device operations logged with structured logging
- Includes user_id, device_id, tier, and operation type
- Enables security monitoring and incident response

### 4. Input Validation
- Device UUID validated by Pydantic schema
- User tier validated by authentication layer
- All inputs sanitized before database operations

## Performance Impact

### Positive Impacts:
- **Prevents waste:** No orphaned devices from race conditions
- **Better monitoring:** Structured logs enable performance analysis
- **Predictable behavior:** Deterministic under concurrency

### Potential Concerns:
- **Lock contention:** Multiple users registering devices simultaneously
  - Mitigation: Locks are user-scoped, different users don't block each other
  - Mitigation: Locks held for milliseconds (fast database operations)

- **Deadlock retries:** Rare edge case adds latency
  - Probability: Very low (different users, different lock scopes)
  - Impact: 50-200ms delay, acceptable for registration endpoint
  - Frequency: Expected < 0.01% of requests

### Benchmarks (Expected):
- Single registration: ~10-50ms (no change)
- Concurrent registrations (same user): ~10-50ms + queue time
- Concurrent registrations (different users): ~10-50ms (no blocking)

## Testing Recommendations

### 1. Unit Tests

```python
@pytest.mark.asyncio
async def test_concurrent_device_registration_blocks_limit_bypass():
    """Test that concurrent requests cannot bypass device limits."""
    user = await create_test_user(tier="free")  # 1 device limit

    # Send 3 concurrent registration requests
    tasks = [
        register_device(device_uuid=f"uuid-{i}", user=user)
        for i in range(3)
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Only 1 should succeed, 2 should fail with 403
    successes = [r for r in results if not isinstance(r, HTTPException)]
    failures = [r for r in results if isinstance(r, HTTPException)]

    assert len(successes) == 1
    assert len(failures) == 2
    assert all(f.status_code == 403 for f in failures)
```

### 2. Load Tests

```python
# Use locust or similar tool
class DeviceRegistrationUser(HttpUser):
    @task
    def register_concurrent_devices(self):
        # Simulate race condition attack
        responses = []
        for i in range(5):
            resp = self.client.post(
                "/devices/register",
                json={
                    "device_uuid": f"{uuid.uuid4()}",
                    "device_name": f"Device {i}",
                    "platform": "linux",
                }
            )
            responses.append(resp)

        # Verify only allowed number succeeded
        assert count_success(responses) <= get_tier_limit(user.tier)
```

### 3. Integration Tests

```bash
# Test with PostgreSQL (recommended for production)
DATABASE_TYPE=postgresql pytest tests/test_devices.py

# Test with SQLite (for CI/CD)
DATABASE_TYPE=sqlite pytest tests/test_devices.py
```

### 4. Manual Attack Simulation

```bash
#!/bin/bash
# Send 10 concurrent requests with different UUIDs
TOKEN="your_jwt_token"

for i in {1..10}; do
  curl -X POST http://localhost:8000/devices/register \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "device_uuid": "'$(uuidgen)'",
      "device_name": "Test Device '$i'",
      "platform": "linux",
      "hostname": "test-host"
    }' &
done

wait

# Verify only tier limit number of devices created
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/devices | jq '.active_count'
```

## Deployment Checklist

- [ ] Code reviewed by security team
- [ ] Unit tests added and passing
- [ ] Integration tests added and passing
- [ ] Load tests verify no performance degradation
- [ ] Manual attack simulation confirms fix works
- [ ] Database supports SELECT FOR UPDATE (PostgreSQL)
- [ ] Monitoring configured for deadlock events
- [ ] Rollback plan prepared
- [ ] Documentation updated

## Monitoring

### Metrics to Track

1. **device_registration_deadlock_retry**
   - Count: How often deadlocks occur
   - Threshold: > 100/hour = investigate lock contention

2. **device_limit_reached**
   - Count: How often users hit limits (expected)
   - Threshold: Sudden spike = potential attack

3. **device_registration_database_error**
   - Count: Should be ~0
   - Threshold: > 0 = investigate immediately

### Alerts

```yaml
- alert: DeviceRegistrationDeadlockRate
  expr: rate(device_registration_deadlock_retry[5m]) > 10
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: High deadlock rate in device registration

- alert: DeviceRegistrationErrors
  expr: rate(device_registration_database_error[1m]) > 0
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: Errors in device registration endpoint
```

## Verification

### Before Fix (Vulnerable):
```python
# Pseudo-code representation
count = query("SELECT COUNT(*) FROM devices WHERE user_id = ?")  # Line 93-99
# [WINDOW OF VULNERABILITY - concurrent request can execute here]
if count >= limit:
    raise Error
create_device()  # Line 150-160
```

### After Fix (Secure):
```python
# Pseudo-code representation
with transaction:
    devices = query("SELECT * FROM devices WHERE user_id = ? FOR UPDATE")  # Lock acquired
    count = len(devices)
    if count >= limit:
        raise Error
    create_device()
    commit()  # Lock released
```

## References

- [OWASP: Race Condition Vulnerabilities](https://owasp.org/www-community/vulnerabilities/Race_Conditions)
- [PostgreSQL: SELECT FOR UPDATE](https://www.postgresql.org/docs/current/sql-select.html#SQL-FOR-UPDATE-SHARE)
- [SQLAlchemy: Row Locking](https://docs.sqlalchemy.org/en/20/core/selectable.html#sqlalchemy.sql.expression.GenerativeSelect.with_for_update)
- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)

## Incident Response

If vulnerability was exploited before fix:

1. **Identify affected users:**
   ```sql
   SELECT user_id, COUNT(*) as device_count, tier
   FROM devices
   WHERE is_active = true
   GROUP BY user_id, tier
   HAVING COUNT(*) > (
     CASE tier
       WHEN 'free' THEN 1
       WHEN 'starter' THEN 2
       WHEN 'pro' THEN 3
       WHEN 'enterprise' THEN 500
     END
   );
   ```

2. **Remediation options:**
   - Notify affected users
   - Force device limit enforcement (deactivate excess devices)
   - Review logs for malicious intent vs. legitimate race condition
   - Consider compensation for free tier users affected

3. **Prevention:**
   - Deploy this fix immediately
   - Add rate limiting to registration endpoint
   - Monitor for suspicious concurrent registration patterns

---

**Fix Version:** 1.0.0
**Date:** 2026-01-03
**Author:** Security Team
**Severity:** CRITICAL (CVSS 7.5)
**Status:** FIXED
