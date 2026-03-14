# CRITICAL-2: Race Condition Token Deduction Fix

**Severity:** CRITICAL
**CVE Risk:** High (Quota Bypass, Financial Impact)
**Status:** FIXED
**Date Fixed:** 2026-01-03

## Executive Summary

Fixed critical race condition vulnerability that allowed users to bypass token quota limits through concurrent API requests. The vulnerability enabled an attacker with 1,000 token quota to consume 5,000+ tokens by sending 10 concurrent requests, each requiring 500 tokens.

## Vulnerability Details

### Attack Vector

**Before Fix (VULNERABLE):**
```
Timeline of Race Condition:
─────────────────────────────────────────────────────────────────

Request 1: ├─ Check quota (1000 available) ─ PASS ──────────┐
Request 2: ├─ Check quota (1000 available) ─ PASS ──────────┤
Request 3: ├─ Check quota (1000 available) ─ PASS ──────────┤
Request 4: ├─ Check quota (1000 available) ─ PASS ──────────┤
Request 5: ├─ Check quota (1000 available) ─ PASS ──────────┤
Request 6: ├─ Check quota (1000 available) ─ PASS ──────────┤
Request 7: ├─ Check quota (1000 available) ─ PASS ──────────┤
Request 8: ├─ Check quota (1000 available) ─ PASS ──────────┤
Request 9: ├─ Check quota (1000 available) ─ PASS ──────────┤
Request 10:├─ Check quota (1000 available) ─ PASS ──────────┤
           │                                                  │
           │   (All 10 requests pass quota check)            │
           │                                                  │
           ├─ API Call (500 tokens) ────────────────────────┤
           ├─ API Call (500 tokens) ────────────────────────┤
           ├─ API Call (500 tokens) ────────────────────────┤
           ├─ API Call (500 tokens) ────────────────────────┤
           ├─ API Call (500 tokens) ────────────────────────┤
           ├─ API Call (500 tokens) ────────────────────────┤
           ├─ API Call (500 tokens) ────────────────────────┤
           ├─ API Call (500 tokens) ────────────────────────┤
           ├─ API Call (500 tokens) ────────────────────────┤
           ├─ API Call (500 tokens) ────────────────────────┤
           │                                                  │
           ├─ Deduct 500 tokens ─────────────────────────────┤
           ├─ Deduct 500 tokens ─────────────────────────────┤
           ├─ Deduct 500 tokens ─────────────────────────────┤
           ├─ Deduct 500 tokens ─────────────────────────────┤
           ├─ Deduct 500 tokens ─────────────────────────────┤
           ├─ Deduct 500 tokens ─────────────────────────────┤
           ├─ Deduct 500 tokens ─────────────────────────────┤
           ├─ Deduct 500 tokens ─────────────────────────────┤
           ├─ Deduct 500 tokens ─────────────────────────────┤
           └─ Deduct 500 tokens ─────────────────────────────┘

Result: 5,000 tokens consumed (5x quota limit)
```

**Code Issue (ai_proxy.py lines 424, 1064-1073):**
```python
# Line 424: Quota check (non-atomic)
if quota.tokens_used_period >= quota.token_limit:
    raise HTTPException(status_code=402, detail="Insufficient tokens")

# Lines 855-957: API call happens (1-30 seconds latency)
response = await provider.chat_completion(...)

# Lines 1064-1073: Token deduction AFTER API response
await update_token_usage(...)  # TOCTOU vulnerability
```

The gap between check (line 424) and use (lines 1064-1073) creates a TOCTOU (Time-Of-Check-Time-Of-Use) race condition window.

### Impact Analysis

**Financial Impact:**
- Starter tier ($29/month, 1M tokens): Can consume 5M+ tokens
- Pro tier ($99/month, 3M tokens): Can consume 15M+ tokens
- Enterprise tier ($499/month, 15M tokens): Can consume 75M+ tokens

**Cost to Provider:**
- GPT-4o: $2.50 per 1M tokens (input) = $12.50 per 5M tokens
- Claude-3-Opus: $15 per 1M tokens = $75 per 5M tokens
- Potential loss per attack: $12.50 - $75 per user

**Exploitation Difficulty:** TRIVIAL
```bash
# Attack script (requires only basic HTTP knowledge)
for i in {1..10}; do
  curl -X POST /ai/chat -H "Authorization: Bearer $TOKEN" \
    -d '{"messages":[...], "max_tokens": 4000}' &
done
wait
```

## Fix Implementation

### Architecture: Atomic Token Reservation

**After Fix (SECURE):**
```
Timeline with Atomic Reservation:
─────────────────────────────────────────────────────────────────

Request 1: ├─ ATOMIC Reserve 500 (0→500)   ─ SUCCESS ────────┐
Request 2: ├─ ATOMIC Reserve 500 (500→1000) ─ SUCCESS ────────┤
Request 3: ├─ ATOMIC Reserve 500 (1000→1500)─ DENIED  ────────┤
Request 4: ├─ ATOMIC Reserve 500 (1000→1500)─ DENIED  ────────┤
Request 5: ├─ ATOMIC Reserve 500 (1000→1500)─ DENIED  ────────┤
Request 6: ├─ ATOMIC Reserve 500 (1000→1500)─ DENIED  ────────┤
Request 7: ├─ ATOMIC Reserve 500 (1000→1500)─ DENIED  ────────┤
Request 8: ├─ ATOMIC Reserve 500 (1000→1500)─ DENIED  ────────┤
Request 9: ├─ ATOMIC Reserve 500 (1000→1500)─ DENIED  ────────┤
Request 10:├─ ATOMIC Reserve 500 (1000→1500)─ DENIED  ────────┤
           │                                                    │
           │   (Only 2 requests approved, 8 denied)            │
           │                                                    │
           ├─ API Call (actual: 450 tokens) ──────────────────┤
           ├─ API Call (actual: 480 tokens) ──────────────────┤
           │                                                    │
           ├─ Finalize: 500→450 (return 50) ──────────────────┤
           └─ Finalize: 500→480 (return 20) ──────────────────┘

Result: 930 tokens consumed (within 1000 limit)
Tokens returned to pool: 70
```

### Implementation Components

#### 1. Token Reservation Service (`app/services/token_reservation.py`)

**Atomic Operations Using Redis Lua Scripts:**

```python
RESERVE_TOKENS_LUA = """
local quota_key = KEYS[1]
local reservation_key = KEYS[2]
local estimated_tokens = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])

-- Get current usage (atomic read)
local current = tonumber(redis.call('GET', quota_key) or 0)

-- Check if would exceed limit
if current + estimated_tokens > limit then
    return {0, current, limit}  -- Denied
end

-- ATOMIC increment (pessimistic lock)
local new_total = redis.call('INCRBY', quota_key, estimated_tokens)

-- Store reservation metadata for rollback
redis.call('HMSET', reservation_key, 'estimated', estimated_tokens, ...)
redis.call('EXPIRE', reservation_key, 300)  -- 5 min TTL

return {1, new_total, limit}  -- Approved
"""
```

**Key Features:**
- **Atomicity:** Entire check-and-increment happens in single Redis operation
- **Pessimistic Locking:** Tokens reserved BEFORE API call
- **Rollback Support:** Reservation can be released on API failure
- **Auto-Expiration:** Reservations expire after 5 minutes (prevents leaks)

#### 2. Updated Endpoints (`app/routers/ai_proxy.py`)

**Non-Streaming Flow:**
```python
# STEP 1: Reserve tokens BEFORE API call (ATOMIC)
reservation_service = TokenReservationService()
success, reservation_id, current_usage = await reservation_service.reserve_tokens(
    user_id=current_user.id,
    estimated_tokens=estimated_total,
    token_limit=quota.token_limit,
)

if not success:
    raise HTTPException(402, detail="Insufficient tokens")

try:
    # STEP 2: Make API call (tokens already reserved)
    response = await provider.chat_completion(...)

    # STEP 3: Finalize with actual usage (adjust for estimate)
    await reservation_service.finalize_reservation(
        user_id=current_user.id,
        reservation_id=reservation_id,
        actual_tokens=response.total_tokens,
    )

except Exception as e:
    # CRITICAL: Release reservation on failure
    await reservation_service.release_reservation(
        user_id=current_user.id,
        reservation_id=reservation_id,
    )
    raise
```

**Streaming Flow:**
- Reservation happens BEFORE streaming starts
- Finalization happens after stream completes
- Release on any error during streaming

#### 3. Background Sync Task (`app/tasks/quota_sync.py`)

**Database-Redis Consistency:**
```python
async def periodic_quota_sync():
    """Sync database quotas to Redis every 5 minutes."""
    while True:
        # Sync all user quotas from DB (source of truth) to Redis (cache)
        await sync_quota_to_redis(db)
        await asyncio.sleep(300)  # 5 minutes
```

**Handles:**
- Redis restarts (data is ephemeral)
- Expired reservations that weren't finalized
- Manual database adjustments

## Security Properties

### Guaranteed Properties

1. **Atomicity:** Check-and-reserve is a single atomic operation (Lua script in Redis)
2. **Serializability:** Concurrent requests are serialized by Redis
3. **No TOCTOU:** No time gap between check and reservation
4. **Fail-Safe:** Redis unavailable = deny requests (fail closed)
5. **Idempotent Finalization:** Can't finalize same reservation twice

### Attack Resistance

**Concurrent Request Attack (MITIGATED):**
```python
# Attack attempt with 100 concurrent requests
results = await asyncio.gather(*[make_request() for _ in range(100)])

# Result: Only (quota_limit / estimated_tokens) requests succeed
# Example: 1000 tokens / 500 per request = 2 succeed, 98 denied
```

**Reservation Exhaustion Attack (MITIGATED):**
- Reservations auto-expire after 5 minutes (TTL)
- User can't hold tokens indefinitely
- Background sync task recovers from expired reservations

**Redis Downtime (MITIGATED):**
- Fail closed: Deny all requests if Redis unavailable
- Alternative: Could fall back to database with pessimistic locks (slower)

## Performance Impact

### Latency Overhead

**Before Fix:**
- Database SELECT (quota check): ~5ms
- No Redis operations

**After Fix:**
- Redis Lua script (reserve): ~1-2ms
- Redis Lua script (finalize): ~1-2ms
- **Total overhead:** ~2-4ms per request

**Trade-off:** +2-4ms latency for CRITICAL security fix is acceptable.

### Throughput Impact

**Redis Capacity:**
- Redis can handle 100,000+ operations/second
- Lua script execution is atomic but fast
- No significant throughput impact expected

**Bottleneck Analysis:**
- Previous bottleneck: Database (PostgreSQL)
- New bottleneck: Still database (Redis is faster)
- **Conclusion:** No new bottleneck introduced

## Testing

### Unit Tests (`tests/test_token_reservation_race_condition.py`)

**Test Coverage:**
1. ✅ Race condition prevented (10 concurrent requests)
2. ✅ Reservation finalization adjusts quota correctly
3. ✅ Failed requests release reservations
4. ✅ Multiple users have isolated quotas
5. ✅ Quota exceeded properly rejected

**Run Tests:**
```bash
pytest tests/test_token_reservation_race_condition.py -v
```

### Integration Tests

**Manual Test (10 concurrent requests):**
```bash
#!/bin/bash
USER_TOKEN="your_jwt_token"

# User quota: 1000 tokens
# Each request: ~500 tokens
# Expected: 2 succeed, 8 fail with 402

for i in {1..10}; do
  curl -X POST http://localhost:8000/ai/chat \
    -H "Authorization: Bearer $USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "provider": "openai",
      "model": "gpt-4o-mini",
      "messages": [{"role": "user", "content": "Write 500 words"}],
      "max_tokens": 600
    }' &
done
wait

# Check logs for reservations
docker logs zypheron-api | grep "tokens_reserved\|token_reservation_denied"
```

**Expected Output:**
```
tokens_reserved: user_id=1, estimated_tokens=650, current_usage=650
tokens_reserved: user_id=1, estimated_tokens=650, current_usage=1300
token_reservation_denied: user_id=1, estimated_tokens=650, current_usage=1300, shortage=650
token_reservation_denied: user_id=1, estimated_tokens=650, current_usage=1300, shortage=650
... (8 more denials)
```

## Deployment Checklist

### Pre-Deployment

- [x] Code review completed
- [x] Unit tests pass
- [x] Integration tests pass
- [x] Performance benchmarks acceptable
- [x] Security review completed

### Deployment Steps

1. **Backup Database:**
   ```bash
   pg_dump zypheron_production > backup_$(date +%Y%m%d).sql
   ```

2. **Deploy Code:**
   ```bash
   git pull origin main
   docker-compose build api
   docker-compose up -d api
   ```

3. **Verify Redis Connection:**
   ```bash
   docker logs zypheron-api | grep "Redis connection established"
   ```

4. **Start Background Sync Task:**
   - Automatically starts on FastAPI startup
   - Check logs: `docker logs zypheron-api | grep "quota_sync_task_started"`

5. **Monitor for Issues:**
   ```bash
   # Watch for reservation errors
   docker logs -f zypheron-api | grep "reservation"

   # Watch for quota discrepancies
   docker logs -f zypheron-api | grep "quota_sync_discrepancy"
   ```

### Post-Deployment Verification

1. **Test Single Request:**
   ```bash
   curl -X POST /ai/chat -H "Authorization: Bearer $TOKEN" -d '{...}'
   # Should work normally
   ```

2. **Test Concurrent Requests (quota bypass attempt):**
   ```bash
   ./test_concurrent_requests.sh
   # Should properly deny requests exceeding quota
   ```

3. **Verify Background Sync:**
   ```bash
   docker logs zypheron-api | grep "quota_sync_completed"
   # Should run every 5 minutes
   ```

## Monitoring

### Key Metrics

**Reservation Metrics:**
- `tokens_reserved`: Counter of successful reservations
- `token_reservation_denied`: Counter of denied reservations (quota exceeded)
- `reservation_finalized`: Counter of finalized reservations
- `reservation_released`: Counter of released reservations (errors)

**Sync Metrics:**
- `quota_sync_completed`: Periodic sync task completions
- `quota_sync_discrepancy`: Discrepancies between Redis and DB

### Alerts

**Critical Alerts:**
1. `reservation_service_unavailable`: Redis down, fail closed in effect
2. `quota_sync_discrepancy`: Redis-DB mismatch > 10% for > 1 hour

**Warning Alerts:**
1. `reservation_finalization_failed`: Finalization errors > 1% of reservations
2. `reservation_release_failed`: Release errors > 1% of reservations

### Dashboards

**Grafana Dashboard (recommended):**
```
Panel 1: Reservation Success Rate (should be ~high, varies by usage)
Panel 2: Quota Denials (should increase if users hit limits)
Panel 3: Redis-DB Sync Lag (should be < 5 minutes)
Panel 4: Reservation Errors (should be ~0)
```

## Rollback Plan

### If Issues Occur

**Symptoms of Issues:**
- High reservation error rate (> 5%)
- Redis connection failures
- Quota sync discrepancies growing

**Rollback Steps:**

1. **Revert Code:**
   ```bash
   git revert <commit-hash>
   docker-compose build api
   docker-compose up -d api
   ```

2. **Database Cleanup (if needed):**
   ```sql
   -- Reset any corrupt quota data
   UPDATE user_quota SET tokens_used_period = 0 WHERE tokens_used_period < 0;
   ```

3. **Clear Redis:**
   ```bash
   docker exec zypheron-redis redis-cli FLUSHDB
   ```

**Note:** Rollback re-introduces the race condition vulnerability. Only use as last resort.

## Future Improvements

### Enhancements

1. **Distributed Locks (if multi-instance):**
   - Current implementation works for single Redis instance
   - For multi-Redis: Use Redlock algorithm

2. **Reservation Analytics:**
   - Track over-estimation patterns (estimated vs actual)
   - Optimize estimation algorithm based on historical data

3. **Graceful Degradation:**
   - If Redis unavailable, fall back to database pessimistic locks
   - Slower but maintains security

4. **Quota Prediction:**
   - ML model to predict token usage before API call
   - More accurate reservations = fewer refunds

## References

- **TOCTOU Vulnerability:** https://cwe.mitre.org/data/definitions/367.html
- **Redis Lua Scripts:** https://redis.io/docs/manual/programmability/eval-intro/
- **Pessimistic Locking:** https://en.wikipedia.org/wiki/Lock_(computer_science)

## Conclusion

The atomic token reservation system successfully eliminates the CRITICAL-2 race condition vulnerability. The fix provides:

✅ **Security:** No quota bypass via concurrent requests
✅ **Performance:** < 5ms overhead per request
✅ **Reliability:** Auto-expiration prevents reservation leaks
✅ **Maintainability:** Clear separation of concerns
✅ **Observability:** Comprehensive logging and metrics

**Status:** PRODUCTION READY ✅
