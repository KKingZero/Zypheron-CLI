#!/usr/bin/env python3
"""Test script to verify atomic rate limiting prevents race condition bypass.

This script simulates concurrent requests to verify that the Lua script
prevents the race condition where multiple requests at the limit boundary
could all pass and bypass the rate limit.

BEFORE FIX: Two requests at 59/60 both see count=59, both pass = 61 total (BYPASS)
AFTER FIX: Atomic Lua script ensures only 60 requests can pass, 61st is denied

Requirements:
- Redis server running
- Run from zypheron-api directory
"""

import asyncio
import sys
import time
from pathlib import Path

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).parent))

from app.core.redis_client import RedisClient


# Lua script from the fix
ATOMIC_RATE_LIMIT_LUA = """
local key = KEYS[1]
local window_start = tonumber(ARGV[1])
local current_time = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local window_size = tonumber(ARGV[5])

-- Remove old entries outside window (cleanup)
redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

-- Get current count in window
local count = redis.call('ZCARD', key)

-- Check if at or over limit
if count >= limit then
    -- Denied - calculate reset time
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local reset_time = current_time + window_size
    if oldest and #oldest > 0 then
        reset_time = tonumber(oldest[2]) + window_size
    end
    return {0, count, reset_time}
end

-- Approved - add new entry atomically
redis.call('ZADD', key, current_time, member)
redis.call('EXPIRE', key, window_size * 2)

return {1, count + 1, current_time + window_size}
"""


async def test_atomic_rate_limit():
    """Test atomic rate limiting under concurrent load."""
    print("=" * 80)
    print("ATOMIC RATE LIMIT RACE CONDITION TEST")
    print("=" * 80)
    print()

    # Connect to Redis
    redis_client = RedisClient()
    await redis_client.connect()

    if not redis_client.is_available:
        print("ERROR: Redis not available. Please start Redis server.")
        return False

    print("✓ Redis connected successfully")
    print()

    # Test configuration
    test_key = "test:ratelimit:race_condition"
    rate_limit = 60
    window_size = 60
    concurrent_requests = 10  # Fire 10 requests simultaneously

    # Clean up any existing test data
    if hasattr(redis_client, '_client') and redis_client._client:
        await redis_client._client.delete(test_key)

    print(f"Test Configuration:")
    print(f"  Rate Limit: {rate_limit} requests/minute")
    print(f"  Window Size: {window_size} seconds")
    print(f"  Concurrent Requests: {concurrent_requests} (fired simultaneously)")
    print()

    # Test 1: Fill to just below limit
    print("Test 1: Pre-populate to limit boundary (59/60)")
    print("-" * 80)

    current_time = int(time.time())
    window_start = current_time - window_size

    # Add 59 entries to get close to limit
    for i in range(59):
        member = f"{current_time}:test_{i}"
        result = await redis_client._client.eval(
            ATOMIC_RATE_LIMIT_LUA,
            1,
            test_key,
            window_start,
            current_time,
            rate_limit,
            member,
            window_size,
        )
        allowed = bool(result[0])
        count = int(result[1])

        if not allowed:
            print(f"  ERROR: Request {i+1} denied (should be allowed)")
            return False

    # Verify we're at 59/60
    final_count = await redis_client._client.zcard(test_key)
    print(f"  Current count: {final_count}/60")

    if final_count != 59:
        print(f"  ERROR: Expected 59 entries, got {final_count}")
        return False

    print("  ✓ Successfully added 59 requests")
    print()

    # Test 2: Concurrent requests at limit boundary
    print("Test 2: Fire concurrent requests at 59/60 (RACE CONDITION TEST)")
    print("-" * 80)
    print(f"  Firing {concurrent_requests} simultaneous requests...")

    async def make_concurrent_request(request_id: int):
        """Make a single rate limit request."""
        import secrets
        current_time = int(time.time())
        window_start = current_time - window_size
        member = f"{current_time}:concurrent_{request_id}:{secrets.token_hex(8)}"

        result = await redis_client._client.eval(
            ATOMIC_RATE_LIMIT_LUA,
            1,
            test_key,
            window_start,
            current_time,
            rate_limit,
            member,
            window_size,
        )

        allowed = bool(result[0])
        count = int(result[1])
        reset_time = int(result[2])

        return {
            'request_id': request_id,
            'allowed': allowed,
            'count': count,
            'reset_time': reset_time,
        }

    # Fire all requests concurrently (simulates race condition)
    tasks = [make_concurrent_request(i) for i in range(concurrent_requests)]
    results = await asyncio.gather(*tasks)

    # Analyze results
    allowed_count = sum(1 for r in results if r['allowed'])
    denied_count = sum(1 for r in results if not r['allowed'])

    print(f"  Results:")
    print(f"    Allowed: {allowed_count}")
    print(f"    Denied:  {denied_count}")
    print()

    # Verify final count
    final_count = await redis_client._client.zcard(test_key)
    print(f"  Final count in Redis: {final_count}/60")
    print()

    # Test 3: Validation
    print("Test 3: Validation")
    print("-" * 80)

    success = True

    # Check 1: Exactly 1 concurrent request should be allowed (59 + 1 = 60)
    if allowed_count != 1:
        print(f"  ✗ FAIL: Expected exactly 1 allowed, got {allowed_count}")
        success = False
    else:
        print(f"  ✓ PASS: Exactly 1 concurrent request allowed")

    # Check 2: 9 requests should be denied
    if denied_count != (concurrent_requests - 1):
        print(f"  ✗ FAIL: Expected {concurrent_requests - 1} denied, got {denied_count}")
        success = False
    else:
        print(f"  ✓ PASS: {denied_count} requests correctly denied")

    # Check 3: Final count should be exactly 60
    if final_count != rate_limit:
        print(f"  ✗ FAIL: Final count should be {rate_limit}, got {final_count}")
        success = False
    else:
        print(f"  ✓ PASS: Final count is exactly {rate_limit} (no bypass)")

    # Check 4: No request should report count > limit
    max_count = max(r['count'] for r in results)
    if max_count > rate_limit:
        print(f"  ✗ FAIL: Some requests saw count > limit ({max_count})")
        success = False
    else:
        print(f"  ✓ PASS: No request exceeded rate limit")

    print()

    # Cleanup
    await redis_client._client.delete(test_key)
    await redis_client.close()

    # Final result
    print("=" * 80)
    if success:
        print("RESULT: ✓ ALL TESTS PASSED - Race condition is FIXED")
        print()
        print("The atomic Lua script successfully prevents concurrent requests from")
        print("bypassing the rate limit. All 10 concurrent requests at 59/60 were")
        print("correctly handled - only 1 allowed (60th request), 9 denied.")
    else:
        print("RESULT: ✗ TESTS FAILED - Race condition may still exist")
    print("=" * 80)

    return success


if __name__ == "__main__":
    print()
    result = asyncio.run(test_atomic_rate_limit())
    print()

    sys.exit(0 if result else 1)
