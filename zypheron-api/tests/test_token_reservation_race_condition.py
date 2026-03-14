"""Test suite for CRITICAL-2 race condition fix in token reservation.

This test demonstrates that the atomic token reservation system prevents
concurrent requests from bypassing quota limits.

Attack Vector Tested:
  User with 1000 tokens sends 10 concurrent requests needing 500 tokens each.
  Expected behavior: First 2 requests succeed, remaining 8 are denied.
  Without fix: All 10 pass initial check, 5000 tokens consumed (VULNERABILITY).
  With fix: Atomic reservation ensures only 2 requests proceed (SECURE).
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.token_reservation import TokenReservationService


class MockRedis:
    """Mock Redis client for testing Lua script execution."""

    def __init__(self):
        self.data = {}
        self.expirations = {}

    async def eval(self, script, num_keys, *args):
        """Mock eval for Lua scripts."""
        quota_key = args[0]
        reservation_key = args[1]

        # Simulate RESERVE_TOKENS_LUA script
        if "INCRBY" in script and "HMSET" in script:
            estimated_tokens = int(args[2])
            limit = int(args[3])

            # Get current usage
            current = int(self.data.get(quota_key, 0))

            # Check if would exceed limit
            if current + estimated_tokens > limit:
                return [0, current, limit]  # Denied

            # Atomically increment (simulating Lua atomicity)
            new_total = current + estimated_tokens
            self.data[quota_key] = new_total

            # Store reservation metadata
            self.data[reservation_key] = {
                'estimated': estimated_tokens,
                'quota_key': quota_key
            }

            return [1, new_total, limit]  # Approved

        # Simulate FINALIZE_TOKENS_LUA script
        elif "HMGET" in script and "DEL" in script and "INCRBY" in script:
            actual_tokens = int(args[2])

            reservation = self.data.get(reservation_key, {})
            estimated_tokens = reservation.get('estimated', 0)

            if estimated_tokens == 0:
                return [0, 'Reservation not found']

            # Adjust quota
            difference = actual_tokens - estimated_tokens
            if difference != 0:
                current = int(self.data.get(quota_key, 0))
                self.data[quota_key] = current + difference

            # Delete reservation
            del self.data[reservation_key]

            final_quota = int(self.data.get(quota_key, 0))
            return [1, final_quota, difference]

        # Simulate RELEASE_RESERVATION_LUA script
        elif "HMGET" in script and "DECRBY" in script:
            reservation = self.data.get(reservation_key, {})
            estimated_tokens = reservation.get('estimated', 0)

            if estimated_tokens == 0:
                return [0, 'Reservation not found']

            # Return tokens to quota
            current = int(self.data.get(quota_key, 0))
            self.data[quota_key] = current - estimated_tokens

            # Delete reservation
            del self.data[reservation_key]

            restored_quota = int(self.data.get(quota_key, 0))
            return [1, restored_quota, estimated_tokens]

        return [0, 'Unknown script']

    async def get(self, key):
        """Mock GET."""
        return str(self.data.get(key, 0))

    async def set(self, key, value, ex=None):
        """Mock SET."""
        self.data[key] = int(value)
        return True


@pytest.mark.asyncio
async def test_race_condition_prevented():
    """Test that concurrent requests are properly serialized by atomic reservation.

    Scenario:
      - User has 1000 token limit
      - 10 concurrent requests, each needing 500 tokens
      - Without fix: All 10 would pass check, 5000 tokens consumed
      - With fix: First 2 reserve tokens atomically, remaining 8 denied
    """
    mock_redis = MockRedis()
    service = TokenReservationService(redis_client=mock_redis)

    user_id = 1
    token_limit = 1000
    tokens_per_request = 500

    # Simulate 10 concurrent reservation attempts
    async def attempt_reservation(request_num):
        """Attempt to reserve tokens."""
        success, reservation_id, current_usage = await service.reserve_tokens(
            user_id=user_id,
            estimated_tokens=tokens_per_request,
            token_limit=token_limit,
        )
        return {
            'request_num': request_num,
            'success': success,
            'reservation_id': reservation_id,
            'current_usage': current_usage,
        }

    # Execute all requests concurrently (simulating race condition)
    results = await asyncio.gather(*[
        attempt_reservation(i) for i in range(10)
    ])

    # Count successes and failures
    successes = [r for r in results if r['success']]
    failures = [r for r in results if not r['success']]

    # CRITICAL ASSERTION: Only 2 requests should succeed (1000 / 500 = 2)
    assert len(successes) == 2, f"Expected 2 successes, got {len(successes)}"
    assert len(failures) == 8, f"Expected 8 failures, got {len(failures)}"

    # Verify final quota state
    final_usage = await service.get_current_usage(user_id)
    assert final_usage == 1000, f"Expected 1000 tokens reserved, got {final_usage}"

    # Verify each success has a unique reservation ID
    reservation_ids = [r['reservation_id'] for r in successes]
    assert len(set(reservation_ids)) == 2, "Reservation IDs should be unique"

    print(f"✓ Race condition prevented: {len(successes)} approved, {len(failures)} denied")


@pytest.mark.asyncio
async def test_reservation_finalization_adjusts_quota():
    """Test that finalization properly adjusts quota for actual vs estimated usage."""
    mock_redis = MockRedis()
    service = TokenReservationService(redis_client=mock_redis)

    user_id = 1
    token_limit = 10000
    estimated_tokens = 1000

    # Reserve tokens
    success, reservation_id, _ = await service.reserve_tokens(
        user_id=user_id,
        estimated_tokens=estimated_tokens,
        token_limit=token_limit,
    )
    assert success, "Reservation should succeed"

    # Verify quota increased by estimate
    usage_after_reserve = await service.get_current_usage(user_id)
    assert usage_after_reserve == estimated_tokens

    # Finalize with lower actual usage (good - return tokens)
    actual_tokens = 600
    final_usage = await service.finalize_reservation(
        user_id=user_id,
        reservation_id=reservation_id,
        actual_tokens=actual_tokens,
    )

    # Final usage should be actual tokens (600), not estimated (1000)
    assert final_usage == actual_tokens, f"Expected {actual_tokens}, got {final_usage}"

    # Test over-estimation return
    tokens_returned = estimated_tokens - actual_tokens
    assert tokens_returned == 400, "Should have returned 400 tokens to pool"

    print(f"✓ Finalization correctly adjusted: {estimated_tokens} → {actual_tokens}")


@pytest.mark.asyncio
async def test_reservation_release_on_failure():
    """Test that failed requests properly release reserved tokens."""
    mock_redis = MockRedis()
    service = TokenReservationService(redis_client=mock_redis)

    user_id = 1
    token_limit = 10000
    estimated_tokens = 1000

    # Reserve tokens
    success, reservation_id, _ = await service.reserve_tokens(
        user_id=user_id,
        estimated_tokens=estimated_tokens,
        token_limit=token_limit,
    )
    assert success

    # Verify tokens are reserved
    usage_after_reserve = await service.get_current_usage(user_id)
    assert usage_after_reserve == estimated_tokens

    # Simulate API call failure - release reservation
    restored_usage = await service.release_reservation(
        user_id=user_id,
        reservation_id=reservation_id,
    )

    # Tokens should be returned to pool
    assert restored_usage == 0, "All tokens should be returned"

    # Verify quota is back to 0
    final_usage = await service.get_current_usage(user_id)
    assert final_usage == 0, "Quota should be reset to 0"

    print(f"✓ Reservation released: {estimated_tokens} tokens returned to pool")


@pytest.mark.asyncio
async def test_multiple_users_isolated_quotas():
    """Test that token reservations are properly isolated per user."""
    mock_redis = MockRedis()
    service = TokenReservationService(redis_client=mock_redis)

    user1_id = 1
    user2_id = 2
    token_limit = 1000
    tokens_per_request = 600

    # User 1 reserves tokens
    success1, res_id1, usage1 = await service.reserve_tokens(
        user_id=user1_id,
        estimated_tokens=tokens_per_request,
        token_limit=token_limit,
    )
    assert success1

    # User 2 should have independent quota
    success2, res_id2, usage2 = await service.reserve_tokens(
        user_id=user2_id,
        estimated_tokens=tokens_per_request,
        token_limit=token_limit,
    )
    assert success2, "User 2 should have independent quota"

    # Verify each user's usage
    user1_usage = await service.get_current_usage(user1_id)
    user2_usage = await service.get_current_usage(user2_id)

    assert user1_usage == tokens_per_request
    assert user2_usage == tokens_per_request

    print(f"✓ User quotas properly isolated: User1={user1_usage}, User2={user2_usage}")


@pytest.mark.asyncio
async def test_quota_exceeded_properly_rejected():
    """Test that requests exceeding quota are properly rejected."""
    mock_redis = MockRedis()
    service = TokenReservationService(redis_client=mock_redis)

    user_id = 1
    token_limit = 1000

    # First request uses most of quota
    success1, res_id1, _ = await service.reserve_tokens(
        user_id=user_id,
        estimated_tokens=900,
        token_limit=token_limit,
    )
    assert success1

    # Second request should be denied (900 + 500 > 1000)
    success2, res_id2, current_usage = await service.reserve_tokens(
        user_id=user_id,
        estimated_tokens=500,
        token_limit=token_limit,
    )
    assert not success2, "Second request should be denied"
    assert current_usage == 900, "Should report current usage accurately"

    # Small request should succeed (900 + 50 < 1000)
    success3, res_id3, _ = await service.reserve_tokens(
        user_id=user_id,
        estimated_tokens=50,
        token_limit=token_limit,
    )
    assert success3, "Small request should succeed"

    final_usage = await service.get_current_usage(user_id)
    assert final_usage == 950

    print(f"✓ Quota enforcement working: {final_usage}/{token_limit} used")


if __name__ == "__main__":
    # Run tests
    print("Testing CRITICAL-2 Race Condition Fix...")
    print("=" * 60)

    asyncio.run(test_race_condition_prevented())
    asyncio.run(test_reservation_finalization_adjusts_quota())
    asyncio.run(test_reservation_release_on_failure())
    asyncio.run(test_multiple_users_isolated_quotas())
    asyncio.run(test_quota_exceeded_properly_rejected())

    print("=" * 60)
    print("All tests passed! Race condition vulnerability is FIXED.")
