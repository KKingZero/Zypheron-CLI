"""Atomic token reservation service to prevent race condition quota bypass.

CRITICAL SECURITY FIX - CRITICAL-2: Race Condition in Token Deduction

This service prevents concurrent requests from bypassing quota limits by implementing
pessimistic locking using Redis Lua scripts for atomic check-and-reserve operations.

Attack Vector Prevented:
  User with 1000 tokens sends 10 concurrent requests needing 500 tokens each.
  Without this fix: All pass quota check, all execute, 5000 tokens consumed.
  With this fix: First 2 requests reserve tokens atomically, rest are denied.

Implementation:
  1. RESERVE tokens BEFORE API call (atomic check-and-increment)
  2. FINALIZE actual usage after API response (adjust for real consumption)
  3. RELEASE reservation if API call fails (rollback)

All Redis operations use Lua scripts to ensure atomicity and prevent TOCTOU vulnerabilities.
"""

import uuid
from typing import Optional

import structlog
from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.redis_client import get_redis_client

logger = structlog.get_logger()

# Redis key prefixes
RESERVATION_KEY_PREFIX = "token_reservation"
QUOTA_KEY_PREFIX = "quota"

# Reservation TTL (5 minutes - covers even slow API calls)
# If reservation isn't finalized within this time, it auto-expires
RESERVATION_TTL_SECONDS = 300

# Lua script for atomic token reservation (pessimistic locking)
# This script ensures NO race condition - tokens are reserved BEFORE the API call
RESERVE_TOKENS_LUA = """
local quota_key = KEYS[1]
local reservation_key = KEYS[2]
local estimated_tokens = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])

-- Get current usage (including all active reservations)
local current = tonumber(redis.call('GET', quota_key) or 0)

-- Check if reservation would exceed limit
if current + estimated_tokens > limit then
    -- DENIED: Return failure with current usage
    return {0, current, limit}
end

-- APPROVED: Reserve tokens atomically (increment quota)
local new_total = redis.call('INCRBY', quota_key, estimated_tokens)

-- Store reservation metadata for potential rollback
-- Format: {estimated_tokens, timestamp}
local timestamp = redis.call('TIME')[1]
redis.call('HMSET', reservation_key,
    'estimated', estimated_tokens,
    'timestamp', timestamp,
    'quota_key', quota_key
)
redis.call('EXPIRE', reservation_key, ttl)

-- Also set expiration on quota key to prevent memory leaks
-- Use TTL longer than reservation to ensure proper cleanup
redis.call('EXPIRE', quota_key, ttl * 2)

-- Return success with new total and limit
return {1, new_total, limit}
"""

# Lua script for finalizing token usage (adjusting for actual consumption)
FINALIZE_TOKENS_LUA = """
local quota_key = KEYS[1]
local reservation_key = KEYS[2]
local actual_tokens = tonumber(ARGV[1])

-- Get reservation metadata
local reservation = redis.call('HMGET', reservation_key, 'estimated', 'quota_key')
local estimated_tokens = tonumber(reservation[1] or 0)
local stored_quota_key = reservation[2]

-- Verify reservation exists and matches quota key
if estimated_tokens == 0 or stored_quota_key ~= quota_key then
    -- Reservation not found or mismatch - return error
    return {0, 'Reservation not found or invalid'}
end

-- Calculate difference between actual and estimated
local difference = actual_tokens - estimated_tokens

-- Adjust quota if there's a difference
if difference ~= 0 then
    redis.call('INCRBY', quota_key, difference)
end

-- Delete reservation (it's been finalized)
redis.call('DEL', reservation_key)

-- Return success with final quota
local final_quota = tonumber(redis.call('GET', quota_key) or 0)
return {1, final_quota, difference}
"""

# Lua script for releasing reservation (rollback on failure)
RELEASE_RESERVATION_LUA = """
local quota_key = KEYS[1]
local reservation_key = KEYS[2]

-- Get reservation metadata
local reservation = redis.call('HMGET', reservation_key, 'estimated', 'quota_key')
local estimated_tokens = tonumber(reservation[1] or 0)
local stored_quota_key = reservation[2]

-- Verify reservation exists and matches quota key
if estimated_tokens == 0 or stored_quota_key ~= quota_key then
    -- Reservation not found or mismatch - already released or expired
    return {0, 'Reservation not found or already released'}
end

-- Return reserved tokens to quota
redis.call('DECRBY', quota_key, estimated_tokens)

-- Delete reservation
redis.call('DEL', reservation_key)

-- Return success with restored quota
local restored_quota = tonumber(redis.call('GET', quota_key) or 0)
return {1, restored_quota, estimated_tokens}
"""


class TokenReservationService:
    """Service for atomic token reservation to prevent quota bypass via race conditions.

    This service implements pessimistic locking for token quota enforcement:

    Normal Flow:
        1. reserve_tokens() - Atomically check and reserve tokens BEFORE API call
        2. [Make API call - external to this service]
        3. finalize_reservation() - Adjust quota for actual usage

    Error Flow:
        1. reserve_tokens() - Atomically check and reserve tokens
        2. [API call fails]
        3. release_reservation() - Return tokens to quota pool

    All operations use Redis Lua scripts for atomic execution, preventing TOCTOU
    (Time-Of-Check-Time-Of-Use) vulnerabilities.
    """

    def __init__(self, redis_client: Optional[Redis] = None):
        """Initialize token reservation service.

        Args:
            redis_client: Optional Redis client. If None, will be fetched from get_redis_client()
        """
        self._redis_client = redis_client

    async def _get_redis(self) -> Redis:
        """Get Redis client, fetching if not provided.

        Returns:
            Redis client

        Raises:
            RuntimeError: If Redis is unavailable
        """
        if self._redis_client is None:
            client = await get_redis_client()
            if not client.is_available or client._client is None:
                raise RuntimeError(
                    "Redis unavailable - token reservation requires Redis for atomic operations"
                )
            self._redis_client = client._client

        return self._redis_client

    @staticmethod
    def _generate_reservation_id(user_id: int) -> str:
        """Generate unique reservation ID.

        Args:
            user_id: User ID

        Returns:
            Unique reservation ID
        """
        unique_id = uuid.uuid4().hex
        return f"{RESERVATION_KEY_PREFIX}:{user_id}:{unique_id}"

    @staticmethod
    def _get_quota_key(user_id: int) -> str:
        """Get Redis key for user quota.

        Args:
            user_id: User ID

        Returns:
            Redis key for quota
        """
        return f"{QUOTA_KEY_PREFIX}:{user_id}"

    async def reserve_tokens(
        self,
        user_id: int,
        estimated_tokens: int,
        token_limit: int,
    ) -> tuple[bool, str, int]:
        """Atomically reserve tokens BEFORE making API call.

        This is the CRITICAL security fix - tokens are reserved ATOMICALLY before
        the API call, preventing concurrent requests from bypassing quota limits.

        Args:
            user_id: User ID
            estimated_tokens: Conservative estimate of tokens needed (use max_tokens if available)
            token_limit: User's token limit for current period

        Returns:
            Tuple of (success, reservation_id, current_usage_after_reserve):
            - success: True if tokens reserved, False if quota exceeded
            - reservation_id: Unique ID for this reservation (needed for finalize/release)
            - current_usage_after_reserve: Current usage including this reservation

        Raises:
            RuntimeError: If Redis is unavailable
            RedisError: On Redis operation failure

        Security:
            Uses Lua script for atomic check-and-reserve to prevent TOCTOU race conditions.
        """
        if estimated_tokens < 0:
            raise ValueError("estimated_tokens must be non-negative")

        if token_limit < 0:
            raise ValueError("token_limit must be non-negative")

        try:
            redis = await self._get_redis()

            quota_key = self._get_quota_key(user_id)
            reservation_id = self._generate_reservation_id(user_id)

            # Execute atomic reservation using Lua script
            # This ensures NO race condition between check and increment
            result = await redis.eval(
                RESERVE_TOKENS_LUA,
                2,  # number of keys
                quota_key,
                reservation_id,
                estimated_tokens,
                token_limit,
                RESERVATION_TTL_SECONDS,
            )

            success = bool(result[0])
            current_usage = int(result[1])
            limit = int(result[2])

            if success:
                logger.info(
                    "tokens_reserved",
                    user_id=user_id,
                    reservation_id=reservation_id,
                    estimated_tokens=estimated_tokens,
                    current_usage=current_usage,
                    limit=limit,
                    remaining=limit - current_usage,
                )
                return True, reservation_id, current_usage
            else:
                logger.warning(
                    "token_reservation_denied",
                    user_id=user_id,
                    estimated_tokens=estimated_tokens,
                    current_usage=current_usage,
                    limit=limit,
                    shortage=current_usage + estimated_tokens - limit,
                )
                return False, "", current_usage

        except RedisError as e:
            logger.error(
                "token_reservation_redis_error",
                user_id=user_id,
                estimated_tokens=estimated_tokens,
                error=str(e),
                error_type=type(e).__name__,
            )
            raise RuntimeError(f"Redis error during token reservation: {e}") from e

    async def finalize_reservation(
        self,
        user_id: int,
        reservation_id: str,
        actual_tokens: int,
    ) -> int:
        """Finalize reservation with actual token usage.

        Call this AFTER the API call completes successfully to adjust the reservation
        to match actual token consumption. If actual usage differs from estimate,
        the quota is adjusted accordingly.

        Args:
            user_id: User ID
            reservation_id: Reservation ID from reserve_tokens()
            actual_tokens: Actual tokens consumed by API call

        Returns:
            Final quota usage after adjustment

        Raises:
            RuntimeError: If Redis unavailable or reservation not found
            ValueError: If actual_tokens is negative

        Security:
            Uses Lua script for atomic adjustment and cleanup.
        """
        if actual_tokens < 0:
            raise ValueError("actual_tokens must be non-negative")

        try:
            redis = await self._get_redis()

            quota_key = self._get_quota_key(user_id)

            # Execute atomic finalization using Lua script
            result = await redis.eval(
                FINALIZE_TOKENS_LUA,
                2,  # number of keys
                quota_key,
                reservation_id,
                actual_tokens,
            )

            success = bool(result[0])
            if not success:
                error_msg = result[1]
                raise RuntimeError(f"Failed to finalize reservation: {error_msg}")

            final_quota = int(result[1])
            difference = int(result[2])

            logger.info(
                "reservation_finalized",
                user_id=user_id,
                reservation_id=reservation_id,
                actual_tokens=actual_tokens,
                adjustment=difference,
                final_quota=final_quota,
            )

            return final_quota

        except RedisError as e:
            logger.error(
                "finalization_redis_error",
                user_id=user_id,
                reservation_id=reservation_id,
                actual_tokens=actual_tokens,
                error=str(e),
                error_type=type(e).__name__,
            )
            raise RuntimeError(f"Redis error during finalization: {e}") from e

    async def release_reservation(
        self,
        user_id: int,
        reservation_id: str,
    ) -> int:
        """Release reservation if API call fails (rollback).

        Call this in exception handler if API call fails to return reserved tokens
        to the quota pool. This ensures users aren't charged for failed requests.

        Args:
            user_id: User ID
            reservation_id: Reservation ID from reserve_tokens()

        Returns:
            Restored quota usage after release

        Raises:
            RuntimeError: If Redis unavailable

        Security:
            Uses Lua script for atomic release and cleanup.
        """
        try:
            redis = await self._get_redis()

            quota_key = self._get_quota_key(user_id)

            # Execute atomic release using Lua script
            result = await redis.eval(
                RELEASE_RESERVATION_LUA,
                2,  # number of keys
                quota_key,
                reservation_id,
            )

            success = bool(result[0])
            if not success:
                # Reservation already released or expired - not an error
                logger.warning(
                    "reservation_already_released",
                    user_id=user_id,
                    reservation_id=reservation_id,
                    message=result[1],
                )
                return 0

            restored_quota = int(result[1])
            released_tokens = int(result[2])

            logger.info(
                "reservation_released",
                user_id=user_id,
                reservation_id=reservation_id,
                released_tokens=released_tokens,
                restored_quota=restored_quota,
            )

            return restored_quota

        except RedisError as e:
            logger.error(
                "release_redis_error",
                user_id=user_id,
                reservation_id=reservation_id,
                error=str(e),
                error_type=type(e).__name__,
            )
            # Log but don't raise - we don't want to mask the original error
            # Reservation will auto-expire after TTL anyway
            return 0

    async def get_current_usage(self, user_id: int) -> int:
        """Get current token usage including active reservations.

        Args:
            user_id: User ID

        Returns:
            Current usage including all active reservations
        """
        try:
            redis = await self._get_redis()
            quota_key = self._get_quota_key(user_id)

            usage = await redis.get(quota_key)
            return int(usage) if usage else 0

        except RedisError as e:
            logger.error(
                "get_usage_redis_error",
                user_id=user_id,
                error=str(e),
            )
            return 0

    async def sync_quota_from_db(self, user_id: int, db_usage: int) -> None:
        """Sync quota from database to Redis.

        Called periodically to ensure Redis quota matches database reality.
        This handles cases where Redis was unavailable or restarted.

        Args:
            user_id: User ID
            db_usage: Current usage from database
        """
        try:
            redis = await self._get_redis()
            quota_key = self._get_quota_key(user_id)

            # Set quota to DB value
            # Use SET (not SETNX) to overwrite any stale value
            await redis.set(quota_key, db_usage, ex=RESERVATION_TTL_SECONDS * 2)

            logger.info(
                "quota_synced_from_db",
                user_id=user_id,
                db_usage=db_usage,
            )

        except RedisError as e:
            logger.error(
                "quota_sync_redis_error",
                user_id=user_id,
                db_usage=db_usage,
                error=str(e),
            )
