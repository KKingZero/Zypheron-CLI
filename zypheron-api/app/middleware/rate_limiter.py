"""Redis-based rate limiting middleware with sliding window algorithm.

Implements tier-based rate limiting for the Zypheron API:
- Free: 10 requests/minute
- Starter: 60 requests/minute
- Pro: 120 requests/minute
- Enterprise: 300 requests/minute

Uses Redis for distributed rate limiting with secure fail-CLOSED fallback when Redis is unavailable.
Emergency fallback uses in-memory rate limiting with conservative limits.

SECURITY: Uses atomic Lua script for check-and-increment to prevent race condition bypasses.
"""

import structlog
import secrets
import time
from collections import defaultdict
from threading import Lock
from typing import Callable, Optional

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import get_settings
from app.core.database import async_session_maker
from app.core.redis_client import get_redis_client
from app.core.security import decode_access_token
from app.models.user import User

logger = structlog.get_logger()
settings = get_settings()

# Atomic rate limiting Lua script for Redis
# Prevents race conditions where concurrent requests can bypass rate limits
# CRITICAL: Without this, two requests at 59/60 both see 59, both pass = 61 total (bypass)
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

# Emergency in-memory rate limiter (fail-CLOSED protection)
# Used when Redis is unavailable to prevent DDoS attacks
_emergency_rate_limits: dict[str, list[float]] = defaultdict(list)
_emergency_lock = Lock()
_emergency_cleanup_last_run = time.time()

# Conservative emergency limits to protect against DDoS when Redis is down
EMERGENCY_LIMIT = 10  # 10 requests per minute per identifier
EMERGENCY_WINDOW = 60  # 1 minute window
EMERGENCY_CLEANUP_INTERVAL = 300  # Clean up every 5 minutes


def _check_emergency_rate_limit(identifier: str) -> tuple[bool, int, int]:
    """Check emergency in-memory rate limit when Redis is unavailable.

    This function implements a fail-CLOSED security policy to prevent DDoS attacks
    when Redis is down. Uses a conservative sliding window rate limiter with
    in-memory storage.

    Security notes:
    - Thread-safe with explicit locking
    - Memory cleanup to prevent unbounded growth
    - Conservative limits (10 req/min) to protect infrastructure
    - All requests logged for security monitoring

    Args:
        identifier: Rate limit key (user ID or IP address)

    Returns:
        Tuple of (is_allowed, current_usage, reset_time)
        - is_allowed: True if request is allowed, False if rate limited
        - current_usage: Current request count in window
        - reset_time: Unix timestamp when rate limit resets
    """
    global _emergency_cleanup_last_run
    current_time = time.time()
    window_start = current_time - EMERGENCY_WINDOW
    reset_time = int(current_time + EMERGENCY_WINDOW)

    with _emergency_lock:
        # Periodic cleanup to prevent memory exhaustion
        if current_time - _emergency_cleanup_last_run > EMERGENCY_CLEANUP_INTERVAL:
            _cleanup_emergency_rate_limits(current_time)
            _emergency_cleanup_last_run = current_time

        # Clean old entries for this identifier
        _emergency_rate_limits[identifier] = [
            t for t in _emergency_rate_limits[identifier]
            if t > window_start
        ]

        current_usage = len(_emergency_rate_limits[identifier])

        # Check limit
        if current_usage >= EMERGENCY_LIMIT:
            logger.warning(
                f"EMERGENCY RATE LIMIT exceeded for {identifier}: "
                f"{current_usage}/{EMERGENCY_LIMIT} requests in window "
                f"(Redis unavailable - fail-CLOSED protection active)"
            )
            return False, current_usage, reset_time

        # Record request
        _emergency_rate_limits[identifier].append(current_time)
        logger.warning(
            f"EMERGENCY RATE LIMIT applied for {identifier}: "
            f"{current_usage + 1}/{EMERGENCY_LIMIT} requests "
            f"(Redis unavailable - fail-CLOSED protection active)"
        )

        return True, current_usage + 1, reset_time


def _cleanup_emergency_rate_limits(current_time: float) -> None:
    """Clean up expired entries from emergency rate limiter.

    Prevents unbounded memory growth by removing:
    1. Identifiers with no requests in the window
    2. Expired timestamp entries

    Must be called while holding _emergency_lock.

    Args:
        current_time: Current timestamp for cleanup comparison
    """
    window_start = current_time - EMERGENCY_WINDOW
    identifiers_to_remove = []

    for identifier, timestamps in _emergency_rate_limits.items():
        # Remove old timestamps
        active_timestamps = [t for t in timestamps if t > window_start]

        if not active_timestamps:
            # Mark identifier for removal if no active requests
            identifiers_to_remove.append(identifier)
        else:
            # Update with cleaned timestamps
            _emergency_rate_limits[identifier] = active_timestamps

    # Remove inactive identifiers
    for identifier in identifiers_to_remove:
        del _emergency_rate_limits[identifier]

    if identifiers_to_remove:
        logger.info(
            f"Emergency rate limiter cleanup: removed {len(identifiers_to_remove)} "
            f"inactive identifiers, {len(_emergency_rate_limits)} active"
        )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using Redis sliding window algorithm.

    Features:
    - Tier-based rate limits (free, starter, pro, enterprise)
    - Sliding window algorithm for smooth rate limiting
    - Redis-backed for distributed deployments
    - SECURE fail-CLOSED fallback when Redis is unavailable
    - Emergency in-memory rate limiter (10 req/min) prevents DDoS when Redis is down
    - Rate limit headers in all responses
    - Proper 429 Too Many Requests responses
    - 503 Service Unavailable when emergency limits exceeded

    Rate limit keys:
    - Authenticated users: ratelimit:{user_id}
    - Unauthenticated requests: ratelimit:ip:{ip_address}

    Security:
    - Fail-CLOSED: When Redis is unavailable, conservative limits are enforced
    - Emergency limiter prevents DDoS attacks during Redis outages
    - All emergency events logged at WARNING/ERROR level for monitoring
    - X-RateLimit-Fallback header indicates emergency mode is active
    """

    # Rate limits per tier (requests per minute)
    RATE_LIMITS = {
        "free": 10,
        "starter": 60,
        "pro": 120,
        "enterprise": 300,
    }

    # Window size for sliding window algorithm (in seconds)
    WINDOW_SIZE = 60  # 1 minute

    # Paths exempt from rate limiting
    EXEMPT_PATHS = {
        "/health",
        "/",
        "/docs",
        "/redoc",
        "/openapi.json",
    }

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        """Process request with rate limiting.

        Args:
            request: Incoming HTTP request
            call_next: Next middleware/route handler

        Returns:
            HTTP response with rate limit headers
        """
        # Check if rate limiting is globally disabled
        if not settings.enable_rate_limiting:
            return await call_next(request)

        # Skip rate limiting for exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Get Redis client
        try:
            redis_client = await get_redis_client()
        except Exception as e:
            logger.error(
                f"CRITICAL: Failed to get Redis client: {e}. "
                f"Activating emergency fail-CLOSED rate limiter."
            )
            redis_client = None

        # Extract user information (needed for both Redis and emergency limiter)
        user_id, user_tier, identifier = await self._get_user_info(request)

        # SECURITY CRITICAL: If Redis is unavailable, use emergency fail-CLOSED limiter
        # This prevents DDoS attacks when Redis is down by enforcing conservative limits
        if not redis_client or not redis_client.is_available:
            logger.error(
                f"CRITICAL: Redis unavailable for rate limiting. "
                f"Activating emergency fail-CLOSED rate limiter with {EMERGENCY_LIMIT} req/min limit. "
                f"This is a degraded security state - investigate Redis immediately!"
            )

            # Use emergency in-memory rate limiter (fail-CLOSED)
            is_allowed, current_usage, reset_time = _check_emergency_rate_limit(identifier)

            if not is_allowed:
                # Emergency rate limit exceeded - return 503 Service Unavailable
                logger.error(
                    f"EMERGENCY RATE LIMIT EXCEEDED for {identifier}: "
                    f"{current_usage}/{EMERGENCY_LIMIT} requests/min. "
                    f"Request denied (fail-CLOSED protection)."
                )
                return JSONResponse(
                    status_code=503,
                    content={
                        "error": "Service Temporarily Unavailable",
                        "message": (
                            "Our rate limiting service is experiencing issues. "
                            "Emergency rate limits are in effect. Please try again later."
                        ),
                    },
                    headers={
                        "X-RateLimit-Limit": str(EMERGENCY_LIMIT),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(reset_time),
                        "X-RateLimit-Fallback": "true",
                        "Retry-After": str(int(reset_time - time.time())),
                    },
                )

            # Request allowed under emergency limits
            response = await call_next(request)

            # Add headers indicating emergency fallback is active
            remaining = max(0, EMERGENCY_LIMIT - current_usage)
            response.headers["X-RateLimit-Limit"] = str(EMERGENCY_LIMIT)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = str(reset_time)
            response.headers["X-RateLimit-Fallback"] = "true"

            return response

        # Get rate limit for user's tier
        rate_limit = self.RATE_LIMITS.get(user_tier, self.RATE_LIMITS["free"])

        # Check rate limit
        is_allowed, current_usage, reset_time = await self._check_rate_limit(
            redis_client, identifier, rate_limit
        )

        # Calculate remaining requests
        remaining = max(0, rate_limit - current_usage)

        # If rate limit exceeded, return 429
        if not is_allowed:
            logger.warning(
                f"Rate limit exceeded for {identifier} "
                f"(tier: {user_tier}, limit: {rate_limit}/min)"
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate Limit Exceeded",
                    "message": "Too many requests. Please try again later.",
                },
                headers={
                    "X-RateLimit-Limit": str(rate_limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_time),
                    "Retry-After": str(int(reset_time - time.time())),
                },
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers to response
        response.headers["X-RateLimit-Limit"] = str(rate_limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_time)

        return response

    async def _get_user_info(
        self, request: Request
    ) -> tuple[Optional[int], str, str]:
        """Extract user ID, tier, and identifier from request.

        Tries to authenticate user from JWT token. Falls back to IP-based
        identification for unauthenticated requests.

        Args:
            request: HTTP request

        Returns:
            Tuple of (user_id, tier, rate_limit_identifier)
            - user_id: User ID if authenticated, None otherwise
            - tier: User's subscription tier (free if unauthenticated)
            - identifier: Rate limit key (user:{id} or ip:{address})
        """
        # Try to extract JWT token from Authorization header
        auth_header = request.headers.get("Authorization")

        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            payload = decode_access_token(token)

            if payload and "sub" in payload:
                try:
                    user_id = int(payload["sub"])

                    # Look up user's tier from database
                    user_tier = await self._get_user_tier(user_id)

                    if user_tier:
                        # Authenticated user
                        identifier = f"ratelimit:{user_id}"
                        return user_id, user_tier, identifier

                except (ValueError, TypeError) as e:
                    logger.debug(f"Invalid user_id in JWT: {e}")

        # Fall back to IP-based rate limiting for unauthenticated requests
        client_ip = self._get_client_ip(request)
        identifier = f"ratelimit:{client_ip}"

        return None, "free", identifier

    async def _get_user_tier(self, user_id: int) -> Optional[str]:
        """Get user's subscription tier from database.

        Args:
            user_id: User ID

        Returns:
            User tier (free, starter, pro, enterprise) or None if not found
        """
        try:
            async with async_session_maker() as session:
                result = await session.execute(
                    select(User.tier).where(User.id == user_id)
                )
                tier = result.scalar_one_or_none()
                return tier if tier else "free"

        except Exception as e:
            logger.error(f"Error fetching user tier for user_id {user_id}: {e}")
            return "free"

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request.

        Checks X-Forwarded-For header first (for proxies/load balancers),
        then falls back to direct client IP.

        Args:
            request: HTTP request

        Returns:
            Client IP address
        """
        # Check X-Forwarded-For header (for proxies/load balancers)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain (original client)
            return forwarded_for.split(",")[0].strip()

        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        # Fall back to direct client IP
        if request.client:
            return request.client.host

        # Default fallback (should never happen)
        return "unknown"

    async def _check_rate_limit(
        self,
        redis_client,
        identifier: str,
        limit: int,
    ) -> tuple[bool, int, int]:
        """Check rate limit using atomic sliding window algorithm.

        SECURITY: Uses Lua script for atomic check-and-increment to prevent race conditions.
        Previous implementation had CRITICAL vulnerability where concurrent requests could
        bypass rate limits (e.g., two requests at 59/60 both see 59, both pass, total=61).

        The atomic sliding window algorithm provides secure rate limiting by:
        1. Removing old entries outside window (atomic cleanup)
        2. Getting current count (atomic read)
        3. Checking limit and incrementing (atomic check-and-set)
        4. All operations in single Lua script = no race conditions

        Args:
            redis_client: Redis client instance
            identifier: Rate limit key (user:{id} or ip:{address})
            limit: Maximum requests allowed in window

        Returns:
            Tuple of (is_allowed, current_usage, reset_time)
            - is_allowed: True if request is allowed, False if rate limited
            - current_usage: Current request count in window
            - reset_time: Unix timestamp when rate limit resets
        """
        current_time = int(time.time())
        window_start = current_time - self.WINDOW_SIZE

        # Use a sorted set for sliding window
        # Key format: ratelimit:{identifier}
        key = identifier

        # SECURITY: Generate cryptographically secure unique member ID
        # This prevents collision attacks and timing attacks
        # Using secrets.token_hex() instead of random.randint() for cryptographic security
        member = f"{current_time}:{secrets.token_hex(8)}"

        try:
            # ATOMIC OPERATION: Execute Lua script for race-condition-free rate limiting
            # This ensures check-and-increment happens atomically, preventing bypass
            if hasattr(redis_client, '_client') and redis_client._client:
                result = await redis_client._client.eval(
                    ATOMIC_RATE_LIMIT_LUA,
                    1,  # Number of keys
                    key,  # KEYS[1]
                    window_start,  # ARGV[1]
                    current_time,  # ARGV[2]
                    limit,  # ARGV[3]
                    member,  # ARGV[4]
                    self.WINDOW_SIZE,  # ARGV[5]
                )

                # Parse result from Lua script
                # result = [allowed, count, reset_time]
                allowed = bool(result[0])
                current_count = int(result[1])
                reset_time = int(result[2])

                return allowed, current_count, reset_time

            else:
                # Redis client not properly initialized - fail open for global middleware
                # (provider-specific rate limiting fails closed)
                logger.error(f"Redis client not initialized for rate limiting: {identifier}")
                return True, 0, current_time + self.WINDOW_SIZE

        except Exception as e:
            logger.error(f"Error checking rate limit for {identifier}: {e}")
            # On error in global middleware, fail open to prevent blocking legitimate traffic
            # Provider-specific rate limiting (in ai_proxy.py) fails closed
            return True, 0, current_time + self.WINDOW_SIZE


def create_rate_limit_middleware() -> RateLimitMiddleware:
    """Factory function to create rate limit middleware instance.

    Returns:
        RateLimitMiddleware instance
    """
    return RateLimitMiddleware(app=None)
