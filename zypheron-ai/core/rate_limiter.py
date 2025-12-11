"""
Rate limiting for AI requests and security scans

Implements token bucket algorithm for rate limiting with configurable limits.
"""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, Optional
from dataclasses import dataclass
from collections import deque


@dataclass
class RateLimitConfig:
    """Rate limit configuration"""
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst_size: int = 10


class RateLimiter:
    """
    Token bucket rate limiter with burst support

    Features:
    - Token bucket algorithm
    - Configurable rate limits
    - Burst allowance
    - Async/await support
    """

    def __init__(self, config: RateLimitConfig = None):
        """
        Initialize rate limiter

        Args:
            config: Rate limit configuration
        """
        self.config = config or RateLimitConfig()
        self.tokens = self.config.burst_size
        self.max_tokens = self.config.burst_size
        self.last_refill = time.time()
        self.lock = asyncio.Lock()

        # Track requests for hourly limit
        self.request_times = deque()

    async def acquire(self, cost: int = 1):
        """
        Acquire permission to make request

        Args:
            cost: Number of tokens to consume (default: 1)

        Raises:
            RateLimitExceeded: If rate limit exceeded
        """
        async with self.lock:
            # Refill tokens based on time passed
            now = time.time()
            elapsed = now - self.last_refill
            refill_rate = self.config.requests_per_minute / 60.0  # Tokens per second
            refill_tokens = int(elapsed * refill_rate)

            if refill_tokens > 0:
                self.tokens = min(self.max_tokens, self.tokens + refill_tokens)
                self.last_refill = now

            # Check hourly limit
            cutoff = now - 3600  # 1 hour ago
            while self.request_times and self.request_times[0] < cutoff:
                self.request_times.popleft()

            if len(self.request_times) >= self.config.requests_per_hour:
                wait_time = self.request_times[0] + 3600 - now
                raise RateLimitExceeded(
                    f"Hourly rate limit exceeded. Try again in {int(wait_time)} seconds."
                )

            # Wait for tokens if needed
            while self.tokens < cost:
                await asyncio.sleep(0.1)
                # Refill
                now = time.time()
                elapsed = now - self.last_refill
                refill_tokens = int(elapsed * refill_rate)
                if refill_tokens > 0:
                    self.tokens = min(self.max_tokens, self.tokens + refill_tokens)
                    self.last_refill = now

            # Consume tokens
            self.tokens -= cost
            self.request_times.append(now)

    def get_stats(self) -> Dict:
        """
        Get rate limiter statistics

        Returns:
            Dictionary with current state
        """
        now = time.time()
        cutoff = now - 3600

        # Clean old requests
        while self.request_times and self.request_times[0] < cutoff:
            self.request_times.popleft()

        return {
            'available_tokens': self.tokens,
            'max_tokens': self.max_tokens,
            'requests_last_hour': len(self.request_times),
            'hourly_limit': self.config.requests_per_hour,
            'per_minute_limit': self.config.requests_per_minute
        }


class ConcurrencyLimiter:
    """
    Limit concurrent operations

    Features:
    - Semaphore-based limiting
    - Queue management
    - Timeout support
    """

    def __init__(self, max_concurrent: int = 5):
        """
        Initialize concurrency limiter

        Args:
            max_concurrent: Maximum concurrent operations
        """
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.max_concurrent = max_concurrent
        self.current_count = 0
        self.lock = asyncio.Lock()

    async def acquire(self, timeout: Optional[float] = None):
        """
        Acquire permission for concurrent operation

        Args:
            timeout: Maximum wait time (None = no timeout)

        Raises:
            TimeoutError: If timeout exceeded
        """
        if timeout:
            await asyncio.wait_for(self.semaphore.acquire(), timeout)
        else:
            await self.semaphore.acquire()

        async with self.lock:
            self.current_count += 1

    def release(self):
        """Release concurrent operation slot"""
        self.semaphore.release()
        async def dec():
            async with self.lock:
                self.current_count -= 1
        asyncio.create_task(dec())

    def get_stats(self) -> Dict:
        """Get concurrency statistics"""
        return {
            'current': self.current_count,
            'max': self.max_concurrent,
            'available': self.max_concurrent - self.current_count
        }


class RateLimitExceeded(Exception):
    """Rate limit exceeded exception"""
    pass


# Global rate limiters
_ai_rate_limiter = None
_scan_rate_limiter = None
_concurrency_limiter = None


def get_ai_rate_limiter() -> RateLimiter:
    """Get global AI rate limiter"""
    global _ai_rate_limiter
    if _ai_rate_limiter is None:
        config = RateLimitConfig(
            requests_per_minute=30,  # Conservative default
            requests_per_hour=500,
            burst_size=5
        )
        _ai_rate_limiter = RateLimiter(config)
    return _ai_rate_limiter


def get_scan_rate_limiter() -> RateLimiter:
    """Get global scan rate limiter"""
    global _scan_rate_limiter
    if _scan_rate_limiter is None:
        config = RateLimitConfig(
            requests_per_minute=10,  # Very conservative for scans
            requests_per_hour=100,
            burst_size=3
        )
        _scan_rate_limiter = RateLimiter(config)
    return _scan_rate_limiter


def get_concurrency_limiter() -> ConcurrencyLimiter:
    """Get global concurrency limiter"""
    global _concurrency_limiter
    if _concurrency_limiter is None:
        _concurrency_limiter = ConcurrencyLimiter(max_concurrent=5)
    return _concurrency_limiter
