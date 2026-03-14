"""WebSocket rate limiting for message throttling.

Implements per-user rate limiting to prevent abuse.
"""

import time
from collections import defaultdict, deque
from typing import DefaultDict


class WebSocketRateLimiter:
    """Rate limiter for WebSocket messages.

    Uses a sliding window algorithm to track message rates per user.
    """

    def __init__(self) -> None:
        """Initialize rate limiter with empty tracking."""
        # Store timestamp deques per user ID
        self._message_times: DefaultDict[int, deque[float]] = defaultdict(deque)

    def is_allowed(
        self,
        user_id: int,
        limit: int,
        window_seconds: int = 60,
    ) -> bool:
        """Check if a message is allowed under rate limit.

        Args:
            user_id: User ID to check
            limit: Maximum messages allowed in window
            window_seconds: Time window in seconds (default: 60)

        Returns:
            True if message is allowed, False if rate limited
        """
        current_time = time.time()
        user_times = self._message_times[user_id]

        # Remove timestamps outside the window
        cutoff_time = current_time - window_seconds
        while user_times and user_times[0] < cutoff_time:
            user_times.popleft()

        # Check if under limit
        if len(user_times) >= limit:
            return False

        # Record this message
        user_times.append(current_time)
        return True

    def get_remaining(
        self,
        user_id: int,
        limit: int,
        window_seconds: int = 60,
    ) -> int:
        """Get remaining message allowance for user.

        Args:
            user_id: User ID to check
            limit: Maximum messages allowed in window
            window_seconds: Time window in seconds (default: 60)

        Returns:
            Number of messages remaining in current window
        """
        current_time = time.time()
        user_times = self._message_times[user_id]

        # Remove timestamps outside the window
        cutoff_time = current_time - window_seconds
        while user_times and user_times[0] < cutoff_time:
            user_times.popleft()

        return max(0, limit - len(user_times))

    def reset(self, user_id: int) -> None:
        """Reset rate limit for a user.

        Args:
            user_id: User ID to reset
        """
        if user_id in self._message_times:
            del self._message_times[user_id]

    def cleanup(self, max_age_seconds: int = 3600) -> None:
        """Clean up old entries to prevent memory growth.

        Args:
            max_age_seconds: Remove entries older than this (default: 1 hour)
        """
        current_time = time.time()
        cutoff_time = current_time - max_age_seconds

        users_to_remove = []
        for user_id, times in self._message_times.items():
            # Remove old timestamps
            while times and times[0] < cutoff_time:
                times.popleft()

            # If empty, mark for removal
            if not times:
                users_to_remove.append(user_id)

        # Remove empty entries
        for user_id in users_to_remove:
            del self._message_times[user_id]


def get_rate_limit_for_tier(tier: str) -> int:
    """Get message rate limit for a subscription tier.

    Args:
        tier: Subscription tier name

    Returns:
        Maximum messages per minute
    """
    tier_limits = {
        "free": 100,  # 100 messages/minute for free tier
        "starter": 200,  # 200 messages/minute for starter
        "pro": 500,  # 500 messages/minute for pro
        "enterprise": 1000,  # 1000 messages/minute for enterprise
    }
    return tier_limits.get(tier, 100)  # Default to free tier limit
