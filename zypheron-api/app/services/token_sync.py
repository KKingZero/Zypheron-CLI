"""Token usage synchronization service for AI proxy and license system.

Provides comprehensive token tracking with:
- Separate tracking of prompt and completion tokens
- Provider-specific cost multipliers
- Redis caching for fast quota checks
- Monthly aggregation and billing period management
- Usage alerts at 80% and 100% thresholds
- Batch processing for high-volume scenarios
"""

import hashlib
from datetime import datetime, timezone
from typing import Literal

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.redis_client import get_redis_client
from app.models.token_usage import TokenUsage, UserQuota
from app.models.user import User

logger = structlog.get_logger()
settings = get_settings()

# Provider cost multipliers (relative to OpenAI GPT-4o baseline)
# These convert actual tokens to "normalized tokens" for billing
PROVIDER_COST_MULTIPLIERS = {
    "openai": {
        "gpt-4o": 1.0,
        "gpt-4o-mini": 0.5,
        "gpt-4-turbo": 1.0,
        "gpt-4": 1.0,
        "gpt-3.5-turbo": 0.5,
        "default": 1.0,
    },
    "anthropic": {
        "claude-3-5-sonnet": 1.2,
        "claude-3-opus": 1.2,
        "claude-3-sonnet": 1.0,
        "claude-3-haiku": 0.8,
        "default": 1.2,
    },
    "grok": {
        "grok-beta": 1.0,
        "default": 1.0,
    },
    "deepseek": {
        "deepseek-chat": 0.3,
        "deepseek-coder": 0.3,
        "default": 0.3,
    },
    "ollama": {
        "default": 0.0,  # Free, local
    },
}

# Usage alert thresholds
ALERT_THRESHOLD_WARNING = 0.80  # 80%
ALERT_THRESHOLD_CRITICAL = 1.00  # 100%

# SECURITY FIX (TOKEN-H1): Maximum tokens per request to prevent integer overflow
# No legitimate request should exceed 10 million tokens (GPT-4 context is ~128k)
MAX_TOKENS_PER_REQUEST = 10_000_000

# Redis key patterns
REDIS_KEY_MONTHLY_USAGE = "tokens:{user_id}:{year}:{month}"
REDIS_KEY_ALERT_SENT = "alert:{user_id}:{year}:{month}:{threshold}"
REDIS_TTL_MONTHLY = 86400 * 35  # 35 days (covers a full month + buffer)
REDIS_TTL_ALERT = 86400 * 7  # 7 days


def validate_user_id(user_id: int) -> int:
    """SECURITY FIX (TOKEN-H2): Validate user_id before Redis key interpolation.

    Prevents Redis key injection by ensuring user_id is a valid positive integer.

    Args:
        user_id: User ID to validate

    Returns:
        The validated user_id

    Raises:
        ValueError: If user_id is not a valid positive integer
    """
    if not isinstance(user_id, int):
        raise ValueError(f"user_id must be an integer, got {type(user_id).__name__}")
    if user_id <= 0:
        raise ValueError(f"user_id must be a positive integer, got {user_id}")
    if user_id > 2**31 - 1:  # Max signed 32-bit integer
        raise ValueError(f"user_id exceeds maximum allowed value: {user_id}")
    return user_id


class TokenSyncService:
    """Service for synchronizing token usage between AI proxy and license system.

    Features:
    - Records detailed usage (prompt + completion tokens separately)
    - Applies provider-specific cost multipliers
    - Caches monthly aggregates in Redis for fast quota checks
    - Tracks billing periods and handles monthly resets
    - Sends usage alerts at configurable thresholds
    """

    def __init__(self, db: AsyncSession):
        """Initialize the token sync service.

        Args:
            db: Async database session for persistence
        """
        self.db = db

    @staticmethod
    def get_cost_multiplier(provider: str, model: str) -> float:
        """Get cost multiplier for a provider/model combination.

        Args:
            provider: AI provider name (openai, anthropic, grok, deepseek, ollama)
            model: Model name

        Returns:
            Cost multiplier (e.g., 1.0 for GPT-4o, 0.3 for DeepSeek, 0.0 for Ollama)
        """
        provider_multipliers = PROVIDER_COST_MULTIPLIERS.get(provider.lower(), {})

        # Try exact match first
        if model in provider_multipliers:
            return provider_multipliers[model]

        # Try prefix match (e.g., "gpt-4o-2024-08-06" matches "gpt-4o")
        for model_prefix, multiplier in provider_multipliers.items():
            if model_prefix != "default" and model.startswith(model_prefix):
                return multiplier

        # Return default for provider
        return provider_multipliers.get("default", 1.0)

    @staticmethod
    def calculate_normalized_tokens(
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> int:
        """Calculate normalized token count with provider multiplier.

        Args:
            provider: AI provider name
            model: Model name
            prompt_tokens: Number of prompt tokens
            completion_tokens: Number of completion tokens

        Returns:
            Normalized token count for billing (rounded to nearest integer)

        Raises:
            ValueError: If token counts are invalid or exceed maximum
        """
        # SECURITY FIX (TOKEN-H1): Validate token counts to prevent integer overflow
        if prompt_tokens < 0 or completion_tokens < 0:
            raise ValueError("Token counts cannot be negative")

        total_tokens = prompt_tokens + completion_tokens

        if total_tokens > MAX_TOKENS_PER_REQUEST:
            logger.warning(
                "token_count_overflow_blocked",
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total=total_tokens,
                max_allowed=MAX_TOKENS_PER_REQUEST,
            )
            raise ValueError(
                f"Token count {total_tokens} exceeds maximum allowed ({MAX_TOKENS_PER_REQUEST})"
            )

        multiplier = TokenSyncService.get_cost_multiplier(provider, model)
        normalized = int(total_tokens * multiplier)

        logger.debug(
            "token_normalization",
            provider=provider,
            model=model,
            raw_tokens=total_tokens,
            multiplier=multiplier,
            normalized_tokens=normalized,
        )

        return normalized

    async def record_usage(
        self,
        user_id: int,
        provider: Literal["openai", "anthropic", "grok", "deepseek", "ollama"],
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        prompt_hash: str | None = None,
        endpoint: str | None = None,
    ) -> tuple[TokenUsage, int]:
        """Record token usage with provider cost multiplier.

        This is the main entry point for tracking AI usage. It:
        1. Calculates normalized tokens using cost multiplier
        2. Creates database record with raw + normalized tokens
        3. Updates monthly aggregate in Redis cache
        4. Updates UserQuota in database
        5. Checks for usage alerts

        Args:
            user_id: User ID
            provider: AI provider
            model: Model name
            prompt_tokens: Number of prompt tokens
            completion_tokens: Number of completion tokens
            prompt_hash: SHA-256 hash of prompt (for deduplication)
            endpoint: API endpoint that triggered usage

        Returns:
            Tuple of (TokenUsage record, normalized_tokens)

        Raises:
            ValueError: If token counts are negative
        """
        if prompt_tokens < 0 or completion_tokens < 0:
            raise ValueError("Token counts must be non-negative")

        # Calculate normalized tokens for billing
        normalized_tokens = self.calculate_normalized_tokens(
            provider=provider,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

        # Create usage record
        usage = TokenUsage(
            user_id=user_id,
            tokens_used=normalized_tokens,  # Store normalized tokens
            prompt_tokens=prompt_tokens,  # Store raw prompt tokens
            completion_tokens=completion_tokens,  # Store raw completion tokens
            provider=provider,
            model=model,
            prompt_hash=prompt_hash,
            endpoint=endpoint,
        )
        self.db.add(usage)

        # Update UserQuota in database
        await self._update_user_quota(user_id, normalized_tokens)

        # Update Redis cache for fast quota checks
        await self._update_redis_cache(user_id, normalized_tokens)

        # Flush to get usage.id
        await self.db.flush()

        logger.info(
            "token_usage_recorded",
            user_id=user_id,
            provider=provider,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            normalized_tokens=normalized_tokens,
            usage_id=usage.id,
        )

        # Check for usage alerts (async, non-blocking)
        await self._check_usage_alerts(user_id)

        return usage, normalized_tokens

    async def _update_user_quota(self, user_id: int, tokens_used: int) -> None:
        """Update UserQuota table with token usage.

        Args:
            user_id: User ID
            tokens_used: Normalized tokens to add
        """
        stmt = select(UserQuota).where(UserQuota.user_id == user_id)
        result = await self.db.execute(stmt)
        quota = result.scalar_one_or_none()

        if quota:
            quota.tokens_used_period += tokens_used
            quota.updated_at = datetime.now(timezone.utc)

            logger.debug(
                "quota_updated",
                user_id=user_id,
                tokens_added=tokens_used,
                total_used=quota.tokens_used_period,
                limit=quota.token_limit,
            )
        else:
            logger.warning(
                "quota_not_found",
                user_id=user_id,
                message="UserQuota not found, should be created during user registration",
            )

    async def _update_redis_cache(self, user_id: int, tokens_used: int) -> None:
        """Update Redis cache with monthly token aggregate.

        Cache key format: tokens:{user_id}:{year}:{month}

        Args:
            user_id: User ID
            tokens_used: Normalized tokens to add
        """
        try:
            # SECURITY FIX (TOKEN-H2): Validate user_id before Redis key interpolation
            validated_user_id = validate_user_id(user_id)

            redis_client = await get_redis_client()
            if not redis_client.is_available:
                logger.warning("redis_unavailable", message="Skipping Redis cache update")
                return

            now = datetime.now(timezone.utc)
            cache_key = REDIS_KEY_MONTHLY_USAGE.format(
                user_id=validated_user_id,
                year=now.year,
                month=now.month,
            )

            # Increment counter
            new_total = await redis_client.incr(cache_key)

            # Set expiration on first increment
            if new_total == tokens_used:
                await redis_client.expire(cache_key, REDIS_TTL_MONTHLY)

            logger.debug(
                "redis_cache_updated",
                user_id=user_id,
                cache_key=cache_key,
                tokens_added=tokens_used,
                new_total=new_total,
            )

        except Exception as e:
            logger.error(
                "redis_cache_update_failed",
                user_id=user_id,
                error=str(e),
                message="Failed to update Redis cache, continuing with DB only",
            )

    async def get_monthly_usage(self, user_id: int) -> int:
        """Get current month usage with Redis cache fallback to DB.

        Tries Redis first for fast access, falls back to database aggregation.

        Args:
            user_id: User ID

        Returns:
            Total normalized tokens used this month
        """
        # SECURITY FIX (TOKEN-H2): Validate user_id before Redis key interpolation
        validated_user_id = validate_user_id(user_id)

        # Try Redis first
        try:
            redis_client = await get_redis_client()
            if redis_client.is_available:
                now = datetime.now(timezone.utc)
                cache_key = REDIS_KEY_MONTHLY_USAGE.format(
                    user_id=validated_user_id,
                    year=now.year,
                    month=now.month,
                )

                cached_value = await redis_client.get(cache_key)
                if cached_value:
                    usage = int(cached_value)
                    logger.debug("redis_cache_hit", user_id=user_id, usage=usage)
                    return usage

        except Exception as e:
            logger.warning("redis_cache_read_failed", user_id=validated_user_id, error=str(e))

        # Fallback to database
        stmt = select(UserQuota).where(UserQuota.user_id == validated_user_id)
        result = await self.db.execute(stmt)
        quota = result.scalar_one_or_none()

        if quota:
            logger.debug("db_fallback", user_id=validated_user_id, usage=quota.tokens_used_period)
            return quota.tokens_used_period

        return 0

    async def get_usage_breakdown(
        self,
        user_id: int,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> dict[str, dict[str, int]]:
        """Get token usage breakdown by provider and model.

        Args:
            user_id: User ID
            start_date: Start of date range (default: current billing period start)
            end_date: End of date range (default: now)

        Returns:
            Dictionary with structure:
            {
                "openai": {"gpt-4o": 1000, "gpt-3.5-turbo": 500},
                "anthropic": {"claude-3-opus": 2000}
            }
        """
        # Get billing period if dates not provided
        if start_date is None or end_date is None:
            quota = await self._get_user_quota(user_id)
            if quota:
                start_date = quota.period_start
                end_date = datetime.now(timezone.utc)
            else:
                # Default to current month
                now = datetime.now(timezone.utc)
                start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                end_date = now

        # Query usage grouped by provider and model
        stmt = (
            select(
                TokenUsage.provider,
                TokenUsage.model,
                func.sum(TokenUsage.tokens_used).label("total_tokens"),
            )
            .where(TokenUsage.user_id == user_id)
            .where(TokenUsage.created_at >= start_date)
            .where(TokenUsage.created_at <= end_date)
            .group_by(TokenUsage.provider, TokenUsage.model)
        )

        result = await self.db.execute(stmt)
        rows = result.all()

        # Build nested dictionary
        breakdown: dict[str, dict[str, int]] = {}
        for provider, model, total_tokens in rows:
            if provider not in breakdown:
                breakdown[provider] = {}
            breakdown[provider][model] = int(total_tokens)

        logger.debug(
            "usage_breakdown_generated",
            user_id=user_id,
            start_date=start_date.isoformat(),
            end_date=end_date.isoformat(),
            providers=list(breakdown.keys()),
        )

        return breakdown

    async def _check_usage_alerts(self, user_id: int) -> None:
        """Check if user has crossed usage thresholds and send alerts.

        Sends alerts at 80% and 100% of quota. Uses Redis to track if alert
        was already sent this billing period.

        Args:
            user_id: User ID
        """
        try:
            quota = await self._get_user_quota(user_id)
            if not quota or quota.byok_enabled:
                return  # No alerts for BYOK users

            # Calculate usage percentage
            if quota.token_limit == 0:
                return  # No limit set

            usage_percentage = quota.tokens_used_period / quota.token_limit

            # Check thresholds
            await self._send_alert_if_needed(
                user_id=user_id,
                usage_percentage=usage_percentage,
                threshold=ALERT_THRESHOLD_WARNING,
                quota=quota,
            )

            await self._send_alert_if_needed(
                user_id=user_id,
                usage_percentage=usage_percentage,
                threshold=ALERT_THRESHOLD_CRITICAL,
                quota=quota,
            )

        except Exception as e:
            logger.error(
                "alert_check_failed",
                user_id=user_id,
                error=str(e),
            )

    async def _send_alert_if_needed(
        self,
        user_id: int,
        usage_percentage: float,
        threshold: float,
        quota: UserQuota,
    ) -> None:
        """Send alert if threshold crossed and not already sent.

        Args:
            user_id: User ID
            usage_percentage: Current usage as percentage (0.0 - 1.0+)
            threshold: Threshold to check (0.80 or 1.00)
            quota: User quota object
        """
        if usage_percentage < threshold:
            return  # Threshold not reached

        # Check if alert already sent this period
        now = datetime.now(timezone.utc)
        alert_key = REDIS_KEY_ALERT_SENT.format(
            user_id=user_id,
            year=now.year,
            month=now.month,
            threshold=int(threshold * 100),
        )

        try:
            redis_client = await get_redis_client()
            if redis_client.is_available:
                # Try to set alert flag (only succeeds if not already set)
                was_set = await redis_client.set(alert_key, "1", ex=REDIS_TTL_ALERT, nx=True)

                if not was_set:
                    # Alert already sent
                    return

        except Exception as e:
            logger.warning("redis_alert_check_failed", user_id=user_id, error=str(e))
            # Continue anyway to ensure alert is sent

        # Send alert
        threshold_name = "WARNING" if threshold == ALERT_THRESHOLD_WARNING else "CRITICAL"

        logger.warning(
            "token_usage_alert",
            user_id=user_id,
            threshold=threshold_name,
            usage_percentage=round(usage_percentage * 100, 2),
            tokens_used=quota.tokens_used_period,
            token_limit=quota.token_limit,
            tier=quota.tier,
        )

        # TODO: Implement webhook notification
        # await self._send_webhook_notification(user_id, threshold_name, quota)

    async def reset_billing_period(self, user_id: int) -> None:
        """Reset token usage for a new billing period.

        Called when subscription renews or monthly period ends.

        Args:
            user_id: User ID
        """
        quota = await self._get_user_quota(user_id)
        if not quota:
            logger.warning("quota_not_found_for_reset", user_id=user_id)
            return

        # Update billing period
        now = datetime.now(timezone.utc)
        period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Calculate next month
        if period_start.month == 12:
            period_end = period_start.replace(year=period_start.year + 1, month=1)
        else:
            period_end = period_start.replace(month=period_start.month + 1)

        # Reset usage
        quota.period_start = period_start
        quota.period_end = period_end
        quota.tokens_used_period = 0
        quota.updated_at = now

        await self.db.flush()

        # Clear Redis cache for new period
        try:
            redis_client = await get_redis_client()
            if redis_client.is_available:
                cache_key = REDIS_KEY_MONTHLY_USAGE.format(
                    user_id=user_id,
                    year=now.year,
                    month=now.month,
                )
                await redis_client.delete(cache_key)

        except Exception as e:
            logger.error("redis_cache_clear_failed", user_id=user_id, error=str(e))

        logger.info(
            "billing_period_reset",
            user_id=user_id,
            new_period_start=period_start.isoformat(),
            new_period_end=period_end.isoformat(),
        )

    async def get_quota_with_alerts(self, user_id: int) -> dict:
        """Get quota info with alert status.

        Returns quota information plus alert indicators for response headers.

        Args:
            user_id: User ID

        Returns:
            Dictionary with quota info and alert flags
        """
        quota = await self._get_user_quota(user_id)
        if not quota:
            return {
                "tokens_used": 0,
                "token_limit": 0,
                "percentage_used": 0.0,
                "alert_warning": False,
                "alert_critical": False,
            }

        percentage_used = (
            (quota.tokens_used_period / quota.token_limit * 100)
            if quota.token_limit > 0
            else 0.0
        )

        return {
            "tokens_used": quota.tokens_used_period,
            "token_limit": quota.token_limit,
            "tokens_remaining": max(0, quota.token_limit - quota.tokens_used_period),
            "percentage_used": round(percentage_used, 2),
            "alert_warning": percentage_used >= 80.0,
            "alert_critical": percentage_used >= 100.0,
            "tier": quota.tier,
            "period_start": quota.period_start.isoformat(),
            "period_end": quota.period_end.isoformat(),
        }

    async def _get_user_quota(self, user_id: int) -> UserQuota | None:
        """Get user quota from database.

        Args:
            user_id: User ID

        Returns:
            UserQuota or None if not found
        """
        stmt = select(UserQuota).where(UserQuota.user_id == user_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_historical_usage(
        self,
        user_id: int,
        months: int = 12,
    ) -> list[dict]:
        """Get historical usage by month.

        Args:
            user_id: User ID
            months: Number of months to retrieve (default: 12)

        Returns:
            List of dictionaries with monthly usage data
        """
        # Calculate start date (beginning of month N months ago)
        now = datetime.now(timezone.utc)

        # SQL query to get monthly aggregates
        stmt = (
            select(
                func.date_trunc('month', TokenUsage.created_at).label('month'),
                func.sum(TokenUsage.tokens_used).label('total_tokens'),
                func.count(TokenUsage.id).label('request_count'),
            )
            .where(TokenUsage.user_id == user_id)
            .where(
                TokenUsage.created_at >= func.date_trunc('month', now) - func.cast(f'{months} months', type_=func.INTERVAL)
            )
            .group_by(func.date_trunc('month', TokenUsage.created_at))
            .order_by(func.date_trunc('month', TokenUsage.created_at).desc())
        )

        result = await self.db.execute(stmt)
        rows = result.all()

        history = [
            {
                "month": row.month.isoformat() if row.month else None,
                "total_tokens": int(row.total_tokens),
                "request_count": int(row.request_count),
            }
            for row in rows
        ]

        logger.debug(
            "historical_usage_retrieved",
            user_id=user_id,
            months=months,
            records=len(history),
        )

        return history
