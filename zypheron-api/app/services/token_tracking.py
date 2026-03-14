"""Token tracking service for monitoring AI API usage and enforcing quotas.

Uses tiktoken for accurate token counting across different models.
Integrates with database to track usage and enforce tier-based limits.
"""

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Literal

import tiktoken
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func

from app.core.config import get_settings
from app.models.token_usage import TokenUsage, UserQuota

settings = get_settings()


# Model name mappings for tiktoken
MODEL_ENCODINGS = {
    # OpenAI models
    "gpt-4": "cl100k_base",
    "gpt-4-turbo": "cl100k_base",
    "gpt-4-turbo-preview": "cl100k_base",
    "gpt-4o": "o200k_base",
    "gpt-4o-mini": "o200k_base",
    "gpt-3.5-turbo": "cl100k_base",
    # Anthropic models (use cl100k_base as approximation)
    "claude-3-opus": "cl100k_base",
    "claude-3-sonnet": "cl100k_base",
    "claude-3-haiku": "cl100k_base",
    "claude-3.5-sonnet": "cl100k_base",
    # Other providers (use cl100k_base as approximation)
    "grok-beta": "cl100k_base",
    "deepseek-chat": "cl100k_base",
    "deepseek-coder": "cl100k_base",
}

# Tier to token limit mapping
TIER_TOKEN_LIMITS = {
    "free": settings.token_limit_free,
    "starter": settings.token_limit_starter,
    "pro": settings.token_limit_pro,
    "enterprise": settings.token_limit_enterprise,
}


class TokenTrackingService:
    """Service for tracking token usage and enforcing quotas."""

    def __init__(self, db: AsyncSession):
        """Initialize the token tracking service.

        Args:
            db: Async database session for persistence
        """
        self.db = db

    @staticmethod
    def count_tokens(text: str, model: str) -> int:
        """Count tokens in text using tiktoken for the specified model.

        Args:
            text: The text to count tokens for
            model: The model name (e.g., "gpt-4", "claude-3-opus")

        Returns:
            Number of tokens in the text

        Raises:
            ValueError: If the model is not supported
        """
        # Get the appropriate encoding for the model
        encoding_name = MODEL_ENCODINGS.get(model)

        if not encoding_name:
            # Try to match partial model names
            for model_prefix, enc_name in MODEL_ENCODINGS.items():
                if model.startswith(model_prefix):
                    encoding_name = enc_name
                    break

        if not encoding_name:
            # Default to cl100k_base for unknown models
            encoding_name = "cl100k_base"

        try:
            encoding = tiktoken.get_encoding(encoding_name)
            return len(encoding.encode(text))
        except Exception as e:
            raise ValueError(f"Failed to count tokens for model {model}: {e}") from e

    @staticmethod
    def hash_prompt(prompt: str) -> str:
        """Generate SHA-256 hash of a prompt for cache key generation.

        Args:
            prompt: The prompt text to hash

        Returns:
            Hexadecimal SHA-256 hash string (64 characters)
        """
        return hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    async def record_usage(
        self,
        user_id: int,
        tokens_used: int,
        provider: Literal["openai", "anthropic", "grok", "deepseek"],
        model: str,
        prompt_hash: str | None = None,
        endpoint: str | None = None,
    ) -> TokenUsage:
        """Record token usage for a user.

        Creates a new TokenUsage record and updates the user's quota.

        Args:
            user_id: The user's ID
            tokens_used: Number of tokens consumed
            provider: AI provider name
            model: Model name
            prompt_hash: Optional SHA-256 hash of the prompt for deduplication
            endpoint: Optional endpoint that triggered the usage

        Returns:
            The created TokenUsage record

        Raises:
            ValueError: If tokens_used is negative
        """
        if tokens_used < 0:
            raise ValueError("tokens_used must be non-negative")

        # Create usage record
        usage = TokenUsage(
            user_id=user_id,
            tokens_used=tokens_used,
            provider=provider,
            model=model,
            prompt_hash=prompt_hash,
            endpoint=endpoint,
        )

        self.db.add(usage)

        # Update user quota (increment tokens_used_period)
        quota_stmt = select(UserQuota).where(UserQuota.user_id == user_id)
        result = await self.db.execute(quota_stmt)
        quota = result.scalar_one_or_none()

        if quota:
            quota.tokens_used_period += tokens_used
            quota.updated_at = datetime.now(timezone.utc)

        await self.db.flush()
        return usage

    async def get_usage(
        self,
        user_id: int,
        period: Literal["day", "week", "month", "all"] = "month",
    ) -> int:
        """Get total token usage for a user in the specified period.

        Args:
            user_id: The user's ID
            period: Time period to query ("day", "week", "month", "all")

        Returns:
            Total tokens used in the period
        """
        # Calculate the start date for the period
        now = datetime.now(timezone.utc)

        if period == "day":
            start_date = now - timedelta(days=1)
        elif period == "week":
            start_date = now - timedelta(weeks=1)
        elif period == "month":
            start_date = now - timedelta(days=30)
        else:  # "all"
            start_date = datetime.min.replace(tzinfo=timezone.utc)

        # Query total usage
        stmt = (
            select(func.coalesce(func.sum(TokenUsage.tokens_used), 0))
            .where(TokenUsage.user_id == user_id)
            .where(TokenUsage.created_at >= start_date)
        )

        result = await self.db.execute(stmt)
        total_tokens = result.scalar_one()

        return int(total_tokens)

    async def get_usage_by_provider(
        self,
        user_id: int,
        period: Literal["day", "week", "month", "all"] = "month",
    ) -> dict[str, int]:
        """Get token usage breakdown by provider for a user.

        Args:
            user_id: The user's ID
            period: Time period to query

        Returns:
            Dictionary mapping provider names to token counts
        """
        # Calculate the start date for the period
        now = datetime.now(timezone.utc)

        if period == "day":
            start_date = now - timedelta(days=1)
        elif period == "week":
            start_date = now - timedelta(weeks=1)
        elif period == "month":
            start_date = now - timedelta(days=30)
        else:  # "all"
            start_date = datetime.min.replace(tzinfo=timezone.utc)

        # Query usage by provider
        stmt = (
            select(TokenUsage.provider, func.sum(TokenUsage.tokens_used))
            .where(TokenUsage.user_id == user_id)
            .where(TokenUsage.created_at >= start_date)
            .group_by(TokenUsage.provider)
        )

        result = await self.db.execute(stmt)
        usage_by_provider = {provider: int(tokens) for provider, tokens in result.all()}

        return usage_by_provider

    async def check_quota(self, user_id: int) -> bool:
        """Check if a user has remaining quota for token usage.

        Args:
            user_id: The user's ID

        Returns:
            True if the user has remaining quota, False otherwise
        """
        stmt = select(UserQuota).where(UserQuota.user_id == user_id)
        result = await self.db.execute(stmt)
        quota = result.scalar_one_or_none()

        if not quota:
            # No quota record found - should not happen in production
            # Return False to be safe
            return False

        # BYOK users have unlimited quota from server pool perspective
        if quota.byok_enabled:
            return True

        # Check if within limit
        return quota.tokens_used_period < quota.token_limit

    async def get_remaining_tokens(self, user_id: int) -> int:
        """Calculate remaining tokens for a user in the current billing period.

        Args:
            user_id: The user's ID

        Returns:
            Number of remaining tokens (0 if quota exceeded or BYOK enabled)
        """
        stmt = select(UserQuota).where(UserQuota.user_id == user_id)
        result = await self.db.execute(stmt)
        quota = result.scalar_one_or_none()

        if not quota:
            return 0

        # BYOK users don't have a server-side limit
        if quota.byok_enabled:
            return 0  # Return 0 to indicate "not applicable"

        remaining = quota.token_limit - quota.tokens_used_period
        return max(0, remaining)

    async def get_quota_info(self, user_id: int) -> dict:
        """Get comprehensive quota information for a user.

        Args:
            user_id: The user's ID

        Returns:
            Dictionary containing quota details
        """
        stmt = select(UserQuota).where(UserQuota.user_id == user_id)
        result = await self.db.execute(stmt)
        quota = result.scalar_one_or_none()

        if not quota:
            return {
                "tier": "unknown",
                "tokens_used": 0,
                "token_limit": 0,
                "tokens_remaining": 0,
                "percentage_used": 0.0,
                "period_start": None,
                "period_end": None,
                "byok_enabled": False,
            }

        return {
            "tier": quota.tier,
            "tokens_used": quota.tokens_used_period,
            "token_limit": quota.token_limit,
            "tokens_remaining": max(0, quota.token_limit - quota.tokens_used_period),
            "period_start": quota.period_start.isoformat(),
            "period_end": quota.period_end.isoformat(),
            "byok_enabled": quota.byok_enabled,
            "percentage_used": (
                (quota.tokens_used_period / quota.token_limit * 100)
                if quota.token_limit > 0
                else 0
            ),
        }

    async def initialize_user_quota(
        self,
        user_id: int,
        tier: Literal["free", "starter", "pro", "enterprise"] = "free",
        byok_enabled: bool = False,
        enterprise_pool_id: str | None = None,
    ) -> UserQuota:
        """Initialize quota tracking for a new user.

        Args:
            user_id: The user's ID
            tier: Subscription tier
            byok_enabled: Whether the user has BYOK enabled
            enterprise_pool_id: Optional enterprise pool ID for shared quotas

        Returns:
            The created UserQuota record
        """
        # Calculate billing period (monthly)
        now = datetime.now(timezone.utc)
        period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Calculate next month
        if period_start.month == 12:
            period_end = period_start.replace(year=period_start.year + 1, month=1)
        else:
            period_end = period_start.replace(month=period_start.month + 1)

        # Get token limit for tier
        token_limit = TIER_TOKEN_LIMITS.get(tier, 0)

        quota = UserQuota(
            user_id=user_id,
            tier=tier,
            period_start=period_start,
            period_end=period_end,
            tokens_used_period=0,
            token_limit=token_limit,
            byok_enabled=byok_enabled,
            enterprise_pool_id=enterprise_pool_id,
        )

        self.db.add(quota)
        await self.db.flush()

        return quota

    async def reset_period_usage(self, user_id: int) -> None:
        """Reset usage for a new billing period.

        Should be called when a billing period ends.

        Args:
            user_id: The user's ID
        """
        stmt = select(UserQuota).where(UserQuota.user_id == user_id)
        result = await self.db.execute(stmt)
        quota = result.scalar_one_or_none()

        if not quota:
            return

        # Update to new billing period
        now = datetime.now(timezone.utc)
        period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        if period_start.month == 12:
            period_end = period_start.replace(year=period_start.year + 1, month=1)
        else:
            period_end = period_start.replace(month=period_start.month + 1)

        quota.period_start = period_start
        quota.period_end = period_end
        quota.tokens_used_period = 0
        quota.updated_at = now

        await self.db.flush()
