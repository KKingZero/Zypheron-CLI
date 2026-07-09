"""Tests for the token tracking service.

Tests cover:
- count_tokens() for various models (gpt-4, claude, etc.)
- Quota enforcement: check_quota returns False when used >= limit
- Period reset (reset_period_usage sets tokens_used_period to 0)
- Unknown model fallback to cl100k_base
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.license import License
from app.models.token_usage import TokenUsage, UserQuota
from app.models.user import User
from app.services.token_tracking import TokenTrackingService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_user_with_quota(
    db: AsyncSession,
    tier: str = "pro",
    tokens_used: int = 100_000,
    token_limit: int = 3_000_000,
    byok_enabled: bool = False,
) -> tuple[User, UserQuota]:
    """Create user with a quota record."""
    user = User(
        email=f"track_{tier}_{tokens_used}@example.com",
        password_hash=hash_password("testpass123"),
        tier=tier,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()

    now = datetime.now(timezone.utc)
    quota = UserQuota(
        user_id=user.id,
        tier=tier,
        period_start=now.replace(day=1),
        period_end=now.replace(day=1) + timedelta(days=31),
        tokens_used_period=tokens_used,
        token_limit=token_limit,
        byok_enabled=byok_enabled,
    )
    db.add(quota)
    await db.commit()
    await db.refresh(user)
    await db.refresh(quota)
    return user, quota


# ---------------------------------------------------------------------------
# count_tokens tests
# ---------------------------------------------------------------------------


class TestCountTokens:
    """Test static count_tokens method for different models."""

    def test_gpt4_tokenizer(self):
        text = "Hello, world! This is a test sentence for token counting."
        tokens = TokenTrackingService.count_tokens(text, "gpt-4")
        assert isinstance(tokens, int)
        assert tokens > 0

    def test_gpt4o_tokenizer(self):
        text = "The quick brown fox jumps over the lazy dog."
        tokens = TokenTrackingService.count_tokens(text, "gpt-4o")
        assert tokens > 0

    def test_gpt35_tokenizer(self):
        tokens = TokenTrackingService.count_tokens("simple text", "gpt-3.5-turbo")
        assert tokens > 0

    def test_claude_model_uses_cl100k(self):
        """Claude models should use cl100k_base as approximation."""
        tokens = TokenTrackingService.count_tokens("hello world", "claude-3-opus")
        assert tokens > 0

    def test_grok_model_uses_cl100k(self):
        tokens = TokenTrackingService.count_tokens("hello world", "grok-beta")
        assert tokens > 0

    def test_deepseek_model(self):
        tokens = TokenTrackingService.count_tokens("hello world", "deepseek-chat")
        assert tokens > 0

    def test_unknown_model_falls_back_to_cl100k(self):
        """Unknown models should fall back to cl100k_base without error."""
        tokens = TokenTrackingService.count_tokens("test text", "totally-unknown-model-xyz")
        assert isinstance(tokens, int)
        assert tokens > 0

    def test_empty_string(self):
        tokens = TokenTrackingService.count_tokens("", "gpt-4")
        assert tokens == 0

    def test_empty_string_fallback_returns_zero(self):
        with patch("app.services.token_tracking.tiktoken.get_encoding", side_effect=RuntimeError("offline")):
            tokens = TokenTrackingService.count_tokens("", "gpt-4")
        assert tokens == 0

    def test_tokenizer_failure_uses_conservative_fallback(self):
        text = "abcdefghi"
        with patch("app.services.token_tracking.tiktoken.get_encoding", side_effect=RuntimeError("offline")):
            tokens = TokenTrackingService.count_tokens(text, "gpt-4")
        assert tokens == 3

    def test_conservative_fallback_rounds_up(self):
        assert TokenTrackingService.conservative_token_estimate("abcd") == 2
        assert TokenTrackingService.conservative_token_estimate("abc") == 1
        assert TokenTrackingService.conservative_token_estimate("") == 0

    def test_long_text(self):
        long_text = "word " * 1000
        tokens = TokenTrackingService.count_tokens(long_text, "gpt-4")
        assert tokens > 100


class TestHashPrompt:
    """Test prompt hashing."""

    def test_deterministic(self):
        h1 = TokenTrackingService.hash_prompt("hello")
        h2 = TokenTrackingService.hash_prompt("hello")
        assert h1 == h2

    def test_different_prompts_different_hashes(self):
        h1 = TokenTrackingService.hash_prompt("hello")
        h2 = TokenTrackingService.hash_prompt("goodbye")
        assert h1 != h2

    def test_hash_length(self):
        h = TokenTrackingService.hash_prompt("test")
        assert len(h) == 64  # SHA-256 hex digest


# ---------------------------------------------------------------------------
# Quota enforcement tests
# ---------------------------------------------------------------------------


class TestCheckQuota:
    """Test check_quota returns correct boolean."""

    async def test_quota_available(self, test_db):
        """User with remaining quota returns True."""
        user, quota = await _create_user_with_quota(
            test_db, tokens_used=100_000, token_limit=3_000_000
        )
        service = TokenTrackingService(test_db)
        assert await service.check_quota(user.id) is True

    async def test_quota_exhausted(self, test_db):
        """User at or over limit returns False."""
        user, quota = await _create_user_with_quota(
            test_db, tokens_used=3_000_000, token_limit=3_000_000
        )
        service = TokenTrackingService(test_db)
        assert await service.check_quota(user.id) is False

    async def test_quota_over_limit(self, test_db):
        """User over limit returns False."""
        user, quota = await _create_user_with_quota(
            test_db, tokens_used=5_000_000, token_limit=3_000_000
        )
        service = TokenTrackingService(test_db)
        assert await service.check_quota(user.id) is False

    async def test_byok_has_unlimited_quota(self, test_db):
        """BYOK-enabled users always have quota."""
        user, quota = await _create_user_with_quota(
            test_db, tokens_used=999_999_999, token_limit=0, byok_enabled=True
        )
        service = TokenTrackingService(test_db)
        assert await service.check_quota(user.id) is True

    async def test_no_quota_record_returns_false(self, test_db):
        """Missing quota record should return False."""
        user = User(
            email="noquota@example.com",
            password_hash=hash_password("testpass123"),
            tier="free",
            is_active=True,
            is_verified=True,
        )
        test_db.add(user)
        await test_db.commit()
        await test_db.refresh(user)

        service = TokenTrackingService(test_db)
        assert await service.check_quota(user.id) is False


# ---------------------------------------------------------------------------
# Record usage tests
# ---------------------------------------------------------------------------


class TestRecordUsage:
    """Test recording token usage."""

    async def test_record_increments_quota(self, test_db):
        user, quota = await _create_user_with_quota(
            test_db, tokens_used=100, token_limit=3_000_000
        )
        service = TokenTrackingService(test_db)
        usage = await service.record_usage(
            user_id=user.id,
            tokens_used=500,
            provider="openai",
            model="gpt-4",
        )
        assert usage.tokens_used == 500
        # Quota should be incremented
        await test_db.refresh(quota)
        assert quota.tokens_used_period == 600

    async def test_record_negative_tokens_raises(self, test_db):
        user, _ = await _create_user_with_quota(test_db)
        service = TokenTrackingService(test_db)
        with pytest.raises(ValueError, match="non-negative"):
            await service.record_usage(
                user_id=user.id,
                tokens_used=-10,
                provider="openai",
                model="gpt-4",
            )


# ---------------------------------------------------------------------------
# Period reset tests
# ---------------------------------------------------------------------------


class TestResetPeriodUsage:
    """Test resetting usage for a new billing period."""

    async def test_reset_sets_tokens_to_zero(self, test_db):
        user, quota = await _create_user_with_quota(
            test_db, tokens_used=500_000, token_limit=3_000_000
        )
        service = TokenTrackingService(test_db)
        await service.reset_period_usage(user.id)

        await test_db.refresh(quota)
        assert quota.tokens_used_period == 0

    async def test_reset_updates_period_dates(self, test_db):
        user, quota = await _create_user_with_quota(test_db, tokens_used=100)
        old_start = quota.period_start

        service = TokenTrackingService(test_db)
        await service.reset_period_usage(user.id)

        await test_db.refresh(quota)
        # Period start should be the first day of the current month
        now = datetime.now(timezone.utc)
        expected_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        assert quota.period_start.day == expected_start.day

    async def test_reset_nonexistent_user_is_noop(self, test_db):
        """Resetting a user without quota should not error."""
        service = TokenTrackingService(test_db)
        await service.reset_period_usage(99999)  # Non-existent user ID


# ---------------------------------------------------------------------------
# Get usage tests
# ---------------------------------------------------------------------------


class TestGetUsage:
    """Test usage querying."""

    async def test_get_usage_returns_total(self, test_db):
        user, _ = await _create_user_with_quota(test_db)
        service = TokenTrackingService(test_db)
        # Record some usage
        await service.record_usage(user.id, 100, "openai", "gpt-4")
        await service.record_usage(user.id, 200, "anthropic", "claude-3-opus")
        await test_db.flush()

        total = await service.get_usage(user.id, period="month")
        assert total == 300

    async def test_get_usage_by_provider(self, test_db):
        user, _ = await _create_user_with_quota(test_db)
        service = TokenTrackingService(test_db)
        await service.record_usage(user.id, 100, "openai", "gpt-4")
        await service.record_usage(user.id, 200, "openai", "gpt-4")
        await service.record_usage(user.id, 50, "anthropic", "claude-3-opus")
        await test_db.flush()

        by_provider = await service.get_usage_by_provider(user.id, period="month")
        assert by_provider.get("openai") == 300
        assert by_provider.get("anthropic") == 50


# ---------------------------------------------------------------------------
# Remaining tokens tests
# ---------------------------------------------------------------------------


class TestGetRemainingTokens:
    """Test remaining tokens calculation."""

    async def test_remaining_positive(self, test_db):
        user, _ = await _create_user_with_quota(
            test_db, tokens_used=100_000, token_limit=3_000_000
        )
        service = TokenTrackingService(test_db)
        remaining = await service.get_remaining_tokens(user.id)
        assert remaining == 2_900_000

    async def test_remaining_zero_when_exhausted(self, test_db):
        user, _ = await _create_user_with_quota(
            test_db, tokens_used=3_000_000, token_limit=3_000_000
        )
        service = TokenTrackingService(test_db)
        remaining = await service.get_remaining_tokens(user.id)
        assert remaining == 0

    async def test_remaining_zero_for_byok(self, test_db):
        """BYOK users get 0 remaining (not applicable)."""
        user, _ = await _create_user_with_quota(
            test_db, tokens_used=0, token_limit=0, byok_enabled=True
        )
        service = TokenTrackingService(test_db)
        remaining = await service.get_remaining_tokens(user.id)
        assert remaining == 0


# ---------------------------------------------------------------------------
# Quota info tests
# ---------------------------------------------------------------------------


class TestGetQuotaInfo:
    """Test comprehensive quota info retrieval."""

    async def test_quota_info_complete(self, test_db):
        user, _ = await _create_user_with_quota(
            test_db, tier="pro", tokens_used=500_000, token_limit=3_000_000
        )
        service = TokenTrackingService(test_db)
        info = await service.get_quota_info(user.id)
        assert info["tier"] == "pro"
        assert info["tokens_used"] == 500_000
        assert info["token_limit"] == 3_000_000
        assert info["tokens_remaining"] == 2_500_000
        assert info["percentage_used"] == pytest.approx(16.67, abs=0.01)

    async def test_quota_info_no_record(self, test_db):
        """Missing quota record should return safe defaults."""
        user = User(
            email="noinfo@example.com",
            password_hash=hash_password("testpass123"),
            tier="free",
            is_active=True,
            is_verified=True,
        )
        test_db.add(user)
        await test_db.commit()
        await test_db.refresh(user)

        service = TokenTrackingService(test_db)
        info = await service.get_quota_info(user.id)
        assert info["tier"] == "unknown"
        assert info["tokens_used"] == 0
