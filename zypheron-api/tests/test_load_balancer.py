"""Tests for the AI load balancer service.

Tests cover:
- Round-robin key rotation
- Health tracking (3 consecutive failures marks unhealthy, cooldown recovery)
- Failover to next healthy key
- All-keys-exhausted error
- BYOK mode bypasses pool
"""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.ai_providers import (
    InvalidKeyError,
    ProviderType,
    QuotaExceededError,
    RateLimitError,
)
from app.services.load_balancer import AILoadBalancer, KeyHealth, ProviderKeyPool


# ---------------------------------------------------------------------------
# KeyHealth unit tests
# ---------------------------------------------------------------------------


class TestKeyHealth:
    """Test KeyHealth dataclass behaviour."""

    def test_initial_state_is_healthy(self):
        kh = KeyHealth(key_index=0)
        assert kh.is_healthy is True
        assert kh.failures == 0
        assert kh.consecutive_failures == 0

    def test_mark_success_resets_consecutive_failures(self):
        kh = KeyHealth(key_index=0, consecutive_failures=2, failures=5)
        kh.mark_success()
        assert kh.consecutive_failures == 0
        assert kh.is_healthy is True

    def test_three_consecutive_failures_marks_unhealthy(self):
        kh = KeyHealth(key_index=0)
        kh.mark_failure(cooldown_seconds=60)
        kh.mark_failure(cooldown_seconds=60)
        assert kh.is_healthy is True  # 2 failures: still healthy
        kh.mark_failure(cooldown_seconds=60)
        assert kh.is_healthy is False  # 3 failures: unhealthy
        assert kh.consecutive_failures == 3
        assert kh.cooldown_until > time.time()

    def test_recovery_after_cooldown(self):
        kh = KeyHealth(key_index=0)
        # Force unhealthy with expired cooldown
        kh.is_healthy = False
        kh.consecutive_failures = 3
        kh.cooldown_until = time.time() - 1  # cooldown already passed
        assert kh.check_recovery() is True
        assert kh.is_healthy is True
        assert kh.consecutive_failures == 0

    def test_no_recovery_during_cooldown(self):
        kh = KeyHealth(key_index=0)
        kh.is_healthy = False
        kh.consecutive_failures = 3
        kh.cooldown_until = time.time() + 60  # still in cooldown
        assert kh.check_recovery() is False
        assert kh.is_healthy is False


# ---------------------------------------------------------------------------
# ProviderKeyPool unit tests
# ---------------------------------------------------------------------------


class TestProviderKeyPool:
    """Test ProviderKeyPool round-robin and health management."""

    def test_round_robin_cycles_through_keys(self):
        pool = ProviderKeyPool(
            provider_type=ProviderType.OPENAI,
            keys=["k0", "k1", "k2"],
        )
        results = []
        for _ in range(6):
            result = pool.get_next_key()
            assert result is not None
            results.append(result[1])  # key_index
        # Should cycle: 0,1,2,0,1,2
        assert results == [0, 1, 2, 0, 1, 2]

    def test_skips_unhealthy_key(self):
        pool = ProviderKeyPool(
            provider_type=ProviderType.OPENAI,
            keys=["k0", "k1", "k2"],
        )
        # Mark key 0 as unhealthy (3 failures)
        pool.mark_failure(0, cooldown_seconds=600)
        pool.mark_failure(0, cooldown_seconds=600)
        pool.mark_failure(0, cooldown_seconds=600)
        assert pool.health_status[0].is_healthy is False

        # get_next_key should skip key 0
        key, idx = pool.get_next_key()
        assert idx != 0

    def test_failover_to_next_healthy_key(self):
        pool = ProviderKeyPool(
            provider_type=ProviderType.OPENAI,
            keys=["k0", "k1"],
        )
        # Mark key 0 unhealthy
        for _ in range(3):
            pool.mark_failure(0, cooldown_seconds=600)

        # Should only return key 1
        for _ in range(5):
            key, idx = pool.get_next_key()
            assert idx == 1
            assert key == "k1"

    def test_no_healthy_keys_returns_none(self):
        pool = ProviderKeyPool(
            provider_type=ProviderType.OPENAI,
            keys=["k0", "k1"],
        )
        # Mark both keys unhealthy
        for key_idx in (0, 1):
            for _ in range(3):
                pool.mark_failure(key_idx, cooldown_seconds=600)

        result = pool.get_next_key()
        assert result is None

    def test_empty_pool_returns_none(self):
        pool = ProviderKeyPool(
            provider_type=ProviderType.OPENAI,
            keys=[],
        )
        assert pool.get_next_key() is None

    def test_mark_success_recovers_key(self):
        pool = ProviderKeyPool(
            provider_type=ProviderType.OPENAI,
            keys=["k0"],
        )
        # Make key unhealthy but do not set high cooldown
        pool.health_status[0].is_healthy = False
        pool.health_status[0].consecutive_failures = 3
        pool.health_status[0].cooldown_until = time.time() - 1  # expired
        # get_next_key checks recovery
        result = pool.get_next_key()
        assert result is not None
        assert result[1] == 0

    def test_get_stats_accurate(self):
        pool = ProviderKeyPool(
            provider_type=ProviderType.OPENAI,
            keys=["k0", "k1", "k2"],
        )
        for _ in range(3):
            pool.mark_failure(0, cooldown_seconds=600)

        stats = pool.get_stats()
        assert stats["total_keys"] == 3
        assert stats["healthy_keys"] == 2
        assert stats["unhealthy_keys"] == 1
        assert stats["total_failures"] == 3


# ---------------------------------------------------------------------------
# AILoadBalancer unit tests
# ---------------------------------------------------------------------------


class TestAILoadBalancer:
    """Test AILoadBalancer initialization, provider creation and BYOK."""

    def test_initialization_with_keys(self):
        lb = AILoadBalancer(
            openai_keys=["ok1", "ok2"],
            anthropic_keys=["ak1"],
            enable_ollama=True,
        )
        providers = lb.get_available_providers()
        assert "openai" in providers
        assert "anthropic" in providers
        assert "ollama" in providers
        assert "grok" not in providers
        assert "deepseek" not in providers

    def test_empty_keys_omitted(self):
        lb = AILoadBalancer(
            openai_keys=None,
            anthropic_keys=None,
            enable_ollama=False,
        )
        assert lb.get_available_providers() == []

    async def test_byok_bypasses_pool(self):
        """BYOK request should use the user-supplied key, not rotate pool."""
        lb = AILoadBalancer(
            openai_keys=["server-key-1"],
            enable_ollama=False,
        )
        provider = await lb.get_provider(
            provider_type=ProviderType.OPENAI,
            user_api_key="user-byok-key",
        )
        # Provider should have been created with the user key
        assert provider._api_key == "user-byok-key"
        await provider.close()

    async def test_server_key_used_when_no_byok(self):
        lb = AILoadBalancer(
            openai_keys=["server-key-1"],
            enable_ollama=False,
        )
        provider = await lb.get_provider(
            provider_type=ProviderType.OPENAI,
        )
        assert provider._api_key == "server-key-1"
        await provider.close()

    async def test_provider_not_available_raises(self):
        lb = AILoadBalancer(enable_ollama=False)
        with pytest.raises(ValueError, match="not available"):
            await lb.get_provider(provider_type=ProviderType.OPENAI)

    async def test_no_healthy_keys_raises(self):
        lb = AILoadBalancer(
            openai_keys=["k1"],
            enable_ollama=False,
        )
        # Mark key unhealthy
        pool = lb._pools[ProviderType.OPENAI]
        for _ in range(3):
            pool.mark_failure(0, cooldown_seconds=600)

        with pytest.raises(ValueError, match="no healthy keys"):
            await lb.get_provider(provider_type=ProviderType.OPENAI)

    def test_get_pool_stats(self):
        lb = AILoadBalancer(
            openai_keys=["k1", "k2"],
            enable_ollama=True,
        )
        stats = lb.get_pool_stats()
        assert "openai" in stats
        assert "ollama" in stats
        assert stats["openai"]["total_keys"] == 2
        assert stats["openai"]["healthy_keys"] == 2

    async def test_validate_user_key_success(self):
        lb = AILoadBalancer(enable_ollama=False)
        # Patch the provider's validate_key to return True
        with patch.object(
            lb,
            "_create_provider",
            return_value=AsyncMock(validate_key=AsyncMock(return_value=True), close=AsyncMock()),
        ):
            result = await lb.validate_user_key(ProviderType.OPENAI, "test-key")
            assert result is True

    async def test_validate_user_key_failure(self):
        lb = AILoadBalancer(enable_ollama=False)
        with patch.object(
            lb,
            "_create_provider",
            return_value=AsyncMock(validate_key=AsyncMock(return_value=False), close=AsyncMock()),
        ):
            result = await lb.validate_user_key(ProviderType.OPENAI, "bad-key")
            assert result is False


class TestExecuteWithFailover:
    """Test execute_with_failover for retry and failover logic."""

    async def test_success_on_first_try(self):
        lb = AILoadBalancer(openai_keys=["k1", "k2"], enable_ollama=False)

        mock_provider = AsyncMock()
        mock_provider.chat_completion = AsyncMock(return_value="result")
        mock_provider.close = AsyncMock()

        with patch.object(lb, "_create_provider", return_value=mock_provider):
            result = await lb.execute_with_failover(
                provider_type=ProviderType.OPENAI,
                operation="chat_completion",
                messages=[{"role": "user", "content": "hi"}],
            )
        assert result == "result"

    async def test_failover_after_rate_limit(self):
        lb = AILoadBalancer(openai_keys=["k1", "k2"], enable_ollama=False)

        call_count = 0

        async def mock_chat(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RateLimitError("rate limited", provider=ProviderType.OPENAI, retry_after=60)
            return "success"

        mock_provider = AsyncMock()
        mock_provider.chat_completion = mock_chat
        mock_provider.close = AsyncMock()

        with patch.object(lb, "_create_provider", return_value=mock_provider):
            result = await lb.execute_with_failover(
                provider_type=ProviderType.OPENAI,
                operation="chat_completion",
                max_retries=3,
                messages=[{"role": "user", "content": "hi"}],
            )
        assert result == "success"
        assert call_count == 2

    async def test_all_retries_exhausted_raises(self):
        lb = AILoadBalancer(openai_keys=["k1"], enable_ollama=False)

        mock_provider = AsyncMock()
        mock_provider.chat_completion = AsyncMock(
            side_effect=RateLimitError("rate limited", provider=ProviderType.OPENAI)
        )
        mock_provider.close = AsyncMock()

        with patch.object(lb, "_create_provider", return_value=mock_provider):
            with pytest.raises(RateLimitError):
                await lb.execute_with_failover(
                    provider_type=ProviderType.OPENAI,
                    operation="chat_completion",
                    max_retries=2,
                    messages=[{"role": "user", "content": "hi"}],
                )
