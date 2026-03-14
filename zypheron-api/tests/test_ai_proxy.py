"""Tests for AI proxy router.

Tests cover:
- Authentication and tier-based authorization
- Chat completion with mocked providers
- Streaming SSE format
- Token quota enforcement (402 when quota exceeded)
- Rate limiting (429 responses)
- BYOK key handling
- Error response mapping (400, 401, 403, 429, 503)
"""

import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.license import License
from app.models.session import Session
from app.models.token_usage import UserQuota
from app.models.user import User
from app.models.user_api_key import UserAPIKey
from app.services.ai_providers import (
    AIProviderError,
    AIResponse,
    InvalidKeyError,
    ProviderType,
    QuotaExceededError,
    RateLimitError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_pro_user_with_quota(
    db: AsyncSession,
    tokens_used: int = 100_000,
    token_limit: int = 3_000_000,
    email: str = "prouser@example.com",
) -> tuple[User, License, UserQuota, str, dict[str, str]]:
    """Create a pro user with quota, session and auth headers."""
    user = User(
        email=email,
        password_hash=hash_password("testpass123"),
        tier="pro",
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()

    license_ = License(
        user_id=user.id,
        tier="pro",
        status="active",
        stripe_customer_id="cus_test",
        stripe_subscription_id="sub_test",
    )
    db.add(license_)

    now = datetime.now(timezone.utc)
    quota = UserQuota(
        user_id=user.id,
        tier="pro",
        period_start=now.replace(day=1),
        period_end=(now.replace(day=1) + timedelta(days=31)),
        tokens_used_period=tokens_used,
        token_limit=token_limit,
        byok_enabled=False,
    )
    db.add(quota)

    token_data = {"sub": str(user.id), "email": user.email}
    token = create_access_token(token_data)
    session = Session(user_id=user.id, token=token)
    db.add(session)

    await db.commit()
    await db.refresh(user)
    await db.refresh(quota)

    headers = {"Authorization": f"Bearer {token}"}
    return user, license_, quota, token, headers


async def _create_free_user(
    db: AsyncSession,
    email: str = "freeuser@example.com",
) -> tuple[User, str, dict[str, str]]:
    """Create a free-tier user with session and auth headers."""
    user = User(
        email=email,
        password_hash=hash_password("testpass123"),
        tier="free",
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()

    token_data = {"sub": str(user.id), "email": user.email}
    token = create_access_token(token_data)
    session = Session(user_id=user.id, token=token)
    db.add(session)

    await db.commit()
    await db.refresh(user)

    headers = {"Authorization": f"Bearer {token}"}
    return user, token, headers


def _mock_ai_response(provider: ProviderType = ProviderType.OPENAI) -> AIResponse:
    """Return a canned AIResponse for mocking."""
    return AIResponse(
        provider=provider,
        model="gpt-4o-mini",
        content="Hello from the mock!",
        prompt_tokens=10,
        completion_tokens=15,
        total_tokens=25,
        latency_ms=100,
        finish_reason="stop",
        metadata={"system_fingerprint": "fp_mock"},
    )


def _mock_provider(provider_type: ProviderType = ProviderType.OPENAI):
    """Create a mock BaseAIProvider."""
    mock = AsyncMock()
    mock.provider_type = provider_type
    mock._get_default_model.return_value = "gpt-4o-mini"
    mock.chat_completion = AsyncMock(return_value=_mock_ai_response(provider_type))
    mock.close = AsyncMock()
    return mock


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAuthAndAuthorization:
    """Test authentication and tier-based authorization."""

    async def test_unauthenticated_request_returns_401(self, test_db, override_get_db):
        """Unauthenticated user cannot access /ai/chat."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post(
                "/ai/chat",
                json={
                    "messages": [{"role": "user", "content": "hello"}],
                    "provider": "ollama",
                },
            )
        assert resp.status_code == 401

    async def test_free_tier_denied_cloud_provider(self, test_db, override_get_db):
        """Free-tier user gets 403 when requesting a cloud provider."""
        _, _, headers = await _create_free_user(test_db)

        # Mock redis and load_balancer to avoid external dependencies
        mock_lb = MagicMock()
        mock_lb.get_available_providers.return_value = ["openai", "ollama"]
        mock_provider_obj = _mock_provider(ProviderType.OPENAI)
        mock_lb.get_provider = AsyncMock(return_value=mock_provider_obj)

        with (
            patch("app.routers.ai_proxy.get_load_balancer", return_value=mock_lb),
            patch("app.routers.ai_proxy.check_provider_rate_limit", new_callable=AsyncMock, return_value=(True, 59, int(time.time()) + 60, "openai_gpt4")),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post(
                    "/ai/chat",
                    json={
                        "messages": [{"role": "user", "content": "hello"}],
                        "provider": "openai",
                    },
                    headers=headers,
                )
            assert resp.status_code == 403
            assert "Starter tier" in resp.json()["detail"]

    async def test_free_tier_auto_select_filters_to_ollama(self, test_db, override_get_db):
        """When no provider is specified, free-tier should auto-select ollama only."""
        _, _, headers = await _create_free_user(test_db)

        mock_lb = MagicMock()
        mock_lb.get_available_providers.return_value = ["openai", "anthropic", "ollama"]
        mock_prov = _mock_provider(ProviderType.OLLAMA)
        mock_prov._get_default_model.return_value = "llama3"
        mock_lb.get_provider = AsyncMock(return_value=mock_prov)

        with (
            patch("app.routers.ai_proxy.get_load_balancer", return_value=mock_lb),
            patch("app.routers.ai_proxy.check_provider_rate_limit", new_callable=AsyncMock, return_value=(True, -1, 0, "ollama")),
            patch("app.routers.ai_proxy.update_token_usage", new_callable=AsyncMock),
            patch("app.routers.ai_proxy.TokenReservationService") as mock_trs_cls,
        ):
            mock_trs = AsyncMock()
            mock_trs.reserve_tokens = AsyncMock(return_value=(True, "res-1", 0))
            mock_trs.finalize_reservation = AsyncMock()
            mock_trs_cls.return_value = mock_trs

            mock_prov.chat_completion = AsyncMock(
                return_value=AIResponse(
                    provider=ProviderType.OLLAMA,
                    model="llama3",
                    content="hi",
                    prompt_tokens=5,
                    completion_tokens=3,
                    total_tokens=8,
                    latency_ms=50,
                    finish_reason="stop",
                )
            )

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post(
                    "/ai/chat",
                    json={"messages": [{"role": "user", "content": "hello"}]},
                    headers=headers,
                )
            assert resp.status_code == 200
            assert resp.json()["provider"] == "ollama"

    async def test_paid_tier_can_use_cloud_provider(self, test_db, override_get_db):
        """Pro-tier user can use OpenAI."""
        user, _, quota, _, headers = await _create_pro_user_with_quota(test_db)

        mock_lb = MagicMock()
        mock_prov = _mock_provider(ProviderType.OPENAI)
        mock_lb.get_provider = AsyncMock(return_value=mock_prov)
        mock_lb.get_available_providers.return_value = ["openai"]

        with (
            patch("app.routers.ai_proxy.get_load_balancer", return_value=mock_lb),
            patch("app.routers.ai_proxy.check_provider_rate_limit", new_callable=AsyncMock, return_value=(True, 59, int(time.time()) + 60, "openai_gpt4")),
            patch("app.routers.ai_proxy.update_token_usage", new_callable=AsyncMock),
            patch("app.routers.ai_proxy.TokenReservationService") as mock_trs_cls,
            patch("app.routers.ai_proxy._check_cache", new_callable=AsyncMock, return_value=None),
            patch("app.routers.ai_proxy._store_cache", new_callable=AsyncMock),
        ):
            mock_trs = AsyncMock()
            mock_trs.reserve_tokens = AsyncMock(return_value=(True, "res-1", 0))
            mock_trs.finalize_reservation = AsyncMock()
            mock_trs_cls.return_value = mock_trs

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post(
                    "/ai/chat",
                    json={
                        "messages": [{"role": "user", "content": "hello"}],
                        "provider": "openai",
                    },
                    headers=headers,
                )
            assert resp.status_code == 200
            data = resp.json()
            assert data["content"] == "Hello from the mock!"
            assert data["provider"] == "openai"


class TestChatCompletion:
    """Test non-streaming chat completion."""

    async def test_successful_completion(self, test_db, override_get_db):
        """Successful non-streaming completion returns proper response shape."""
        _, _, _, _, headers = await _create_pro_user_with_quota(test_db)

        mock_lb = MagicMock()
        mock_prov = _mock_provider()
        mock_lb.get_provider = AsyncMock(return_value=mock_prov)
        mock_lb.get_available_providers.return_value = ["openai"]

        with (
            patch("app.routers.ai_proxy.get_load_balancer", return_value=mock_lb),
            patch("app.routers.ai_proxy.check_provider_rate_limit", new_callable=AsyncMock, return_value=(True, 59, int(time.time()) + 60, "openai_gpt4")),
            patch("app.routers.ai_proxy.update_token_usage", new_callable=AsyncMock),
            patch("app.routers.ai_proxy.TokenReservationService") as mock_trs_cls,
            patch("app.routers.ai_proxy._check_cache", new_callable=AsyncMock, return_value=None),
            patch("app.routers.ai_proxy._store_cache", new_callable=AsyncMock),
        ):
            mock_trs = AsyncMock()
            mock_trs.reserve_tokens = AsyncMock(return_value=(True, "res-1", 0))
            mock_trs.finalize_reservation = AsyncMock()
            mock_trs_cls.return_value = mock_trs

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post(
                    "/ai/chat",
                    json={
                        "messages": [{"role": "user", "content": "hello"}],
                        "provider": "openai",
                    },
                    headers=headers,
                )
            assert resp.status_code == 200
            body = resp.json()
            assert "content" in body
            assert "usage" in body
            assert body["usage"]["total_tokens"] == 25

    async def test_unsupported_provider_returns_400(self, test_db, override_get_db):
        """Invalid provider name triggers 400."""
        _, _, _, _, headers = await _create_pro_user_with_quota(test_db)

        mock_lb = MagicMock()
        mock_lb.get_available_providers.return_value = ["openai"]
        mock_prov = _mock_provider()
        mock_lb.get_provider = AsyncMock(return_value=mock_prov)

        with (
            patch("app.routers.ai_proxy.get_load_balancer", return_value=mock_lb),
            patch("app.routers.ai_proxy.check_provider_rate_limit", new_callable=AsyncMock, return_value=(True, 59, int(time.time()) + 60, "openai_gpt4")),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post(
                    "/ai/chat",
                    json={
                        "messages": [{"role": "user", "content": "hello"}],
                        "provider": "fakeprovider",
                    },
                    headers=headers,
                )
            # Pydantic validation on Literal type should catch this
            assert resp.status_code == 422 or resp.status_code == 400


class TestStreamingSSE:
    """Test streaming SSE format."""

    async def test_streaming_response_is_sse(self, test_db, override_get_db):
        """Streaming response uses text/event-stream content type and SSE format."""
        _, _, _, _, headers = await _create_pro_user_with_quota(test_db)

        from app.services.ai_providers import StreamChunk, StreamChunkType

        async def mock_stream(*args, **kwargs):
            yield StreamChunk(type=StreamChunkType.CONTENT, content="Hello")
            yield StreamChunk(type=StreamChunkType.CONTENT, content=" world")
            yield StreamChunk(
                type=StreamChunkType.DONE,
                metadata={"total_tokens": 10, "prompt_tokens": 5, "completion_tokens": 5, "finish_reason": "stop"},
            )

        mock_lb = MagicMock()
        mock_prov = _mock_provider()
        mock_prov.chat_completion = AsyncMock(return_value=mock_stream())
        mock_prov._get_default_model.return_value = "gpt-4o-mini"
        mock_lb.get_provider = AsyncMock(return_value=mock_prov)
        mock_lb.get_available_providers.return_value = ["openai"]

        with (
            patch("app.routers.ai_proxy.get_load_balancer", return_value=mock_lb),
            patch("app.routers.ai_proxy.check_provider_rate_limit", new_callable=AsyncMock, return_value=(True, 59, int(time.time()) + 60, "openai_gpt4")),
            patch("app.routers.ai_proxy.update_token_usage", new_callable=AsyncMock),
            patch("app.routers.ai_proxy.update_byok_last_used", new_callable=AsyncMock),
            patch("app.routers.ai_proxy.TokenReservationService") as mock_trs_cls,
        ):
            mock_trs = AsyncMock()
            mock_trs.reserve_tokens = AsyncMock(return_value=(True, "res-1", 0))
            mock_trs.finalize_reservation = AsyncMock()
            mock_trs_cls.return_value = mock_trs

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post(
                    "/ai/chat",
                    json={
                        "messages": [{"role": "user", "content": "hello"}],
                        "provider": "openai",
                        "stream": True,
                    },
                    headers=headers,
                )
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers.get("content-type", "")
            # Each SSE data line starts with "data: "
            lines = [l for l in resp.text.strip().split("\n") if l.startswith("data: ")]
            assert len(lines) >= 2
            first_chunk = json.loads(lines[0].replace("data: ", ""))
            assert first_chunk["type"] in ("content", "done")


class TestTokenQuotaEnforcement:
    """Test 402 when token quota exceeded."""

    async def test_quota_exceeded_returns_402(self, test_db, override_get_db):
        """User with exhausted tokens gets 402."""
        _, _, _, _, headers = await _create_pro_user_with_quota(
            test_db, tokens_used=3_000_000, token_limit=3_000_000
        )

        mock_lb = MagicMock()
        mock_prov = _mock_provider()
        mock_lb.get_provider = AsyncMock(return_value=mock_prov)
        mock_lb.get_available_providers.return_value = ["openai"]

        with (
            patch("app.routers.ai_proxy.get_load_balancer", return_value=mock_lb),
            patch("app.routers.ai_proxy.check_provider_rate_limit", new_callable=AsyncMock, return_value=(True, 59, int(time.time()) + 60, "openai_gpt4")),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post(
                    "/ai/chat",
                    json={
                        "messages": [{"role": "user", "content": "hello"}],
                        "provider": "openai",
                    },
                    headers=headers,
                )
            assert resp.status_code == 402
            assert "Insufficient tokens" in resp.json()["detail"]


class TestRateLimiting:
    """Test 429 rate limiting."""

    async def test_rate_limit_returns_429(self, test_db, override_get_db):
        """Provider rate limit exceeded returns 429 with headers."""
        _, _, _, _, headers = await _create_pro_user_with_quota(test_db)

        reset_at = int(time.time()) + 60
        mock_lb = MagicMock()
        mock_prov = _mock_provider()
        mock_lb.get_provider = AsyncMock(return_value=mock_prov)
        mock_lb.get_available_providers.return_value = ["openai"]

        with (
            patch("app.routers.ai_proxy.get_load_balancer", return_value=mock_lb),
            patch(
                "app.routers.ai_proxy.check_provider_rate_limit",
                new_callable=AsyncMock,
                return_value=(False, 0, reset_at, "openai_gpt4"),
            ),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post(
                    "/ai/chat",
                    json={
                        "messages": [{"role": "user", "content": "hello"}],
                        "provider": "openai",
                    },
                    headers=headers,
                )
            assert resp.status_code == 429
            assert "Rate limit exceeded" in resp.json()["detail"]
            assert resp.headers.get("retry-after") is not None


class TestBYOKHandling:
    """Test Bring-Your-Own-Key handling."""

    async def test_byok_key_passed_to_provider(self, test_db, override_get_db):
        """BYOK decrypted key is forwarded to load_balancer.get_provider."""
        user, _, quota, _, headers = await _create_pro_user_with_quota(test_db)

        # Create a UserAPIKey record
        api_key_record = UserAPIKey(
            user_id=user.id,
            provider="openai",
            encrypted_key="encrypted_test_key",
            key_masked="...key1",
            is_valid=True,
        )
        test_db.add(api_key_record)
        await test_db.commit()

        mock_lb = MagicMock()
        mock_prov = _mock_provider()
        mock_lb.get_provider = AsyncMock(return_value=mock_prov)
        mock_lb.get_available_providers.return_value = ["openai"]

        with (
            patch("app.routers.ai_proxy.get_load_balancer", return_value=mock_lb),
            patch("app.routers.ai_proxy.check_provider_rate_limit", new_callable=AsyncMock, return_value=(True, 59, int(time.time()) + 60, "openai_gpt4")),
            patch("app.routers.ai_proxy.decrypt_api_key", return_value="sk-decrypted-key"),
            patch("app.routers.ai_proxy.update_byok_last_used", new_callable=AsyncMock),
            patch("app.routers.ai_proxy._check_cache", new_callable=AsyncMock, return_value=None),
            patch("app.routers.ai_proxy._store_cache", new_callable=AsyncMock),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post(
                    "/ai/chat",
                    json={
                        "messages": [{"role": "user", "content": "hello"}],
                        "provider": "openai",
                    },
                    headers=headers,
                )
            assert resp.status_code == 200
            # Verify load_balancer received the decrypted BYOK key
            call_kwargs = mock_lb.get_provider.call_args_list
            # The second call (inside _handle_complete_chat) should have user_api_key
            found_byok = any(
                call.kwargs.get("user_api_key") == "sk-decrypted-key"
                for call in call_kwargs
            )
            assert found_byok, "Decrypted BYOK key was not passed to get_provider"


class TestErrorResponses:
    """Test error response mapping from provider exceptions."""

    async def test_invalid_key_error_returns_401(self, test_db, override_get_db):
        """InvalidKeyError from provider maps to 401."""
        _, _, _, _, headers = await _create_pro_user_with_quota(test_db)

        mock_lb = MagicMock()
        mock_prov = _mock_provider()
        mock_prov.chat_completion = AsyncMock(
            side_effect=InvalidKeyError("Bad key", provider=ProviderType.OPENAI)
        )
        mock_lb.get_provider = AsyncMock(return_value=mock_prov)
        mock_lb.get_available_providers.return_value = ["openai"]

        with (
            patch("app.routers.ai_proxy.get_load_balancer", return_value=mock_lb),
            patch("app.routers.ai_proxy.check_provider_rate_limit", new_callable=AsyncMock, return_value=(True, 59, int(time.time()) + 60, "openai_gpt4")),
            patch("app.routers.ai_proxy.TokenReservationService") as mock_trs_cls,
            patch("app.routers.ai_proxy._check_cache", new_callable=AsyncMock, return_value=None),
        ):
            mock_trs = AsyncMock()
            mock_trs.reserve_tokens = AsyncMock(return_value=(True, "res-1", 0))
            mock_trs.release_reservation = AsyncMock()
            mock_trs_cls.return_value = mock_trs

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post(
                    "/ai/chat",
                    json={
                        "messages": [{"role": "user", "content": "hello"}],
                        "provider": "openai",
                    },
                    headers=headers,
                )
            assert resp.status_code == 401

    async def test_rate_limit_error_from_provider_returns_429(self, test_db, override_get_db):
        """RateLimitError from the upstream provider maps to 429."""
        _, _, _, _, headers = await _create_pro_user_with_quota(test_db)

        mock_lb = MagicMock()
        mock_prov = _mock_provider()
        mock_prov.chat_completion = AsyncMock(
            side_effect=RateLimitError("Rate limit", provider=ProviderType.OPENAI, retry_after=30)
        )
        mock_lb.get_provider = AsyncMock(return_value=mock_prov)
        mock_lb.get_available_providers.return_value = ["openai"]

        with (
            patch("app.routers.ai_proxy.get_load_balancer", return_value=mock_lb),
            patch("app.routers.ai_proxy.check_provider_rate_limit", new_callable=AsyncMock, return_value=(True, 59, int(time.time()) + 60, "openai_gpt4")),
            patch("app.routers.ai_proxy.TokenReservationService") as mock_trs_cls,
            patch("app.routers.ai_proxy._check_cache", new_callable=AsyncMock, return_value=None),
        ):
            mock_trs = AsyncMock()
            mock_trs.reserve_tokens = AsyncMock(return_value=(True, "res-1", 0))
            mock_trs.release_reservation = AsyncMock()
            mock_trs_cls.return_value = mock_trs

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post(
                    "/ai/chat",
                    json={
                        "messages": [{"role": "user", "content": "hello"}],
                        "provider": "openai",
                    },
                    headers=headers,
                )
            assert resp.status_code == 429

    async def test_quota_exceeded_error_returns_402(self, test_db, override_get_db):
        """QuotaExceededError from upstream returns 402."""
        _, _, _, _, headers = await _create_pro_user_with_quota(test_db)

        mock_lb = MagicMock()
        mock_prov = _mock_provider()
        mock_prov.chat_completion = AsyncMock(
            side_effect=QuotaExceededError("Quota exceeded", provider=ProviderType.OPENAI)
        )
        mock_lb.get_provider = AsyncMock(return_value=mock_prov)
        mock_lb.get_available_providers.return_value = ["openai"]

        with (
            patch("app.routers.ai_proxy.get_load_balancer", return_value=mock_lb),
            patch("app.routers.ai_proxy.check_provider_rate_limit", new_callable=AsyncMock, return_value=(True, 59, int(time.time()) + 60, "openai_gpt4")),
            patch("app.routers.ai_proxy.TokenReservationService") as mock_trs_cls,
            patch("app.routers.ai_proxy._check_cache", new_callable=AsyncMock, return_value=None),
        ):
            mock_trs = AsyncMock()
            mock_trs.reserve_tokens = AsyncMock(return_value=(True, "res-1", 0))
            mock_trs.release_reservation = AsyncMock()
            mock_trs_cls.return_value = mock_trs

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post(
                    "/ai/chat",
                    json={
                        "messages": [{"role": "user", "content": "hello"}],
                        "provider": "openai",
                    },
                    headers=headers,
                )
            assert resp.status_code == 402

    async def test_retryable_provider_error_returns_503(self, test_db, override_get_db):
        """Retryable AIProviderError maps to 503."""
        _, _, _, _, headers = await _create_pro_user_with_quota(test_db)

        mock_lb = MagicMock()
        mock_prov = _mock_provider()
        mock_prov.chat_completion = AsyncMock(
            side_effect=AIProviderError("Server error", provider=ProviderType.OPENAI, retryable=True)
        )
        mock_lb.get_provider = AsyncMock(return_value=mock_prov)
        mock_lb.get_available_providers.return_value = ["openai"]

        with (
            patch("app.routers.ai_proxy.get_load_balancer", return_value=mock_lb),
            patch("app.routers.ai_proxy.check_provider_rate_limit", new_callable=AsyncMock, return_value=(True, 59, int(time.time()) + 60, "openai_gpt4")),
            patch("app.routers.ai_proxy.TokenReservationService") as mock_trs_cls,
            patch("app.routers.ai_proxy._check_cache", new_callable=AsyncMock, return_value=None),
        ):
            mock_trs = AsyncMock()
            mock_trs.reserve_tokens = AsyncMock(return_value=(True, "res-1", 0))
            mock_trs.release_reservation = AsyncMock()
            mock_trs_cls.return_value = mock_trs

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post(
                    "/ai/chat",
                    json={
                        "messages": [{"role": "user", "content": "hello"}],
                        "provider": "openai",
                    },
                    headers=headers,
                )
            assert resp.status_code == 503


class TestSanitizeErrorMessage:
    """Test that error messages are sanitized to prevent key leakage."""

    def test_openai_key_redacted(self):
        from app.routers.ai_proxy import _sanitize_error_message

        msg = "Error with key sk-abcdefghijklmnopqrstuvwxyz1234567890abcd"
        result = _sanitize_error_message(msg)
        assert "sk-" not in result
        assert "[REDACTED]" in result

    def test_bearer_token_redacted(self):
        from app.routers.ai_proxy import _sanitize_error_message

        msg = "Auth failed: Bearer eyJhbGciOiJIUzI1NiJ9.test.sig"
        result = _sanitize_error_message(msg)
        assert "eyJ" not in result

    def test_clean_message_unchanged(self):
        from app.routers.ai_proxy import _sanitize_error_message

        msg = "Connection timed out"
        assert _sanitize_error_message(msg) == msg


class TestCacheKeyComputation:
    """Test cache key computation."""

    def test_same_request_same_key(self):
        from app.routers.ai_proxy import _compute_cache_key
        from app.schemas.ai_proxy import ChatCompletionRequest, ChatMessage

        req = ChatCompletionRequest(
            messages=[ChatMessage(role="user", content="hello")],
            provider="openai",
            model="gpt-4o",
        )
        key1 = _compute_cache_key(req)
        key2 = _compute_cache_key(req)
        assert key1 == key2

    def test_different_messages_different_key(self):
        from app.routers.ai_proxy import _compute_cache_key
        from app.schemas.ai_proxy import ChatCompletionRequest, ChatMessage

        req1 = ChatCompletionRequest(
            messages=[ChatMessage(role="user", content="hello")],
            provider="openai",
        )
        req2 = ChatCompletionRequest(
            messages=[ChatMessage(role="user", content="bye")],
            provider="openai",
        )
        assert _compute_cache_key(req1) != _compute_cache_key(req2)
