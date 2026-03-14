"""Tests for the rate limiter middleware.

Tests cover:
- Tier-based limits (free=10, starter=60, pro=120, enterprise=300)
- Exempt paths (/health, /docs, /webhooks/stripe)
- In-memory emergency fallback when Redis unavailable
- 429 response with correct headers
- Rate limit headers on normal responses
"""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient

from app.middleware.rate_limiter import (
    EMERGENCY_LIMIT,
    EMERGENCY_WINDOW,
    RateLimitMiddleware,
    _check_emergency_rate_limit,
    _cleanup_emergency_rate_limits,
    _emergency_rate_limits,
)


# ---------------------------------------------------------------------------
# Emergency in-memory rate limiter tests
# ---------------------------------------------------------------------------


class TestEmergencyRateLimiter:
    """Test the in-memory emergency fallback rate limiter."""

    def setup_method(self):
        """Clear global emergency state between tests."""
        _emergency_rate_limits.clear()

    def test_allows_under_limit(self):
        allowed, count, reset_time = _check_emergency_rate_limit("user:1")
        assert allowed is True
        assert count == 1
        assert reset_time > int(time.time())

    def test_blocks_at_limit(self):
        ident = "user:block"
        # Fill to limit
        for i in range(EMERGENCY_LIMIT):
            allowed, _, _ = _check_emergency_rate_limit(ident)
            assert allowed is True

        # Next request should be blocked
        allowed, count, _ = _check_emergency_rate_limit(ident)
        assert allowed is False
        assert count == EMERGENCY_LIMIT

    def test_separate_identifiers_independent(self):
        for _ in range(EMERGENCY_LIMIT):
            _check_emergency_rate_limit("user:a")

        # user:b should still be allowed
        allowed, _, _ = _check_emergency_rate_limit("user:b")
        assert allowed is True

    def test_old_entries_expire(self):
        ident = "user:expire"
        # Add entries with timestamps in the past
        _emergency_rate_limits[ident] = [time.time() - EMERGENCY_WINDOW - 10] * EMERGENCY_LIMIT
        # Should be allowed because old entries are outside window
        allowed, count, _ = _check_emergency_rate_limit(ident)
        assert allowed is True
        assert count == 1

    def test_cleanup_removes_inactive(self):
        _emergency_rate_limits["active"] = [time.time()]
        _emergency_rate_limits["stale"] = [time.time() - EMERGENCY_WINDOW - 100]
        _cleanup_emergency_rate_limits(time.time())
        assert "active" in _emergency_rate_limits
        assert "stale" not in _emergency_rate_limits


# ---------------------------------------------------------------------------
# RateLimitMiddleware tier-based tests
# ---------------------------------------------------------------------------


class TestRateLimitMiddleware:
    """Test the middleware with various scenarios."""

    def test_tier_limits_defined(self):
        assert RateLimitMiddleware.RATE_LIMITS["free"] == 10
        assert RateLimitMiddleware.RATE_LIMITS["starter"] == 60
        assert RateLimitMiddleware.RATE_LIMITS["pro"] == 120
        assert RateLimitMiddleware.RATE_LIMITS["enterprise"] == 300

    def test_exempt_paths(self):
        exempts = RateLimitMiddleware.EXEMPT_PATHS
        assert "/health" in exempts
        assert "/docs" in exempts
        assert "/" in exempts
        assert "/redoc" in exempts
        assert "/openapi.json" in exempts


class TestRateLimitMiddlewareIntegration:
    """Integration tests with a real FastAPI app and the middleware."""

    @pytest.fixture
    def test_app(self):
        """Create a minimal FastAPI app with rate limit middleware."""
        test_app = FastAPI()

        @test_app.get("/health")
        async def health():
            return {"status": "ok"}

        @test_app.get("/api/test")
        async def api_test():
            return {"data": "result"}

        return test_app

    async def test_exempt_path_not_rate_limited(self, test_app):
        """Exempt paths bypass rate limiting entirely."""
        # Add middleware with rate limiting enabled
        with (
            patch("app.middleware.rate_limiter.settings") as mock_settings,
            patch("app.middleware.rate_limiter.get_redis_client", new_callable=AsyncMock) as mock_redis_fn,
        ):
            mock_settings.enable_rate_limiting = True
            mock_redis = AsyncMock()
            mock_redis.is_available = True
            mock_redis._client = AsyncMock()
            mock_redis._client.eval = AsyncMock(return_value=[1, 1, int(time.time()) + 60])
            mock_redis_fn.return_value = mock_redis

            middleware = RateLimitMiddleware(test_app)

            transport = ASGITransport(app=middleware)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.get("/health")
            assert resp.status_code == 200
            # No rate limit headers on exempt paths
            assert "X-RateLimit-Limit" not in resp.headers

    async def test_rate_limit_disabled_passes_through(self, test_app):
        """When rate limiting is globally disabled, all requests pass."""
        with patch("app.middleware.rate_limiter.settings") as mock_settings:
            mock_settings.enable_rate_limiting = False

            middleware = RateLimitMiddleware(test_app)
            transport = ASGITransport(app=middleware)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.get("/api/test")
            assert resp.status_code == 200

    async def test_429_response_with_headers(self, test_app):
        """Rate-limited response includes correct headers."""
        reset_time = int(time.time()) + 60

        with (
            patch("app.middleware.rate_limiter.settings") as mock_settings,
            patch("app.middleware.rate_limiter.get_redis_client", new_callable=AsyncMock) as mock_redis_fn,
        ):
            mock_settings.enable_rate_limiting = True

            mock_redis = AsyncMock()
            mock_redis.is_available = True
            mock_redis._client = AsyncMock()
            # Return denied: [0, count, reset_time]
            mock_redis._client.eval = AsyncMock(return_value=[0, 10, reset_time])
            mock_redis_fn.return_value = mock_redis

            middleware = RateLimitMiddleware(test_app)

            # Patch _get_user_info to return a known user
            with patch.object(
                middleware,
                "_get_user_info",
                new_callable=AsyncMock,
                return_value=(1, "free", "ratelimit:1"),
            ):
                transport = ASGITransport(app=middleware)
                async with AsyncClient(transport=transport, base_url="http://test") as ac:
                    resp = await ac.get("/api/test")

            assert resp.status_code == 429
            assert resp.headers["X-RateLimit-Limit"] == "10"
            assert resp.headers["X-RateLimit-Remaining"] == "0"
            assert "Retry-After" in resp.headers

    async def test_normal_response_has_rate_limit_headers(self, test_app):
        """Normal responses include X-RateLimit-* headers."""
        reset_time = int(time.time()) + 60

        with (
            patch("app.middleware.rate_limiter.settings") as mock_settings,
            patch("app.middleware.rate_limiter.get_redis_client", new_callable=AsyncMock) as mock_redis_fn,
        ):
            mock_settings.enable_rate_limiting = True

            mock_redis = AsyncMock()
            mock_redis.is_available = True
            mock_redis._client = AsyncMock()
            # Return allowed: [1, 5, reset_time]
            mock_redis._client.eval = AsyncMock(return_value=[1, 5, reset_time])
            mock_redis_fn.return_value = mock_redis

            middleware = RateLimitMiddleware(test_app)

            with patch.object(
                middleware,
                "_get_user_info",
                new_callable=AsyncMock,
                return_value=(1, "pro", "ratelimit:1"),
            ):
                transport = ASGITransport(app=middleware)
                async with AsyncClient(transport=transport, base_url="http://test") as ac:
                    resp = await ac.get("/api/test")

            assert resp.status_code == 200
            assert "X-RateLimit-Limit" in resp.headers
            assert "X-RateLimit-Remaining" in resp.headers
            assert "X-RateLimit-Reset" in resp.headers
            assert resp.headers["X-RateLimit-Limit"] == "120"  # pro tier

    async def test_redis_unavailable_uses_emergency_limiter(self, test_app):
        """When Redis is unavailable, emergency in-memory limiter kicks in."""
        _emergency_rate_limits.clear()

        with (
            patch("app.middleware.rate_limiter.settings") as mock_settings,
            patch("app.middleware.rate_limiter.get_redis_client", new_callable=AsyncMock) as mock_redis_fn,
        ):
            mock_settings.enable_rate_limiting = True
            # Redis unavailable
            mock_redis = AsyncMock()
            mock_redis.is_available = False
            mock_redis_fn.return_value = mock_redis

            middleware = RateLimitMiddleware(test_app)

            with patch.object(
                middleware,
                "_get_user_info",
                new_callable=AsyncMock,
                return_value=(1, "pro", "ratelimit:1"),
            ):
                transport = ASGITransport(app=middleware)
                async with AsyncClient(transport=transport, base_url="http://test") as ac:
                    resp = await ac.get("/api/test")

            assert resp.status_code == 200
            # Emergency fallback header present
            assert resp.headers.get("X-RateLimit-Fallback") == "true"
            assert resp.headers["X-RateLimit-Limit"] == str(EMERGENCY_LIMIT)

    async def test_redis_exception_uses_emergency_limiter(self, test_app):
        """When get_redis_client raises, emergency limiter is used."""
        _emergency_rate_limits.clear()

        with (
            patch("app.middleware.rate_limiter.settings") as mock_settings,
            patch("app.middleware.rate_limiter.get_redis_client", new_callable=AsyncMock, side_effect=Exception("conn refused")),
        ):
            mock_settings.enable_rate_limiting = True

            middleware = RateLimitMiddleware(test_app)

            with patch.object(
                middleware,
                "_get_user_info",
                new_callable=AsyncMock,
                return_value=(None, "free", "ratelimit:127.0.0.1"),
            ):
                transport = ASGITransport(app=middleware)
                async with AsyncClient(transport=transport, base_url="http://test") as ac:
                    resp = await ac.get("/api/test")

            assert resp.status_code == 200
            assert resp.headers.get("X-RateLimit-Fallback") == "true"


# ---------------------------------------------------------------------------
# Client IP extraction
# ---------------------------------------------------------------------------


class TestClientIPExtraction:
    """Test _get_client_ip logic."""

    def test_x_forwarded_for(self):
        middleware = RateLimitMiddleware.__new__(RateLimitMiddleware)
        request = MagicMock()
        request.headers = {"X-Forwarded-For": "1.2.3.4, 5.6.7.8"}
        assert middleware._get_client_ip(request) == "1.2.3.4"

    def test_x_real_ip(self):
        middleware = RateLimitMiddleware.__new__(RateLimitMiddleware)
        request = MagicMock()
        request.headers = {"X-Real-IP": "9.8.7.6"}
        assert middleware._get_client_ip(request) == "9.8.7.6"

    def test_direct_client(self):
        middleware = RateLimitMiddleware.__new__(RateLimitMiddleware)
        request = MagicMock()
        request.headers = {}
        request.client.host = "10.0.0.1"
        assert middleware._get_client_ip(request) == "10.0.0.1"

    def test_no_client_returns_unknown(self):
        middleware = RateLimitMiddleware.__new__(RateLimitMiddleware)
        request = MagicMock()
        request.headers = {}
        request.client = None
        assert middleware._get_client_ip(request) == "unknown"
