"""Tests for the cache service.

Tests cover:
- InMemoryCacheBackend: get/set/TTL expiry/LRU eviction
- RedisCacheBackend with mocked redis: get/set/compression
- Gzip compression for >1KB payloads
- CacheService.get_cached_response / cache_response
- Metrics tracking (hits, misses, stores)
- Fallback behaviour (cache miss returns None)
"""

import gzip
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.cache import (
    COMPRESSION_PREFIX,
    COMPRESSION_THRESHOLD,
    CacheMetrics,
    CacheService,
    InMemoryCacheBackend,
    RedisCacheBackend,
)


# ---------------------------------------------------------------------------
# CacheMetrics
# ---------------------------------------------------------------------------


class TestCacheMetrics:
    """Test CacheMetrics computations."""

    def test_hit_rate_zero_total(self):
        m = CacheMetrics()
        assert m.hit_rate == 0.0

    def test_hit_rate_calculation(self):
        m = CacheMetrics(hits=3, misses=7)
        assert m.hit_rate == pytest.approx(30.0)

    def test_to_dict_keys(self):
        m = CacheMetrics(hits=1, misses=2, stores=3, evictions=4, errors=0, bytes_saved=100)
        d = m.to_dict()
        assert "hits" in d
        assert "misses" in d
        assert "stores" in d
        assert "evictions" in d
        assert "hit_rate_percent" in d
        assert "bytes_saved_by_compression" in d
        assert "avg_latency_ms" in d


# ---------------------------------------------------------------------------
# InMemoryCacheBackend
# ---------------------------------------------------------------------------


class TestInMemoryCacheBackend:
    """Test in-memory LRU cache."""

    async def test_set_and_get(self):
        cache = InMemoryCacheBackend(max_size=100)
        await cache.set("key1", "value1", ttl=60)
        result = await cache.get("key1")
        assert result == "value1"

    async def test_get_missing_key_returns_none(self):
        cache = InMemoryCacheBackend()
        result = await cache.get("nonexistent")
        assert result is None

    async def test_ttl_expiry(self):
        cache = InMemoryCacheBackend()
        await cache.set("key1", "value1", ttl=1)
        # Manually expire the entry
        cache._cache["key1"] = ("value1", time.time() - 1)
        result = await cache.get("key1")
        assert result is None

    async def test_lru_eviction(self):
        cache = InMemoryCacheBackend(max_size=3)
        await cache.set("a", "1", ttl=300)
        await cache.set("b", "2", ttl=300)
        await cache.set("c", "3", ttl=300)
        # Cache is full, adding a fourth should evict the LRU entry ('a')
        await cache.set("d", "4", ttl=300)
        assert await cache.get("a") is None
        assert await cache.get("d") == "4"

    async def test_lru_access_order(self):
        cache = InMemoryCacheBackend(max_size=3)
        await cache.set("a", "1", ttl=300)
        await cache.set("b", "2", ttl=300)
        await cache.set("c", "3", ttl=300)
        # Access 'a' to make it most recent
        await cache.get("a")
        # Now adding 'd' should evict 'b' (the new LRU)
        await cache.set("d", "4", ttl=300)
        assert await cache.get("b") is None
        assert await cache.get("a") == "1"

    async def test_exists(self):
        cache = InMemoryCacheBackend()
        await cache.set("k", "v", ttl=60)
        assert await cache.exists("k") is True
        assert await cache.exists("nope") is False

    async def test_delete(self):
        cache = InMemoryCacheBackend()
        await cache.set("k", "v", ttl=60)
        await cache.delete("k")
        assert await cache.get("k") is None

    async def test_close_clears_cache(self):
        cache = InMemoryCacheBackend()
        await cache.set("k", "v", ttl=60)
        await cache.close()
        assert await cache.size() == 0

    async def test_size(self):
        cache = InMemoryCacheBackend()
        assert await cache.size() == 0
        await cache.set("a", "1", ttl=60)
        await cache.set("b", "2", ttl=60)
        assert await cache.size() == 2

    async def test_metrics_tracking(self):
        cache = InMemoryCacheBackend()
        # Miss
        await cache.get("miss")
        assert cache.metrics.misses == 1
        # Store
        await cache.set("key", "val", ttl=60)
        assert cache.metrics.stores == 1
        # Hit
        await cache.get("key")
        assert cache.metrics.hits == 1


# ---------------------------------------------------------------------------
# RedisCacheBackend (mocked)
# ---------------------------------------------------------------------------


class TestRedisCacheBackend:
    """Test Redis cache backend with mocked Redis client."""

    @pytest.fixture
    def redis_backend(self):
        """Create a RedisCacheBackend with mocked connection."""
        backend = RedisCacheBackend(redis_url="redis://localhost:6379", pool_size=5)
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock()
        backend._redis = mock_redis
        backend._connected = True
        backend._pool = MagicMock()
        return backend

    async def test_get_returns_string(self, redis_backend):
        redis_backend._redis.get = AsyncMock(return_value=b"hello")
        result = await redis_backend.get("key")
        assert result == "hello"
        assert redis_backend.metrics.hits == 1

    async def test_get_returns_none_on_miss(self, redis_backend):
        redis_backend._redis.get = AsyncMock(return_value=None)
        result = await redis_backend.get("key")
        assert result is None
        assert redis_backend.metrics.misses == 1

    async def test_get_decompresses_gzipped_data(self, redis_backend):
        original = "test data that was compressed"
        compressed = COMPRESSION_PREFIX + gzip.compress(original.encode("utf-8"))
        redis_backend._redis.get = AsyncMock(return_value=compressed)
        result = await redis_backend.get("key")
        assert result == original
        assert redis_backend.metrics.hits == 1

    async def test_set_compresses_large_payload(self, redis_backend):
        # Create data larger than COMPRESSION_THRESHOLD
        large_value = "x" * (COMPRESSION_THRESHOLD + 500)
        redis_backend._redis.setex = AsyncMock()
        await redis_backend.set("key", large_value, ttl=60)

        redis_backend._redis.setex.assert_called_once()
        stored_data = redis_backend._redis.setex.call_args[0][2]
        # Should be compressed (starts with prefix)
        assert stored_data.startswith(COMPRESSION_PREFIX)
        assert redis_backend.metrics.stores == 1
        assert redis_backend.metrics.bytes_saved > 0

    async def test_set_small_payload_not_compressed(self, redis_backend):
        small_value = "tiny"
        redis_backend._redis.setex = AsyncMock()
        await redis_backend.set("key", small_value, ttl=60)

        stored_data = redis_backend._redis.setex.call_args[0][2]
        # Small payload: stored as raw bytes, no compression prefix
        assert not stored_data.startswith(COMPRESSION_PREFIX)

    async def test_get_error_returns_none(self, redis_backend):
        redis_backend._redis.get = AsyncMock(side_effect=Exception("connection lost"))
        result = await redis_backend.get("key")
        assert result is None
        assert redis_backend.metrics.errors == 1

    async def test_set_error_increments_errors(self, redis_backend):
        redis_backend._redis.setex = AsyncMock(side_effect=Exception("write failed"))
        await redis_backend.set("key", "val", ttl=60)
        assert redis_backend.metrics.errors == 1

    async def test_delete(self, redis_backend):
        redis_backend._redis.delete = AsyncMock()
        await redis_backend.delete("key")
        redis_backend._redis.delete.assert_called_once_with("key")

    async def test_exists(self, redis_backend):
        redis_backend._redis.exists = AsyncMock(return_value=1)
        assert await redis_backend.exists("key") is True


# ---------------------------------------------------------------------------
# CacheService
# ---------------------------------------------------------------------------


class TestCacheService:
    """Test high-level CacheService methods."""

    @pytest.fixture
    def service(self):
        """Create CacheService with in-memory backend."""
        with patch("app.services.cache.settings") as mock_settings:
            mock_settings.redis_enabled = False
            mock_settings.redis_url = None
            mock_settings.cache_ttl_prompt = 3600
            mock_settings.cache_ttl_vuln_desc = 86400
            svc = CacheService()
        return svc

    async def test_cache_response_and_retrieve(self, service):
        prompt_hash = "abc123"
        response = {"content": "AI response", "model": "gpt-4"}
        await service.cache_response(prompt_hash, response, ttl=60)

        cached = await service.get_cached_response(prompt_hash)
        assert cached is not None
        assert cached["content"] == "AI response"
        assert cached["cached"] is True

    async def test_cache_miss_returns_none(self, service):
        result = await service.get_cached_response("nonexistent_hash")
        assert result is None

    async def test_get_stats(self, service):
        stats = await service.get_stats()
        assert stats["backend"] == "InMemoryCacheBackend"
        assert "size" in stats
        assert "metrics" in stats

    async def test_invalidate_cache(self, service):
        await service.cache_response("hash1", {"data": "x"}, ttl=60)
        assert await service.check_cache_exists("hash1") is True
        await service.invalidate_cache("ai_response:hash1")
        assert await service.check_cache_exists("hash1") is False

    async def test_corrupted_json_returns_none(self, service):
        """If cached data is invalid JSON, return None and clean up."""
        key = "ai_response:badhash"
        await service.backend.set(key, "not-json{{{", ttl=60)
        result = await service.get_cached_response("badhash")
        assert result is None

    async def test_get_metrics(self, service):
        # Generate some activity
        await service.cache_response("h1", {"data": "d"}, ttl=60)
        await service.get_cached_response("h1")
        await service.get_cached_response("miss")

        metrics = service.get_metrics()
        assert metrics["stores"] >= 1
        assert metrics["hits"] >= 1
        assert metrics["misses"] >= 1

    async def test_vuln_cache(self, service):
        """Test vulnerability description cache methods."""
        await service.cache_vuln_description("CVE-2024-0001", {"severity": "high"}, ttl=60)
        result = await service.get_cached_vuln_description("cve-2024-0001")
        assert result is not None
        assert result["severity"] == "high"
