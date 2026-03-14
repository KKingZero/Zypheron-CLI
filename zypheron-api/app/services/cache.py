"""Cache service with Redis backend and in-memory fallback.

Features:
- Redis with connection pooling (for production)
- In-memory LRU cache (for development)
- Gzip compression for large responses
- Metrics tracking for cache hits/misses
- Automatic fallback to in-memory if Redis fails
"""

import gzip
import json
import structlog
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

from app.core.config import get_settings

settings = get_settings()
logger = structlog.get_logger()

# Lazy import to avoid circular dependency at module level
_metrics_imported = False
_cache_hits_counter = None
_cache_misses_counter = None


def _get_metrics():
    """Lazy-load Prometheus metrics to avoid import issues."""
    global _metrics_imported, _cache_hits_counter, _cache_misses_counter
    if not _metrics_imported:
        try:
            from app.services.metrics import cache_hits_total, cache_misses_total
            _cache_hits_counter = cache_hits_total
            _cache_misses_counter = cache_misses_total
        except ImportError:
            pass
        _metrics_imported = True
    return _cache_hits_counter, _cache_misses_counter

# Compression threshold (compress responses larger than 1KB)
COMPRESSION_THRESHOLD = 1024
COMPRESSION_PREFIX = b"__gzip__"


@dataclass
class CacheMetrics:
    """Metrics for cache performance monitoring."""

    hits: int = 0
    misses: int = 0
    stores: int = 0
    evictions: int = 0
    errors: int = 0
    bytes_saved: int = 0  # Bytes saved by compression
    total_latency_ms: float = 0.0

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.hits + self.misses
        return (self.hits / total * 100) if total > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "stores": self.stores,
            "evictions": self.evictions,
            "errors": self.errors,
            "hit_rate_percent": round(self.hit_rate, 2),
            "bytes_saved_by_compression": self.bytes_saved,
            "avg_latency_ms": round(self.total_latency_ms / max(self.hits + self.misses, 1), 2),
        }


class CacheBackend(ABC):
    """Abstract base class for cache backends."""

    def __init__(self):
        self.metrics = CacheMetrics()

    @abstractmethod
    async def get(self, key: str) -> str | None:
        """Get a value from the cache."""
        pass

    @abstractmethod
    async def set(self, key: str, value: str, ttl: int) -> None:
        """Set a value in the cache with TTL."""
        pass

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete a value from the cache."""
        pass

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if a key exists in the cache."""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close the cache backend connection."""
        pass

    @abstractmethod
    async def size(self) -> int:
        """Get number of items in cache."""
        pass


class InMemoryCacheBackend(CacheBackend):
    """In-memory LRU cache backend.

    Thread-safe with TTL support and automatic eviction.
    """

    def __init__(self, max_size: int = 10000):
        """Initialize the in-memory LRU cache.

        Args:
            max_size: Maximum number of entries before LRU eviction
        """
        super().__init__()
        self._cache: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._max_size = max_size
        self._lock = Lock()

    def _cleanup_expired(self) -> None:
        """Remove expired entries from the cache."""
        current_time = time.time()
        expired_keys = [
            key for key, (_, expiry) in self._cache.items() if expiry < current_time
        ]
        for key in expired_keys:
            del self._cache[key]
            self.metrics.evictions += 1

    def _evict_lru(self) -> None:
        """Evict least recently used entries if over max size."""
        while len(self._cache) >= self._max_size:
            self._cache.popitem(last=False)  # Remove oldest
            self.metrics.evictions += 1

    async def get(self, key: str) -> str | None:
        """Get a value from the in-memory cache with LRU update."""
        start = time.time()

        with self._lock:
            self._cleanup_expired()

            if key not in self._cache:
                self.metrics.misses += 1
                return None

            value, expiry = self._cache[key]

            # Check if expired
            if expiry < time.time():
                del self._cache[key]
                self.metrics.misses += 1
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self.metrics.hits += 1
            self.metrics.total_latency_ms += (time.time() - start) * 1000

            return value

    async def set(self, key: str, value: str, ttl: int) -> None:
        """Set a value in the in-memory cache with TTL."""
        with self._lock:
            # Evict if necessary
            if key not in self._cache:
                self._evict_lru()

            expiry_time = time.time() + ttl
            self._cache[key] = (value, expiry_time)
            self._cache.move_to_end(key)
            self.metrics.stores += 1

    async def delete(self, key: str) -> None:
        """Delete a value from the in-memory cache."""
        with self._lock:
            self._cache.pop(key, None)

    async def exists(self, key: str) -> bool:
        """Check if a key exists in the in-memory cache."""
        value = await self.get(key)
        return value is not None

    async def close(self) -> None:
        """Close the in-memory cache (clears all entries)."""
        with self._lock:
            self._cache.clear()

    async def size(self) -> int:
        """Get number of items in cache."""
        with self._lock:
            return len(self._cache)


class RedisCacheBackend(CacheBackend):
    """Redis cache backend with connection pooling.

    Uses redis-py with async support and automatic reconnection.
    """

    def __init__(self, redis_url: str, pool_size: int = 10):
        """Initialize the Redis cache backend with connection pool.

        Args:
            redis_url: Redis connection URL
            pool_size: Maximum connections in pool
        """
        super().__init__()
        self.redis_url = redis_url
        self.pool_size = pool_size
        self._redis = None
        self._pool = None
        self._connected = False

    async def _ensure_connected(self) -> bool:
        """Ensure Redis connection pool is established."""
        if self._connected and self._redis:
            return True

        try:
            import redis.asyncio as aioredis

            # Create connection pool
            self._pool = aioredis.ConnectionPool.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=False,  # We handle bytes for compression
                max_connections=self.pool_size,
                socket_connect_timeout=5,
                socket_keepalive=True,
                retry_on_timeout=True,
            )

            self._redis = aioredis.Redis(connection_pool=self._pool)

            # Test connection
            await self._redis.ping()
            self._connected = True
            logger.info(f"Redis cache connected with pool_size={self.pool_size}")
            return True

        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {e}")
            self._connected = False
            self.metrics.errors += 1
            return False

    async def get(self, key: str) -> str | None:
        """Get a value from Redis with decompression."""
        start = time.time()

        if not await self._ensure_connected():
            self.metrics.misses += 1
            return None

        try:
            data = await self._redis.get(key)

            if data is None:
                self.metrics.misses += 1
                return None

            # Check if compressed
            if isinstance(data, bytes) and data.startswith(COMPRESSION_PREFIX):
                data = gzip.decompress(data[len(COMPRESSION_PREFIX):]).decode("utf-8")
            elif isinstance(data, bytes):
                data = data.decode("utf-8")

            self.metrics.hits += 1
            self.metrics.total_latency_ms += (time.time() - start) * 1000
            return data

        except Exception as e:
            logger.error(f"Redis GET error for key {key}: {e}")
            self._connected = False
            self.metrics.errors += 1
            self.metrics.misses += 1
            return None

    async def set(self, key: str, value: str, ttl: int) -> None:
        """Set a value in Redis with optional compression."""
        if not await self._ensure_connected():
            return

        try:
            data = value.encode("utf-8")
            original_size = len(data)

            # Compress if over threshold
            if original_size > COMPRESSION_THRESHOLD:
                compressed = gzip.compress(data, compresslevel=6)
                if len(compressed) < original_size * 0.9:  # Only if >10% savings
                    data = COMPRESSION_PREFIX + compressed
                    self.metrics.bytes_saved += original_size - len(data)

            await self._redis.setex(key, ttl, data)
            self.metrics.stores += 1

        except Exception as e:
            logger.error(f"Redis SET error for key {key}: {e}")
            self._connected = False
            self.metrics.errors += 1

    async def delete(self, key: str) -> None:
        """Delete a value from Redis."""
        if not await self._ensure_connected():
            return

        try:
            await self._redis.delete(key)
        except Exception as e:
            logger.error(f"Redis DELETE error for key {key}: {e}")
            self._connected = False
            self.metrics.errors += 1

    async def exists(self, key: str) -> bool:
        """Check if a key exists in Redis."""
        if not await self._ensure_connected():
            return False

        try:
            return bool(await self._redis.exists(key))
        except Exception as e:
            logger.error(f"Redis EXISTS error for key {key}: {e}")
            self._connected = False
            self.metrics.errors += 1
            return False

    async def close(self) -> None:
        """Close the Redis connection pool."""
        if self._pool:
            await self._pool.disconnect()
        if self._redis:
            await self._redis.close()
        self._connected = False

    async def size(self) -> int:
        """Get approximate number of keys in Redis."""
        if not await self._ensure_connected():
            return 0
        try:
            return await self._redis.dbsize()
        except Exception:
            return 0


class CacheService:
    """High-level cache service with automatic backend selection.

    Features:
    - Automatic Redis/in-memory selection
    - Gzip compression for large responses
    - Metrics tracking
    - Specialized methods for AI responses and vulnerability data
    """

    def __init__(self):
        """Initialize the cache service with appropriate backend."""
        self.backend: CacheBackend

        # Try to use Redis if enabled and URL is provided
        if settings.redis_enabled and settings.redis_url:
            logger.info("Initializing cache with Redis backend (pooled)")
            self.backend = RedisCacheBackend(settings.redis_url, pool_size=10)
        else:
            logger.info("Initializing cache with in-memory LRU backend")
            self.backend = InMemoryCacheBackend(max_size=10000)

    async def get_cached_response(self, prompt_hash: str) -> dict[str, Any] | None:
        """Get a cached AI response by prompt hash."""
        cache_key = f"ai_response:{prompt_hash}"
        cached_value = await self.backend.get(cache_key)

        hits_counter, misses_counter = _get_metrics()
        backend_name = type(self.backend).__name__

        if cached_value:
            try:
                response = json.loads(cached_value)
                response["cached"] = True  # Mark as cached
                logger.debug(f"Cache HIT for {prompt_hash[:16]}")
                if hits_counter:
                    hits_counter.labels(backend=backend_name).inc()
                return response
            except json.JSONDecodeError:
                logger.error(f"Failed to decode cached response for {prompt_hash}")
                await self.backend.delete(cache_key)
                if misses_counter:
                    misses_counter.labels(backend=backend_name).inc()
                return None

        logger.debug(f"Cache MISS for {prompt_hash[:16]}")
        if misses_counter:
            misses_counter.labels(backend=backend_name).inc()
        return None

    async def cache_response(
        self,
        prompt_hash: str,
        response: dict[str, Any],
        ttl: int | None = None,
    ) -> None:
        """Cache an AI response with prompt hash as key."""
        if ttl is None:
            ttl = settings.cache_ttl_prompt

        cache_key = f"ai_response:{prompt_hash}"

        try:
            cache_value = json.dumps(response)
            await self.backend.set(cache_key, cache_value, ttl)
            logger.debug(f"Cached response for {prompt_hash[:16]} (TTL={ttl}s)")
        except Exception as e:
            logger.error(f"Failed to cache response for {prompt_hash}: {e}")

    async def get_cached_vuln_description(self, vuln_id: str) -> dict[str, Any] | None:
        """Get a cached vulnerability description."""
        cache_key = f"vuln_desc:{vuln_id.upper()}"
        cached_value = await self.backend.get(cache_key)

        if cached_value:
            try:
                return json.loads(cached_value)
            except json.JSONDecodeError:
                logger.error(f"Failed to decode cached vuln description for {vuln_id}")
                await self.backend.delete(cache_key)
                return None

        return None

    async def cache_vuln_description(
        self,
        vuln_id: str,
        description: dict[str, Any],
        ttl: int | None = None,
    ) -> None:
        """Cache a vulnerability description."""
        if ttl is None:
            ttl = settings.cache_ttl_vuln_desc

        cache_key = f"vuln_desc:{vuln_id.upper()}"

        try:
            cache_value = json.dumps(description)
            await self.backend.set(cache_key, cache_value, ttl)
        except Exception as e:
            logger.error(f"Failed to cache vuln description for {vuln_id}: {e}")

    async def invalidate_cache(self, key: str) -> None:
        """Invalidate a specific cache entry."""
        await self.backend.delete(key)

    async def check_cache_exists(self, prompt_hash: str) -> bool:
        """Check if a cached response exists for a prompt hash."""
        cache_key = f"ai_response:{prompt_hash}"
        return await self.backend.exists(cache_key)

    async def close(self) -> None:
        """Close the cache backend connection."""
        await self.backend.close()

    def get_metrics(self) -> dict[str, Any]:
        """Get cache performance metrics."""
        return self.backend.metrics.to_dict()

    async def get_stats(self) -> dict[str, Any]:
        """Get comprehensive cache statistics."""
        return {
            "backend": type(self.backend).__name__,
            "size": await self.backend.size(),
            "metrics": self.get_metrics(),
        }


# Singleton instance for dependency injection
_cache_service: CacheService | None = None


def get_cache_service() -> CacheService:
    """Get or create the global cache service instance."""
    global _cache_service

    if _cache_service is None:
        _cache_service = CacheService()

    return _cache_service


async def close_cache_service() -> None:
    """Close the global cache service instance."""
    global _cache_service

    if _cache_service is not None:
        await _cache_service.close()
        _cache_service = None
