"""Redis client for connection management and health checks.

Provides connection pool management, graceful reconnection, and health monitoring
for Redis-based operations like rate limiting and caching.
"""

import structlog
from typing import Optional

import redis.asyncio as aioredis
from redis.asyncio.connection import ConnectionPool
from redis.exceptions import ConnectionError, RedisError, TimeoutError

from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()


class RedisClient:
    """Redis client with connection pool and automatic reconnection.

    Features:
    - Connection pooling for efficient resource usage
    - Health checks to verify connectivity
    - Graceful error handling with fallback support
    - TLS/SSL support for secure connections
    - Automatic reconnection on connection failures
    """

    def __init__(self) -> None:
        """Initialize Redis client (connection created lazily)."""
        self._pool: Optional[ConnectionPool] = None
        self._client: Optional[aioredis.Redis] = None
        self._is_healthy: bool = False

    async def connect(self) -> None:
        """Establish Redis connection with connection pool.

        Creates a connection pool based on environment configuration.
        Supports both REDIS_URL and individual REDIS_HOST/PORT/PASSWORD settings.

        Raises:
            RedisError: If connection fails and redis is required
        """
        try:
            if settings.redis_url:
                # Use REDIS_URL (priority)
                logger.info("Connecting to Redis using REDIS_URL")
                self._pool = ConnectionPool.from_url(
                    settings.redis_url,
                    encoding="utf-8",
                    decode_responses=True,
                    max_connections=20,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True,
                    health_check_interval=30,
                )
            else:
                # Construct from individual settings
                redis_host = getattr(settings, 'redis_host', 'localhost')
                redis_port = getattr(settings, 'redis_port', 6379)
                redis_password = getattr(settings, 'redis_password', None)
                redis_db = getattr(settings, 'redis_db', 0)

                logger.info(f"Connecting to Redis at {redis_host}:{redis_port}")
                self._pool = ConnectionPool(
                    host=redis_host,
                    port=redis_port,
                    password=redis_password,
                    db=redis_db,
                    encoding="utf-8",
                    decode_responses=True,
                    max_connections=20,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True,
                    health_check_interval=30,
                    ssl=settings.redis_ssl if hasattr(settings, 'redis_ssl') else False,
                )

            self._client = aioredis.Redis(connection_pool=self._pool)

            # Test connection
            await self.health_check()
            logger.info("Redis connection established successfully")

        except (ConnectionError, TimeoutError) as e:
            logger.warning(f"Failed to connect to Redis: {e}")
            self._is_healthy = False
            if settings.redis_enabled:
                # If Redis is explicitly enabled, this is an error
                raise
            else:
                # Otherwise, just log warning and continue without Redis
                logger.warning("Redis unavailable - rate limiting will be disabled")

        except Exception as e:
            logger.error(f"Unexpected error connecting to Redis: {e}")
            self._is_healthy = False
            raise

    async def disconnect(self) -> None:
        """Close Redis connection and cleanup resources."""
        if self._client:
            try:
                await self._client.aclose()
                logger.info("Redis connection closed")
            except Exception as e:
                logger.error(f"Error closing Redis connection: {e}")
            finally:
                self._client = None
                self._pool = None
                self._is_healthy = False

    async def health_check(self) -> bool:
        """Verify Redis connection is healthy.

        Returns:
            True if Redis is available and responsive, False otherwise
        """
        try:
            if not self._client:
                self._is_healthy = False
                return False

            # Simple PING command to test connectivity
            response = await self._client.ping()
            self._is_healthy = response is True
            return self._is_healthy

        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.warning(f"Redis health check failed: {e}")
            self._is_healthy = False
            return False

        except Exception as e:
            logger.error(f"Unexpected error during Redis health check: {e}")
            self._is_healthy = False
            return False

    async def get(self, key: str) -> Optional[str]:
        """Get value from Redis with error handling.

        Args:
            key: Redis key to retrieve

        Returns:
            Value if found, None if key doesn't exist or on error
        """
        try:
            if not self._client or not self._is_healthy:
                return None

            return await self._client.get(key)

        except (ConnectionError, TimeoutError) as e:
            logger.warning(f"Redis GET failed for key {key}: {e}")
            self._is_healthy = False
            return None

        except Exception as e:
            logger.error(f"Unexpected error in Redis GET for key {key}: {e}")
            return None

    async def set(
        self,
        key: str,
        value: str,
        ex: Optional[int] = None,
        nx: bool = False
    ) -> bool:
        """Set value in Redis with error handling.

        Args:
            key: Redis key
            value: Value to store
            ex: Expiration time in seconds
            nx: Only set if key doesn't exist (SET NX)

        Returns:
            True if successful, False otherwise
        """
        try:
            if not self._client or not self._is_healthy:
                return False

            result = await self._client.set(key, value, ex=ex, nx=nx)
            return bool(result)

        except (ConnectionError, TimeoutError) as e:
            logger.warning(f"Redis SET failed for key {key}: {e}")
            self._is_healthy = False
            return False

        except Exception as e:
            logger.error(f"Unexpected error in Redis SET for key {key}: {e}")
            return False

    async def incr(self, key: str) -> Optional[int]:
        """Increment value in Redis.

        Args:
            key: Redis key to increment

        Returns:
            New value after increment, None on error
        """
        try:
            if not self._client or not self._is_healthy:
                return None

            return await self._client.incr(key)

        except (ConnectionError, TimeoutError) as e:
            logger.warning(f"Redis INCR failed for key {key}: {e}")
            self._is_healthy = False
            return None

        except Exception as e:
            logger.error(f"Unexpected error in Redis INCR for key {key}: {e}")
            return None

    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration time on a key.

        Args:
            key: Redis key
            seconds: Expiration time in seconds

        Returns:
            True if successful, False otherwise
        """
        try:
            if not self._client or not self._is_healthy:
                return False

            result = await self._client.expire(key, seconds)
            return bool(result)

        except (ConnectionError, TimeoutError) as e:
            logger.warning(f"Redis EXPIRE failed for key {key}: {e}")
            self._is_healthy = False
            return False

        except Exception as e:
            logger.error(f"Unexpected error in Redis EXPIRE for key {key}: {e}")
            return False

    async def ttl(self, key: str) -> Optional[int]:
        """Get remaining TTL for a key.

        Args:
            key: Redis key

        Returns:
            Remaining TTL in seconds, -1 if no expiry, -2 if key doesn't exist, None on error
        """
        try:
            if not self._client or not self._is_healthy:
                return None

            return await self._client.ttl(key)

        except (ConnectionError, TimeoutError) as e:
            logger.warning(f"Redis TTL failed for key {key}: {e}")
            self._is_healthy = False
            return None

        except Exception as e:
            logger.error(f"Unexpected error in Redis TTL for key {key}: {e}")
            return None

    async def delete(self, key: str) -> bool:
        """Delete a key from Redis.

        Args:
            key: Redis key to delete

        Returns:
            True if key was deleted, False otherwise
        """
        try:
            if not self._client or not self._is_healthy:
                return False

            result = await self._client.delete(key)
            return result > 0

        except (ConnectionError, TimeoutError) as e:
            logger.warning(f"Redis DELETE failed for key {key}: {e}")
            self._is_healthy = False
            return False

        except Exception as e:
            logger.error(f"Unexpected error in Redis DELETE for key {key}: {e}")
            return False

    @property
    def is_available(self) -> bool:
        """Check if Redis client is available and healthy.

        Returns:
            True if Redis is connected and healthy, False otherwise
        """
        return self._client is not None and self._is_healthy


# Global Redis client instance
_redis_client: Optional[RedisClient] = None


async def get_redis_client() -> RedisClient:
    """Get or create the global Redis client instance.

    Returns:
        RedisClient instance
    """
    global _redis_client

    if _redis_client is None:
        _redis_client = RedisClient()
        await _redis_client.connect()

    return _redis_client


async def close_redis_client() -> None:
    """Close the global Redis client instance."""
    global _redis_client

    if _redis_client is not None:
        await _redis_client.disconnect()
        _redis_client = None
