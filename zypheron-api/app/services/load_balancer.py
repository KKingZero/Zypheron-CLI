"""Load balancer for AI provider API key pool management.

Security features:
- API keys never logged
- Automatic failover on rate limits
- Key health tracking with cooldown periods
- Thread-safe key rotation
"""

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

import structlog

from .ai_providers import (
    AnthropicProvider,
    BaseAIProvider,
    DeepSeekProvider,
    GrokProvider,
    InvalidKeyError,
    OllamaProvider,
    OpenAIProvider,
    ProviderType,
    QuotaExceededError,
    RateLimitError,
)

logger = structlog.get_logger()


@dataclass
class KeyHealth:
    """Track health status of an API key."""

    key_index: int
    failures: int = 0
    last_failure_time: float = 0.0
    consecutive_failures: int = 0
    is_healthy: bool = True
    cooldown_until: float = 0.0

    def mark_success(self) -> None:
        """Mark successful request - reset failure counters."""
        self.consecutive_failures = 0
        self.is_healthy = True

    def mark_failure(self, cooldown_seconds: int = 60) -> None:
        """Mark failed request - increment counters and set cooldown."""
        self.failures += 1
        self.consecutive_failures += 1
        self.last_failure_time = time.time()

        # Set cooldown period for unhealthy keys
        if self.consecutive_failures >= 3:
            self.is_healthy = False
            self.cooldown_until = time.time() + cooldown_seconds
            logger.warning(
                "api_key_unhealthy",
                key_index=self.key_index,
                consecutive_failures=self.consecutive_failures,
                cooldown_seconds=cooldown_seconds,
            )

    def check_recovery(self) -> bool:
        """Check if key has recovered from cooldown period.

        Returns:
            True if key is now healthy, False otherwise
        """
        if not self.is_healthy and time.time() >= self.cooldown_until:
            self.is_healthy = True
            self.consecutive_failures = 0
            logger.info(
                "api_key_recovered",
                key_index=self.key_index,
            )
            return True
        return self.is_healthy


@dataclass
class ProviderKeyPool:
    """Manages a pool of API keys for a single provider."""

    provider_type: ProviderType
    keys: list[str]
    current_index: int = 0
    health_status: dict[int, KeyHealth] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def __post_init__(self) -> None:
        """Initialize health tracking for all keys."""
        for i in range(len(self.keys)):
            self.health_status[i] = KeyHealth(key_index=i)

    def get_next_key(self) -> tuple[str, int] | None:
        """Get next healthy API key using round-robin selection.

        Returns:
            Tuple of (api_key, key_index) or None if no healthy keys available

        Thread-safe operation using lock.
        """
        with self._lock:
            if not self.keys:
                return None

            # Check for recovered keys
            for health in self.health_status.values():
                health.check_recovery()

            # Try to find healthy key (max attempts = pool size)
            attempts = 0
            max_attempts = len(self.keys)

            while attempts < max_attempts:
                key_index = self.current_index
                health = self.health_status[key_index]

                # Move to next key for next request (round-robin)
                self.current_index = (self.current_index + 1) % len(self.keys)
                attempts += 1

                # Check if current key is healthy
                if health.is_healthy:
                    return self.keys[key_index], key_index

            # No healthy keys available
            logger.error(
                "no_healthy_keys",
                provider=self.provider_type.value,
                total_keys=len(self.keys),
            )
            return None

    def mark_success(self, key_index: int) -> None:
        """Mark successful request for a key.

        Args:
            key_index: Index of the key that succeeded
        """
        with self._lock:
            if key_index in self.health_status:
                self.health_status[key_index].mark_success()

    def mark_failure(self, key_index: int, cooldown_seconds: int = 60) -> None:
        """Mark failed request for a key.

        Args:
            key_index: Index of the key that failed
            cooldown_seconds: Cooldown period before retry (default: 60s)
        """
        with self._lock:
            if key_index in self.health_status:
                self.health_status[key_index].mark_failure(cooldown_seconds)

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about key pool health.

        Returns:
            Dictionary with pool statistics
        """
        with self._lock:
            healthy_count = sum(1 for h in self.health_status.values() if h.is_healthy)
            total_failures = sum(h.failures for h in self.health_status.values())

            return {
                "provider": self.provider_type.value,
                "total_keys": len(self.keys),
                "healthy_keys": healthy_count,
                "unhealthy_keys": len(self.keys) - healthy_count,
                "total_failures": total_failures,
            }


class AILoadBalancer:
    """Load balancer for AI provider API keys.

    Features:
    - Round-robin key selection per provider
    - Automatic failover on rate limits and errors
    - Key health tracking with cooldown
    - Support for BYOK (Bring Your Own Key)

    Security:
    - API keys never logged
    - Thread-safe operations
    - Automatic circuit breaking for failed keys
    """

    def __init__(
        self,
        openai_keys: list[str] | None = None,
        anthropic_keys: list[str] | None = None,
        grok_keys: list[str] | None = None,
        deepseek_keys: list[str] | None = None,
        enable_ollama: bool = True,
        ollama_base_url: str | None = None,
    ):
        """Initialize load balancer with provider key pools.

        Args:
            openai_keys: List of OpenAI API keys
            anthropic_keys: List of Anthropic API keys
            grok_keys: List of Grok API keys
            deepseek_keys: List of DeepSeek API keys
            enable_ollama: Enable Ollama provider (default: True)
            ollama_base_url: Base URL for Ollama server (default: http://localhost:11434)
        """
        self._pools: dict[ProviderType, ProviderKeyPool] = {}
        self._ollama_base_url = ollama_base_url

        # Initialize key pools for each provider
        if openai_keys:
            self._pools[ProviderType.OPENAI] = ProviderKeyPool(
                provider_type=ProviderType.OPENAI,
                keys=openai_keys,
            )
            logger.info("load_balancer_pool_initialized", provider="openai", key_count=len(openai_keys))

        if anthropic_keys:
            self._pools[ProviderType.ANTHROPIC] = ProviderKeyPool(
                provider_type=ProviderType.ANTHROPIC,
                keys=anthropic_keys,
            )
            logger.info("load_balancer_pool_initialized", provider="anthropic", key_count=len(anthropic_keys))

        if grok_keys:
            self._pools[ProviderType.GROK] = ProviderKeyPool(
                provider_type=ProviderType.GROK,
                keys=grok_keys,
            )
            logger.info("load_balancer_pool_initialized", provider="grok", key_count=len(grok_keys))

        if deepseek_keys:
            self._pools[ProviderType.DEEPSEEK] = ProviderKeyPool(
                provider_type=ProviderType.DEEPSEEK,
                keys=deepseek_keys,
            )
            logger.info("load_balancer_pool_initialized", provider="deepseek", key_count=len(deepseek_keys))

        # Ollama is special - it's always available if enabled (no API keys needed)
        # We use a dummy key since Ollama doesn't require authentication
        if enable_ollama:
            self._pools[ProviderType.OLLAMA] = ProviderKeyPool(
                provider_type=ProviderType.OLLAMA,
                keys=["ollama-local"],  # Dummy key for pool management
            )
            logger.info("load_balancer_pool_initialized", provider="ollama", note="local-server-no-key-required")

    def _create_provider(
        self,
        provider_type: ProviderType,
        api_key: str,
        timeout: int = 30,
    ) -> BaseAIProvider:
        """Create provider instance with given API key.

        Args:
            provider_type: Type of provider to create
            api_key: API key for the provider
            timeout: Request timeout in seconds

        Returns:
            Provider instance

        Raises:
            ValueError: If provider type is not supported
        """
        provider_map = {
            ProviderType.OPENAI: OpenAIProvider,
            ProviderType.ANTHROPIC: AnthropicProvider,
            ProviderType.GROK: GrokProvider,
            ProviderType.DEEPSEEK: DeepSeekProvider,
            ProviderType.OLLAMA: OllamaProvider,
        }

        provider_class = provider_map.get(provider_type)
        if not provider_class:
            raise ValueError(f"Unsupported provider type: {provider_type}")

        # Special handling for Ollama - it doesn't need an API key
        if provider_type == ProviderType.OLLAMA:
            return provider_class(timeout=timeout, base_url=self._ollama_base_url)

        return provider_class(api_key=api_key, timeout=timeout)

    async def get_provider(
        self,
        provider_type: ProviderType,
        user_api_key: str | None = None,
        timeout: int = 30,
        max_retries: int = 3,
    ) -> BaseAIProvider:
        """Get AI provider with automatic failover and retries.

        Args:
            provider_type: Type of provider to get
            user_api_key: User's own API key (BYOK), if provided
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts with different keys

        Returns:
            Provider instance ready to use

        Raises:
            ValueError: If provider is not available
            InvalidKeyError: If BYOK key is invalid
        """
        # BYOK mode - use user's key directly
        if user_api_key:
            logger.info(
                "load_balancer_byok",
                provider=provider_type.value,
            )
            return self._create_provider(provider_type, user_api_key, timeout)

        # Server key mode - get from pool with failover
        pool = self._pools.get(provider_type)
        if not pool:
            raise ValueError(
                f"Provider {provider_type.value} not available - no server keys configured"
            )

        # Try to get a healthy key
        key_result = pool.get_next_key()
        if not key_result:
            raise ValueError(
                f"Provider {provider_type.value} not available - no healthy keys"
            )

        api_key, key_index = key_result

        logger.info(
            "load_balancer_key_selected",
            provider=provider_type.value,
            key_index=key_index,
        )

        return self._create_provider(provider_type, api_key, timeout)

    async def execute_with_failover(
        self,
        provider_type: ProviderType,
        operation: str,
        user_api_key: str | None = None,
        timeout: int = 30,
        max_retries: int = 3,
        **kwargs: Any,
    ) -> Any:
        """Execute AI provider operation with automatic failover.

        Args:
            provider_type: Type of provider to use
            operation: Operation name (e.g., "chat_completion")
            user_api_key: User's own API key (BYOK), if provided
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts with different keys
            **kwargs: Arguments to pass to the operation

        Returns:
            Operation result

        Raises:
            ValueError: If provider is not available
            AIProviderError: If all retries fail
        """
        # BYOK mode - single attempt, no failover
        if user_api_key:
            provider = await self.get_provider(provider_type, user_api_key, timeout)
            try:
                operation_func = getattr(provider, operation)
                return await operation_func(**kwargs)
            finally:
                await provider.close()

        # Server key mode - retry with failover
        pool = self._pools.get(provider_type)
        if not pool:
            raise ValueError(
                f"Provider {provider_type.value} not available - no server keys configured"
            )

        last_error = None
        for attempt in range(max_retries):
            # Get next healthy key
            key_result = pool.get_next_key()
            if not key_result:
                raise ValueError(
                    f"Provider {provider_type.value} not available - no healthy keys"
                )

            api_key, key_index = key_result

            # Create provider and execute operation
            provider = self._create_provider(provider_type, api_key, timeout)

            try:
                operation_func = getattr(provider, operation)
                result = await operation_func(**kwargs)

                # Success - mark key as healthy
                pool.mark_success(key_index)

                logger.info(
                    "load_balancer_success",
                    provider=provider_type.value,
                    key_index=key_index,
                    attempt=attempt + 1,
                )

                return result

            except (RateLimitError, QuotaExceededError) as e:
                # Rate limit or quota - mark key as unhealthy and retry
                cooldown = e.retry_after if isinstance(e, RateLimitError) and e.retry_after else 300
                pool.mark_failure(key_index, cooldown_seconds=cooldown)

                logger.warning(
                    "load_balancer_key_failed",
                    provider=provider_type.value,
                    key_index=key_index,
                    error_type=type(e).__name__,
                    attempt=attempt + 1,
                    will_retry=attempt < max_retries - 1,
                )

                last_error = e
                # Continue to next key

            except InvalidKeyError as e:
                # Invalid key - mark as permanently unhealthy
                pool.mark_failure(key_index, cooldown_seconds=86400)  # 24 hour cooldown

                logger.error(
                    "load_balancer_invalid_key",
                    provider=provider_type.value,
                    key_index=key_index,
                )

                last_error = e
                # Continue to next key

            except Exception as e:
                # Other errors - don't mark key as unhealthy, might be transient
                logger.warning(
                    "load_balancer_request_error",
                    provider=provider_type.value,
                    key_index=key_index,
                    error=str(e),
                    error_type=type(e).__name__,
                )

                last_error = e
                # Continue to next key

            finally:
                await provider.close()

        # All retries exhausted
        logger.error(
            "load_balancer_all_retries_failed",
            provider=provider_type.value,
            max_retries=max_retries,
        )

        # Raise the last error
        if last_error:
            raise last_error
        else:
            raise ValueError(f"All {max_retries} retry attempts failed for {provider_type.value}")

    def get_available_providers(self) -> list[str]:
        """Get list of available provider names.

        Returns:
            List of provider names that have configured keys
        """
        return [provider_type.value for provider_type in self._pools.keys()]

    def get_pool_stats(self) -> dict[str, Any]:
        """Get statistics for all key pools.

        Returns:
            Dictionary mapping provider names to their statistics
        """
        return {
            provider_type.value: pool.get_stats()
            for provider_type, pool in self._pools.items()
        }

    async def validate_user_key(
        self,
        provider_type: ProviderType,
        api_key: str,
    ) -> bool:
        """Validate a user's API key for a provider.

        Args:
            provider_type: Type of provider to validate
            api_key: API key to validate

        Returns:
            True if key is valid, False otherwise
        """
        provider = self._create_provider(provider_type, api_key, timeout=10)
        try:
            is_valid = await provider.validate_key()
            logger.info(
                "user_key_validation",
                provider=provider_type.value,
                is_valid=is_valid,
            )
            return is_valid
        except Exception as e:
            logger.warning(
                "user_key_validation_error",
                provider=provider_type.value,
                error=str(e),
            )
            return False
        finally:
            await provider.close()
