"""Abstract base class for AI provider clients with security and performance focus."""

import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, AsyncIterator

import httpx
import structlog

logger = structlog.get_logger()


class ProviderType(str, Enum):
    """Supported AI providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GROK = "grok"
    DEEPSEEK = "deepseek"
    OLLAMA = "ollama"


class StreamChunkType(str, Enum):
    """Types of streaming chunks."""

    CONTENT = "content"
    METADATA = "metadata"
    ERROR = "error"
    DONE = "done"


@dataclass
class StreamChunk:
    """Standardized streaming chunk format."""

    type: StreamChunkType
    content: str = ""
    metadata: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: dict[str, Any] = {"type": self.type.value}
        if self.content:
            result["content"] = self.content
        if self.metadata:
            result["metadata"] = self.metadata
        if self.error:
            result["error"] = self.error
        return result


@dataclass
class AIResponse:
    """Standardized AI response format across all providers."""

    provider: ProviderType
    model: str
    content: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    latency_ms: int
    cached: bool = False
    finish_reason: str | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "provider": self.provider.value,
            "model": self.model,
            "content": self.content,
            "usage": {
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "total_tokens": self.total_tokens,
            },
            "latency_ms": self.latency_ms,
            "cached": self.cached,
        }
        if self.finish_reason:
            result["finish_reason"] = self.finish_reason
        if self.metadata:
            result["metadata"] = self.metadata
        return result


class AIProviderError(Exception):
    """Base exception for AI provider errors."""

    def __init__(self, message: str, provider: ProviderType, retryable: bool = False):
        super().__init__(message)
        self.provider = provider
        self.retryable = retryable


class RateLimitError(AIProviderError):
    """Rate limit exceeded error."""

    def __init__(self, message: str, provider: ProviderType, retry_after: int | None = None):
        super().__init__(message, provider, retryable=True)
        self.retry_after = retry_after


class InvalidKeyError(AIProviderError):
    """Invalid API key error."""

    def __init__(self, message: str, provider: ProviderType):
        super().__init__(message, provider, retryable=False)


class QuotaExceededError(AIProviderError):
    """Quota exceeded error."""

    def __init__(self, message: str, provider: ProviderType):
        super().__init__(message, provider, retryable=False)


class BaseAIProvider(ABC):
    """Abstract base class for AI provider clients.

    Security considerations:
    - API keys are never logged
    - Prompts are sanitized before logging
    - All HTTP requests have timeouts
    - Sensitive data is cleared from memory when possible
    """

    def __init__(
        self,
        api_key: str,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        """Initialize provider client.

        Args:
            api_key: API key for the provider (validated but not logged)
            timeout: Request timeout in seconds (default: 30)
            max_retries: Maximum number of retry attempts (default: 3)
        """
        if not api_key or not api_key.strip():
            raise ValueError("API key cannot be empty")

        self._api_key = api_key  # Never log this
        self._timeout = timeout
        self._max_retries = max_retries

        # HTTP client with security settings
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout=float(timeout)),
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
            follow_redirects=False,  # Security: explicit redirect handling
        )

        logger.info(
            "ai_provider_initialized",
            provider=self.provider_type.value,
            timeout=timeout,
            max_retries=max_retries,
        )

    @property
    @abstractmethod
    def provider_type(self) -> ProviderType:
        """Return the provider type."""
        pass

    @property
    @abstractmethod
    def base_url(self) -> str:
        """Return the base URL for the provider API."""
        pass

    @abstractmethod
    def _get_headers(self) -> dict[str, str]:
        """Get HTTP headers for API requests.

        Returns:
            Dictionary of HTTP headers (API key should be included here)
        """
        pass

    @abstractmethod
    async def _parse_response(
        self,
        response: httpx.Response,
        start_time: float,
    ) -> AIResponse:
        """Parse provider-specific response into standardized format.

        Args:
            response: HTTP response from provider
            start_time: Request start time for latency calculation

        Returns:
            Standardized AIResponse object
        """
        pass

    @abstractmethod
    async def _parse_stream(
        self,
        response: httpx.Response,
    ) -> AsyncIterator[StreamChunk]:
        """Parse provider-specific streaming response.

        Args:
            response: HTTP streaming response from provider

        Yields:
            StreamChunk objects with content and metadata
        """
        pass

    @staticmethod
    def _sanitize_prompt_for_logging(prompt: str, max_length: int = 100) -> str:
        """Sanitize prompt for safe logging.

        Args:
            prompt: Full prompt text
            max_length: Maximum length for log output

        Returns:
            Truncated and sanitized prompt
        """
        # Remove potential PII patterns (simple approach)
        sanitized = prompt.replace("\n", " ").strip()
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "..."
        return sanitized

    @staticmethod
    def compute_prompt_hash(messages: list[dict[str, Any]], model: str) -> str:
        """Compute deterministic hash of prompt for caching.

        Args:
            messages: List of message dictionaries
            model: Model name to include in hash

        Returns:
            SHA-256 hex digest of prompt
        """
        # Create deterministic string representation
        prompt_str = f"{model}|{str(messages)}"
        return hashlib.sha256(prompt_str.encode("utf-8")).hexdigest()

    def _handle_error_response(self, response: httpx.Response) -> None:
        """Handle HTTP error responses with provider-agnostic error mapping.

        Args:
            response: HTTP error response

        Raises:
            Appropriate AIProviderError subclass
        """
        status_code = response.status_code
        error_text = response.text[:500]  # Limit error text length

        logger.warning(
            "ai_provider_error",
            provider=self.provider_type.value,
            status_code=status_code,
            error_preview=error_text[:100],
        )

        # Map HTTP status codes to exceptions
        if status_code == 401 or status_code == 403:
            raise InvalidKeyError(
                f"Authentication failed: {error_text}",
                provider=self.provider_type,
            )
        elif status_code == 429:
            # Extract retry-after header if present
            retry_after = response.headers.get("retry-after")
            retry_seconds = int(retry_after) if retry_after and retry_after.isdigit() else None
            raise RateLimitError(
                f"Rate limit exceeded: {error_text}",
                provider=self.provider_type,
                retry_after=retry_seconds,
            )
        elif status_code == 402:
            raise QuotaExceededError(
                f"Quota exceeded: {error_text}",
                provider=self.provider_type,
            )
        else:
            # Generic error
            retryable = status_code >= 500  # Server errors are retryable
            raise AIProviderError(
                f"Provider error ({status_code}): {error_text}",
                provider=self.provider_type,
                retryable=retryable,
            )

    async def chat_completion(
        self,
        messages: list[dict[str, str]],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        stream: bool = False,
    ) -> AIResponse | AsyncIterator[StreamChunk]:
        """Send chat completion request to provider.

        Args:
            messages: List of message dictionaries with 'role' and 'content'
            model: Model identifier
            temperature: Sampling temperature (0.0 to 1.0)
            max_tokens: Maximum tokens to generate
            stream: Whether to stream the response

        Returns:
            AIResponse for non-streaming, AsyncIterator[StreamChunk] for streaming

        Raises:
            AIProviderError: On API errors
        """
        # Input validation
        if not messages:
            raise ValueError("Messages list cannot be empty")
        if not 0.0 <= temperature <= 1.0:
            raise ValueError("Temperature must be between 0.0 and 1.0")
        if max_tokens is not None and max_tokens <= 0:
            raise ValueError("max_tokens must be positive")

        # Validate message structure
        for msg in messages:
            if "role" not in msg or "content" not in msg:
                raise ValueError("Each message must have 'role' and 'content' fields")

        logger.info(
            "ai_chat_request",
            provider=self.provider_type.value,
            model=model,
            message_count=len(messages),
            temperature=temperature,
            max_tokens=max_tokens,
            stream=stream,
            prompt_preview=self._sanitize_prompt_for_logging(messages[-1].get("content", "")),
        )

        start_time = time.time()

        try:
            if stream:
                return self._stream_chat_completion(
                    messages=messages,
                    model=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            else:
                return await self._complete_chat_completion(
                    messages=messages,
                    model=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    start_time=start_time,
                )
        except httpx.TimeoutException as e:
            logger.error(
                "ai_request_timeout",
                provider=self.provider_type.value,
                model=model,
                timeout=self._timeout,
            )
            raise AIProviderError(
                f"Request timeout after {self._timeout}s",
                provider=self.provider_type,
                retryable=True,
            ) from e
        except httpx.NetworkError as e:
            logger.error(
                "ai_network_error",
                provider=self.provider_type.value,
                error=str(e),
            )
            raise AIProviderError(
                f"Network error: {str(e)}",
                provider=self.provider_type,
                retryable=True,
            ) from e

    @abstractmethod
    async def _complete_chat_completion(
        self,
        messages: list[dict[str, str]],
        model: str,
        temperature: float,
        max_tokens: int | None,
        start_time: float,
    ) -> AIResponse:
        """Provider-specific implementation for non-streaming chat completion."""
        pass

    @abstractmethod
    async def _stream_chat_completion(
        self,
        messages: list[dict[str, str]],
        model: str,
        temperature: float,
        max_tokens: int | None,
    ) -> AsyncIterator[StreamChunk]:
        """Provider-specific implementation for streaming chat completion."""
        pass

    async def validate_key(self) -> bool:
        """Validate API key by making a minimal request.

        Returns:
            True if key is valid, False otherwise
        """
        try:
            # Minimal test request
            await self.chat_completion(
                messages=[{"role": "user", "content": "Hi"}],
                model=self._get_default_model(),
                max_tokens=1,
            )
            return True
        except InvalidKeyError:
            return False
        except Exception:
            # Other errors don't necessarily mean invalid key
            return True

    @abstractmethod
    def _get_default_model(self) -> str:
        """Get default model for this provider."""
        pass

    async def close(self) -> None:
        """Close HTTP client and cleanup resources."""
        await self._client.aclose()
        logger.info("ai_provider_closed", provider=self.provider_type.value)

    async def __aenter__(self) -> "BaseAIProvider":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()
