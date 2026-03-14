"""Ollama API client with local server support and health checking.

Ollama is a local LLM server that runs models like Llama3, CodeLlama, Mistral, etc.
Unlike cloud providers, it requires no API key and runs entirely locally.
"""

import ipaddress
import json
import os
import time
from typing import Any, AsyncIterator
from urllib.parse import urlparse

import httpx
import structlog

from .base import (
    AIProviderError,
    AIResponse,
    BaseAIProvider,
    ProviderType,
    StreamChunk,
    StreamChunkType,
)

logger = structlog.get_logger()


# SSRF Protection: Blocked hosts for cloud metadata endpoints
BLOCKED_HOSTS = {
    "169.254.169.254",  # AWS metadata service
    "metadata.google.internal",  # GCP metadata service
    "metadata.internal",  # Generic cloud metadata
    "metadata",  # Short form metadata endpoint
    "fd00:ec2::254",  # AWS IPv6 metadata
}

# Blocked internal domain suffixes
BLOCKED_DOMAIN_SUFFIXES = (
    ".internal",
    ".local",
    ".corp",
    ".lan",
    ".intranet",
)


def validate_ollama_url(url: str) -> str:
    """Validate Ollama URL to prevent SSRF attacks.

    This function implements strict validation to prevent Server-Side Request Forgery
    (SSRF) attacks by blocking:
    - Non-HTTP/HTTPS schemes (file://, gopher://, etc.)
    - Cloud metadata endpoints (AWS, GCP, Azure)
    - Private IP ranges (except localhost for development)
    - Link-local addresses
    - Reserved IP ranges
    - Internal domain names

    Allowed URLs:
    - localhost / 127.0.0.1 / ::1 (for local Ollama development)
    - Public IP addresses
    - Public domain names

    Args:
        url: The Ollama base URL to validate

    Returns:
        The validated URL if safe

    Raises:
        ValueError: If the URL is potentially unsafe for SSRF reasons
    """
    try:
        parsed = urlparse(url)

        # CRITICAL: Only allow http/https schemes
        # This blocks file://, gopher://, ftp://, etc.
        if parsed.scheme not in ("http", "https"):
            logger.error(
                "ollama_url_validation_failed_scheme",
                url=url,
                scheme=parsed.scheme,
                reason="Only http/https schemes allowed",
            )
            raise ValueError(
                f"Invalid URL scheme: {parsed.scheme}. "
                "Only http/https schemes are allowed to prevent SSRF attacks."
            )

        # Must have hostname
        if not parsed.hostname:
            logger.error(
                "ollama_url_validation_failed_no_hostname",
                url=url,
            )
            raise ValueError("URL must have a hostname")

        hostname_lower = parsed.hostname.lower()

        # Check if hostname is an IP address first (before string matching)
        is_ip_address = False
        ip = None
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            is_ip_address = True
        except ValueError:
            # Not an IP address - will be treated as hostname below
            pass

        if is_ip_address and ip is not None:
            # Hostname is an IP address - validate it

            # Allow localhost (127.0.0.0/8 and ::1)
            if ip.is_loopback:
                logger.info(
                    "ollama_url_validation_passed_localhost",
                    url=url,
                    ip=str(ip),
                )
                return url

            # CRITICAL: Block link-local addresses (169.254.0.0/16, fe80::/10)
            # These are often used for cloud metadata services
            # Check this BEFORE is_private because link-local is also considered private
            if ip.is_link_local:
                logger.error(
                    "ollama_url_validation_blocked_link_local",
                    url=url,
                    ip=str(ip),
                    reason="Link-local address blocked (often used for metadata services)",
                )
                raise ValueError(
                    f"Link-local IP address not allowed: {ip}. "
                    "This range is commonly used for cloud metadata services."
                )

            # CRITICAL: Block private IP ranges (RFC 1918)
            # - 10.0.0.0/8
            # - 172.16.0.0/12
            # - 192.168.0.0/16
            if ip.is_private:
                logger.error(
                    "ollama_url_validation_blocked_private_ip",
                    url=url,
                    ip=str(ip),
                    reason="Private IP address blocked",
                )
                raise ValueError(
                    f"Private IP address not allowed: {ip}. "
                    "Use localhost (127.0.0.1) for local Ollama instances."
                )

            # CRITICAL: Block reserved IP ranges
            if ip.is_reserved:
                logger.error(
                    "ollama_url_validation_blocked_reserved",
                    url=url,
                    ip=str(ip),
                    reason="Reserved IP address blocked",
                )
                raise ValueError(
                    f"Reserved IP address not allowed: {ip}"
                )

            # CRITICAL: Block multicast addresses
            if ip.is_multicast:
                logger.error(
                    "ollama_url_validation_blocked_multicast",
                    url=url,
                    ip=str(ip),
                    reason="Multicast address blocked",
                )
                raise ValueError(
                    f"Multicast IP address not allowed: {ip}"
                )

            # If we get here, it's a public IP - allow it
            logger.info(
                "ollama_url_validation_passed_public_ip",
                url=url,
                ip=str(ip),
            )
            return url

        else:
            # Not an IP address - it's a hostname/domain

            # Allow localhost hostname explicitly
            if hostname_lower == "localhost":
                logger.info(
                    "ollama_url_validation_passed_localhost_hostname",
                    url=url,
                )
                return url

            # CRITICAL: Block known cloud metadata endpoints (hostname-based)
            if hostname_lower in BLOCKED_HOSTS:
                logger.error(
                    "ollama_url_validation_blocked_metadata",
                    url=url,
                    hostname=parsed.hostname,
                    reason="Cloud metadata endpoint blocked",
                )
                raise ValueError(
                    f"Blocked cloud metadata endpoint: {parsed.hostname}. "
                    "This URL is not allowed to prevent SSRF attacks."
                )

            # CRITICAL: Block internal-looking domain suffixes
            # These are commonly used for internal networks
            if any(hostname_lower.endswith(suffix) for suffix in BLOCKED_DOMAIN_SUFFIXES):
                logger.error(
                    "ollama_url_validation_blocked_internal_domain",
                    url=url,
                    hostname=parsed.hostname,
                    reason="Internal domain suffix blocked",
                )
                raise ValueError(
                    f"Internal domain name not allowed: {parsed.hostname}. "
                    "Domains ending in .internal, .local, .corp, .lan are blocked."
                )

            # Public domain name - allow it
            logger.info(
                "ollama_url_validation_passed_public_domain",
                url=url,
                hostname=parsed.hostname,
            )
            return url

    except ValueError as e:
        # Re-raise validation errors with context
        raise
    except Exception as e:
        logger.error(
            "ollama_url_validation_error",
            url=url,
            error=str(e),
            error_type=type(e).__name__,
        )
        raise ValueError(f"Invalid Ollama URL '{url}': {str(e)}") from e


class OllamaConnectionError(AIProviderError):
    """Raised when Ollama server is not running or unreachable."""

    def __init__(self, message: str):
        super().__init__(
            message,
            provider=ProviderType.OLLAMA,
            retryable=False,  # User needs to start Ollama
        )


class OllamaProvider(BaseAIProvider):
    """Ollama API client for local LLM inference.

    Features:
    - Local inference (no API key required)
    - Health checking to verify Ollama is running
    - Support for /api/chat and /api/generate endpoints
    - Streaming support
    - Model availability checking

    Note: Since Ollama runs locally, this provider:
    - Does not require an API key (uses empty string)
    - Does not implement rate limiting
    - Has connection errors when Ollama is not running
    """

    def __init__(
        self,
        api_key: str = "",  # Ollama doesn't need API key
        timeout: int = 60,  # Longer timeout for local inference
        max_retries: int = 1,  # No retries for local server
        base_url: str | None = None,
    ):
        """Initialize Ollama provider.

        Args:
            api_key: Not used for Ollama (defaults to empty string)
            timeout: Request timeout in seconds (default: 60 for local inference)
            max_retries: Maximum retry attempts (default: 1, no retries needed locally)
            base_url: Custom Ollama server URL (default: from OLLAMA_BASE_URL env or localhost)

        Raises:
            ValueError: If the provided URL fails SSRF validation
        """
        # Override API key validation for Ollama since it doesn't need one
        # We'll set it to a dummy value to pass base class validation
        if not api_key:
            api_key = "ollama-local-no-key-required"

        # CRITICAL: Validate base URL to prevent SSRF attacks
        # Get raw URL from parameter or environment variable
        raw_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

        # Validate URL before using it
        try:
            self._base_url = validate_ollama_url(raw_url)
        except ValueError as e:
            logger.error(
                "ollama_provider_initialization_failed",
                raw_url=raw_url,
                error=str(e),
                reason="SSRF validation failed",
            )
            raise ValueError(
                f"Failed to initialize Ollama provider: {str(e)}"
            ) from e

        # Initialize base provider
        super().__init__(api_key=api_key, timeout=timeout, max_retries=max_retries)

        logger.info(
            "ollama_provider_initialized",
            base_url=self._base_url,
            timeout=timeout,
            ssrf_validation="passed",
        )

    @property
    def provider_type(self) -> ProviderType:
        """Return Ollama provider type."""
        return ProviderType.OLLAMA

    @property
    def base_url(self) -> str:
        """Return Ollama API base URL."""
        return self._base_url

    def _get_headers(self) -> dict[str, str]:
        """Get HTTP headers for Ollama API requests.

        Ollama doesn't require authentication headers.
        """
        return {
            "Content-Type": "application/json",
        }

    def _get_default_model(self) -> str:
        """Get default Ollama model."""
        return "llama3"

    async def health_check(self) -> bool:
        """Check if Ollama server is running and accessible.

        Returns:
            True if Ollama is running, False otherwise

        Raises:
            OllamaConnectionError: If Ollama is not running
        """
        try:
            response = await self._client.get(f"{self.base_url}/api/tags")

            if response.status_code == 200:
                logger.info("ollama_health_check_passed")
                return True
            else:
                logger.warning(
                    "ollama_health_check_failed",
                    status_code=response.status_code,
                )
                return False

        except (httpx.ConnectError, httpx.TimeoutException) as e:
            logger.error(
                "ollama_connection_failed",
                error=str(e),
                base_url=self.base_url,
            )
            raise OllamaConnectionError(
                f"Ollama server not reachable at {self.base_url}. "
                "Please ensure Ollama is installed and running. "
                "Install: https://ollama.ai/download or start with: ollama serve"
            ) from e

    async def list_models(self) -> list[str]:
        """List available models on the Ollama server.

        Returns:
            List of model names

        Raises:
            OllamaConnectionError: If Ollama is not running
        """
        try:
            response = await self._client.get(f"{self.base_url}/api/tags")

            if response.status_code != 200:
                logger.error(
                    "ollama_list_models_failed",
                    status_code=response.status_code,
                )
                return []

            data = response.json()
            models = [model["name"] for model in data.get("models", [])]

            logger.info(
                "ollama_models_listed",
                count=len(models),
            )

            return models

        except (httpx.ConnectError, httpx.TimeoutException) as e:
            logger.error("ollama_list_models_error", error=str(e))
            raise OllamaConnectionError(
                f"Failed to list Ollama models. Server not reachable at {self.base_url}"
            ) from e

    async def _complete_chat_completion(
        self,
        messages: list[dict[str, str]],
        model: str,
        temperature: float,
        max_tokens: int | None,
        start_time: float,
    ) -> AIResponse:
        """Ollama-specific non-streaming chat completion implementation."""
        # Build request payload using Ollama's /api/chat endpoint
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }

        # Ollama uses num_predict instead of max_tokens
        if max_tokens is not None:
            payload["options"]["num_predict"] = max_tokens

        # Make request
        try:
            response = await self._client.post(
                f"{self.base_url}/api/chat",
                headers=self._get_headers(),
                json=payload,
            )

            # Handle errors
            if response.status_code != 200:
                # Check if it's a connection issue
                if response.status_code == 404:
                    raise OllamaConnectionError(
                        f"Model '{model}' not found. Pull it with: ollama pull {model}"
                    )
                self._handle_error_response(response)

            # Parse response
            return await self._parse_response(response, start_time)

        except httpx.ConnectError as e:
            raise OllamaConnectionError(
                f"Cannot connect to Ollama at {self.base_url}. "
                "Ensure Ollama is running with: ollama serve"
            ) from e

    async def _stream_chat_completion(
        self,
        messages: list[dict[str, str]],
        model: str,
        temperature: float,
        max_tokens: int | None,
    ) -> AsyncIterator[StreamChunk]:
        """Ollama-specific streaming chat completion implementation."""
        # Build request payload
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": True,
            "options": {
                "temperature": temperature,
            },
        }

        # Ollama uses num_predict instead of max_tokens
        if max_tokens is not None:
            payload["options"]["num_predict"] = max_tokens

        # Make streaming request
        try:
            async with self._client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                headers=self._get_headers(),
                json=payload,
            ) as response:
                # Handle errors
                if response.status_code != 200:
                    if response.status_code == 404:
                        raise OllamaConnectionError(
                            f"Model '{model}' not found. Pull it with: ollama pull {model}"
                        )
                    self._handle_error_response(response)

                # Stream response
                async for chunk in self._parse_stream(response):
                    yield chunk

        except httpx.ConnectError as e:
            raise OllamaConnectionError(
                f"Cannot connect to Ollama at {self.base_url}. "
                "Ensure Ollama is running with: ollama serve"
            ) from e

    async def _parse_response(
        self,
        response: httpx.Response,
        start_time: float,
    ) -> AIResponse:
        """Parse Ollama response into standardized format."""
        latency_ms = int((time.time() - start_time) * 1000)

        try:
            data = response.json()
        except json.JSONDecodeError as e:
            raise AIProviderError(
                f"Invalid JSON response from Ollama: {str(e)}",
                provider=self.provider_type,
                retryable=False,
            ) from e

        # Extract fields with validation
        try:
            # Ollama response format
            content = data.get("message", {}).get("content", "")
            model = data.get("model", "unknown")

            # Ollama provides token counts in eval_count and prompt_eval_count
            prompt_tokens = data.get("prompt_eval_count", 0)
            completion_tokens = data.get("eval_count", 0)
            total_tokens = prompt_tokens + completion_tokens

            return AIResponse(
                provider=self.provider_type,
                model=model,
                content=content,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                latency_ms=latency_ms,
                finish_reason=data.get("done_reason"),
                metadata={
                    "total_duration": data.get("total_duration"),
                    "load_duration": data.get("load_duration"),
                    "prompt_eval_duration": data.get("prompt_eval_duration"),
                    "eval_duration": data.get("eval_duration"),
                },
            )
        except (KeyError, TypeError) as e:
            logger.error(
                "ollama_parse_error",
                error=str(e),
                response_preview=str(data)[:200],
            )
            raise AIProviderError(
                f"Failed to parse Ollama response: {str(e)}",
                provider=self.provider_type,
                retryable=False,
            ) from e

    async def _parse_stream(
        self,
        response: httpx.Response,
    ) -> AsyncIterator[StreamChunk]:
        """Parse Ollama streaming response.

        Ollama streams newline-delimited JSON objects.
        Each line is a complete JSON object with message content.
        """
        accumulated_content = ""
        prompt_tokens = 0
        completion_tokens = 0
        finish_reason = None

        try:
            async for line in response.aiter_lines():
                # Skip empty lines
                if not line.strip():
                    continue

                # Parse JSON line
                try:
                    chunk_data = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("ollama_invalid_stream_chunk", chunk=line[:100])
                    continue

                # Extract content from message
                try:
                    message = chunk_data.get("message", {})
                    content_delta = message.get("content", "")

                    if content_delta:
                        accumulated_content += content_delta
                        yield StreamChunk(
                            type=StreamChunkType.CONTENT,
                            content=content_delta,
                        )

                    # Check if this is the final chunk
                    if chunk_data.get("done", False):
                        # Extract final metrics
                        prompt_tokens = chunk_data.get("prompt_eval_count", 0)
                        completion_tokens = chunk_data.get("eval_count", 0)
                        finish_reason = chunk_data.get("done_reason", "stop")

                        yield StreamChunk(
                            type=StreamChunkType.DONE,
                            metadata={
                                "finish_reason": finish_reason,
                                "prompt_tokens": prompt_tokens,
                                "completion_tokens": completion_tokens,
                                "total_tokens": prompt_tokens + completion_tokens,
                                "total_duration": chunk_data.get("total_duration"),
                                "load_duration": chunk_data.get("load_duration"),
                                "eval_duration": chunk_data.get("eval_duration"),
                            },
                        )
                        break

                except (KeyError, TypeError) as e:
                    logger.warning(
                        "ollama_stream_parse_warning",
                        error=str(e),
                        chunk_preview=str(chunk_data)[:200],
                    )
                    continue

        except Exception as e:
            logger.error(
                "ollama_stream_error",
                error=str(e),
                error_type=type(e).__name__,
            )
            yield StreamChunk(
                type=StreamChunkType.ERROR,
                error=f"Stream processing error: {str(e)}",
            )

    async def validate_key(self) -> bool:
        """Validate Ollama server is running.

        For Ollama, we check if the server is accessible rather than validating an API key.

        Returns:
            True if server is accessible, False otherwise
        """
        try:
            return await self.health_check()
        except OllamaConnectionError:
            return False
        except Exception:
            # Other errors don't necessarily mean server is down
            return True
