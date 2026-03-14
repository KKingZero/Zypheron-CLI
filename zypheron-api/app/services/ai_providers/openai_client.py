"""OpenAI API client with security and performance optimizations."""

import json
import time
from typing import Any, AsyncIterator

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


class OpenAIProvider(BaseAIProvider):
    """OpenAI API client with streaming support and error handling."""

    @property
    def provider_type(self) -> ProviderType:
        """Return OpenAI provider type."""
        return ProviderType.OPENAI

    @property
    def base_url(self) -> str:
        """Return OpenAI API base URL."""
        return "https://api.openai.com/v1"

    def _get_headers(self) -> dict[str, str]:
        """Get HTTP headers for OpenAI API requests."""
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    def _get_default_model(self) -> str:
        """Get default OpenAI model."""
        return "gpt-4o-mini"

    async def _complete_chat_completion(
        self,
        messages: list[dict[str, str]],
        model: str,
        temperature: float,
        max_tokens: int | None,
        start_time: float,
    ) -> AIResponse:
        """OpenAI-specific non-streaming chat completion implementation."""
        # Build request payload
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        # Make request
        response = await self._client.post(
            f"{self.base_url}/chat/completions",
            headers=self._get_headers(),
            json=payload,
        )

        # Handle errors
        if response.status_code != 200:
            self._handle_error_response(response)

        # Parse response
        return await self._parse_response(response, start_time)

    async def _stream_chat_completion(
        self,
        messages: list[dict[str, str]],
        model: str,
        temperature: float,
        max_tokens: int | None,
    ) -> AsyncIterator[StreamChunk]:
        """OpenAI-specific streaming chat completion implementation."""
        # Build request payload
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "stream": True,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        # Make streaming request
        async with self._client.stream(
            "POST",
            f"{self.base_url}/chat/completions",
            headers=self._get_headers(),
            json=payload,
        ) as response:
            # Handle errors
            if response.status_code != 200:
                self._handle_error_response(response)

            # Stream response
            async for chunk in self._parse_stream(response):
                yield chunk

    async def _parse_response(
        self,
        response: httpx.Response,
        start_time: float,
    ) -> AIResponse:
        """Parse OpenAI response into standardized format."""
        latency_ms = int((time.time() - start_time) * 1000)

        try:
            data = response.json()
        except json.JSONDecodeError as e:
            raise AIProviderError(
                f"Invalid JSON response: {str(e)}",
                provider=self.provider_type,
                retryable=False,
            ) from e

        # Extract fields with validation
        try:
            choice = data["choices"][0]
            content = choice["message"]["content"]
            usage = data["usage"]
            model = data["model"]

            return AIResponse(
                provider=self.provider_type,
                model=model,
                content=content,
                prompt_tokens=usage["prompt_tokens"],
                completion_tokens=usage["completion_tokens"],
                total_tokens=usage["total_tokens"],
                latency_ms=latency_ms,
                finish_reason=choice.get("finish_reason"),
                metadata={
                    "system_fingerprint": data.get("system_fingerprint"),
                },
            )
        except (KeyError, IndexError, TypeError) as e:
            logger.error(
                "openai_parse_error",
                error=str(e),
                response_preview=str(data)[:200],
            )
            raise AIProviderError(
                f"Failed to parse OpenAI response: {str(e)}",
                provider=self.provider_type,
                retryable=False,
            ) from e

    async def _parse_stream(
        self,
        response: httpx.Response,
    ) -> AsyncIterator[StreamChunk]:
        """Parse OpenAI streaming response."""
        accumulated_content = ""
        prompt_tokens = 0
        completion_tokens = 0
        finish_reason = None

        try:
            async for line in response.aiter_lines():
                # Skip empty lines
                if not line.strip():
                    continue

                # OpenAI SSE format: "data: {json}"
                if not line.startswith("data: "):
                    continue

                data_str = line[6:]  # Remove "data: " prefix

                # Check for stream end
                if data_str == "[DONE]":
                    yield StreamChunk(
                        type=StreamChunkType.DONE,
                        metadata={
                            "finish_reason": finish_reason,
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "total_tokens": prompt_tokens + completion_tokens,
                        },
                    )
                    break

                # Parse JSON chunk
                try:
                    chunk_data = json.loads(data_str)
                except json.JSONDecodeError:
                    logger.warning("openai_invalid_stream_chunk", chunk=data_str[:100])
                    continue

                # Extract content delta
                try:
                    choice = chunk_data["choices"][0]
                    delta = choice.get("delta", {})
                    content_delta = delta.get("content", "")

                    if content_delta:
                        accumulated_content += content_delta
                        yield StreamChunk(
                            type=StreamChunkType.CONTENT,
                            content=content_delta,
                        )

                    # Check for finish reason
                    if choice.get("finish_reason"):
                        finish_reason = choice["finish_reason"]

                    # Extract usage if present (usually in last chunk)
                    if "usage" in chunk_data:
                        usage = chunk_data["usage"]
                        prompt_tokens = usage.get("prompt_tokens", 0)
                        completion_tokens = usage.get("completion_tokens", 0)

                except (KeyError, IndexError, TypeError) as e:
                    logger.warning(
                        "openai_stream_parse_warning",
                        error=str(e),
                        chunk_preview=str(chunk_data)[:200],
                    )
                    continue

        except Exception as e:
            logger.error(
                "openai_stream_error",
                error=str(e),
                error_type=type(e).__name__,
            )
            yield StreamChunk(
                type=StreamChunkType.ERROR,
                error=f"Stream processing error: {str(e)}",
            )
