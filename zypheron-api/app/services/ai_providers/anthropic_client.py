"""Anthropic (Claude) API client with security and performance optimizations."""

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


class AnthropicProvider(BaseAIProvider):
    """Anthropic (Claude) API client with streaming support and error handling."""

    @property
    def provider_type(self) -> ProviderType:
        """Return Anthropic provider type."""
        return ProviderType.ANTHROPIC

    @property
    def base_url(self) -> str:
        """Return Anthropic API base URL."""
        return "https://api.anthropic.com/v1"

    def _get_headers(self) -> dict[str, str]:
        """Get HTTP headers for Anthropic API requests."""
        return {
            "x-api-key": self._api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }

    def _get_default_model(self) -> str:
        """Get default Anthropic model."""
        return "claude-3-5-sonnet-20241022"

    def _convert_messages_format(
        self,
        messages: list[dict[str, str]],
    ) -> tuple[str | None, list[dict[str, str]]]:
        """Convert OpenAI-style messages to Anthropic format.

        Anthropic requires system messages to be separate from the messages array.

        Args:
            messages: OpenAI-style messages

        Returns:
            Tuple of (system_message, user_assistant_messages)
        """
        system_message = None
        converted_messages = []

        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")

            if role == "system":
                # Extract system message (Anthropic only supports one)
                system_message = content
            elif role in ("user", "assistant"):
                converted_messages.append({"role": role, "content": content})
            else:
                # Map other roles to user for compatibility
                logger.warning(
                    "anthropic_unknown_role",
                    role=role,
                    mapped_to="user",
                )
                converted_messages.append({"role": "user", "content": content})

        return system_message, converted_messages

    async def _complete_chat_completion(
        self,
        messages: list[dict[str, str]],
        model: str,
        temperature: float,
        max_tokens: int | None,
        start_time: float,
    ) -> AIResponse:
        """Anthropic-specific non-streaming chat completion implementation."""
        # Convert message format
        system_message, converted_messages = self._convert_messages_format(messages)

        # Build request payload
        payload: dict[str, Any] = {
            "model": model,
            "messages": converted_messages,
            "temperature": temperature,
            "max_tokens": max_tokens or 4096,  # Anthropic requires max_tokens
        }
        if system_message:
            payload["system"] = system_message

        # Make request
        response = await self._client.post(
            f"{self.base_url}/messages",
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
        """Anthropic-specific streaming chat completion implementation."""
        # Convert message format
        system_message, converted_messages = self._convert_messages_format(messages)

        # Build request payload
        payload: dict[str, Any] = {
            "model": model,
            "messages": converted_messages,
            "temperature": temperature,
            "max_tokens": max_tokens or 4096,
            "stream": True,
        }
        if system_message:
            payload["system"] = system_message

        # Make streaming request
        async with self._client.stream(
            "POST",
            f"{self.base_url}/messages",
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
        """Parse Anthropic response into standardized format."""
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
            # Anthropic returns content as array of content blocks
            content_blocks = data["content"]
            content = "".join(
                block["text"] for block in content_blocks if block["type"] == "text"
            )

            usage = data["usage"]
            model = data["model"]

            return AIResponse(
                provider=self.provider_type,
                model=model,
                content=content,
                prompt_tokens=usage["input_tokens"],
                completion_tokens=usage["output_tokens"],
                total_tokens=usage["input_tokens"] + usage["output_tokens"],
                latency_ms=latency_ms,
                finish_reason=data.get("stop_reason"),
                metadata={
                    "stop_sequence": data.get("stop_sequence"),
                },
            )
        except (KeyError, IndexError, TypeError) as e:
            logger.error(
                "anthropic_parse_error",
                error=str(e),
                response_preview=str(data)[:200],
            )
            raise AIProviderError(
                f"Failed to parse Anthropic response: {str(e)}",
                provider=self.provider_type,
                retryable=False,
            ) from e

    async def _parse_stream(
        self,
        response: httpx.Response,
    ) -> AsyncIterator[StreamChunk]:
        """Parse Anthropic streaming response.

        Anthropic uses SSE format with multiple event types:
        - message_start: Initial message metadata
        - content_block_start: Start of content block
        - content_block_delta: Content chunk
        - content_block_stop: End of content block
        - message_delta: Usage updates
        - message_stop: End of message
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

                # Anthropic SSE format: "event: {type}" followed by "data: {json}"
                if line.startswith("event: "):
                    event_type = line[7:].strip()
                    continue
                elif line.startswith("data: "):
                    data_str = line[6:]
                else:
                    continue

                # Parse JSON chunk
                try:
                    chunk_data = json.loads(data_str)
                except json.JSONDecodeError:
                    logger.warning("anthropic_invalid_stream_chunk", chunk=data_str[:100])
                    continue

                # Handle different event types
                event_type = chunk_data.get("type", "")

                if event_type == "message_start":
                    # Extract initial token counts
                    usage = chunk_data.get("message", {}).get("usage", {})
                    prompt_tokens = usage.get("input_tokens", 0)

                elif event_type == "content_block_delta":
                    # Extract content delta
                    delta = chunk_data.get("delta", {})
                    if delta.get("type") == "text_delta":
                        content_delta = delta.get("text", "")
                        if content_delta:
                            accumulated_content += content_delta
                            yield StreamChunk(
                                type=StreamChunkType.CONTENT,
                                content=content_delta,
                            )

                elif event_type == "message_delta":
                    # Extract usage updates
                    delta = chunk_data.get("delta", {})
                    finish_reason = delta.get("stop_reason")
                    usage = chunk_data.get("usage", {})
                    completion_tokens = usage.get("output_tokens", 0)

                elif event_type == "message_stop":
                    # End of stream
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

                elif event_type == "error":
                    # Error event
                    error_msg = chunk_data.get("error", {}).get("message", "Unknown error")
                    logger.error("anthropic_stream_error", error=error_msg)
                    yield StreamChunk(
                        type=StreamChunkType.ERROR,
                        error=error_msg,
                    )
                    break

        except Exception as e:
            logger.error(
                "anthropic_stream_error",
                error=str(e),
                error_type=type(e).__name__,
            )
            yield StreamChunk(
                type=StreamChunkType.ERROR,
                error=f"Stream processing error: {str(e)}",
            )
