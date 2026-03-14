"""Tests for AI provider clients (OpenAI, Anthropic, Grok, DeepSeek).

Follows the pattern in test_ollama_provider.py:
- Mock httpx calls, never make real API calls
- Test chat_completion, _get_headers, _get_default_model
- Test streaming response parsing
- Test error handling (401, 429, 402, 5xx)
"""

import json
import time
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from app.services.ai_providers import (
    AIProviderError,
    AIResponse,
    InvalidKeyError,
    ProviderType,
    QuotaExceededError,
    RateLimitError,
    StreamChunkType,
)
from app.services.ai_providers.anthropic_client import AnthropicProvider
from app.services.ai_providers.deepseek_client import DeepSeekProvider
from app.services.ai_providers.grok_client import GrokProvider
from app.services.ai_providers.openai_client import OpenAIProvider


# ---------------------------------------------------------------------------
# OpenAI Provider
# ---------------------------------------------------------------------------


class TestOpenAIProvider:
    """Test suite for OpenAIProvider."""

    @pytest.fixture
    def provider(self):
        return OpenAIProvider(api_key="sk-test-key-12345", timeout=30)

    def test_provider_type(self, provider):
        assert provider.provider_type == ProviderType.OPENAI

    def test_base_url(self, provider):
        assert provider.base_url == "https://api.openai.com/v1"

    def test_get_headers(self, provider):
        headers = provider._get_headers()
        assert headers["Authorization"] == "Bearer sk-test-key-12345"
        assert headers["Content-Type"] == "application/json"

    def test_default_model(self, provider):
        assert provider._get_default_model() == "gpt-4o-mini"

    def test_empty_api_key_raises(self):
        with pytest.raises(ValueError, match="API key cannot be empty"):
            OpenAIProvider(api_key="")

    async def test_chat_completion_success(self, provider):
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {"content": "Hello from GPT!"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
            },
            "model": "gpt-4o-mini",
            "system_fingerprint": "fp_test",
        }

        with patch.object(provider._client, "post", new_callable=AsyncMock, return_value=mock_response):
            response = await provider.chat_completion(
                messages=[{"role": "user", "content": "Hello"}],
                model="gpt-4o-mini",
                temperature=0.7,
                stream=False,
            )

        assert isinstance(response, AIResponse)
        assert response.provider == ProviderType.OPENAI
        assert response.content == "Hello from GPT!"
        assert response.prompt_tokens == 10
        assert response.completion_tokens == 5
        assert response.total_tokens == 15
        assert response.finish_reason == "stop"

    async def test_chat_completion_401_raises_invalid_key(self, provider):
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_response.headers = {}

        with patch.object(provider._client, "post", new_callable=AsyncMock, return_value=mock_response):
            with pytest.raises(InvalidKeyError):
                await provider.chat_completion(
                    messages=[{"role": "user", "content": "Hello"}],
                    model="gpt-4o-mini",
                    stream=False,
                )

    async def test_chat_completion_429_raises_rate_limit(self, provider):
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 429
        mock_response.text = "Rate limit exceeded"
        mock_response.headers = {"retry-after": "30"}

        with patch.object(provider._client, "post", new_callable=AsyncMock, return_value=mock_response):
            with pytest.raises(RateLimitError) as exc_info:
                await provider.chat_completion(
                    messages=[{"role": "user", "content": "Hello"}],
                    model="gpt-4o-mini",
                    stream=False,
                )
            assert exc_info.value.retry_after == 30

    async def test_chat_completion_402_raises_quota_exceeded(self, provider):
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 402
        mock_response.text = "Quota exceeded"
        mock_response.headers = {}

        with patch.object(provider._client, "post", new_callable=AsyncMock, return_value=mock_response):
            with pytest.raises(QuotaExceededError):
                await provider.chat_completion(
                    messages=[{"role": "user", "content": "Hello"}],
                    model="gpt-4o-mini",
                    stream=False,
                )

    async def test_chat_completion_500_raises_retryable(self, provider):
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_response.headers = {}

        with patch.object(provider._client, "post", new_callable=AsyncMock, return_value=mock_response):
            with pytest.raises(AIProviderError) as exc_info:
                await provider.chat_completion(
                    messages=[{"role": "user", "content": "Hello"}],
                    model="gpt-4o-mini",
                    stream=False,
                )
            assert exc_info.value.retryable is True

    async def test_streaming_parse(self, provider):
        stream_lines = [
            'data: {"choices":[{"delta":{"content":"Hi"},"finish_reason":null}]}',
            'data: {"choices":[{"delta":{"content":" there"},"finish_reason":null}]}',
            'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}',
            "data: [DONE]",
        ]

        async def mock_aiter_lines():
            for line in stream_lines:
                yield line

        mock_response = Mock(spec=httpx.Response)
        mock_response.aiter_lines = mock_aiter_lines

        chunks = []
        async for chunk in provider._parse_stream(mock_response):
            chunks.append(chunk)

        content_chunks = [c for c in chunks if c.type == StreamChunkType.CONTENT]
        done_chunks = [c for c in chunks if c.type == StreamChunkType.DONE]
        assert len(content_chunks) == 2
        assert content_chunks[0].content == "Hi"
        assert content_chunks[1].content == " there"
        assert len(done_chunks) == 1
        assert done_chunks[0].metadata["finish_reason"] == "stop"

    async def test_validate_key_success(self, provider):
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "x"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            "model": "gpt-4o-mini",
        }

        with patch.object(provider._client, "post", new_callable=AsyncMock, return_value=mock_response):
            is_valid = await provider.validate_key()
            assert is_valid is True

    async def test_validate_key_invalid(self, provider):
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 401
        mock_response.text = "Invalid API key"
        mock_response.headers = {}

        with patch.object(provider._client, "post", new_callable=AsyncMock, return_value=mock_response):
            is_valid = await provider.validate_key()
            assert is_valid is False

    async def test_empty_messages_raises(self, provider):
        with pytest.raises(ValueError, match="Messages list cannot be empty"):
            await provider.chat_completion(messages=[], model="gpt-4o-mini", stream=False)

    async def test_invalid_temperature_raises(self, provider):
        with pytest.raises(ValueError, match="Temperature must be between"):
            await provider.chat_completion(
                messages=[{"role": "user", "content": "hi"}],
                model="gpt-4o-mini",
                temperature=1.5,
                stream=False,
            )

    async def test_close(self, provider):
        await provider.close()
        # Should not raise on double close
        await provider.close()


# ---------------------------------------------------------------------------
# Anthropic Provider
# ---------------------------------------------------------------------------


class TestAnthropicProvider:
    """Test suite for AnthropicProvider."""

    @pytest.fixture
    def provider(self):
        return AnthropicProvider(api_key="ant-test-key-12345", timeout=30)

    def test_provider_type(self, provider):
        assert provider.provider_type == ProviderType.ANTHROPIC

    def test_base_url(self, provider):
        assert provider.base_url == "https://api.anthropic.com/v1"

    def test_get_headers(self, provider):
        headers = provider._get_headers()
        assert headers["x-api-key"] == "ant-test-key-12345"
        assert headers["Content-Type"] == "application/json"
        assert headers["anthropic-version"] == "2023-06-01"

    def test_default_model(self, provider):
        assert provider._get_default_model() == "claude-3-5-sonnet-20241022"

    def test_convert_messages_extracts_system(self, provider):
        messages = [
            {"role": "system", "content": "You are helpful"},
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi"},
        ]
        system, converted = provider._convert_messages_format(messages)
        assert system == "You are helpful"
        assert len(converted) == 2
        assert converted[0]["role"] == "user"
        assert converted[1]["role"] == "assistant"

    async def test_chat_completion_success(self, provider):
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "content": [{"type": "text", "text": "Hello from Claude!"}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
            "model": "claude-3-5-sonnet-20241022",
            "stop_reason": "end_turn",
            "stop_sequence": None,
        }

        with patch.object(provider._client, "post", new_callable=AsyncMock, return_value=mock_response):
            response = await provider.chat_completion(
                messages=[{"role": "user", "content": "Hello"}],
                model="claude-3-5-sonnet-20241022",
                temperature=0.7,
                stream=False,
            )

        assert response.provider == ProviderType.ANTHROPIC
        assert response.content == "Hello from Claude!"
        assert response.prompt_tokens == 10
        assert response.completion_tokens == 5
        assert response.total_tokens == 15

    async def test_chat_completion_401(self, provider):
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_response.headers = {}

        with patch.object(provider._client, "post", new_callable=AsyncMock, return_value=mock_response):
            with pytest.raises(InvalidKeyError):
                await provider.chat_completion(
                    messages=[{"role": "user", "content": "Hello"}],
                    model="claude-3-5-sonnet-20241022",
                    stream=False,
                )

    async def test_streaming_parse(self, provider):
        stream_lines = [
            'event: message_start',
            'data: {"type":"message_start","message":{"usage":{"input_tokens":10}}}',
            '',
            'event: content_block_delta',
            'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}',
            '',
            'event: content_block_delta',
            'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":" world"}}',
            '',
            'event: message_delta',
            'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}',
            '',
            'event: message_stop',
            'data: {"type":"message_stop"}',
        ]

        async def mock_aiter_lines():
            for line in stream_lines:
                yield line

        mock_response = Mock(spec=httpx.Response)
        mock_response.aiter_lines = mock_aiter_lines

        chunks = []
        async for chunk in provider._parse_stream(mock_response):
            chunks.append(chunk)

        content_chunks = [c for c in chunks if c.type == StreamChunkType.CONTENT]
        done_chunks = [c for c in chunks if c.type == StreamChunkType.DONE]
        assert len(content_chunks) == 2
        assert content_chunks[0].content == "Hello"
        assert content_chunks[1].content == " world"
        assert len(done_chunks) == 1
        assert done_chunks[0].metadata["prompt_tokens"] == 10
        assert done_chunks[0].metadata["completion_tokens"] == 5

    async def test_validate_key_success(self, provider):
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "content": [{"type": "text", "text": "x"}],
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "model": "claude-3-5-sonnet-20241022",
        }

        with patch.object(provider._client, "post", new_callable=AsyncMock, return_value=mock_response):
            assert await provider.validate_key() is True


# ---------------------------------------------------------------------------
# Grok Provider
# ---------------------------------------------------------------------------


class TestGrokProvider:
    """Test suite for GrokProvider."""

    @pytest.fixture
    def provider(self):
        return GrokProvider(api_key="grok-test-key-12345", timeout=30)

    def test_provider_type(self, provider):
        assert provider.provider_type == ProviderType.GROK

    def test_base_url(self, provider):
        assert provider.base_url == "https://api.x.ai/v1"

    def test_get_headers(self, provider):
        headers = provider._get_headers()
        assert headers["Authorization"] == "Bearer grok-test-key-12345"
        assert headers["Content-Type"] == "application/json"

    def test_default_model(self, provider):
        assert provider._get_default_model() == "grok-beta"

    async def test_chat_completion_success(self, provider):
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {"content": "Hello from Grok!"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 8,
                "completion_tokens": 4,
                "total_tokens": 12,
            },
            "model": "grok-beta",
            "system_fingerprint": None,
        }

        with patch.object(provider._client, "post", new_callable=AsyncMock, return_value=mock_response):
            response = await provider.chat_completion(
                messages=[{"role": "user", "content": "Hello"}],
                model="grok-beta",
                temperature=0.7,
                stream=False,
            )

        assert response.provider == ProviderType.GROK
        assert response.content == "Hello from Grok!"
        assert response.total_tokens == 12

    async def test_chat_completion_429(self, provider):
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 429
        mock_response.text = "Too many requests"
        mock_response.headers = {}

        with patch.object(provider._client, "post", new_callable=AsyncMock, return_value=mock_response):
            with pytest.raises(RateLimitError):
                await provider.chat_completion(
                    messages=[{"role": "user", "content": "Hello"}],
                    model="grok-beta",
                    stream=False,
                )

    async def test_streaming_parse(self, provider):
        stream_lines = [
            'data: {"choices":[{"delta":{"content":"Grok"},"finish_reason":null}]}',
            'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}',
            "data: [DONE]",
        ]

        async def mock_aiter_lines():
            for line in stream_lines:
                yield line

        mock_response = Mock(spec=httpx.Response)
        mock_response.aiter_lines = mock_aiter_lines

        chunks = []
        async for chunk in provider._parse_stream(mock_response):
            chunks.append(chunk)

        content_chunks = [c for c in chunks if c.type == StreamChunkType.CONTENT]
        assert len(content_chunks) == 1
        assert content_chunks[0].content == "Grok"

    async def test_validate_key_invalid(self, provider):
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        mock_response.headers = {}

        with patch.object(provider._client, "post", new_callable=AsyncMock, return_value=mock_response):
            assert await provider.validate_key() is False


# ---------------------------------------------------------------------------
# DeepSeek Provider
# ---------------------------------------------------------------------------


class TestDeepSeekProvider:
    """Test suite for DeepSeekProvider."""

    @pytest.fixture
    def provider(self):
        return DeepSeekProvider(api_key="ds-test-key-12345", timeout=30)

    def test_provider_type(self, provider):
        assert provider.provider_type == ProviderType.DEEPSEEK

    def test_base_url(self, provider):
        assert provider.base_url == "https://api.deepseek.com/v1"

    def test_get_headers(self, provider):
        headers = provider._get_headers()
        assert headers["Authorization"] == "Bearer ds-test-key-12345"
        assert headers["Content-Type"] == "application/json"

    def test_default_model(self, provider):
        assert provider._get_default_model() == "deepseek-chat"

    async def test_chat_completion_success(self, provider):
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {"content": "Hello from DeepSeek!"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 6,
                "total_tokens": 18,
            },
            "model": "deepseek-chat",
            "system_fingerprint": None,
        }

        with patch.object(provider._client, "post", new_callable=AsyncMock, return_value=mock_response):
            response = await provider.chat_completion(
                messages=[{"role": "user", "content": "Hello"}],
                model="deepseek-chat",
                temperature=0.7,
                stream=False,
            )

        assert response.provider == ProviderType.DEEPSEEK
        assert response.content == "Hello from DeepSeek!"
        assert response.total_tokens == 18

    async def test_chat_completion_server_error(self, provider):
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 502
        mock_response.text = "Bad Gateway"
        mock_response.headers = {}

        with patch.object(provider._client, "post", new_callable=AsyncMock, return_value=mock_response):
            with pytest.raises(AIProviderError) as exc_info:
                await provider.chat_completion(
                    messages=[{"role": "user", "content": "Hello"}],
                    model="deepseek-chat",
                    stream=False,
                )
            assert exc_info.value.retryable is True

    async def test_streaming_parse(self, provider):
        stream_lines = [
            'data: {"choices":[{"delta":{"content":"Deep"},"finish_reason":null}]}',
            'data: {"choices":[{"delta":{"content":"Seek"},"finish_reason":null}]}',
            'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}',
            "data: [DONE]",
        ]

        async def mock_aiter_lines():
            for line in stream_lines:
                yield line

        mock_response = Mock(spec=httpx.Response)
        mock_response.aiter_lines = mock_aiter_lines

        chunks = []
        async for chunk in provider._parse_stream(mock_response):
            chunks.append(chunk)

        content_chunks = [c for c in chunks if c.type == StreamChunkType.CONTENT]
        done_chunks = [c for c in chunks if c.type == StreamChunkType.DONE]
        assert len(content_chunks) == 2
        assert content_chunks[0].content == "Deep"
        assert content_chunks[1].content == "Seek"
        assert len(done_chunks) == 1

    async def test_timeout_raises_retryable(self, provider):
        with patch.object(
            provider._client,
            "post",
            new_callable=AsyncMock,
            side_effect=httpx.TimeoutException("timeout"),
        ):
            with pytest.raises(AIProviderError) as exc_info:
                await provider.chat_completion(
                    messages=[{"role": "user", "content": "Hello"}],
                    model="deepseek-chat",
                    stream=False,
                )
            assert exc_info.value.retryable is True

    async def test_network_error_raises_retryable(self, provider):
        with patch.object(
            provider._client,
            "post",
            new_callable=AsyncMock,
            side_effect=httpx.NetworkError("connection refused"),
        ):
            with pytest.raises(AIProviderError) as exc_info:
                await provider.chat_completion(
                    messages=[{"role": "user", "content": "Hello"}],
                    model="deepseek-chat",
                    stream=False,
                )
            assert exc_info.value.retryable is True


# ---------------------------------------------------------------------------
# Base class shared tests
# ---------------------------------------------------------------------------


class TestBaseProviderBehavior:
    """Test behavior inherited from BaseAIProvider via any concrete provider."""

    def test_sanitize_prompt_for_logging(self):
        from app.services.ai_providers.base import BaseAIProvider

        long_prompt = "x" * 200
        sanitized = BaseAIProvider._sanitize_prompt_for_logging(long_prompt, max_length=50)
        assert len(sanitized) <= 53  # 50 + "..."
        assert sanitized.endswith("...")

    def test_compute_prompt_hash_deterministic(self):
        from app.services.ai_providers.base import BaseAIProvider

        messages = [{"role": "user", "content": "hello"}]
        h1 = BaseAIProvider.compute_prompt_hash(messages, "gpt-4")
        h2 = BaseAIProvider.compute_prompt_hash(messages, "gpt-4")
        assert h1 == h2

    def test_compute_prompt_hash_model_matters(self):
        from app.services.ai_providers.base import BaseAIProvider

        messages = [{"role": "user", "content": "hello"}]
        h1 = BaseAIProvider.compute_prompt_hash(messages, "gpt-4")
        h2 = BaseAIProvider.compute_prompt_hash(messages, "gpt-3.5-turbo")
        assert h1 != h2

    async def test_context_manager(self):
        async with OpenAIProvider(api_key="test-key-123") as provider:
            assert provider.provider_type == ProviderType.OPENAI
        # After exiting, client should be closed (no error)
