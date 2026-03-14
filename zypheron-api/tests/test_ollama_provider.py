"""Tests for Ollama provider integration.

These tests require Ollama to be running locally with at least one model installed.
To run: pytest tests/test_ollama_provider.py
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, Mock, patch

from app.services.ai_providers import (
    OllamaProvider,
    ProviderType,
    StreamChunkType,
)
from app.services.ai_providers.ollama_client import OllamaConnectionError, validate_ollama_url


class TestSSRFValidation:
    """Test suite for SSRF URL validation."""

    def test_valid_localhost_ip(self):
        """Test that localhost IP addresses are allowed."""
        assert validate_ollama_url("http://127.0.0.1:11434") == "http://127.0.0.1:11434"
        assert validate_ollama_url("http://127.0.0.2:11434") == "http://127.0.0.2:11434"
        assert validate_ollama_url("http://[::1]:11434") == "http://[::1]:11434"

    def test_valid_localhost_hostname(self):
        """Test that localhost hostname is allowed."""
        assert validate_ollama_url("http://localhost:11434") == "http://localhost:11434"
        assert validate_ollama_url("https://localhost:11434") == "https://localhost:11434"

    def test_valid_public_domain(self):
        """Test that public domains are allowed."""
        assert validate_ollama_url("https://api.example.com") == "https://api.example.com"
        assert validate_ollama_url("http://ollama.mydomain.com:11434") == "http://ollama.mydomain.com:11434"

    def test_valid_public_ip(self):
        """Test that public IP addresses are allowed."""
        # Using public IP addresses (Google DNS, Cloudflare DNS)
        assert validate_ollama_url("http://8.8.8.8:11434") == "http://8.8.8.8:11434"
        assert validate_ollama_url("http://1.1.1.1:11434") == "http://1.1.1.1:11434"

    def test_block_aws_metadata(self):
        """Test that AWS metadata endpoint is blocked."""
        with pytest.raises(ValueError, match="(Link-local IP|not allowed)"):
            validate_ollama_url("http://169.254.169.254/latest/meta-data/")

    def test_block_gcp_metadata(self):
        """Test that GCP metadata endpoint is blocked."""
        with pytest.raises(ValueError, match="(Blocked cloud metadata|not allowed)"):
            validate_ollama_url("http://metadata.google.internal/computeMetadata/v1/")

    def test_block_generic_metadata(self):
        """Test that generic metadata endpoints are blocked."""
        with pytest.raises(ValueError, match="(Blocked cloud metadata|not allowed)"):
            validate_ollama_url("http://metadata.internal/")
        with pytest.raises(ValueError, match="(Blocked cloud metadata|not allowed)"):
            validate_ollama_url("http://metadata/")

    def test_block_private_ip_10(self):
        """Test that 10.x.x.x private IPs are blocked."""
        with pytest.raises(ValueError, match="(Private IP|not allowed)"):
            validate_ollama_url("http://10.0.0.1:11434")
        with pytest.raises(ValueError, match="(Private IP|not allowed)"):
            validate_ollama_url("http://10.10.10.10:11434")
        with pytest.raises(ValueError, match="(Private IP|not allowed)"):
            validate_ollama_url("http://10.255.255.255:11434")

    def test_block_private_ip_172(self):
        """Test that 172.16-31.x.x private IPs are blocked."""
        with pytest.raises(ValueError, match="(Private IP|not allowed)"):
            validate_ollama_url("http://172.16.0.1:11434")
        with pytest.raises(ValueError, match="(Private IP|not allowed)"):
            validate_ollama_url("http://172.20.0.1:11434")
        with pytest.raises(ValueError, match="(Private IP|not allowed)"):
            validate_ollama_url("http://172.31.255.255:11434")

    def test_block_private_ip_192(self):
        """Test that 192.168.x.x private IPs are blocked."""
        with pytest.raises(ValueError, match="(Private IP|not allowed)"):
            validate_ollama_url("http://192.168.0.1:11434")
        with pytest.raises(ValueError, match="(Private IP|not allowed)"):
            validate_ollama_url("http://192.168.1.100:11434")
        with pytest.raises(ValueError, match="(Private IP|not allowed)"):
            validate_ollama_url("http://192.168.255.255:11434")

    def test_block_file_scheme(self):
        """Test that file:// scheme is blocked."""
        with pytest.raises(ValueError, match="(Invalid URL scheme|file)"):
            validate_ollama_url("file:///etc/passwd")

    def test_block_gopher_scheme(self):
        """Test that gopher:// scheme is blocked."""
        with pytest.raises(ValueError, match="(Invalid URL scheme|gopher)"):
            validate_ollama_url("gopher://evil.com:70/1")

    def test_block_ftp_scheme(self):
        """Test that ftp:// scheme is blocked."""
        with pytest.raises(ValueError, match="(Invalid URL scheme|ftp)"):
            validate_ollama_url("ftp://ftp.example.com/")

    def test_block_internal_domains(self):
        """Test that internal domain suffixes are blocked."""
        with pytest.raises(ValueError, match="(Internal domain|not allowed)"):
            validate_ollama_url("http://server.internal:11434")
        with pytest.raises(ValueError, match="(Internal domain|not allowed)"):
            validate_ollama_url("http://ollama.local:11434")
        with pytest.raises(ValueError, match="(Internal domain|not allowed)"):
            validate_ollama_url("http://api.corp:11434")
        with pytest.raises(ValueError, match="(Internal domain|not allowed)"):
            validate_ollama_url("http://service.lan:11434")

    def test_block_ipv6_metadata(self):
        """Test that IPv6 AWS metadata endpoint is blocked."""
        with pytest.raises(ValueError, match="(Blocked cloud metadata|not allowed)"):
            validate_ollama_url("http://[fd00:ec2::254]/latest/meta-data/")

    def test_block_link_local_ipv6(self):
        """Test that link-local IPv6 addresses are blocked."""
        with pytest.raises(ValueError, match="(Link-local IP|not allowed)"):
            validate_ollama_url("http://[fe80::1]:11434")

    def test_block_multicast_ip(self):
        """Test that multicast IP addresses are blocked."""
        with pytest.raises(ValueError, match="(Multicast IP|not allowed)"):
            validate_ollama_url("http://224.0.0.1:11434")
        with pytest.raises(ValueError, match="(Multicast IP|not allowed)"):
            validate_ollama_url("http://[ff02::1]:11434")

    def test_url_without_hostname(self):
        """Test that URLs without hostname are rejected."""
        with pytest.raises(ValueError, match="URL must have a hostname"):
            validate_ollama_url("http://:11434")

    def test_provider_initialization_with_valid_url(self):
        """Test that provider initializes with valid URL."""
        provider = OllamaProvider(base_url="http://localhost:11434")
        assert provider.base_url == "http://localhost:11434"

    def test_provider_initialization_blocks_ssrf(self):
        """Test that provider initialization blocks SSRF URLs."""
        # AWS metadata
        with pytest.raises(ValueError, match="Failed to initialize Ollama provider"):
            OllamaProvider(base_url="http://169.254.169.254/")

        # Private IP
        with pytest.raises(ValueError, match="Failed to initialize Ollama provider"):
            OllamaProvider(base_url="http://192.168.1.1:11434")

        # File scheme
        with pytest.raises(ValueError, match="Failed to initialize Ollama provider"):
            OllamaProvider(base_url="file:///etc/passwd")

        # Internal domain
        with pytest.raises(ValueError, match="Failed to initialize Ollama provider"):
            OllamaProvider(base_url="http://ollama.internal:11434")

    def test_provider_initialization_with_env_var(self):
        """Test that provider validates URL from environment variable."""
        # Valid URL
        with patch.dict("os.environ", {"OLLAMA_BASE_URL": "http://localhost:11434"}):
            provider = OllamaProvider()
            assert provider.base_url == "http://localhost:11434"

        # Invalid URL (SSRF)
        with patch.dict("os.environ", {"OLLAMA_BASE_URL": "http://169.254.169.254/"}):
            with pytest.raises(ValueError, match="Failed to initialize Ollama provider"):
                OllamaProvider()


class TestOllamaProvider:
    """Test suite for OllamaProvider."""

    @pytest.fixture
    def provider(self):
        """Create an OllamaProvider instance for testing."""
        return OllamaProvider(timeout=30)

    def test_provider_type(self, provider):
        """Test that provider type is correctly set."""
        assert provider.provider_type == ProviderType.OLLAMA

    def test_base_url_default(self):
        """Test default base URL."""
        provider = OllamaProvider()
        assert provider.base_url == "http://localhost:11434"

    def test_base_url_custom_public_domain(self):
        """Test custom base URL with public domain."""
        custom_url = "https://ollama.example.com:11434"
        provider = OllamaProvider(base_url=custom_url)
        assert provider.base_url == custom_url

    def test_base_url_from_env(self):
        """Test base URL from environment variable."""
        with patch.dict("os.environ", {"OLLAMA_BASE_URL": "https://public.ollama.com:11434"}):
            provider = OllamaProvider()
            assert provider.base_url == "https://public.ollama.com:11434"

    def test_get_headers(self, provider):
        """Test headers generation."""
        headers = provider._get_headers()
        assert headers == {"Content-Type": "application/json"}
        # Ollama doesn't require authentication
        assert "Authorization" not in headers

    def test_default_model(self, provider):
        """Test default model selection."""
        assert provider._get_default_model() == "llama3"

    @pytest.mark.asyncio
    async def test_health_check_success(self, provider):
        """Test successful health check."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"models": []}

        with patch.object(provider._client, "get", return_value=mock_response):
            result = await provider.health_check()
            assert result is True

    @pytest.mark.asyncio
    async def test_health_check_failure(self, provider):
        """Test failed health check."""
        mock_response = Mock()
        mock_response.status_code = 500

        with patch.object(provider._client, "get", return_value=mock_response):
            result = await provider.health_check()
            assert result is False

    @pytest.mark.asyncio
    async def test_health_check_connection_error(self, provider):
        """Test health check with connection error."""
        import httpx

        with patch.object(
            provider._client, "get", side_effect=httpx.ConnectError("Connection failed")
        ):
            with pytest.raises(OllamaConnectionError) as exc_info:
                await provider.health_check()
            assert "not reachable" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_list_models(self, provider):
        """Test listing available models."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "models": [
                {"name": "llama3"},
                {"name": "mistral"},
                {"name": "codellama"},
            ]
        }

        with patch.object(provider._client, "get", return_value=mock_response):
            models = await provider.list_models()
            assert len(models) == 3
            assert "llama3" in models
            assert "mistral" in models
            assert "codellama" in models

    @pytest.mark.asyncio
    async def test_parse_response(self, provider):
        """Test response parsing."""
        import httpx
        import time

        start_time = time.time()

        mock_response = Mock(spec=httpx.Response)
        mock_response.json.return_value = {
            "model": "llama3",
            "message": {"content": "Hello, I am Llama!"},
            "prompt_eval_count": 10,
            "eval_count": 20,
            "done_reason": "stop",
            "total_duration": 1000000,
            "load_duration": 100000,
            "prompt_eval_duration": 200000,
            "eval_duration": 700000,
        }

        response = await provider._parse_response(mock_response, start_time)

        assert response.provider == ProviderType.OLLAMA
        assert response.model == "llama3"
        assert response.content == "Hello, I am Llama!"
        assert response.prompt_tokens == 10
        assert response.completion_tokens == 20
        assert response.total_tokens == 30
        assert response.finish_reason == "stop"
        assert response.metadata["total_duration"] == 1000000

    @pytest.mark.asyncio
    async def test_chat_completion_model_not_found(self, provider):
        """Test chat completion with non-existent model."""
        import httpx

        mock_response = Mock()
        mock_response.status_code = 404

        messages = [{"role": "user", "content": "Hello"}]

        with patch.object(provider._client, "post", return_value=mock_response):
            with pytest.raises(OllamaConnectionError) as exc_info:
                await provider._complete_chat_completion(
                    messages=messages,
                    model="nonexistent-model",
                    temperature=0.7,
                    max_tokens=100,
                    start_time=0.0,
                )
            assert "Pull it with: ollama pull" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_streaming_parse(self, provider):
        """Test streaming response parsing."""
        import httpx

        # Mock streaming response lines
        stream_lines = [
            '{"message":{"content":"Hello"},"done":false}',
            '{"message":{"content":" world"},"done":false}',
            '{"message":{"content":"!"},"done":true,"prompt_eval_count":5,"eval_count":3,"done_reason":"stop"}',
        ]

        async def mock_aiter_lines():
            for line in stream_lines:
                yield line

        mock_response = Mock(spec=httpx.Response)
        mock_response.aiter_lines = mock_aiter_lines

        chunks = []
        async for chunk in provider._parse_stream(mock_response):
            chunks.append(chunk)

        # Should have 4 chunks: 3 content + 1 done
        assert len(chunks) == 4

        # Check content chunks
        assert chunks[0].type == StreamChunkType.CONTENT
        assert chunks[0].content == "Hello"
        assert chunks[1].type == StreamChunkType.CONTENT
        assert chunks[1].content == " world"
        assert chunks[2].type == StreamChunkType.CONTENT
        assert chunks[2].content == "!"

        # Check done chunk
        assert chunks[3].type == StreamChunkType.DONE
        assert chunks[3].metadata["prompt_tokens"] == 5
        assert chunks[3].metadata["completion_tokens"] == 3
        assert chunks[3].metadata["finish_reason"] == "stop"

    @pytest.mark.asyncio
    async def test_validate_key(self, provider):
        """Test key validation (health check for Ollama)."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"models": []}

        with patch.object(provider._client, "get", return_value=mock_response):
            is_valid = await provider.validate_key()
            assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_key_connection_error(self, provider):
        """Test key validation with connection error."""
        import httpx

        with patch.object(
            provider._client, "get", side_effect=httpx.ConnectError("Connection failed")
        ):
            is_valid = await provider.validate_key()
            assert is_valid is False


# Integration tests (require actual Ollama server running)
@pytest.mark.integration
@pytest.mark.asyncio
class TestOllamaIntegration:
    """Integration tests for Ollama provider (requires running Ollama server)."""

    @pytest.fixture
    def provider(self):
        """Create an OllamaProvider instance for integration testing."""
        return OllamaProvider(timeout=60)

    async def test_health_check_real(self, provider):
        """Test real health check against Ollama server."""
        try:
            result = await provider.health_check()
            assert isinstance(result, bool)
        except OllamaConnectionError:
            pytest.skip("Ollama server not running")

    async def test_list_models_real(self, provider):
        """Test listing real models from Ollama server."""
        try:
            models = await provider.list_models()
            assert isinstance(models, list)
            # If Ollama is running, should have at least one model
            if models:
                assert all(isinstance(m, str) for m in models)
        except OllamaConnectionError:
            pytest.skip("Ollama server not running")

    async def test_chat_completion_real(self, provider):
        """Test real chat completion against Ollama server.

        Note: This test is skipped by default because it requires:
        1. Ollama server running
        2. At least one model installed (e.g., llama3)
        """
        pytest.skip("Skipped by default - requires Ollama with model installed")

        messages = [{"role": "user", "content": "Say 'test successful' and nothing else"}]

        try:
            response = await provider.chat_completion(
                messages=messages,
                model="llama3",
                temperature=0.1,
                max_tokens=10,
                stream=False,
            )

            assert response.content is not None
            assert response.prompt_tokens > 0
            assert response.completion_tokens > 0
            assert response.provider == ProviderType.OLLAMA

        except OllamaConnectionError:
            pytest.skip("Ollama server not running or model not available")


if __name__ == "__main__":
    # Run basic unit tests
    pytest.main([__file__, "-v", "-m", "not integration"])
