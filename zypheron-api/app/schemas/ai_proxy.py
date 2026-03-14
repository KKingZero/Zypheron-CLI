"""Pydantic schemas for AI proxy endpoints."""

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class ChatMessage(BaseModel):
    """Single chat message."""

    role: Literal["system", "user", "assistant"] = Field(
        description="Role of the message sender"
    )
    content: str = Field(
        min_length=1,
        max_length=100000,  # 100k character limit
        description="Content of the message",
    )

    @field_validator("content")
    @classmethod
    def validate_content(cls, v: str) -> str:
        """Validate and sanitize content."""
        # Strip leading/trailing whitespace
        v = v.strip()
        if not v:
            raise ValueError("Content cannot be empty after stripping whitespace")
        return v


class ChatCompletionRequest(BaseModel):
    """Request for chat completion."""

    messages: list[ChatMessage] = Field(
        min_length=1,
        max_length=100,  # Reasonable conversation length
        description="List of messages in the conversation",
    )
    provider: Literal["openai", "anthropic", "grok", "deepseek", "ollama"] | None = Field(
        default=None,
        description="AI provider to use (auto-select if not specified)",
    )
    model: str | None = Field(
        default=None,
        max_length=100,
        description="Model to use (provider default if not specified)",
    )
    temperature: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Sampling temperature (0.0 to 1.0)",
    )
    max_tokens: int | None = Field(
        default=None,
        gt=0,
        le=32000,  # Reasonable upper limit
        description="Maximum tokens to generate",
    )
    stream: bool = Field(
        default=False,
        description="Enable streaming response",
    )
    user_api_key: str | None = Field(
        default=None,
        max_length=500,
        description="User's own API key (BYOK)",
    )

    @field_validator("user_api_key")
    @classmethod
    def validate_user_api_key(cls, v: str | None) -> str | None:
        """Validate and sanitize user API key."""
        if v is not None:
            v = v.strip()
            if not v:
                return None
        return v


class TokenUsage(BaseModel):
    """Token usage information."""

    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)


class ChatCompletionResponse(BaseModel):
    """Response for chat completion."""

    provider: str = Field(description="AI provider that handled the request")
    model: str = Field(description="Model that generated the response")
    content: str = Field(description="Generated content")
    usage: TokenUsage = Field(description="Token usage information")
    latency_ms: int = Field(ge=0, description="Request latency in milliseconds")
    cached: bool = Field(default=False, description="Whether response was cached")
    finish_reason: str | None = Field(
        default=None,
        description="Reason for completion finish",
    )
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Additional provider-specific metadata",
    )


class StreamChunkResponse(BaseModel):
    """Single chunk in streaming response."""

    type: Literal["content", "metadata", "error", "done"] = Field(
        description="Type of chunk"
    )
    content: str | None = Field(
        default=None,
        description="Content delta (for content chunks)",
    )
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Metadata (for metadata/done chunks)",
    )
    error: str | None = Field(
        default=None,
        description="Error message (for error chunks)",
    )


class ProviderInfo(BaseModel):
    """Information about an AI provider."""

    name: str = Field(description="Provider name")
    available: bool = Field(description="Whether provider is available")
    models: list[str] = Field(description="Available models for this provider")
    supports_streaming: bool = Field(
        default=True,
        description="Whether provider supports streaming",
    )


class AvailableProvidersResponse(BaseModel):
    """Response listing available providers."""

    providers: list[ProviderInfo] = Field(
        description="List of available providers"
    )
    total_count: int = Field(ge=0, description="Total number of available providers")


class ValidateKeyRequest(BaseModel):
    """Request to validate a user's API key."""

    provider: Literal["openai", "anthropic", "grok", "deepseek", "ollama"] = Field(
        description="AI provider to validate key for"
    )
    api_key: str = Field(
        min_length=1,
        max_length=500,
        description="API key to validate",
    )

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v: str) -> str:
        """Validate and sanitize API key."""
        v = v.strip()
        if not v:
            raise ValueError("API key cannot be empty after stripping whitespace")
        return v


class ValidateKeyResponse(BaseModel):
    """Response for key validation."""

    provider: str = Field(description="Provider that was validated")
    valid: bool = Field(description="Whether the key is valid")
    message: str = Field(description="Validation result message")


class ErrorResponse(BaseModel):
    """Error response format."""

    error: str = Field(description="Error type")
    message: str = Field(description="Error message")
    provider: str | None = Field(
        default=None,
        description="Provider that caused the error (if applicable)",
    )
    retryable: bool = Field(
        default=False,
        description="Whether the error is retryable",
    )
