"""BYOK (Bring Your Own Key) schemas for API key management.

Handles validation and serialization for user-provided API keys.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


# Supported AI providers
ProviderType = Literal["openai", "anthropic", "gemini", "deepseek", "grok"]


class BYOKKeyCreate(BaseModel):
    """Request schema for creating a new BYOK API key.

    Validates the provider and API key format before storage.
    """

    provider: ProviderType = Field(
        ...,
        description="AI provider name (openai, anthropic, gemini, deepseek, grok)",
    )
    api_key: str = Field(
        ...,
        min_length=10,
        max_length=500,
        description="API key from the provider",
    )

    @field_validator("api_key")
    @classmethod
    def validate_api_key_format(cls, v: str, info) -> str:
        """Validate API key format based on provider.

        Each provider has specific key prefixes and formats:
        - OpenAI: starts with 'sk-' or 'sk-proj-'
        - Anthropic: starts with 'sk-ant-'
        - Gemini: alphanumeric, typically 39 chars
        - DeepSeek: starts with 'sk-'
        - Grok: starts with 'xai-' or similar

        Args:
            v: API key to validate
            info: Validation context with provider information

        Returns:
            Validated API key

        Raises:
            ValueError: If API key format is invalid for the provider
        """
        provider = info.data.get("provider")
        v = v.strip()

        if not v:
            raise ValueError("API key cannot be empty")

        # Provider-specific validation
        if provider == "openai":
            if not (v.startswith("sk-") or v.startswith("sk-proj-")):
                raise ValueError("OpenAI API key must start with 'sk-' or 'sk-proj-'")
            if len(v) < 20:
                raise ValueError("OpenAI API key is too short")

        elif provider == "anthropic":
            if not v.startswith("sk-ant-"):
                raise ValueError("Anthropic API key must start with 'sk-ant-'")
            if len(v) < 20:
                raise ValueError("Anthropic API key is too short")

        elif provider == "gemini":
            # Gemini keys are typically alphanumeric, around 39 chars
            if not v.replace("-", "").replace("_", "").isalnum():
                raise ValueError("Gemini API key contains invalid characters")
            if len(v) < 20:
                raise ValueError("Gemini API key is too short")

        elif provider == "deepseek":
            if not v.startswith("sk-"):
                raise ValueError("DeepSeek API key must start with 'sk-'")
            if len(v) < 20:
                raise ValueError("DeepSeek API key is too short")

        elif provider == "grok":
            # Grok/xAI keys may start with 'xai-' or other prefixes
            if len(v) < 20:
                raise ValueError("Grok API key is too short")

        return v


class BYOKKeyResponse(BaseModel):
    """Response schema for a BYOK API key.

    Returns masked key information without exposing the full key.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="Unique key ID")
    provider: str = Field(..., description="AI provider name")
    key_masked: str = Field(..., description="Masked API key (shows only last 4 chars)")
    is_valid: bool = Field(..., description="Validation status of the key")
    last_validated_at: datetime | None = Field(
        None,
        description="Last successful validation timestamp",
    )
    last_used_at: datetime | None = Field(
        None,
        description="Last usage timestamp",
    )
    created_at: datetime = Field(..., description="Key creation timestamp")


class BYOKKeyList(BaseModel):
    """Response schema for listing user's BYOK keys."""

    keys: list[BYOKKeyResponse] = Field(
        default_factory=list,
        description="List of user's API keys",
    )
    total: int = Field(..., description="Total number of keys")


class BYOKKeyValidateResponse(BaseModel):
    """Response schema for key validation endpoint."""

    is_valid: bool = Field(..., description="Whether the key is valid")
    message: str = Field(..., description="Validation result message")
    provider: str = Field(..., description="AI provider name")
    validated_at: datetime = Field(..., description="Validation timestamp")


class BYOKKeyDeleteResponse(BaseModel):
    """Response schema for key deletion."""

    success: bool = Field(..., description="Whether deletion was successful")
    message: str = Field(..., description="Deletion result message")
