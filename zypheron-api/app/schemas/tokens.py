"""Token usage tracking schemas for quota monitoring and analytics.

Provides response models for token usage endpoints.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class TokenUsageResponse(BaseModel):
    """Token usage record response."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    tokens_used: int
    provider: Literal["openai", "anthropic", "grok", "deepseek"]
    model: str
    prompt_hash: str | None
    endpoint: str | None
    created_at: datetime


class UsageSummaryResponse(BaseModel):
    """Summary of token usage for a time period."""

    total_tokens: int = Field(..., description="Total tokens used in period")
    period: Literal["day", "week", "month", "all"] = Field(
        ...,
        description="Time period for the summary",
    )
    by_provider: dict[str, int] = Field(
        ...,
        description="Token usage breakdown by provider",
    )


class QuotaInfoResponse(BaseModel):
    """Comprehensive quota information for a user."""

    tier: Literal["free", "starter", "pro", "enterprise", "unknown"]
    tokens_used: int = Field(..., description="Tokens used in current period")
    token_limit: int = Field(..., description="Token limit for current tier")
    tokens_remaining: int = Field(..., description="Remaining tokens in period")
    percentage_used: float = Field(..., description="Percentage of quota used")
    period_start: str | None = Field(..., description="Billing period start (ISO format)")
    period_end: str | None = Field(..., description="Billing period end (ISO format)")
    byok_enabled: bool = Field(..., description="Whether BYOK is enabled")


class UsageHistoryResponse(BaseModel):
    """Paginated token usage history."""

    items: list[TokenUsageResponse] = Field(..., description="Usage records")
    total: int = Field(..., description="Total number of records")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Number of items per page")
    total_pages: int = Field(..., description="Total number of pages")


class RemainingTokensResponse(BaseModel):
    """Remaining token quota information."""

    tokens_remaining: int = Field(..., description="Tokens remaining in current period")
    token_limit: int = Field(..., description="Token limit for current tier")
    tier: str = Field(..., description="User's subscription tier")
    byok_enabled: bool = Field(..., description="Whether BYOK is enabled")


class UsageBreakdownResponse(BaseModel):
    """Token usage breakdown by provider and model."""

    by_provider: dict[str, dict[str, int]] = Field(
        ...,
        description="Nested dict of provider -> model -> token count",
    )
    total_tokens: int = Field(..., description="Total tokens used in period")
    period_start: str = Field(..., description="Billing period start (ISO format)")
    period_end: str = Field(..., description="Billing period end (ISO format)")


class MonthlyHistoryResponse(BaseModel):
    """Monthly token usage history."""

    month: str | None = Field(..., description="Month timestamp (ISO format)")
    total_tokens: int = Field(..., description="Total tokens used in month")
    request_count: int = Field(..., description="Number of AI requests made")
