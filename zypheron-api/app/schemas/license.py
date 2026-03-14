"""License and subscription schemas for tier management.

Defines feature access per tier and license validation responses.
"""

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class BillingInterval(str, Enum):
    """Billing interval options."""
    MONTHLY = "monthly"
    ANNUAL = "annual"


class LicenseResponse(BaseModel):
    """License information response."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    tier: Literal["free", "starter", "pro", "enterprise"]
    status: str = Field(..., description="Subscription status (active, canceled, etc.)")
    stripe_customer_id: str | None = None
    stripe_subscription_id: str | None = None
    valid_from: datetime
    valid_until: datetime | None = None
    cancel_at_period_end: bool = False
    created_at: datetime
    updated_at: datetime


class LicenseValidateResponse(BaseModel):
    """License validation response.

    Returns whether license is valid and tier information.
    """

    is_valid: bool = Field(..., description="Whether license is currently valid")
    tier: Literal["free", "starter", "pro", "enterprise"]
    status: str = Field(..., description="Subscription status")
    valid_until: datetime | None = Field(None, description="License expiration date")
    days_remaining: int | None = Field(None, description="Days until expiration")
    features: "LicenseFeatures" = Field(..., description="Available features for tier")


class LicenseFeatures(BaseModel):
    """Feature access per subscription tier.

    Defines what features are available for each tier.
    """

    tier: Literal["free", "starter", "pro", "enterprise"]

    # Token limits (monthly)
    token_limit: int = Field(..., description="Monthly token limit")
    tokens_included: bool = Field(
        ...,
        description="Whether API keys are provided (or BYOK required)",
    )

    # Rate limiting
    rate_limit: int = Field(..., description="Requests per minute")

    # Device limits
    max_devices: int = Field(..., description="Maximum number of registered devices")

    # AI providers
    available_providers: list[str] = Field(
        ...,
        description="Available AI providers (openai, anthropic, grok, deepseek)",
    )

    # Features
    features: dict[str, bool] = Field(
        ...,
        description="Feature flags (caching, priority_support, etc.)",
    )

    # Cache settings
    cache_enabled: bool = Field(..., description="Whether prompt caching is enabled")
    cache_ttl_minutes: int = Field(..., description="Cache TTL in minutes")


class LicenseRefreshResponse(BaseModel):
    """Response from license refresh operation.

    Used to sync license data from Stripe.
    """

    success: bool = Field(..., description="Whether refresh was successful")
    license: LicenseResponse | None = Field(None, description="Updated license data")
    message: str = Field(..., description="Status message")


# Tier configuration helper
def get_tier_features(tier: str) -> LicenseFeatures:
    """Get feature set for a subscription tier.

    Args:
        tier: Subscription tier name

    Returns:
        LicenseFeatures object with tier configuration
    """
    tier_configs = {
        "free": LicenseFeatures(
            tier="free",
            token_limit=0,
            tokens_included=False,
            rate_limit=10,
            max_devices=1,
            available_providers=["openai", "anthropic", "grok", "deepseek"],
            features={
                "byok_required": True,
                "caching": False,
                "priority_support": False,
                "advanced_scanning": False,
                "websocket_streaming": True,
            },
            cache_enabled=False,
            cache_ttl_minutes=0,
        ),
        "starter": LicenseFeatures(
            tier="starter",
            token_limit=1_000_000,
            tokens_included=True,
            rate_limit=60,
            max_devices=2,
            available_providers=["openai", "anthropic", "grok", "deepseek"],
            features={
                "byok_required": False,
                "caching": True,
                "priority_support": False,
                "advanced_scanning": True,
                "websocket_streaming": True,
            },
            cache_enabled=True,
            cache_ttl_minutes=15,
        ),
        "pro": LicenseFeatures(
            tier="pro",
            token_limit=3_000_000,
            tokens_included=True,
            rate_limit=120,
            max_devices=3,
            available_providers=["openai", "anthropic", "grok", "deepseek"],
            features={
                "byok_required": False,
                "caching": True,
                "priority_support": True,
                "advanced_scanning": True,
                "websocket_streaming": True,
            },
            cache_enabled=True,
            cache_ttl_minutes=15,
        ),
        "enterprise": LicenseFeatures(
            tier="enterprise",
            token_limit=15_000_000,  # Per 5 users
            tokens_included=True,
            rate_limit=300,
            max_devices=500,
            available_providers=["openai", "anthropic", "grok", "deepseek"],
            features={
                "byok_required": False,
                "caching": True,
                "priority_support": True,
                "advanced_scanning": True,
                "websocket_streaming": True,
                "custom_integrations": True,
                "sso": True,
            },
            cache_enabled=True,
            cache_ttl_minutes=60,
        ),
    }

    return tier_configs.get(tier, tier_configs["free"])


class CheckoutSession(BaseModel):
    """Stripe checkout session response."""
    checkout_url: str
    session_id: str


class PortalSession(BaseModel):
    """Stripe customer portal session."""
    portal_url: str


class SubscriptionCreate(BaseModel):
    """Schema for creating a new subscription."""
    tier: Literal["starter", "pro", "enterprise"]
    billing_interval: BillingInterval = BillingInterval.MONTHLY
    success_url: str
    cancel_url: str
