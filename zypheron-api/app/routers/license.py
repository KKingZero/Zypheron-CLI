"""License and subscription management router.

Supports:
- License validation
- Feature access per tier
- Stripe subscription refresh
- Tier information
"""

import structlog
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.models.license import License
from app.models.user import User
from app.routers.auth import CurrentUser
from app.schemas.license import (
    BillingInterval,
    CheckoutSession,
    LicenseFeatures,
    LicenseRefreshResponse,
    LicenseResponse,
    LicenseValidateResponse,
    PortalSession,
    SubscriptionCreate,
    get_tier_features,
)
from app.services.stripe_service import StripeService

settings = get_settings()
logger = structlog.get_logger()

router = APIRouter(prefix="/license", tags=["License"])


def _validate_redirect_url(url: str, field_name: str = "url") -> None:
    """Validate that a redirect URL points to an allowed domain.

    Prevents open redirect attacks via Stripe checkout/portal flows.

    Args:
        url: URL to validate
        field_name: Name of the field for error messages

    Raises:
        HTTPException: If URL domain is not in the allowlist
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {field_name}: malformed URL",
        )

    allowed = settings.allowed_redirect_domains
    is_allowed = any(
        hostname == domain or hostname.endswith(f".{domain}")
        for domain in allowed
    )

    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {field_name}: domain '{hostname}' is not allowed. "
                   f"Allowed domains: {', '.join(allowed)}",
        )


async def get_user_license(
    user_id: int,
    db: AsyncSession,
) -> License | None:
    """Get the active license for a user.

    Args:
        user_id: User ID to get license for
        db: Database session

    Returns:
        Active license or None if no license found
    """
    stmt = (
        select(License)
        .where(License.user_id == user_id)
        .order_by(License.created_at.desc())
    )
    result = await db.execute(stmt)
    license = result.scalar_one_or_none()
    return license


@router.get("/validate", response_model=LicenseValidateResponse)
async def validate_license(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> LicenseValidateResponse:
    """Validate current user's license and return tier information.

    Returns license status, validity, and available features.

    Args:
        current_user: Currently authenticated user
        db: Database session

    Returns:
        LicenseValidateResponse with validation status and features

    Raises:
        HTTPException: If no license found
    """
    # Get user's license
    license = await get_user_license(current_user.id, db)

    if not license:
        # No license found - create default free license
        license = License(
            user_id=current_user.id,
            tier="free",
            status="active",
        )
        db.add(license)
        await db.commit()
        await db.refresh(license)

    # Check if license is valid
    is_valid = license.is_valid()

    # Calculate days remaining if valid_until is set
    days_remaining = None
    if license.valid_until:
        delta = license.valid_until - datetime.now(timezone.utc)
        days_remaining = max(0, delta.days)

    # Get features for tier
    features = get_tier_features(license.tier)

    return LicenseValidateResponse(
        is_valid=is_valid,
        tier=license.tier,
        status=license.status,
        valid_until=license.valid_until,
        days_remaining=days_remaining,
        features=features,
    )


@router.get("/features", response_model=LicenseFeatures)
async def get_license_features(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> LicenseFeatures:
    """Get available features for current user's tier.

    Returns feature access flags and limits.

    Args:
        current_user: Currently authenticated user
        db: Database session

    Returns:
        LicenseFeatures with tier configuration
    """
    # Get user's license or default to free tier
    license = await get_user_license(current_user.id, db)
    tier = license.tier if license else "free"

    return get_tier_features(tier)


@router.get("", response_model=LicenseResponse)
async def get_license(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> LicenseResponse:
    """Get current user's license information.

    Returns full license details including Stripe IDs.

    Args:
        current_user: Currently authenticated user
        db: Database session

    Returns:
        LicenseResponse with license details

    Raises:
        HTTPException: If no license found
    """
    license = await get_user_license(current_user.id, db)

    if not license:
        # Create default free license
        license = License(
            user_id=current_user.id,
            tier="free",
            status="active",
        )
        db.add(license)
        await db.commit()
        await db.refresh(license)

    return LicenseResponse.model_validate(license)


@router.post("/refresh", response_model=LicenseRefreshResponse)
async def refresh_license(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> LicenseRefreshResponse:
    """Refresh license data from Stripe subscription.

    Syncs local license status with Stripe subscription status.
    Used to handle subscription changes, cancellations, etc.

    Args:
        current_user: Currently authenticated user
        db: Database session

    Returns:
        LicenseRefreshResponse with refresh status and updated license

    Raises:
        HTTPException: If Stripe refresh fails or is not configured
    """
    # Get user's license
    license = await get_user_license(current_user.id, db)

    if not license:
        return LicenseRefreshResponse(
            success=False,
            license=None,
            message="No license found for user",
        )

    # If no Stripe subscription, return current license
    if not license.stripe_subscription_id:
        return LicenseRefreshResponse(
            success=True,
            license=LicenseResponse.model_validate(license),
            message="Free tier license (no Stripe subscription)",
        )

    # Check if Stripe is configured
    if not settings.stripe_secret_key:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Stripe integration not configured. Add STRIPE_SECRET_KEY to environment.",
        )

    # Refresh from Stripe
    try:
        stripe_service = StripeService(db)
        updated_license = await stripe_service.refresh_subscription(license)

        return LicenseRefreshResponse(
            success=True,
            license=LicenseResponse.model_validate(updated_license),
            message="License refreshed successfully from Stripe",
        )

    except ValueError as e:
        logger.error(f"Validation error refreshing license: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Error refreshing license: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh license. Please try again later.",
        )


@router.get("/tiers", response_model=dict[str, LicenseFeatures])
async def get_all_tiers() -> dict[str, LicenseFeatures]:
    """Get feature comparison for all subscription tiers.

    Returns all tier configurations for pricing page display.

    Returns:
        Dictionary mapping tier names to their feature sets
    """
    return {
        "free": get_tier_features("free"),
        "starter": get_tier_features("starter"),
        "pro": get_tier_features("pro"),
        "enterprise": get_tier_features("enterprise"),
    }


@router.post("/upgrade/{tier}", response_model=dict)
async def initiate_upgrade(
    tier: str,
    current_user: CurrentUser,
    success_url: str,
    cancel_url: str,
    billing_interval: str = "monthly",
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Initiate subscription upgrade to a paid tier.

    Creates Stripe checkout session and returns checkout URL.

    Args:
        tier: Target tier (starter, pro, enterprise)
        current_user: Currently authenticated user
        success_url: URL to redirect after successful checkout
        cancel_url: URL to redirect if checkout is cancelled
        billing_interval: "monthly" or "annual"
        db: Database session

    Returns:
        Dictionary with checkout_url for Stripe Checkout

    Raises:
        HTTPException: If tier invalid or Stripe not configured
    """
    # Validate redirect URLs (prevent open redirect)
    _validate_redirect_url(success_url, "success_url")
    _validate_redirect_url(cancel_url, "cancel_url")

    # Validate tier
    valid_paid_tiers = ["starter", "pro", "enterprise"]
    if tier not in valid_paid_tiers:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid tier. Must be one of: {', '.join(valid_paid_tiers)}",
        )

    # Validate billing interval
    if billing_interval not in ("monthly", "annual"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid billing_interval. Must be 'monthly' or 'annual'.",
        )

    # Check if Stripe is configured
    if not settings.stripe_secret_key:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Stripe checkout not configured. Add STRIPE_SECRET_KEY and price IDs to environment.",
        )

    # Get user from database to pass full model
    stmt = select(User).where(User.id == current_user.id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Create checkout session
    try:
        stripe_service = StripeService(db)
        checkout_url, session_id = await stripe_service.create_checkout_session(
            user=user,
            tier=tier,  # type: ignore
            success_url=success_url,
            cancel_url=cancel_url,
            billing_interval=billing_interval,
        )

        return {
            "checkout_url": checkout_url,
            "session_id": session_id,
            "tier": tier,
            "billing_interval": billing_interval,
            "message": f"Checkout session created for {tier} tier ({billing_interval})",
        }

    except ValueError as e:
        logger.error(f"Validation error creating checkout: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Error creating checkout session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create checkout session. Please try again later.",
        )


@router.post("/portal", response_model=PortalSession)
async def create_portal_session(
    return_url: str,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> PortalSession:
    """Create a Stripe billing portal session.

    Allows users to manage subscription, update payment method, etc.

    Args:
        return_url: URL to redirect after portal session
        current_user: Currently authenticated user
        db: Database session

    Returns:
        PortalSession with portal URL

    Raises:
        HTTPException: If no billing account or Stripe not configured
    """
    # Validate redirect URL (prevent open redirect)
    _validate_redirect_url(return_url, "return_url")

    if not settings.stripe_secret_key:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Stripe not configured.",
        )

    # Get user's license to find customer ID
    license = await get_user_license(current_user.id, db)
    if not license or not license.stripe_customer_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No billing account found. Subscribe to a plan first.",
        )

    try:
        stripe_service = StripeService(db)
        portal_url = await stripe_service.create_portal_session(
            customer_id=license.stripe_customer_id,
            return_url=return_url,
        )
        return PortalSession(portal_url=portal_url)
    except Exception as e:
        logger.error(f"Error creating portal session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create portal session. Please try again later.",
        )


@router.post("/reactivate", response_model=LicenseRefreshResponse)
async def reactivate_subscription(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> LicenseRefreshResponse:
    """Reactivate a cancelled subscription.

    Only works if subscription is scheduled for cancellation at period end.

    Args:
        current_user: Currently authenticated user
        db: Database session

    Returns:
        LicenseRefreshResponse with reactivation status

    Raises:
        HTTPException: If no subscription or not cancelled
    """
    if not settings.stripe_secret_key:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Stripe not configured.",
        )

    license = await get_user_license(current_user.id, db)
    if not license or not license.stripe_subscription_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active subscription found.",
        )

    if not license.cancel_at_period_end:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Subscription is not scheduled for cancellation.",
        )

    try:
        stripe_service = StripeService(db)
        updated_license = await stripe_service.reactivate_subscription(license)
        return LicenseRefreshResponse(
            success=True,
            license=LicenseResponse.model_validate(updated_license),
            message="Subscription reactivated successfully",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Error reactivating subscription: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reactivate subscription. Please try again later.",
        )


@router.get("/prices")
async def get_prices() -> dict:
    """Get current pricing information for all tiers.

    Returns:
        Dictionary with currency and tier pricing info
    """
    return {
        "currency": "usd",
        "tiers": {
            "free": {
                "monthly": 0,
                "annual": 0,
                "tokens": settings.token_limit_free,
                "devices": 1,
                "features": ["Scanning", "Recon", "OSINT", "BYOK AI"],
            },
            "starter": {
                "monthly": settings.price_starter_monthly / 100,
                "annual": settings.price_starter_annual / 100,
                "annual_savings": "25%",
                "tokens": settings.token_limit_starter,
                "devices": 2,
                "features": ["Everything in Free", "Cloud AI", "Exploitation", "PDF Reports"],
            },
            "pro": {
                "monthly": settings.price_pro_monthly / 100,
                "annual": settings.price_pro_annual / 100,
                "annual_savings": "25%",
                "tokens": settings.token_limit_pro,
                "devices": 3,
                "features": ["Everything in Starter", "Priority support", "3M tokens"],
            },
            "enterprise": {
                "monthly": settings.price_enterprise_monthly / 100,
                "annual": settings.price_enterprise_annual / 100,
                "annual_savings": "25%",
                "per_user": True,
                "min_seats": settings.enterprise_min_seats,
                "tokens": settings.token_limit_enterprise,
                "devices": 500,
                "features": [
                    "Everything in Pro",
                    "Team management",
                    "Compliance reports",
                    "SSO",
                    "Custom integrations",
                ],
            },
        },
    }


@router.post("/cancel", response_model=LicenseRefreshResponse)
async def cancel_subscription(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
    cancel_immediately: bool = False,
) -> LicenseRefreshResponse:
    """Cancel current subscription.

    By default, cancels at period end (user keeps access until renewal date).
    Set cancel_immediately=True to cancel access immediately with prorated refund.

    Args:
        current_user: Currently authenticated user
        db: Database session
        cancel_immediately: Whether to cancel immediately vs at period end

    Returns:
        LicenseRefreshResponse with cancellation status

    Raises:
        HTTPException: If no active subscription or Stripe error
    """
    license = await get_user_license(current_user.id, db)

    if not license or not license.stripe_subscription_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active subscription to cancel",
        )

    # Check if Stripe is configured
    if not settings.stripe_secret_key:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Stripe cancellation not configured. Add STRIPE_SECRET_KEY to environment.",
        )

    # Cancel subscription
    try:
        stripe_service = StripeService(db)
        updated_license = await stripe_service.cancel_subscription(
            license=license,
            immediately=cancel_immediately,
        )

        cancellation_type = "immediately" if cancel_immediately else "at period end"
        message = f"Subscription cancelled {cancellation_type}"

        return LicenseRefreshResponse(
            success=True,
            license=LicenseResponse.model_validate(updated_license),
            message=message,
        )

    except ValueError as e:
        logger.error(f"Validation error cancelling subscription: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Error cancelling subscription: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel subscription. Please try again later.",
        )
