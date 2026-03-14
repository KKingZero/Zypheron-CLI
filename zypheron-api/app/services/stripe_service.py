"""Stripe integration service for subscription and billing management.

Handles:
- Customer creation and retrieval
- Checkout session creation
- Subscription lifecycle management
- Webhook event processing
- Payment grace period handling
"""

import structlog
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import stripe
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.license import License
from app.models.token_usage import UserQuota
from app.models.user import User
from app.services.token_tracking import TokenTrackingService

settings = get_settings()
logger = structlog.get_logger()

# Initialize Stripe API key
if settings.stripe_secret_key:
    stripe.api_key = settings.stripe_secret_key

# Price ID to tier mapping (supports both monthly and annual)
PRICE_TO_TIER: dict[str, Literal["starter", "pro", "enterprise"]] = {}
for _price_id, _tier in [
    (settings.stripe_price_id_starter_monthly, "starter"),
    (settings.stripe_price_id_starter_annual, "starter"),
    (settings.stripe_price_id_pro_monthly, "pro"),
    (settings.stripe_price_id_pro_annual, "pro"),
    (settings.stripe_price_id_enterprise_monthly, "enterprise"),
    (settings.stripe_price_id_enterprise_annual, "enterprise"),
]:
    if _price_id:
        PRICE_TO_TIER[_price_id] = _tier

# Price ID to billing interval mapping
PRICE_TO_INTERVAL: dict[str, str] = {}
for _price_id, _interval in [
    (settings.stripe_price_id_starter_monthly, "monthly"),
    (settings.stripe_price_id_starter_annual, "annual"),
    (settings.stripe_price_id_pro_monthly, "monthly"),
    (settings.stripe_price_id_pro_annual, "annual"),
    (settings.stripe_price_id_enterprise_monthly, "monthly"),
    (settings.stripe_price_id_enterprise_annual, "annual"),
]:
    if _price_id:
        PRICE_TO_INTERVAL[_price_id] = _interval

# Tier + interval to price ID mapping
TIER_INTERVAL_TO_PRICE: dict[tuple[str, str], str | None] = {
    ("starter", "monthly"): settings.stripe_price_id_starter_monthly,
    ("starter", "annual"): settings.stripe_price_id_starter_annual,
    ("pro", "monthly"): settings.stripe_price_id_pro_monthly,
    ("pro", "annual"): settings.stripe_price_id_pro_annual,
    ("enterprise", "monthly"): settings.stripe_price_id_enterprise_monthly,
    ("enterprise", "annual"): settings.stripe_price_id_enterprise_annual,
}

# Legacy flat mapping (defaults to monthly)
TIER_TO_PRICE: dict[str, str | None] = {
    "starter": settings.stripe_price_id_starter_monthly,
    "pro": settings.stripe_price_id_pro_monthly,
    "enterprise": settings.stripe_price_id_enterprise_monthly,
}


class StripeService:
    """Service for Stripe payment and subscription management.

    Handles all Stripe-related operations including customer management,
    checkout sessions, subscriptions, and webhook event processing.
    """

    def __init__(self, db: AsyncSession):
        """Initialize the Stripe service.

        Args:
            db: Async database session for persistence

        Raises:
            RuntimeError: If Stripe is not configured
        """
        self.db = db

        if not settings.stripe_secret_key:
            raise RuntimeError(
                "Stripe is not configured. Set STRIPE_SECRET_KEY environment variable."
            )

    async def get_or_create_customer(self, user: User) -> str:
        """Get or create a Stripe customer for a user.

        Creates a new customer if one doesn't exist, otherwise returns existing.

        Args:
            user: User model instance

        Returns:
            Stripe customer ID

        Raises:
            stripe.error.StripeError: If Stripe API call fails
        """
        # Get user's license
        stmt = select(License).where(License.user_id == user.id).order_by(License.created_at.desc())
        result = await self.db.execute(stmt)
        license = result.scalar_one_or_none()

        # Return existing customer if available
        if license and license.stripe_customer_id:
            logger.info(f"Using existing Stripe customer: {license.stripe_customer_id}")
            return license.stripe_customer_id

        # Create new Stripe customer
        try:
            customer = stripe.Customer.create(
                email=user.email,
                metadata={
                    "user_id": str(user.id),
                    "environment": settings.environment,
                },
            )

            logger.info(f"Created Stripe customer: {customer.id} for user {user.id}")

            # Update or create license with customer ID
            if license:
                license.stripe_customer_id = customer.id
            else:
                license = License(
                    user_id=user.id,
                    tier="free",
                    status="active",
                    stripe_customer_id=customer.id,
                )
                self.db.add(license)

            await self.db.commit()
            return customer.id

        except stripe.error.StripeError as e:
            logger.error(f"Failed to create Stripe customer: {e}")
            raise

    async def create_checkout_session(
        self,
        user: User,
        tier: Literal["starter", "pro", "enterprise"],
        success_url: str,
        cancel_url: str,
        billing_interval: str = "monthly",
    ) -> tuple[str, str]:
        """Create a Stripe Checkout session for subscription upgrade.

        Args:
            user: User model instance
            tier: Target subscription tier
            success_url: URL to redirect after successful checkout
            cancel_url: URL to redirect if checkout is cancelled
            billing_interval: "monthly" or "annual"

        Returns:
            Tuple of (checkout_url, session_id)

        Raises:
            ValueError: If tier is invalid or price ID not configured
            stripe.error.StripeError: If Stripe API call fails
        """
        # Get price ID for tier + interval
        price_id = TIER_INTERVAL_TO_PRICE.get((tier, billing_interval))
        if not price_id:
            # Fallback to monthly
            price_id = TIER_TO_PRICE.get(tier)
        if not price_id:
            raise ValueError(
                f"Price ID not configured for tier '{tier}' ({billing_interval}). "
                f"Set STRIPE_PRICE_ID_{tier.upper()}_{billing_interval.upper()} environment variable."
            )

        # Get or create customer
        customer_id = await self.get_or_create_customer(user)

        # Create checkout session
        try:
            checkout_kwargs: dict[str, Any] = {
                "customer": customer_id,
                "mode": "subscription",
                "payment_method_types": ["card"],
                "line_items": [
                    {
                        "price": price_id,
                        "quantity": 1,
                    }
                ],
                "success_url": success_url,
                "cancel_url": cancel_url,
                "metadata": {
                    "user_id": str(user.id),
                    "tier": tier,
                    "billing_interval": billing_interval,
                    "environment": settings.environment,
                },
                "subscription_data": {
                    "metadata": {
                        "user_id": str(user.id),
                        "tier": tier,
                        "billing_interval": billing_interval,
                    },
                },
            }

            # Apply annual discount coupon
            if billing_interval == "annual":
                checkout_kwargs["discounts"] = [{"coupon": "ANNUAL25"}]

            checkout_session = stripe.checkout.Session.create(**checkout_kwargs)

            logger.info(
                f"Created checkout session {checkout_session.id} for user {user.id}, "
                f"tier {tier}, interval {billing_interval}"
            )

            return checkout_session.url, checkout_session.id

        except stripe.error.StripeError as e:
            logger.error(f"Failed to create checkout session: {e}")
            raise

    async def create_portal_session(
        self,
        customer_id: str,
        return_url: str,
    ) -> str:
        """Create a Stripe billing portal session.

        Args:
            customer_id: Stripe customer ID
            return_url: URL to redirect after portal session

        Returns:
            Portal session URL

        Raises:
            stripe.error.StripeError: If Stripe API call fails
        """
        try:
            session = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=return_url,
            )
            logger.info(f"Created portal session for customer {customer_id}")
            return session.url
        except stripe.error.StripeError as e:
            logger.error(f"Failed to create portal session: {e}")
            raise

    async def reactivate_subscription(self, license: "License") -> "License":
        """Reactivate a cancelled subscription (undo cancel_at_period_end).

        Args:
            license: License model instance

        Returns:
            Updated license model

        Raises:
            ValueError: If no subscription or not cancelled
            stripe.error.StripeError: If Stripe API call fails
        """
        if not license.stripe_subscription_id:
            raise ValueError("No active subscription to reactivate")

        if not license.cancel_at_period_end:
            raise ValueError("Subscription is not scheduled for cancellation")

        try:
            stripe.Subscription.modify(
                license.stripe_subscription_id,
                cancel_at_period_end=False,
            )
            license.cancel_at_period_end = False

            await self.db.commit()
            logger.info(f"Reactivated subscription {license.stripe_subscription_id}")
            return license
        except stripe.error.StripeError as e:
            logger.error(f"Failed to reactivate subscription: {e}")
            raise

    async def cancel_subscription(
        self,
        license: License,
        immediately: bool = False,
    ) -> License:
        """Cancel a subscription.

        Args:
            license: License model instance
            immediately: If True, cancel immediately with prorated refund.
                        If False, cancel at period end (default).

        Returns:
            Updated license model

        Raises:
            ValueError: If no active subscription found
            stripe.error.StripeError: If Stripe API call fails
        """
        if not license.stripe_subscription_id:
            raise ValueError("No active subscription to cancel")

        try:
            if immediately:
                # Cancel immediately with prorated refund
                stripe.Subscription.cancel(
                    license.stripe_subscription_id,
                    proration_behavior="create_prorations",
                )
                license.status = "canceled"
                license.valid_until = datetime.now(timezone.utc)
                license.cancel_at_period_end = False

                logger.info(
                    f"Immediately canceled subscription {license.stripe_subscription_id}"
                )
            else:
                # Cancel at period end
                subscription = stripe.Subscription.modify(
                    license.stripe_subscription_id,
                    cancel_at_period_end=True,
                )
                license.cancel_at_period_end = True
                license.valid_until = datetime.fromtimestamp(
                    subscription.current_period_end, tz=timezone.utc
                )

                logger.info(
                    f"Scheduled cancellation for subscription {license.stripe_subscription_id} "
                    f"at {license.valid_until}"
                )

            await self.db.commit()
            return license

        except stripe.error.StripeError as e:
            logger.error(f"Failed to cancel subscription: {e}")
            raise

    async def refresh_subscription(self, license: License) -> License:
        """Refresh license data from Stripe subscription.

        Syncs local license with current Stripe subscription status.

        Args:
            license: License model instance

        Returns:
            Updated license model

        Raises:
            ValueError: If no subscription ID found
            stripe.error.StripeError: If Stripe API call fails
        """
        if not license.stripe_subscription_id:
            raise ValueError("No subscription ID to refresh")

        try:
            subscription = stripe.Subscription.retrieve(license.stripe_subscription_id)

            # Update license from subscription data
            license.status = subscription.status
            license.cancel_at_period_end = subscription.cancel_at_period_end

            # Update tier from price ID
            if subscription.items and subscription.items.data:
                price_id = subscription.items.data[0].price.id
                tier = PRICE_TO_TIER.get(price_id, license.tier)
                license.tier = tier
                license.stripe_price_id = price_id

            # Update validity period
            if subscription.current_period_end:
                license.valid_until = datetime.fromtimestamp(
                    subscription.current_period_end, tz=timezone.utc
                )

            logger.info(f"Refreshed subscription {license.stripe_subscription_id}")

            await self.db.commit()
            return license

        except stripe.error.StripeError as e:
            logger.error(f"Failed to refresh subscription: {e}")
            raise

    # Webhook Handlers

    async def handle_subscription_created(self, subscription: dict[str, Any]) -> None:
        """Handle subscription.created webhook event.

        Creates or updates license when subscription is created.

        Args:
            subscription: Stripe subscription object
        """
        try:
            metadata = subscription.get("metadata", {})
            user_id_str = metadata.get("user_id")
            if not user_id_str:
                logger.error(
                    f"No user_id in subscription metadata for {subscription.get('id')}. "
                    "Cannot process subscription.created webhook."
                )
                return
            user_id = int(user_id_str)
            tier = metadata.get("tier", "free")

            # Get user
            stmt = select(User).where(User.id == user_id)
            result = await self.db.execute(stmt)
            user = result.scalar_one_or_none()

            if not user:
                logger.error(f"User {user_id} not found for subscription {subscription['id']}")
                return

            # Get or create license
            license_stmt = select(License).where(License.user_id == user_id).order_by(
                License.created_at.desc()
            )
            license_result = await self.db.execute(license_stmt)
            license = license_result.scalar_one_or_none()

            # Extract price ID
            price_id = None
            if subscription.get("items") and subscription["items"].get("data"):
                price_id = subscription["items"]["data"][0]["price"]["id"]
                # Determine tier from price ID if not in metadata
                tier = PRICE_TO_TIER.get(price_id, tier)

            # Determine billing interval from price ID
            billing_interval = PRICE_TO_INTERVAL.get(price_id, "monthly") if price_id else "monthly"
            # Also check metadata for billing_interval
            if subscription.get("metadata", {}).get("billing_interval"):
                billing_interval = subscription["metadata"]["billing_interval"]

            if license:
                license.stripe_subscription_id = subscription["id"]
                license.stripe_customer_id = subscription["customer"]
                license.stripe_price_id = price_id
                license.tier = tier
                license.status = subscription["status"]
                license.cancel_at_period_end = subscription.get("cancel_at_period_end", False)
                license.billing_interval = billing_interval
            else:
                license = License(
                    user_id=user_id,
                    stripe_subscription_id=subscription["id"],
                    stripe_customer_id=subscription["customer"],
                    stripe_price_id=price_id,
                    tier=tier,
                    status=subscription["status"],
                    cancel_at_period_end=subscription.get("cancel_at_period_end", False),
                    billing_interval=billing_interval,
                )
                self.db.add(license)

            # Update user tier
            user.tier = tier

            # Update validity period
            if subscription.get("current_period_end"):
                license.valid_until = datetime.fromtimestamp(
                    subscription["current_period_end"], tz=timezone.utc
                )

            await self.db.commit()
            logger.info(
                f"Created/updated subscription {subscription['id']} for user {user_id}, tier {tier}"
            )

        except Exception as e:
            logger.error(f"Error handling subscription.created: {e}")
            await self.db.rollback()
            raise

    async def handle_subscription_updated(self, subscription: dict[str, Any]) -> None:
        """Handle subscription.updated webhook event.

        Updates license when subscription changes (renewal, upgrade, downgrade).
        Resets token usage on renewal.

        Args:
            subscription: Stripe subscription object
        """
        try:
            # Find license by subscription ID
            stmt = select(License).where(
                License.stripe_subscription_id == subscription["id"]
            )
            result = await self.db.execute(stmt)
            license = result.scalar_one_or_none()

            if not license:
                logger.warning(
                    f"License not found for subscription {subscription['id']}, creating..."
                )
                # Fallback: treat as created event
                await self.handle_subscription_created(subscription)
                return

            # Get old period end for renewal detection
            old_period_end = license.valid_until

            # Update license status
            old_status = license.status
            license.status = subscription["status"]
            license.cancel_at_period_end = subscription.get("cancel_at_period_end", False)

            # Update tier from price ID
            if subscription.get("items") and subscription["items"].get("data"):
                price_id = subscription["items"]["data"][0]["price"]["id"]
                old_tier = license.tier
                license.tier = PRICE_TO_TIER.get(price_id, license.tier)
                license.stripe_price_id = price_id

                # Log tier changes
                if old_tier != license.tier:
                    logger.info(
                        f"Tier changed for user {license.user_id}: {old_tier} -> {license.tier}"
                    )

            # Update validity period
            new_period_end = None
            if subscription.get("current_period_end"):
                new_period_end = datetime.fromtimestamp(
                    subscription["current_period_end"], tz=timezone.utc
                )
                license.valid_until = new_period_end

            # Detect renewal (period end has advanced)
            is_renewal = (
                old_period_end
                and new_period_end
                and new_period_end > old_period_end
                and subscription["status"] == "active"
            )

            if is_renewal:
                logger.info(f"Subscription renewed for user {license.user_id}")
                # Reset token usage for new billing period
                token_service = TokenTrackingService(self.db)
                await token_service.reset_period_usage(license.user_id)

            # Update user tier
            user_stmt = select(User).where(User.id == license.user_id)
            user_result = await self.db.execute(user_stmt)
            user = user_result.scalar_one_or_none()
            if user:
                user.tier = license.tier

            # Clear past_due status if subscription is now active
            if old_status == "past_due" and subscription["status"] == "active":
                logger.info(f"Cleared past_due status for user {license.user_id}")

            await self.db.commit()
            logger.info(f"Updated subscription {subscription['id']}")

        except Exception as e:
            logger.error(f"Error handling subscription.updated: {e}")
            await self.db.rollback()
            raise

    async def handle_subscription_deleted(self, subscription: dict[str, Any]) -> None:
        """Handle subscription.deleted webhook event.

        Downgrades user to free tier when subscription is cancelled.

        Args:
            subscription: Stripe subscription object
        """
        try:
            # Find license by subscription ID
            stmt = select(License).where(
                License.stripe_subscription_id == subscription["id"]
            )
            result = await self.db.execute(stmt)
            license = result.scalar_one_or_none()

            if not license:
                logger.warning(f"License not found for deleted subscription {subscription['id']}")
                return

            # Downgrade to free tier
            old_tier = license.tier
            license.tier = "free"
            license.status = "canceled"
            license.valid_until = datetime.now(timezone.utc)
            license.cancel_at_period_end = False

            # Update user tier
            user_stmt = select(User).where(User.id == license.user_id)
            user_result = await self.db.execute(user_stmt)
            user = user_result.scalar_one_or_none()
            if user:
                user.tier = "free"

            # Update quota to free tier
            quota_stmt = select(UserQuota).where(UserQuota.user_id == license.user_id)
            quota_result = await self.db.execute(quota_stmt)
            quota = quota_result.scalar_one_or_none()
            if quota:
                quota.tier = "free"
                quota.token_limit = 0  # Free tier has no server-side tokens
                quota.byok_enabled = True  # Free tier must use BYOK

            await self.db.commit()
            logger.info(
                f"Downgraded user {license.user_id} from {old_tier} to free "
                f"due to subscription deletion"
            )

        except Exception as e:
            logger.error(f"Error handling subscription.deleted: {e}")
            await self.db.rollback()
            raise

    async def handle_invoice_payment_failed(self, invoice: dict[str, Any]) -> None:
        """Handle invoice.payment_failed webhook event.

        Sets grace period when payment fails.

        Args:
            invoice: Stripe invoice object
        """
        try:
            subscription_id = invoice.get("subscription")
            if not subscription_id:
                logger.warning("No subscription ID in failed invoice")
                return

            # Find license by subscription ID
            stmt = select(License).where(License.stripe_subscription_id == subscription_id)
            result = await self.db.execute(stmt)
            license = result.scalar_one_or_none()

            if not license:
                logger.warning(f"License not found for subscription {subscription_id}")
                return

            # Set status to past_due
            license.status = "past_due"

            # Set grace period end date
            grace_period_end = datetime.now(timezone.utc) + timedelta(
                days=settings.stripe_payment_grace_period_days
            )
            license.valid_until = grace_period_end

            await self.db.commit()
            logger.warning(
                f"Payment failed for user {license.user_id}. "
                f"Grace period until {grace_period_end}"
            )

        except Exception as e:
            logger.error(f"Error handling invoice.payment_failed: {e}")
            await self.db.rollback()
            raise

    async def check_grace_period_expiration(self) -> int:
        """Check and suspend licenses whose grace period has expired.

        Queries licenses with status='past_due' and valid_until < now,
        and downgrades them to free tier.

        Returns:
            Number of licenses suspended
        """
        try:
            now = datetime.now(timezone.utc)
            stmt = select(License).where(
                License.status == "past_due",
                License.valid_until < now,
            )
            result = await self.db.execute(stmt)
            expired_licenses = result.scalars().all()

            suspended_count = 0
            for license in expired_licenses:
                old_tier = license.tier
                license.tier = "free"
                license.status = "suspended"
                license.cancel_at_period_end = False

                # Update user tier
                user_stmt = select(User).where(User.id == license.user_id)
                user_result = await self.db.execute(user_stmt)
                user = user_result.scalar_one_or_none()
                if user:
                    user.tier = "free"

                # Update quota
                quota_stmt = select(UserQuota).where(UserQuota.user_id == license.user_id)
                quota_result = await self.db.execute(quota_stmt)
                quota = quota_result.scalar_one_or_none()
                if quota:
                    quota.tier = "free"
                    quota.token_limit = 0
                    quota.byok_enabled = True

                suspended_count += 1
                logger.warning(
                    f"Suspended user {license.user_id} (was {old_tier}) - "
                    f"grace period expired"
                )

            if suspended_count > 0:
                await self.db.commit()
                logger.info(f"Suspended {suspended_count} licenses with expired grace periods")

            return suspended_count

        except Exception as e:
            logger.error(f"Error checking grace period expiration: {e}")
            await self.db.rollback()
            raise

    async def handle_invoice_payment_succeeded(self, invoice: dict[str, Any]) -> None:
        """Handle invoice.payment_succeeded webhook event.

        Clears past_due status when payment succeeds.

        Args:
            invoice: Stripe invoice object
        """
        try:
            subscription_id = invoice.get("subscription")
            if not subscription_id:
                # One-time payment, not subscription-related
                return

            # Find license by subscription ID
            stmt = select(License).where(License.stripe_subscription_id == subscription_id)
            result = await self.db.execute(stmt)
            license = result.scalar_one_or_none()

            if not license:
                logger.warning(f"License not found for subscription {subscription_id}")
                return

            # Clear past_due status if present
            if license.status == "past_due":
                license.status = "active"
                logger.info(f"Cleared past_due status for user {license.user_id}")

            await self.db.commit()

        except Exception as e:
            logger.error(f"Error handling invoice.payment_succeeded: {e}")
            await self.db.rollback()
            raise
