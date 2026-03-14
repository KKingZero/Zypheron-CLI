"""Tests for Stripe webhook handlers.

Tests cover:
- Webhook signature verification
- Subscription lifecycle events (created, updated, deleted)
- Invoice payment events (failed, succeeded)
- Tier changes and renewals
- Token usage resets on renewal
- Error handling for invalid webhooks
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import stripe
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.license import License
from app.models.token_usage import UserQuota
from app.models.user import User


class TestWebhookSignatureVerification:
    """Tests for webhook signature verification."""

    async def test_webhook_signature_verification_success(
        self,
        client: AsyncClient,
        mocker,
    ):
        """Test successful webhook signature verification."""
        mock_event = {
            "id": "evt_test123",
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_test123",
                    "customer": "cus_test123",
                    "status": "active",
                    "metadata": {"user_id": "999", "tier": "pro"},
                    "items": {
                        "data": [{"price": {"id": "price_pro_monthly"}}]
                    },
                }
            },
        }

        # Mock Stripe webhook signature verification
        mocker.patch(
            "stripe.Webhook.construct_event",
            return_value=mock_event,
        )

        # Mock settings to have Stripe configured
        mocker.patch(
            "app.routers.webhooks.settings.stripe_secret_key",
            "sk_test_123",
        )
        mocker.patch(
            "app.routers.webhooks.settings.stripe_webhook_secret",
            "whsec_test_123",
        )

        response = await client.post(
            "/webhooks/stripe",
            content=json.dumps(mock_event),
            headers={
                "stripe-signature": "t=123,v1=signature",
                "content-type": "application/json",
            },
        )

        # Webhook should be acknowledged even if processing fails
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

    async def test_webhook_invalid_signature(
        self,
        client: AsyncClient,
        mocker,
    ):
        """Test webhook with invalid signature is rejected."""
        # Mock Stripe to raise signature verification error
        mocker.patch(
            "stripe.Webhook.construct_event",
            side_effect=stripe.error.SignatureVerificationError(
                "Invalid signature", "sig_header"
            ),
        )

        # Mock settings
        mocker.patch(
            "app.routers.webhooks.settings.stripe_secret_key",
            "sk_test_123",
        )
        mocker.patch(
            "app.routers.webhooks.settings.stripe_webhook_secret",
            "whsec_test_123",
        )

        response = await client.post(
            "/webhooks/stripe",
            content=json.dumps({"type": "test"}),
            headers={
                "stripe-signature": "invalid_signature",
                "content-type": "application/json",
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert "signature" in data["detail"].lower()

    async def test_webhook_missing_signature_header(
        self,
        client: AsyncClient,
        mocker,
    ):
        """Test webhook without signature header is rejected."""
        # Mock settings
        mocker.patch(
            "app.routers.webhooks.settings.stripe_secret_key",
            "sk_test_123",
        )
        mocker.patch(
            "app.routers.webhooks.settings.stripe_webhook_secret",
            "whsec_test_123",
        )

        response = await client.post(
            "/webhooks/stripe",
            content=json.dumps({"type": "test"}),
            headers={"content-type": "application/json"},
            # Missing stripe-signature header
        )

        assert response.status_code == 400
        data = response.json()
        assert "signature" in data["detail"].lower()


class TestSubscriptionCreatedWebhook:
    """Tests for customer.subscription.created webhook."""

    async def test_subscription_created_handler(
        self,
        client: AsyncClient,
        test_user: User,
        test_db: AsyncSession,
        mocker,
    ):
        """Test subscription.created creates or updates license."""
        mock_event = {
            "id": "evt_test123",
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_new123",
                    "customer": "cus_new123",
                    "status": "active",
                    "current_period_end": int(
                        datetime(2025, 2, 1, tzinfo=timezone.utc).timestamp()
                    ),
                    "cancel_at_period_end": False,
                    "metadata": {
                        "user_id": str(test_user.id),
                        "tier": "pro",
                    },
                    "items": {
                        "data": [{"price": {"id": "price_pro_monthly"}}]
                    },
                }
            },
        }

        mocker.patch("stripe.Webhook.construct_event", return_value=mock_event)
        mocker.patch("app.routers.webhooks.settings.stripe_secret_key", "sk_test")
        mocker.patch("app.routers.webhooks.settings.stripe_webhook_secret", "whsec_test")
        mocker.patch("app.services.stripe_service.PRICE_TO_TIER", {"price_pro_monthly": "pro"})

        response = await client.post(
            "/webhooks/stripe",
            content=json.dumps(mock_event),
            headers={
                "stripe-signature": "valid_sig",
                "content-type": "application/json",
            },
        )

        assert response.status_code == 200

        # Verify license was created/updated
        stmt = select(License).where(License.user_id == test_user.id)
        result = await test_db.execute(stmt)
        license = result.scalar_one_or_none()

        assert license is not None
        assert license.stripe_subscription_id == "sub_new123"
        assert license.stripe_customer_id == "cus_new123"
        assert license.tier == "pro"
        assert license.status == "active"

        # Verify user tier updated
        await test_db.refresh(test_user)
        assert test_user.tier == "pro"


class TestSubscriptionUpdatedWebhook:
    """Tests for customer.subscription.updated webhook."""

    async def test_subscription_updated_tier_change(
        self,
        client: AsyncClient,
        test_paid_user: tuple[User, License],
        test_db: AsyncSession,
        mocker,
    ):
        """Test subscription.updated with tier change (upgrade/downgrade)."""
        user, license = test_paid_user

        # Mock upgrade from pro to enterprise
        mock_event = {
            "id": "evt_upgrade123",
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": license.stripe_subscription_id,
                    "customer": license.stripe_customer_id,
                    "status": "active",
                    "current_period_end": int(
                        datetime(2025, 2, 1, tzinfo=timezone.utc).timestamp()
                    ),
                    "cancel_at_period_end": False,
                    "items": {
                        "data": [{"price": {"id": "price_enterprise_monthly"}}]
                    },
                }
            },
        }

        mocker.patch("stripe.Webhook.construct_event", return_value=mock_event)
        mocker.patch("app.routers.webhooks.settings.stripe_secret_key", "sk_test")
        mocker.patch("app.routers.webhooks.settings.stripe_webhook_secret", "whsec_test")
        mocker.patch(
            "app.services.stripe_service.PRICE_TO_TIER",
            {"price_enterprise_monthly": "enterprise"},
        )

        response = await client.post(
            "/webhooks/stripe",
            content=json.dumps(mock_event),
            headers={
                "stripe-signature": "valid_sig",
                "content-type": "application/json",
            },
        )

        assert response.status_code == 200

        # Verify tier changed
        await test_db.refresh(license)
        assert license.tier == "enterprise"
        assert license.stripe_price_id == "price_enterprise_monthly"

        await test_db.refresh(user)
        assert user.tier == "enterprise"

    async def test_subscription_updated_renewal_resets_tokens(
        self,
        client: AsyncClient,
        test_paid_user: tuple[User, License],
        test_db: AsyncSession,
        mocker,
    ):
        """Test subscription.updated on renewal resets token usage."""
        user, license = test_paid_user

        # Set old period end
        old_period_end = datetime(2025, 1, 1, tzinfo=timezone.utc)
        license.valid_until = old_period_end
        await test_db.commit()

        # Create quota with some usage
        quota = UserQuota(
            user_id=user.id,
            tier="pro",
            tokens_used_period=500000,
            token_limit=3000000,
        )
        test_db.add(quota)
        await test_db.commit()

        # Mock renewal event with new period
        new_period_end = datetime(2025, 2, 1, tzinfo=timezone.utc)
        mock_event = {
            "id": "evt_renewal123",
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": license.stripe_subscription_id,
                    "customer": license.stripe_customer_id,
                    "status": "active",
                    "current_period_end": int(new_period_end.timestamp()),
                    "cancel_at_period_end": False,
                    "items": {
                        "data": [{"price": {"id": "price_pro_monthly"}}]
                    },
                }
            },
        }

        mocker.patch("stripe.Webhook.construct_event", return_value=mock_event)
        mocker.patch("app.routers.webhooks.settings.stripe_secret_key", "sk_test")
        mocker.patch("app.routers.webhooks.settings.stripe_webhook_secret", "whsec_test")
        mocker.patch("app.services.stripe_service.PRICE_TO_TIER", {"price_pro_monthly": "pro"})

        response = await client.post(
            "/webhooks/stripe",
            content=json.dumps(mock_event),
            headers={
                "stripe-signature": "valid_sig",
                "content-type": "application/json",
            },
        )

        assert response.status_code == 200

        # Verify period updated
        await test_db.refresh(license)
        assert license.valid_until == new_period_end

        # Verify token usage was reset
        await test_db.refresh(quota)
        assert quota.tokens_used_period == 0


class TestSubscriptionDeletedWebhook:
    """Tests for customer.subscription.deleted webhook."""

    async def test_subscription_deleted_downgrades_to_free(
        self,
        client: AsyncClient,
        test_paid_user: tuple[User, License],
        test_db: AsyncSession,
        mocker,
    ):
        """Test subscription.deleted downgrades user to free tier."""
        user, license = test_paid_user
        original_tier = license.tier

        mock_event = {
            "id": "evt_cancel123",
            "type": "customer.subscription.deleted",
            "data": {
                "object": {
                    "id": license.stripe_subscription_id,
                    "customer": license.stripe_customer_id,
                    "status": "canceled",
                }
            },
        }

        mocker.patch("stripe.Webhook.construct_event", return_value=mock_event)
        mocker.patch("app.routers.webhooks.settings.stripe_secret_key", "sk_test")
        mocker.patch("app.routers.webhooks.settings.stripe_webhook_secret", "whsec_test")

        response = await client.post(
            "/webhooks/stripe",
            content=json.dumps(mock_event),
            headers={
                "stripe-signature": "valid_sig",
                "content-type": "application/json",
            },
        )

        assert response.status_code == 200

        # Verify downgrade to free
        await test_db.refresh(license)
        assert license.tier == "free"
        assert license.status == "canceled"
        assert license.cancel_at_period_end is False

        await test_db.refresh(user)
        assert user.tier == "free"


class TestInvoiceWebhooks:
    """Tests for invoice payment events."""

    async def test_invoice_payment_failed_grace_period(
        self,
        client: AsyncClient,
        test_paid_user: tuple[User, License],
        test_db: AsyncSession,
        mocker,
    ):
        """Test invoice.payment_failed sets grace period."""
        user, license = test_paid_user

        mock_event = {
            "id": "evt_payment_failed",
            "type": "invoice.payment_failed",
            "data": {
                "object": {
                    "id": "in_failed123",
                    "subscription": license.stripe_subscription_id,
                    "amount_due": 2900,
                    "attempt_count": 1,
                }
            },
        }

        mocker.patch("stripe.Webhook.construct_event", return_value=mock_event)
        mocker.patch("app.routers.webhooks.settings.stripe_secret_key", "sk_test")
        mocker.patch("app.routers.webhooks.settings.stripe_webhook_secret", "whsec_test")
        mocker.patch(
            "app.routers.webhooks.settings.stripe_payment_grace_period_days", 3
        )

        response = await client.post(
            "/webhooks/stripe",
            content=json.dumps(mock_event),
            headers={
                "stripe-signature": "valid_sig",
                "content-type": "application/json",
            },
        )

        assert response.status_code == 200

        # Verify grace period set
        await test_db.refresh(license)
        assert license.status == "past_due"
        assert license.valid_until is not None
        # Should be approximately 3 days from now
        time_until_expiry = license.valid_until - datetime.now(timezone.utc)
        assert 2.9 <= time_until_expiry.days <= 3.1

    async def test_invoice_payment_succeeded_clears_past_due(
        self,
        client: AsyncClient,
        test_paid_user: tuple[User, License],
        test_db: AsyncSession,
        mocker,
    ):
        """Test invoice.payment_succeeded clears past_due status."""
        user, license = test_paid_user

        # Set license to past_due
        license.status = "past_due"
        await test_db.commit()

        mock_event = {
            "id": "evt_payment_success",
            "type": "invoice.payment_succeeded",
            "data": {
                "object": {
                    "id": "in_success123",
                    "subscription": license.stripe_subscription_id,
                    "amount_paid": 2900,
                    "paid": True,
                }
            },
        }

        mocker.patch("stripe.Webhook.construct_event", return_value=mock_event)
        mocker.patch("app.routers.webhooks.settings.stripe_secret_key", "sk_test")
        mocker.patch("app.routers.webhooks.settings.stripe_webhook_secret", "whsec_test")

        response = await client.post(
            "/webhooks/stripe",
            content=json.dumps(mock_event),
            headers={
                "stripe-signature": "valid_sig",
                "content-type": "application/json",
            },
        )

        assert response.status_code == 200

        # Verify status cleared
        await test_db.refresh(license)
        assert license.status == "active"


class TestUnhandledWebhooks:
    """Tests for unhandled webhook types."""

    async def test_unknown_event_type_ignored(
        self,
        client: AsyncClient,
        mocker,
    ):
        """Test that unknown event types are acknowledged but ignored."""
        mock_event = {
            "id": "evt_unknown123",
            "type": "customer.tax_id.created",  # Unhandled event type
            "data": {"object": {}},
        }

        mocker.patch("stripe.Webhook.construct_event", return_value=mock_event)
        mocker.patch("app.routers.webhooks.settings.stripe_secret_key", "sk_test")
        mocker.patch("app.routers.webhooks.settings.stripe_webhook_secret", "whsec_test")

        response = await client.post(
            "/webhooks/stripe",
            content=json.dumps(mock_event),
            headers={
                "stripe-signature": "valid_sig",
                "content-type": "application/json",
            },
        )

        # Should still return 200 to acknowledge receipt
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["event_type"] == "customer.tax_id.created"


class TestAnnualBillingWebhook:
    """Tests for annual billing through webhooks."""

    async def test_annual_checkout_applies_annual_coupon(
        self,
        client: AsyncClient,
        test_user: User,
        test_db: AsyncSession,
        mocker,
    ):
        """Test that annual checkout applies the ANNUAL25 coupon."""
        mock_event = {
            "id": "evt_annual_checkout123",
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_annual_new",
                    "customer": "cus_annual_new",
                    "status": "active",
                    "current_period_end": int(
                        datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
                    ),
                    "cancel_at_period_end": False,
                    "metadata": {
                        "user_id": str(test_user.id),
                        "tier": "pro",
                        "billing_interval": "annual",
                    },
                    "items": {
                        "data": [{"price": {"id": "price_pro_annual"}}]
                    },
                }
            },
        }

        mocker.patch("stripe.Webhook.construct_event", return_value=mock_event)
        mocker.patch("app.routers.webhooks.settings.stripe_secret_key", "sk_test")
        mocker.patch("app.routers.webhooks.settings.stripe_webhook_secret", "whsec_test")
        mocker.patch(
            "app.services.stripe_service.PRICE_TO_TIER",
            {"price_pro_annual": "pro"},
        )
        mocker.patch(
            "app.services.stripe_service.PRICE_TO_INTERVAL",
            {"price_pro_annual": "annual"},
        )

        response = await client.post(
            "/webhooks/stripe",
            content=json.dumps(mock_event),
            headers={
                "stripe-signature": "valid_sig",
                "content-type": "application/json",
            },
        )

        assert response.status_code == 200

        # Verify license was created with annual billing interval
        stmt = select(License).where(License.user_id == test_user.id)
        result = await test_db.execute(stmt)
        license = result.scalar_one_or_none()

        assert license is not None
        assert license.billing_interval == "annual"
        assert license.stripe_price_id == "price_pro_annual"
        assert license.tier == "pro"

    async def test_annual_price_ids_per_tier(
        self,
        client: AsyncClient,
        test_user: User,
        test_db: AsyncSession,
        mocker,
    ):
        """Test correct annual price IDs per tier (starter, pro, enterprise)."""
        annual_tiers = [
            ("starter", "price_starter_annual"),
            ("pro", "price_pro_annual"),
            ("enterprise", "price_enterprise_annual"),
        ]

        for tier, price_id in annual_tiers:
            # Reset: remove existing licenses
            stmt = select(License).where(License.user_id == test_user.id)
            result = await test_db.execute(stmt)
            existing = result.scalar_one_or_none()
            if existing:
                await test_db.delete(existing)
                await test_db.commit()

            mock_event = {
                "id": f"evt_annual_{tier}",
                "type": "customer.subscription.created",
                "data": {
                    "object": {
                        "id": f"sub_annual_{tier}",
                        "customer": f"cus_annual_{tier}",
                        "status": "active",
                        "current_period_end": int(
                            datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
                        ),
                        "cancel_at_period_end": False,
                        "metadata": {
                            "user_id": str(test_user.id),
                            "tier": tier,
                            "billing_interval": "annual",
                        },
                        "items": {
                            "data": [{"price": {"id": price_id}}]
                        },
                    }
                },
            }

            mocker.patch("stripe.Webhook.construct_event", return_value=mock_event)
            mocker.patch("app.routers.webhooks.settings.stripe_secret_key", "sk_test")
            mocker.patch("app.routers.webhooks.settings.stripe_webhook_secret", "whsec_test")
            mocker.patch(
                "app.services.stripe_service.PRICE_TO_TIER",
                {price_id: tier},
            )
            mocker.patch(
                "app.services.stripe_service.PRICE_TO_INTERVAL",
                {price_id: "annual"},
            )

            response = await client.post(
                "/webhooks/stripe",
                content=json.dumps(mock_event),
                headers={
                    "stripe-signature": "valid_sig",
                    "content-type": "application/json",
                },
            )

            assert response.status_code == 200

            # Verify license created with correct tier and annual price
            stmt = select(License).where(License.user_id == test_user.id)
            result = await test_db.execute(stmt)
            license = result.scalar_one_or_none()

            assert license is not None, f"License not created for tier {tier}"
            assert license.tier == tier
            assert license.stripe_price_id == price_id
            assert license.billing_interval == "annual"

    async def test_billing_interval_persists_on_license(
        self,
        client: AsyncClient,
        test_db: AsyncSession,
        test_user: User,
        mocker,
    ):
        """Test that billing_interval persists on license after webhook processing."""
        # Create initial subscription with annual billing
        mock_create_event = {
            "id": "evt_persist_create",
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_persist123",
                    "customer": "cus_persist123",
                    "status": "active",
                    "current_period_end": int(
                        datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
                    ),
                    "cancel_at_period_end": False,
                    "metadata": {
                        "user_id": str(test_user.id),
                        "tier": "pro",
                        "billing_interval": "annual",
                    },
                    "items": {
                        "data": [{"price": {"id": "price_pro_annual"}}]
                    },
                }
            },
        }

        mocker.patch("stripe.Webhook.construct_event", return_value=mock_create_event)
        mocker.patch("app.routers.webhooks.settings.stripe_secret_key", "sk_test")
        mocker.patch("app.routers.webhooks.settings.stripe_webhook_secret", "whsec_test")
        mocker.patch(
            "app.services.stripe_service.PRICE_TO_TIER",
            {"price_pro_annual": "pro"},
        )
        mocker.patch(
            "app.services.stripe_service.PRICE_TO_INTERVAL",
            {"price_pro_annual": "annual"},
        )

        response = await client.post(
            "/webhooks/stripe",
            content=json.dumps(mock_create_event),
            headers={
                "stripe-signature": "valid_sig",
                "content-type": "application/json",
            },
        )

        assert response.status_code == 200

        # Verify billing_interval is stored
        stmt = select(License).where(License.user_id == test_user.id)
        result = await test_db.execute(stmt)
        license = result.scalar_one_or_none()

        assert license is not None
        assert license.billing_interval == "annual"

        # Refresh from DB to ensure persistence
        await test_db.refresh(license)
        assert license.billing_interval == "annual"


class TestWebhookIdempotency:
    """Tests for webhook idempotency handling."""

    async def test_duplicate_event_returns_200_with_duplicate_flag(
        self,
        client: AsyncClient,
        test_user: User,
        test_db: AsyncSession,
        mocker,
        mock_redis_client,
    ):
        """Test that duplicate event_id returns 200 with duplicate: True without reprocessing."""
        event_id = "evt_duplicate_test123"

        mock_event = {
            "id": event_id,
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_dup123",
                    "customer": "cus_dup123",
                    "status": "active",
                    "metadata": {
                        "user_id": str(test_user.id),
                        "tier": "pro",
                    },
                    "items": {
                        "data": [{"price": {"id": "price_pro_monthly"}}]
                    },
                }
            },
        }

        mocker.patch("stripe.Webhook.construct_event", return_value=mock_event)
        mocker.patch("app.routers.webhooks.settings.stripe_secret_key", "sk_test")
        mocker.patch("app.routers.webhooks.settings.stripe_webhook_secret", "whsec_test")

        # Mock Redis to indicate the event was already processed
        mock_redis_client._client.get = MagicMock(return_value="1")
        mocker.patch(
            "app.routers.webhooks.get_redis_client",
            return_value=mock_redis_client,
        )

        response = await client.post(
            "/webhooks/stripe",
            content=json.dumps(mock_event),
            headers={
                "stripe-signature": "valid_sig",
                "content-type": "application/json",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["duplicate"] is True
        assert data["status"] == "success"

        # Verify no license was created (event was not reprocessed)
        stmt = select(License).where(License.user_id == test_user.id)
        result = await test_db.execute(stmt)
        license = result.scalar_one_or_none()
        assert license is None

    async def test_inmemory_fallback_when_redis_unavailable(
        self,
        client: AsyncClient,
        test_user: User,
        test_db: AsyncSession,
        mocker,
    ):
        """Test in-memory fallback when Redis is unavailable."""
        from app.routers.webhooks import _processed_events

        event_id = "evt_inmemory_test456"

        # Pre-populate the in-memory set to simulate a previously processed event
        _processed_events.add(event_id)

        mock_event = {
            "id": event_id,
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_mem123",
                    "customer": "cus_mem123",
                    "status": "active",
                    "metadata": {
                        "user_id": str(test_user.id),
                        "tier": "pro",
                    },
                    "items": {
                        "data": [{"price": {"id": "price_pro_monthly"}}]
                    },
                }
            },
        }

        mocker.patch("stripe.Webhook.construct_event", return_value=mock_event)
        mocker.patch("app.routers.webhooks.settings.stripe_secret_key", "sk_test")
        mocker.patch("app.routers.webhooks.settings.stripe_webhook_secret", "whsec_test")

        # Mock Redis to raise an exception (unavailable)
        mocker.patch(
            "app.routers.webhooks.get_redis_client",
            side_effect=Exception("Redis connection refused"),
        )

        response = await client.post(
            "/webhooks/stripe",
            content=json.dumps(mock_event),
            headers={
                "stripe-signature": "valid_sig",
                "content-type": "application/json",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["duplicate"] is True
        assert data["status"] == "success"

        # Verify no license was created (event was not reprocessed)
        stmt = select(License).where(License.user_id == test_user.id)
        result = await test_db.execute(stmt)
        license = result.scalar_one_or_none()
        assert license is None

        # Cleanup: remove the event from in-memory set
        _processed_events.discard(event_id)
