"""Tests for subscription management endpoints.

Tests cover:
- Portal session creation (POST /license/portal)
- Subscription reactivation (POST /license/reactivate)
- Prices endpoint (GET /license/prices)
- Annual upgrade (POST /license/upgrade/{tier})
"""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import stripe
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token
from app.models.license import License
from app.models.session import Session
from app.models.user import User


class TestPortalSession:
    """Tests for POST /license/portal endpoint."""

    async def test_portal_session_success(
        self,
        client: AsyncClient,
        test_paid_user: tuple[User, License],
        paid_user_headers: dict[str, str],
        mock_stripe_portal_session,
        mocker,
        test_db: AsyncSession,
    ):
        """Test successful portal session creation with mock stripe.billing_portal.Session.create."""
        user, license = test_paid_user

        mocker.patch(
            "app.routers.license.settings.stripe_secret_key",
            "sk_test_123",
        )
        mocker.patch(
            "stripe.billing_portal.Session.create",
            return_value=mock_stripe_portal_session,
        )

        response = await client.post(
            "/license/portal",
            params={"return_url": "https://app.example.com/account"},
            headers=paid_user_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert "portal_url" in data
        assert data["portal_url"] == "https://billing.stripe.com/session/test_portal"

        # Verify Stripe was called with correct customer ID
        stripe.billing_portal.Session.create.assert_called_once_with(
            customer=license.stripe_customer_id,
            return_url="https://app.example.com/account",
        )

    async def test_portal_session_error_no_customer_id(
        self,
        client: AsyncClient,
        auth_headers: dict[str, str],
        test_user: User,
        mocker,
        test_db: AsyncSession,
    ):
        """Test portal session fails when user has no customer_id (no billing account)."""
        mocker.patch(
            "app.routers.license.settings.stripe_secret_key",
            "sk_test_123",
        )

        response = await client.post(
            "/license/portal",
            params={"return_url": "https://app.example.com/account"},
            headers=auth_headers,
        )

        assert response.status_code == 400
        data = response.json()
        assert "no billing account" in data["detail"].lower()


class TestReactivation:
    """Tests for POST /license/reactivate endpoint."""

    async def test_reactivate_cancelled_subscription(
        self,
        client: AsyncClient,
        test_paid_user: tuple[User, License],
        paid_user_headers: dict[str, str],
        mocker,
        test_db: AsyncSession,
    ):
        """Test reactivating a cancelled subscription."""
        user, license = test_paid_user

        # Set the subscription as scheduled for cancellation
        license.cancel_at_period_end = True
        await test_db.commit()

        mocker.patch(
            "app.routers.license.settings.stripe_secret_key",
            "sk_test_123",
        )
        mocker.patch(
            "stripe.Subscription.modify",
            return_value=MagicMock(
                id=license.stripe_subscription_id,
                cancel_at_period_end=False,
            ),
        )

        response = await client.post(
            "/license/reactivate",
            headers=paid_user_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "reactivated" in data["message"].lower()

        # Verify the subscription was reactivated via Stripe
        stripe.Subscription.modify.assert_called_once_with(
            license.stripe_subscription_id,
            cancel_at_period_end=False,
        )

        # Verify license updated in DB
        await test_db.refresh(license)
        assert license.cancel_at_period_end is False

    async def test_reactivate_error_not_cancelled(
        self,
        client: AsyncClient,
        test_paid_user: tuple[User, License],
        paid_user_headers: dict[str, str],
        mocker,
        test_db: AsyncSession,
    ):
        """Test reactivation fails when subscription is not cancelled."""
        user, license = test_paid_user

        # Ensure cancel_at_period_end is False (subscription is active)
        license.cancel_at_period_end = False
        await test_db.commit()

        mocker.patch(
            "app.routers.license.settings.stripe_secret_key",
            "sk_test_123",
        )

        response = await client.post(
            "/license/reactivate",
            headers=paid_user_headers,
        )

        assert response.status_code == 400
        data = response.json()
        assert "not scheduled for cancellation" in data["detail"].lower()


class TestPricesEndpoint:
    """Tests for GET /license/prices endpoint."""

    async def test_get_prices_returns_all_tiers(
        self,
        client: AsyncClient,
    ):
        """Test that /license/prices returns all tiers with correct structure."""
        response = await client.get("/license/prices")

        assert response.status_code == 200
        data = response.json()

        # Verify top-level structure
        assert "currency" in data
        assert data["currency"] == "usd"
        assert "tiers" in data

        tiers = data["tiers"]

        # Verify all tiers present
        assert "free" in tiers
        assert "starter" in tiers
        assert "pro" in tiers
        assert "enterprise" in tiers

        # Verify free tier structure
        free = tiers["free"]
        assert "monthly" in free
        assert "annual" in free
        assert "tokens" in free
        assert "devices" in free
        assert "features" in free
        assert free["monthly"] == 0
        assert free["annual"] == 0
        assert free["devices"] == 1

        # Verify paid tier structure (starter)
        starter = tiers["starter"]
        assert "monthly" in starter
        assert "annual" in starter
        assert "annual_savings" in starter
        assert "tokens" in starter
        assert "devices" in starter
        assert "features" in starter
        assert starter["devices"] == 2
        assert isinstance(starter["features"], list)

        # Verify pro tier
        pro = tiers["pro"]
        assert pro["devices"] == 3
        assert isinstance(pro["features"], list)

        # Verify enterprise tier
        enterprise = tiers["enterprise"]
        assert enterprise["devices"] == 500
        assert "per_user" in enterprise
        assert enterprise["per_user"] is True
        assert "min_seats" in enterprise
        assert isinstance(enterprise["features"], list)


class TestAnnualUpgrade:
    """Tests for POST /license/upgrade/{tier} with annual billing."""

    async def test_upgrade_with_annual_billing_interval(
        self,
        client: AsyncClient,
        auth_headers: dict[str, str],
        mock_stripe_client,
        mocker,
    ):
        """Test upgrade with billing_interval=annual creates correct checkout session."""
        mocker.patch(
            "app.routers.license.settings.stripe_secret_key",
            "sk_test_123",
        )
        mocker.patch(
            "app.services.stripe_service.TIER_INTERVAL_TO_PRICE",
            {
                ("pro", "annual"): "price_pro_annual",
                ("pro", "monthly"): "price_pro_monthly",
            },
        )
        mocker.patch(
            "app.services.stripe_service.TIER_TO_PRICE",
            {
                "starter": "price_starter",
                "pro": "price_pro_monthly",
                "enterprise": "price_enterprise",
            },
        )

        response = await client.post(
            "/license/upgrade/pro",
            params={
                "success_url": "https://app.example.com/success",
                "cancel_url": "https://app.example.com/cancel",
                "billing_interval": "annual",
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert "checkout_url" in data
        assert data["tier"] == "pro"
        assert data["billing_interval"] == "annual"
        assert "checkout.stripe.com" in data["checkout_url"]

        # Verify Stripe checkout was called
        mock_stripe_client["checkout_create"].assert_called_once()

        # Verify the checkout call included the annual price and ANNUAL25 coupon
        call_kwargs = mock_stripe_client["checkout_create"].call_args
        if call_kwargs.kwargs:
            checkout_args = call_kwargs.kwargs
        else:
            checkout_args = call_kwargs[1] if len(call_kwargs) > 1 else {}

        # The line_items should contain the annual price
        line_items = checkout_args.get("line_items", [])
        assert len(line_items) == 1
        assert line_items[0]["price"] == "price_pro_annual"

        # The discounts should include the ANNUAL25 coupon
        discounts = checkout_args.get("discounts", [])
        assert len(discounts) == 1
        assert discounts[0]["coupon"] == "ANNUAL25"
