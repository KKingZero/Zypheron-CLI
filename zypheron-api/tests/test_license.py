"""Tests for license and subscription management endpoints.

Tests cover:
- License validation
- Feature access per tier
- Subscription upgrades (mocked Stripe)
- Subscription cancellation (mocked Stripe)
- License refresh from Stripe
- Tier information retrieval
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.license import License
from app.models.user import User


class TestLicenseValidation:
    """Tests for GET /license/validate endpoint."""

    async def test_validate_license_free_tier(
        self,
        client: AsyncClient,
        auth_headers: dict[str, str],
        test_user: User,
        test_db: AsyncSession,
    ):
        """Test license validation for free tier user."""
        # Create free license
        license = License(
            user_id=test_user.id,
            tier="free",
            status="active",
        )
        test_db.add(license)
        await test_db.commit()

        response = await client.get(
            "/license/validate",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert data["is_valid"] is True
        assert data["tier"] == "free"
        assert data["status"] == "active"
        assert data["features"]["byok_required"] is True
        assert data["features"]["token_limit"] == 0
        assert data["features"]["max_devices"] == 1

    async def test_validate_license_paid_tier(
        self,
        client: AsyncClient,
        paid_user_headers: dict[str, str],
        test_paid_user: tuple[User, License],
    ):
        """Test license validation for paid tier user."""
        user, license = test_paid_user

        response = await client.get(
            "/license/validate",
            headers=paid_user_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert data["is_valid"] is True
        assert data["tier"] == "pro"
        assert data["status"] == "active"
        assert data["features"]["byok_required"] is False
        assert data["features"]["token_limit"] == 3_000_000
        assert data["features"]["max_devices"] == 3

    async def test_validate_license_creates_default_if_missing(
        self,
        client: AsyncClient,
        auth_headers: dict[str, str],
        test_user: User,
        test_db: AsyncSession,
    ):
        """Test that validate endpoint creates default license if missing."""
        # Ensure no license exists
        stmt = select(License).where(License.user_id == test_user.id)
        result = await test_db.execute(stmt)
        assert result.scalar_one_or_none() is None

        response = await client.get(
            "/license/validate",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert data["tier"] == "free"
        assert data["status"] == "active"

        # Verify license was created
        result = await test_db.execute(stmt)
        license = result.scalar_one_or_none()
        assert license is not None
        assert license.tier == "free"

    async def test_validate_license_expired(
        self,
        client: AsyncClient,
        test_user: User,
        test_db: AsyncSession,
    ):
        """Test validation of expired license."""
        # Create expired license
        license = License(
            user_id=test_user.id,
            tier="pro",
            status="active",
            valid_until=datetime.now(timezone.utc) - timedelta(days=1),
        )
        test_db.add(license)
        await test_db.commit()

        # Create auth headers
        from app.core.security import create_access_token
        from app.models.session import Session

        token = create_access_token({"sub": str(test_user.id), "email": test_user.email})
        session = Session(user_id=test_user.id, token=token)
        test_db.add(session)
        await test_db.commit()

        response = await client.get(
            "/license/validate",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()

        assert data["is_valid"] is False
        assert data["days_remaining"] == 0


class TestLicenseFeatures:
    """Tests for GET /license/features endpoint."""

    async def test_get_license_features_by_tier(
        self,
        client: AsyncClient,
        paid_user_headers: dict[str, str],
    ):
        """Test retrieving features for current user's tier."""
        response = await client.get(
            "/license/features",
            headers=paid_user_headers,
        )

        assert response.status_code == 200
        data = response.json()

        # Pro tier features
        assert data["tier"] == "pro"
        assert data["byok_required"] is False
        assert data["token_limit"] == 3_000_000
        assert data["max_devices"] == 3
        assert data["rate_limit"] == 120
        assert "ai_proxy" in data["features"]


class TestTierInformation:
    """Tests for GET /license/tiers endpoint."""

    async def test_get_all_tiers(self, client: AsyncClient):
        """Test retrieving all tier configurations."""
        response = await client.get("/license/tiers")

        assert response.status_code == 200
        data = response.json()

        # Verify all tiers present
        assert "free" in data
        assert "starter" in data
        assert "pro" in data
        assert "enterprise" in data

        # Verify tier structure
        assert data["free"]["tier"] == "free"
        assert data["free"]["byok_required"] is True
        assert data["free"]["token_limit"] == 0

        assert data["pro"]["tier"] == "pro"
        assert data["pro"]["token_limit"] == 3_000_000
        assert data["pro"]["max_devices"] == 3


class TestSubscriptionUpgrade:
    """Tests for POST /license/upgrade/{tier} endpoint."""

    async def test_upgrade_creates_checkout_session(
        self,
        client: AsyncClient,
        auth_headers: dict[str, str],
        mock_stripe_client,
        mocker,
    ):
        """Test upgrade creates Stripe checkout session (mocked)."""
        # Mock settings
        mocker.patch(
            "app.routers.license.settings.stripe_secret_key",
            "sk_test_123",
        )
        mocker.patch(
            "app.services.stripe_service.TIER_TO_PRICE",
            {
                "starter": "price_starter",
                "pro": "price_pro",
                "enterprise": "price_enterprise",
            },
        )

        response = await client.post(
            "/license/upgrade/pro",
            params={
                "success_url": "https://app.example.com/success",
                "cancel_url": "https://app.example.com/cancel",
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert "checkout_url" in data
        assert data["tier"] == "pro"
        assert "checkout.stripe.com" in data["checkout_url"]

        # Verify Stripe checkout was called
        mock_stripe_client["checkout_create"].assert_called_once()

    async def test_upgrade_invalid_tier(
        self,
        client: AsyncClient,
        auth_headers: dict[str, str],
    ):
        """Test upgrade to invalid tier returns error."""
        response = await client.post(
            "/license/upgrade/invalid_tier",
            params={
                "success_url": "https://app.example.com/success",
                "cancel_url": "https://app.example.com/cancel",
            },
            headers=auth_headers,
        )

        assert response.status_code == 400
        data = response.json()
        assert "invalid tier" in data["detail"].lower()

    async def test_upgrade_without_stripe_configured(
        self,
        client: AsyncClient,
        auth_headers: dict[str, str],
        mocker,
    ):
        """Test upgrade fails gracefully when Stripe not configured."""
        # Mock settings to have no Stripe key
        mocker.patch("app.routers.license.settings.stripe_secret_key", None)

        response = await client.post(
            "/license/upgrade/pro",
            params={
                "success_url": "https://app.example.com/success",
                "cancel_url": "https://app.example.com/cancel",
            },
            headers=auth_headers,
        )

        assert response.status_code == 501
        data = response.json()
        assert "not configured" in data["detail"].lower()


class TestSubscriptionCancellation:
    """Tests for POST /license/cancel endpoint."""

    async def test_cancel_subscription(
        self,
        client: AsyncClient,
        paid_user_headers: dict[str, str],
        test_paid_user: tuple[User, License],
        mock_stripe_client,
        mocker,
        test_db: AsyncSession,
    ):
        """Test subscription cancellation (mocked Stripe)."""
        user, license = test_paid_user

        # Mock settings
        mocker.patch("app.routers.license.settings.stripe_secret_key", "sk_test_123")

        response = await client.post(
            "/license/cancel",
            params={"cancel_immediately": False},
            headers=paid_user_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert "at period end" in data["message"].lower()
        assert data["license"]["tier"] == "pro"

        # Verify Stripe cancellation was called
        mock_stripe_client["subscription_modify"].assert_called_once()

        # Verify license updated
        await test_db.refresh(license)
        assert license.cancel_at_period_end is True

    async def test_cancel_subscription_immediately(
        self,
        client: AsyncClient,
        paid_user_headers: dict[str, str],
        test_paid_user: tuple[User, License],
        mock_stripe_client,
        mocker,
        test_db: AsyncSession,
    ):
        """Test immediate subscription cancellation."""
        user, license = test_paid_user

        mocker.patch("app.routers.license.settings.stripe_secret_key", "sk_test_123")

        response = await client.post(
            "/license/cancel",
            params={"cancel_immediately": True},
            headers=paid_user_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert "immediately" in data["message"].lower()

        # Verify Stripe deletion was called
        mock_stripe_client["subscription_delete"].assert_called_once()

    async def test_cancel_without_subscription(
        self,
        client: AsyncClient,
        auth_headers: dict[str, str],
    ):
        """Test cancellation without active subscription fails."""
        response = await client.post(
            "/license/cancel",
            headers=auth_headers,
        )

        assert response.status_code == 400
        data = response.json()
        assert "no active subscription" in data["detail"].lower()


class TestLicenseRefresh:
    """Tests for POST /license/refresh endpoint."""

    async def test_refresh_subscription(
        self,
        client: AsyncClient,
        paid_user_headers: dict[str, str],
        test_paid_user: tuple[User, License],
        mock_stripe_client,
        mocker,
        test_db: AsyncSession,
    ):
        """Test refreshing license from Stripe subscription (mocked)."""
        user, license = test_paid_user

        # Mock settings
        mocker.patch("app.routers.license.settings.stripe_secret_key", "sk_test_123")
        mocker.patch(
            "app.services.stripe_service.PRICE_TO_TIER",
            {"price_pro_monthly": "pro"},
        )

        response = await client.post(
            "/license/refresh",
            headers=paid_user_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert "refreshed successfully" in data["message"].lower()
        assert data["license"]["tier"] == "pro"

        # Verify Stripe API was called
        mock_stripe_client["subscription_retrieve"].assert_called_once()

    async def test_refresh_free_tier_license(
        self,
        client: AsyncClient,
        auth_headers: dict[str, str],
        test_user: User,
        test_db: AsyncSession,
    ):
        """Test refreshing free tier license (no Stripe subscription)."""
        # Create free license
        license = License(
            user_id=test_user.id,
            tier="free",
            status="active",
        )
        test_db.add(license)
        await test_db.commit()

        response = await client.post(
            "/license/refresh",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert "no stripe subscription" in data["message"].lower()
        assert data["license"]["tier"] == "free"


class TestLicenseRetrieval:
    """Tests for GET /license endpoint."""

    async def test_get_license(
        self,
        client: AsyncClient,
        paid_user_headers: dict[str, str],
        test_paid_user: tuple[User, License],
    ):
        """Test retrieving current user's license."""
        user, license = test_paid_user

        response = await client.get(
            "/license",
            headers=paid_user_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert data["id"] == license.id
        assert data["tier"] == "pro"
        assert data["status"] == "active"
        assert data["stripe_customer_id"] == license.stripe_customer_id
        assert data["stripe_subscription_id"] == license.stripe_subscription_id
