"""Tests for device authentication flow (OAuth 2.0 Device Authorization Grant).

Tests cover:
- Device code creation
- Device code authorization by user
- Device token polling
- Expiration handling
- Error cases and edge conditions
"""

from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.device_code import DeviceCode
from app.models.session import Session
from app.models.user import User


class TestDeviceCodeCreation:
    """Tests for POST /auth/device/code endpoint."""

    async def test_request_device_code_success(self, client: AsyncClient):
        """Test successful device code generation."""
        response = await client.post(
            "/auth/device/code",
            json={
                "device_info": {
                    "os": "Linux",
                    "platform": "Ubuntu 22.04",
                    "hostname": "test-machine",
                    "python_version": "3.11.0",
                }
            },
        )

        assert response.status_code == 201
        data = response.json()

        # Verify response structure
        assert "device_code" in data
        assert "user_code" in data
        assert "verification_url" in data
        assert "expires_in" in data
        assert "interval" in data

        # Verify device_code format (32 characters)
        assert len(data["device_code"]) == 32
        assert data["device_code"].isalnum()

        # Verify user_code format (XXXX-XXXX)
        assert len(data["user_code"]) == 9  # 4 + 1 + 4
        assert "-" in data["user_code"]
        parts = data["user_code"].split("-")
        assert len(parts) == 2
        assert all(len(part) == 4 for part in parts)

        # Verify timing parameters
        assert data["expires_in"] == 300  # 5 minutes in seconds
        assert data["interval"] == 5  # 5-second polling interval

    async def test_request_device_code_invalid_device_info(self, client: AsyncClient):
        """Test device code creation with missing device_info."""
        response = await client.post(
            "/auth/device/code",
            json={},  # Missing device_info
        )

        # Should still succeed but with null device_info
        # Or return 422 if validation requires it
        assert response.status_code in [201, 422]

    async def test_request_device_code_stores_in_database(
        self, client: AsyncClient, test_db: AsyncSession
    ):
        """Test that device code is properly stored in database."""
        response = await client.post(
            "/auth/device/code",
            json={"device_info": {"os": "macOS"}},
        )

        assert response.status_code == 201
        data = response.json()

        # Verify in database
        stmt = select(DeviceCode).where(DeviceCode.device_code == data["device_code"])
        result = await test_db.execute(stmt)
        device_code = result.scalar_one_or_none()

        assert device_code is not None
        assert device_code.user_code == data["user_code"]
        assert device_code.status == "pending"
        assert device_code.device_info == {"os": "macOS"}
        assert device_code.user_id is None


class TestDeviceAuthorization:
    """Tests for POST /auth/device/authorize endpoint."""

    async def test_authorize_device_code_success(
        self,
        client: AsyncClient,
        test_device_code: DeviceCode,
        auth_headers: dict[str, str],
        test_db: AsyncSession,
    ):
        """Test successful device code authorization by authenticated user."""
        response = await client.post(
            "/auth/device/authorize",
            json={"user_code": test_device_code.user_code},
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert "authorized successfully" in data["message"].lower()
        assert data["device_info"] == test_device_code.device_info

        # Verify status updated in database
        await test_db.refresh(test_device_code)
        assert test_device_code.status == "authorized"
        assert test_device_code.user_id is not None
        assert test_device_code.authorized_at is not None

    async def test_authorize_device_code_not_found(
        self,
        client: AsyncClient,
        auth_headers: dict[str, str],
    ):
        """Test authorization with invalid user_code."""
        response = await client.post(
            "/auth/device/authorize",
            json={"user_code": "INVALID-CODE"},
            headers=auth_headers,
        )

        assert response.status_code == 404
        data = response.json()
        assert "invalid device code" in data["detail"].lower()

    async def test_authorize_device_code_expired(
        self,
        client: AsyncClient,
        expired_device_code: DeviceCode,
        auth_headers: dict[str, str],
        test_db: AsyncSession,
    ):
        """Test authorization of expired device code."""
        response = await client.post(
            "/auth/device/authorize",
            json={"user_code": expired_device_code.user_code},
            headers=auth_headers,
        )

        assert response.status_code == 400
        data = response.json()
        assert "expired" in data["detail"].lower()

        # Verify status marked as expired
        await test_db.refresh(expired_device_code)
        assert expired_device_code.status == "expired"

    async def test_authorize_device_code_unauthorized(
        self,
        client: AsyncClient,
        test_device_code: DeviceCode,
    ):
        """Test authorization without authentication (no JWT token)."""
        response = await client.post(
            "/auth/device/authorize",
            json={"user_code": test_device_code.user_code},
            # No Authorization header
        )

        assert response.status_code == 401
        data = response.json()
        assert "authorization" in data["detail"].lower()

    async def test_authorize_already_authorized_code(
        self,
        client: AsyncClient,
        test_device_code: DeviceCode,
        auth_headers: dict[str, str],
        test_db: AsyncSession,
    ):
        """Test attempting to authorize an already-authorized code."""
        # First authorization
        response1 = await client.post(
            "/auth/device/authorize",
            json={"user_code": test_device_code.user_code},
            headers=auth_headers,
        )
        assert response1.status_code == 200

        # Attempt second authorization
        response2 = await client.post(
            "/auth/device/authorize",
            json={"user_code": test_device_code.user_code},
            headers=auth_headers,
        )

        assert response2.status_code == 400
        data = response2.json()
        assert "already been authorized" in data["detail"].lower()


class TestDeviceTokenPolling:
    """Tests for POST /auth/device/token endpoint."""

    async def test_poll_device_token_pending(
        self,
        client: AsyncClient,
        test_device_code: DeviceCode,
    ):
        """Test polling before user has authorized (pending state)."""
        response = await client.post(
            "/auth/device/token",
            json={"device_code": test_device_code.device_code},
        )

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "pending"
        assert "access_token" not in data or data.get("access_token") is None

    async def test_poll_device_token_authorized(
        self,
        client: AsyncClient,
        test_device_code: DeviceCode,
        test_user: User,
        test_db: AsyncSession,
    ):
        """Test polling after user has authorized (success case)."""
        # Authorize the device code
        test_device_code.authorize(test_user.id)
        await test_db.commit()

        # Poll for token
        response = await client.post(
            "/auth/device/token",
            json={"device_code": test_device_code.device_code},
        )

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "authorized"
        assert "access_token" in data
        assert data["access_token"] is not None
        assert data["token_type"] == "bearer"
        assert data["user_id"] == test_user.id
        assert data["email"] == test_user.email
        assert data["tier"] == test_user.tier

        # Verify session was created
        stmt = select(Session).where(Session.user_id == test_user.id)
        result = await test_db.execute(stmt)
        session = result.scalar_one_or_none()
        assert session is not None
        assert session.token == data["access_token"]

    async def test_poll_device_token_expired(
        self,
        client: AsyncClient,
        expired_device_code: DeviceCode,
    ):
        """Test polling an expired device code."""
        response = await client.post(
            "/auth/device/token",
            json={"device_code": expired_device_code.device_code},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "expired"

    async def test_poll_device_token_denied(
        self,
        client: AsyncClient,
        test_device_code: DeviceCode,
        test_db: AsyncSession,
    ):
        """Test polling a denied device code."""
        # Deny the device code
        test_device_code.deny()
        await test_db.commit()

        response = await client.post(
            "/auth/device/token",
            json={"device_code": test_device_code.device_code},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "denied"

    async def test_poll_device_token_not_found(
        self,
        client: AsyncClient,
    ):
        """Test polling with invalid device code."""
        response = await client.post(
            "/auth/device/token",
            json={"device_code": "invalid_device_code_123"},
        )

        assert response.status_code == 404
        data = response.json()
        assert "invalid device code" in data["detail"].lower()

    async def test_poll_updates_user_last_login(
        self,
        client: AsyncClient,
        test_device_code: DeviceCode,
        test_user: User,
        test_db: AsyncSession,
    ):
        """Test that successful polling updates user's last_login timestamp."""
        # Record original last_login
        original_last_login = test_user.last_login

        # Authorize and poll
        test_device_code.authorize(test_user.id)
        await test_db.commit()

        response = await client.post(
            "/auth/device/token",
            json={"device_code": test_device_code.device_code},
        )

        assert response.status_code == 200
        assert response.json()["status"] == "authorized"

        # Verify last_login was updated
        await test_db.refresh(test_user)
        assert test_user.last_login is not None
        if original_last_login:
            assert test_user.last_login > original_last_login


class TestDeviceCodeCleanup:
    """Tests for device code cleanup and expiration."""

    async def test_device_code_cleanup(
        self,
        client: AsyncClient,
        test_db: AsyncSession,
    ):
        """Test that cleanup_expired_codes removes expired codes."""
        # Create several expired codes
        for i in range(3):
            expired_code = DeviceCode(
                device_code=f"expired_code_{i}",
                user_code=f"EXP{i}-{i}{i}{i}{i}",
                status="pending",
                expires_at=datetime.now(timezone.utc) - timedelta(minutes=10),
            )
            test_db.add(expired_code)

        # Create one active code
        active_code = DeviceCode(
            device_code="active_code_999",
            user_code="ACTV-9999",
            status="pending",
            expires_at=DeviceCode.generate_expiration(minutes=5),
        )
        test_db.add(active_code)
        await test_db.commit()

        # Trigger cleanup by creating a new device code
        # (cleanup is called in the create endpoint)
        response = await client.post(
            "/auth/device/code",
            json={"device_info": {"os": "Linux"}},
        )
        assert response.status_code == 201

        # Verify expired codes were cleaned up
        stmt = select(DeviceCode).where(DeviceCode.device_code.like("expired_code_%"))
        result = await test_db.execute(stmt)
        expired_codes = result.scalars().all()

        # Cleanup should have removed them
        assert len(expired_codes) == 0

        # Active code should still exist
        stmt = select(DeviceCode).where(DeviceCode.device_code == "active_code_999")
        result = await test_db.execute(stmt)
        assert result.scalar_one_or_none() is not None

    async def test_device_code_expiration_check(self, test_db: AsyncSession):
        """Test the is_expired() method on DeviceCode model."""
        # Create code that just expired
        expired = DeviceCode(
            device_code="test_expired",
            user_code="TEST-0001",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )

        # Create code that's still valid
        valid = DeviceCode(
            device_code="test_valid",
            user_code="TEST-0002",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )

        test_db.add_all([expired, valid])
        await test_db.commit()

        assert expired.is_expired() is True
        assert valid.is_expired() is False
        assert valid.is_pending() is True
