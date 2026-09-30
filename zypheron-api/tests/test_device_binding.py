"""Tests for device binding enforcement.

These tests verify:
- Device registration with tier-based limits
- Device validation dependencies
- Device deactivation and reactivation
- Error messages and responses
"""

import pytest
from fastapi import APIRouter, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.dependencies import OptionalDevice, ValidatedDevice
from app.main import app
from app.models.session import Session
from app.models.user import User
from app.routers.auth import hash_token


# No production route uses the device dependencies yet; mount two probes so the
# dependencies themselves are exercised through the real request pipeline.
_probe = APIRouter()


@_probe.get("/protected-endpoint")
async def _protected(device: ValidatedDevice) -> dict:
    return {"device_uuid": device.device_uuid}


@_probe.get("/hybrid-endpoint")
async def _hybrid(device: OptionalDevice) -> dict:
    return {"device_uuid": device.device_uuid if device else None}


app.include_router(_probe)


async def _headers_for(db: AsyncSession, email: str, tier: str) -> dict[str, str]:
    user = User(email=email, password_hash=hash_password("testpass123"), tier=tier, is_active=True)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    token = create_access_token({"sub": str(user.id), "email": user.email})
    db.add(Session(user_id=user.id, token=hash_token(token)))
    await db.commit()
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def free_user_headers(test_db):
    return await _headers_for(test_db, "free@example.com", "free")


@pytest.fixture
async def starter_user_headers(test_db):
    return await _headers_for(test_db, "starter@example.com", "starter")


@pytest.fixture
async def pro_user_headers(test_db):
    return await _headers_for(test_db, "pro@example.com", "pro")


@pytest.fixture
async def enterprise_user_headers(test_db):
    return await _headers_for(test_db, "enterprise@example.com", "enterprise")


@pytest.fixture
async def user1_headers(test_db):
    return await _headers_for(test_db, "user1@example.com", "pro")


@pytest.fixture
async def user2_headers(test_db):
    return await _headers_for(test_db, "user2@example.com", "pro")


class TestDeviceRegistration:
    """Test device registration with tier-based limits."""

    @pytest.mark.asyncio
    async def test_register_first_device_success(self, client, auth_headers):
        """Test registering first device succeeds for all tiers."""
        response = await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "uuid-0000-device-uuid-1",
                "device_name": "Test Device",
                "platform": "linux",
                "hostname": "test-machine",
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["device_name"] == "Test Device"
        assert data["platform"] == "linux"
        assert data["is_active"] is True

    @pytest.mark.asyncio
    async def test_free_tier_device_limit(self, client, free_user_headers):
        """Test free tier is limited to 1 device."""
        # Register first device - should succeed
        response = await client.post(
            "/devices/register",
            headers=free_user_headers,
            json={
                "device_uuid": "uuid-0000-free-device-1",
                "device_name": "Device 1",
                "platform": "linux",
            },
        )
        assert response.status_code == status.HTTP_201_CREATED

        # Try to register second device - should fail
        response = await client.post(
            "/devices/register",
            headers=free_user_headers,
            json={
                "device_uuid": "uuid-0000-free-device-2",
                "device_name": "Device 2",
                "platform": "darwin",
            },
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        error = response.json()["detail"]
        assert error["error"] == "device_limit_reached"
        assert error["tier"] == "free"
        assert error["limit"] == 1
        assert error["current"] == 1
        assert len(error["devices"]) == 1
        assert "Upgrade to Starter" in error["message"]

    @pytest.mark.asyncio
    async def test_starter_tier_device_limit(self, client, starter_user_headers):
        """Test starter tier is limited to 2 devices."""
        # Register 2 devices - should succeed
        for i in range(2):
            response = await client.post(
                "/devices/register",
                headers=starter_user_headers,
                json={
                    "device_uuid": f"uuid-0000-starter-device-{i}",
                    "device_name": f"Device {i}",
                    "platform": "linux",
                },
            )
            assert response.status_code == status.HTTP_201_CREATED

        # Try to register third device - should fail
        response = await client.post(
            "/devices/register",
            headers=starter_user_headers,
            json={
                "device_uuid": "uuid-0000-starter-device-3",
                "device_name": "Device 3",
                "platform": "win32",
            },
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        error = response.json()["detail"]
        assert error["tier"] == "starter"
        assert error["limit"] == 2
        assert error["current"] == 2
        assert "Upgrade to Pro" in error["message"]

    @pytest.mark.asyncio
    async def test_pro_tier_device_limit(self, client, pro_user_headers):
        """Test pro tier is limited to 3 devices."""
        # Register 3 devices - should succeed
        for i in range(3):
            response = await client.post(
                "/devices/register",
                headers=pro_user_headers,
                json={
                    "device_uuid": f"uuid-0000-pro-device-{i}",
                    "device_name": f"Device {i}",
                    "platform": "linux",
                },
            )
            assert response.status_code == status.HTTP_201_CREATED

        # Try to register fourth device - should fail
        response = await client.post(
            "/devices/register",
            headers=pro_user_headers,
            json={
                "device_uuid": "uuid-0000-pro-device-4",
                "device_name": "Device 4",
                "platform": "darwin",
            },
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        error = response.json()["detail"]
        assert error["tier"] == "pro"
        assert error["limit"] == 3
        assert error["current"] == 3
        assert "Upgrade to Enterprise" in error["message"]

    @pytest.mark.asyncio
    async def test_enterprise_unlimited_devices(self, client, enterprise_user_headers):
        """Test enterprise tier has unlimited devices."""
        # Register 10 devices - all should succeed
        for i in range(10):
            response = await client.post(
                "/devices/register",
                headers=enterprise_user_headers,
                json={
                    "device_uuid": f"uuid-0000-enterprise-device-{i}",
                    "device_name": f"Device {i}",
                    "platform": "linux",
                },
            )
            assert response.status_code == status.HTTP_201_CREATED

    @pytest.mark.asyncio
    async def test_device_reactivation(self, client, auth_headers):
        """Test re-registering a deactivated device reactivates it."""
        # Register device
        response = await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "uuid-0000-reactivate-test",
                "device_name": "Test Device",
                "platform": "linux",
            },
        )
        device_id = response.json()["id"]

        # Deactivate device
        response = await client.delete(f"/devices/{device_id}", headers=auth_headers)
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Re-register same device - should reactivate
        response = await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "uuid-0000-reactivate-test",
                "device_name": "Reactivated Device",
                "platform": "darwin",
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["id"] == device_id  # Same device
        assert data["is_active"] is True
        assert data["device_name"] == "Reactivated Device"

    @pytest.mark.asyncio
    async def test_device_conflict_different_user(self, client, user1_headers, user2_headers):
        """Test device UUID cannot be registered to multiple users."""
        device_uuid = "uuid-0000-shared-uuid-test"

        # User 1 registers device
        response = await client.post(
            "/devices/register",
            headers=user1_headers,
            json={
                "device_uuid": device_uuid,
                "device_name": "User 1 Device",
                "platform": "linux",
            },
        )
        assert response.status_code == status.HTTP_201_CREATED

        # User 2 tries to register same UUID - should fail
        response = await client.post(
            "/devices/register",
            headers=user2_headers,
            json={
                "device_uuid": device_uuid,
                "device_name": "User 2 Device",
                "platform": "linux",
            },
        )

        assert response.status_code == status.HTTP_409_CONFLICT
        assert "already registered to another user" in response.json()["detail"]


class TestDeviceManagement:
    """Test device management endpoints."""

    @pytest.mark.asyncio
    async def test_list_devices(self, client, starter_user_headers):
        """Test listing user's devices (starter tier allows 2)."""
        # Register 2 devices
        for i in range(2):
            await client.post(
                "/devices/register",
                headers=starter_user_headers,
                json={
                    "device_uuid": f"uuid-0000-list-test-{i}",
                    "device_name": f"Device {i}",
                    "platform": "linux",
                },
            )

        # List devices
        response = await client.get("/devices", headers=starter_user_headers)
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["total"] == 2
        assert data["active_count"] == 2
        assert len(data["devices"]) == 2

    @pytest.mark.asyncio
    async def test_get_device_limit_info(self, client, auth_headers):
        """Test getting device limit information."""
        # Register 1 device
        await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "uuid-0000-limit-test",
                "device_name": "Test Device",
                "platform": "linux",
            },
        )

        # Get limit info
        response = await client.get("/devices/limit", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert "tier" in data
        assert "limit" in data
        assert "current" in data
        assert "remaining" in data
        assert "can_add" in data
        assert data["current"] == 1

    @pytest.mark.asyncio
    async def test_deactivate_device(self, client, auth_headers):
        """Test deactivating a device."""
        # Register device
        response = await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "uuid-0000-deactivate-test",
                "device_name": "Test Device",
                "platform": "linux",
            },
        )
        device_id = response.json()["id"]

        # Deactivate
        response = await client.delete(f"/devices/{device_id}", headers=auth_headers)
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Verify device is inactive
        response = await client.get(f"/devices/{device_id}", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["is_active"] is False

    @pytest.mark.asyncio
    async def test_cannot_deactivate_other_user_device(
        self, client, user1_headers, user2_headers
    ):
        """Test users cannot deactivate other users' devices."""
        # User 1 registers device
        response = await client.post(
            "/devices/register",
            headers=user1_headers,
            json={
                "device_uuid": "uuid-0000-user1-device",
                "device_name": "User 1 Device",
                "platform": "linux",
            },
        )
        device_id = response.json()["id"]

        # User 2 tries to deactivate User 1's device
        response = await client.delete(f"/devices/{device_id}", headers=user2_headers)
        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestDeviceValidation:
    """Test device validation dependencies."""

    @pytest.mark.asyncio
    async def test_validated_device_success(self, client, auth_headers):
        """Test accessing protected endpoint with valid device."""
        # Register device
        response = await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "uuid-0000-valid-device",
                "device_name": "Valid Device",
                "platform": "linux",
            },
        )

        # Access protected endpoint with device header
        headers_with_device = {
            **auth_headers,
            "X-Device-UUID": "uuid-0000-valid-device",
        }
        response = await client.get("/protected-endpoint", headers=headers_with_device)
        # Should succeed (endpoint-specific assertions)

    @pytest.mark.asyncio
    async def test_validated_device_missing_header(self, client, auth_headers):
        """Test accessing protected endpoint without device header fails."""
        response = await client.get("/protected-endpoint", headers=auth_headers)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        error = response.json()["detail"]
        assert error["error"] == "missing_device_header"

    @pytest.mark.asyncio
    async def test_validated_device_not_registered(self, client, auth_headers):
        """Test accessing with unregistered device UUID fails."""
        headers_with_device = {
            **auth_headers,
            "X-Device-UUID": "uuid-0000-unregistered-device",
        }
        response = await client.get("/protected-endpoint", headers=headers_with_device)
        assert response.status_code == status.HTTP_403_FORBIDDEN

        error = response.json()["detail"]
        assert error["error"] == "device_not_registered"

    @pytest.mark.asyncio
    async def test_validated_device_deactivated(self, client, auth_headers):
        """Test accessing with deactivated device fails."""
        # Register and deactivate device
        response = await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "uuid-0000-deactivated-device",
                "device_name": "Deactivated Device",
                "platform": "linux",
            },
        )
        device_id = response.json()["id"]
        await client.delete(f"/devices/{device_id}", headers=auth_headers)

        # Try to access with deactivated device
        headers_with_device = {
            **auth_headers,
            "X-Device-UUID": "uuid-0000-deactivated-device",
        }
        response = await client.get("/protected-endpoint", headers=headers_with_device)
        assert response.status_code == status.HTTP_403_FORBIDDEN

        error = response.json()["detail"]
        assert error["error"] == "device_deactivated"

    @pytest.mark.asyncio
    async def test_validated_device_wrong_user(
        self, client, user1_headers, user2_headers
    ):
        """Test accessing with another user's device UUID fails."""
        # User 1 registers device
        await client.post(
            "/devices/register",
            headers=user1_headers,
            json={
                "device_uuid": "uuid-0000-user1-device",
                "device_name": "User 1 Device",
                "platform": "linux",
            },
        )

        # User 2 tries to access with User 1's device UUID
        headers_with_device = {
            **user2_headers,
            "X-Device-UUID": "uuid-0000-user1-device",
        }
        response = await client.get("/protected-endpoint", headers=headers_with_device)
        assert response.status_code == status.HTTP_403_FORBIDDEN

        error = response.json()["detail"]
        assert error["error"] == "device_not_authorized"

    @pytest.mark.asyncio
    async def test_optional_device_with_header(self, client, auth_headers):
        """Test optional device validation succeeds with valid device."""
        # Register device
        await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "uuid-0000-optional-device",
                "device_name": "Optional Device",
                "platform": "linux",
            },
        )

        # Access hybrid endpoint with device
        headers_with_device = {
            **auth_headers,
            "X-Device-UUID": "uuid-0000-optional-device",
        }
        response = await client.get("/hybrid-endpoint", headers=headers_with_device)
        # Should succeed with device context

    @pytest.mark.asyncio
    async def test_optional_device_without_header(self, client, auth_headers):
        """Test optional device validation succeeds without device header."""
        # Access hybrid endpoint without device header
        response = await client.get("/hybrid-endpoint", headers=auth_headers)
        # Should succeed without device context

    @pytest.mark.asyncio
    async def test_last_seen_updated(self, client, auth_headers):
        """Test that last_seen is updated on device validation."""
        # Register device
        response = await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "uuid-0000-last-seen-test",
                "device_name": "Last Seen Test",
                "platform": "linux",
            },
        )
        device_id = response.json()["id"]
        original_last_seen = response.json()["last_seen"]

        # Wait a moment
        import asyncio
        await asyncio.sleep(1)

        # Access endpoint with device (triggers validation)
        headers_with_device = {
            **auth_headers,
            "X-Device-UUID": "uuid-0000-last-seen-test",
        }
        await client.get("/protected-endpoint", headers=headers_with_device)

        # Check last_seen was updated
        response = await client.get(f"/devices/{device_id}", headers=auth_headers)
        new_last_seen = response.json()["last_seen"]
        assert new_last_seen > original_last_seen
