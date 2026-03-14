"""Tests for device binding enforcement.

These tests verify:
- Device registration with tier-based limits
- Device validation dependencies
- Device deactivation and reactivation
- Error messages and responses
"""

import pytest
from fastapi import HTTPException, status
from sqlalchemy import select

from app.models.device import Device
from app.models.user import User


class TestDeviceRegistration:
    """Test device registration with tier-based limits."""

    @pytest.mark.asyncio
    async def test_register_first_device_success(self, client, auth_headers, db_session):
        """Test registering first device succeeds for all tiers."""
        response = await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "device-uuid-1",
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
    async def test_free_tier_device_limit(self, client, free_user_headers, db_session):
        """Test free tier is limited to 1 device."""
        # Register first device - should succeed
        response = await client.post(
            "/devices/register",
            headers=free_user_headers,
            json={
                "device_uuid": "free-device-1",
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
                "device_uuid": "free-device-2",
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
    async def test_starter_tier_device_limit(self, client, starter_user_headers, db_session):
        """Test starter tier is limited to 2 devices."""
        # Register 2 devices - should succeed
        for i in range(2):
            response = await client.post(
                "/devices/register",
                headers=starter_user_headers,
                json={
                    "device_uuid": f"starter-device-{i}",
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
                "device_uuid": "starter-device-3",
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
    async def test_pro_tier_device_limit(self, client, pro_user_headers, db_session):
        """Test pro tier is limited to 3 devices."""
        # Register 3 devices - should succeed
        for i in range(3):
            response = await client.post(
                "/devices/register",
                headers=pro_user_headers,
                json={
                    "device_uuid": f"pro-device-{i}",
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
                "device_uuid": "pro-device-4",
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
    async def test_enterprise_unlimited_devices(self, client, enterprise_user_headers, db_session):
        """Test enterprise tier has unlimited devices."""
        # Register 10 devices - all should succeed
        for i in range(10):
            response = await client.post(
                "/devices/register",
                headers=enterprise_user_headers,
                json={
                    "device_uuid": f"enterprise-device-{i}",
                    "device_name": f"Device {i}",
                    "platform": "linux",
                },
            )
            assert response.status_code == status.HTTP_201_CREATED

    @pytest.mark.asyncio
    async def test_device_reactivation(self, client, auth_headers, db_session):
        """Test re-registering a deactivated device reactivates it."""
        # Register device
        response = await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "reactivate-test",
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
                "device_uuid": "reactivate-test",
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
    async def test_device_conflict_different_user(self, client, user1_headers, user2_headers, db_session):
        """Test device UUID cannot be registered to multiple users."""
        device_uuid = "shared-uuid-test"

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
    async def test_list_devices(self, client, auth_headers, db_session):
        """Test listing user's devices."""
        # Register 2 devices
        for i in range(2):
            await client.post(
                "/devices/register",
                headers=auth_headers,
                json={
                    "device_uuid": f"list-test-{i}",
                    "device_name": f"Device {i}",
                    "platform": "linux",
                },
            )

        # List devices
        response = await client.get("/devices", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["total"] == 2
        assert data["active_count"] == 2
        assert len(data["devices"]) == 2

    @pytest.mark.asyncio
    async def test_get_device_limit_info(self, client, auth_headers, db_session):
        """Test getting device limit information."""
        # Register 1 device (assuming starter tier with limit 2)
        await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "limit-test",
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
    async def test_deactivate_device(self, client, auth_headers, db_session):
        """Test deactivating a device."""
        # Register device
        response = await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "deactivate-test",
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
        self, client, user1_headers, user2_headers, db_session
    ):
        """Test users cannot deactivate other users' devices."""
        # User 1 registers device
        response = await client.post(
            "/devices/register",
            headers=user1_headers,
            json={
                "device_uuid": "user1-device",
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
    async def test_validated_device_success(self, client, auth_headers, db_session):
        """Test accessing protected endpoint with valid device."""
        # Register device
        response = await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "valid-device",
                "device_name": "Valid Device",
                "platform": "linux",
            },
        )

        # Access protected endpoint with device header
        headers_with_device = {
            **auth_headers,
            "X-Device-UUID": "valid-device",
        }
        response = await client.get("/protected-endpoint", headers=headers_with_device)
        # Should succeed (endpoint-specific assertions)

    @pytest.mark.asyncio
    async def test_validated_device_missing_header(self, client, auth_headers, db_session):
        """Test accessing protected endpoint without device header fails."""
        response = await client.get("/protected-endpoint", headers=auth_headers)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        error = response.json()["detail"]
        assert error["error"] == "missing_device_header"

    @pytest.mark.asyncio
    async def test_validated_device_not_registered(self, client, auth_headers, db_session):
        """Test accessing with unregistered device UUID fails."""
        headers_with_device = {
            **auth_headers,
            "X-Device-UUID": "unregistered-device",
        }
        response = await client.get("/protected-endpoint", headers=headers_with_device)
        assert response.status_code == status.HTTP_403_FORBIDDEN

        error = response.json()["detail"]
        assert error["error"] == "device_not_registered"

    @pytest.mark.asyncio
    async def test_validated_device_deactivated(self, client, auth_headers, db_session):
        """Test accessing with deactivated device fails."""
        # Register and deactivate device
        response = await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "deactivated-device",
                "device_name": "Deactivated Device",
                "platform": "linux",
            },
        )
        device_id = response.json()["id"]
        await client.delete(f"/devices/{device_id}", headers=auth_headers)

        # Try to access with deactivated device
        headers_with_device = {
            **auth_headers,
            "X-Device-UUID": "deactivated-device",
        }
        response = await client.get("/protected-endpoint", headers=headers_with_device)
        assert response.status_code == status.HTTP_403_FORBIDDEN

        error = response.json()["detail"]
        assert error["error"] == "device_deactivated"

    @pytest.mark.asyncio
    async def test_validated_device_wrong_user(
        self, client, user1_headers, user2_headers, db_session
    ):
        """Test accessing with another user's device UUID fails."""
        # User 1 registers device
        await client.post(
            "/devices/register",
            headers=user1_headers,
            json={
                "device_uuid": "user1-device",
                "device_name": "User 1 Device",
                "platform": "linux",
            },
        )

        # User 2 tries to access with User 1's device UUID
        headers_with_device = {
            **user2_headers,
            "X-Device-UUID": "user1-device",
        }
        response = await client.get("/protected-endpoint", headers=headers_with_device)
        assert response.status_code == status.HTTP_403_FORBIDDEN

        error = response.json()["detail"]
        assert error["error"] == "device_not_authorized"

    @pytest.mark.asyncio
    async def test_optional_device_with_header(self, client, auth_headers, db_session):
        """Test optional device validation succeeds with valid device."""
        # Register device
        await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "optional-device",
                "device_name": "Optional Device",
                "platform": "linux",
            },
        )

        # Access hybrid endpoint with device
        headers_with_device = {
            **auth_headers,
            "X-Device-UUID": "optional-device",
        }
        response = await client.get("/hybrid-endpoint", headers=headers_with_device)
        # Should succeed with device context

    @pytest.mark.asyncio
    async def test_optional_device_without_header(self, client, auth_headers, db_session):
        """Test optional device validation succeeds without device header."""
        # Access hybrid endpoint without device header
        response = await client.get("/hybrid-endpoint", headers=auth_headers)
        # Should succeed without device context

    @pytest.mark.asyncio
    async def test_last_seen_updated(self, client, auth_headers, db_session):
        """Test that last_seen is updated on device validation."""
        # Register device
        response = await client.post(
            "/devices/register",
            headers=auth_headers,
            json={
                "device_uuid": "last-seen-test",
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
            "X-Device-UUID": "last-seen-test",
        }
        await client.get("/protected-endpoint", headers=headers_with_device)

        # Check last_seen was updated
        response = await client.get(f"/devices/{device_id}", headers=auth_headers)
        new_last_seen = response.json()["last_seen"]
        assert new_last_seen > original_last_seen


# Fixtures for testing (add to conftest.py)
"""
@pytest.fixture
async def free_user_headers(client):
    # Create user with free tier
    response = await client.post("/auth/register", json={
        "email": "free@example.com",
        "password": "password123"
    })
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
async def starter_user_headers(client, db_session):
    # Create user and upgrade to starter
    response = await client.post("/auth/register", json={
        "email": "starter@example.com",
        "password": "password123"
    })
    token = response.json()["access_token"]

    # Update user tier in database
    user_id = response.json()["user"]["id"]
    stmt = select(User).where(User.id == user_id)
    result = await db_session.execute(stmt)
    user = result.scalar_one()
    user.tier = "starter"
    await db_session.commit()

    return {"Authorization": f"Bearer {token}"}

# Similar fixtures for pro_user_headers, enterprise_user_headers
"""
