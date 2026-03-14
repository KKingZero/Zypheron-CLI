"""Device binding dependencies for API endpoint protection.

These dependencies enforce that requests come from registered, active devices.
Use these on endpoints that should only be accessible from authorized devices.
"""

from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.device import Device
from app.models.user import User
from app.routers.auth import CurrentUser


async def get_device_from_header(
    x_device_uuid: str | None = Header(None, description="Device UUID from CLI"),
    current_user: CurrentUser = Depends(),
    db: AsyncSession = Depends(get_db),
) -> Device:
    """Validate that the request comes from a registered, active device.

    This dependency checks the X-Device-UUID header and validates:
    1. The header is present
    2. A device with that UUID exists
    3. The device belongs to the current user
    4. The device is active (not deactivated)

    Args:
        x_device_uuid: Device UUID from request header
        current_user: Currently authenticated user
        db: Database session

    Returns:
        Validated Device instance

    Raises:
        HTTPException 400: If device UUID header is missing
        HTTPException 403: If device is not registered, belongs to another user,
                          or has been deactivated

    Security Notes:
        - Prevents users from accessing API with deactivated devices
        - Prevents device UUID spoofing (validates ownership)
        - Returns 403 instead of 404 to avoid leaking device existence
    """
    # Check if device UUID header is present
    if not x_device_uuid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "missing_device_header",
                "message": "X-Device-UUID header is required for this endpoint",
                "hint": "Register your device first using POST /devices/register",
            },
        )

    # Find device by UUID
    stmt = select(Device).where(Device.device_uuid == x_device_uuid)
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()

    # Validate device exists
    if not device:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "device_not_registered",
                "message": "This device is not registered to your account",
                "hint": "Register your device using POST /devices/register",
            },
        )

    # Validate device belongs to current user (prevent spoofing)
    if device.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "device_not_authorized",
                "message": "This device is registered to another user",
                "hint": "Each device can only be used with the account it was registered to",
            },
        )

    # Validate device is active
    if not device.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "device_deactivated",
                "message": "This device has been deactivated",
                "hint": "Reactivate your device by registering it again with POST /devices/register",
            },
        )

    # Update last_seen timestamp for device activity tracking
    device.update_last_seen()
    await db.commit()

    return device


async def get_optional_device(
    x_device_uuid: str | None = Header(None, description="Device UUID from CLI"),
    current_user: CurrentUser = Depends(),
    db: AsyncSession = Depends(get_db),
) -> Device | None:
    """Optional device validation - returns None if header is missing.

    Use this for endpoints that support both CLI (with device) and web (without device).

    Args:
        x_device_uuid: Device UUID from request header (optional)
        current_user: Currently authenticated user
        db: Database session

    Returns:
        Device instance if header present and valid, None otherwise

    Raises:
        HTTPException 403: If device UUID is provided but invalid

    Security Notes:
        - Only validates if header is present
        - Still enforces ownership and active status if UUID provided
        - Useful for hybrid endpoints
    """
    # If no device UUID header, return None (web access)
    if not x_device_uuid:
        return None

    # If header present, validate it (reuse strict validation logic)
    stmt = select(Device).where(Device.device_uuid == x_device_uuid)
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()

    if not device or device.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "device_not_authorized",
                "message": "Invalid or unauthorized device UUID",
            },
        )

    if not device.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "device_deactivated",
                "message": "This device has been deactivated",
            },
        )

    # Update last_seen
    device.update_last_seen()
    await db.commit()

    return device


# Type aliases for easy dependency injection
ValidatedDevice = Annotated[Device, Depends(get_device_from_header)]
OptionalDevice = Annotated[Device | None, Depends(get_optional_device)]
