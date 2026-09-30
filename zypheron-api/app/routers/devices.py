"""Device management router for CLI device registration and tracking.

Supports:
- Device registration with tier-based limits
- Listing user devices
- Device deactivation
- Device limit enforcement
"""

import asyncio
from datetime import datetime, timezone
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.device import Device
from app.models.user import User
from app.routers.auth import CurrentUser
from app.schemas.device import (
    DEVICE_LIMITS,
    DeviceCreate,
    DeviceLimitInfo,
    DeviceListResponse,
    DeviceResponse,
    DeviceUpdate,
    get_device_limit,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/devices", tags=["Devices"])


async def _register_device_impl(
    request: DeviceCreate,
    current_user: CurrentUser,
    db: AsyncSession,
) -> DeviceResponse:
    """Internal implementation of device registration with row-level locking.

    This function implements atomic device registration using SELECT FOR UPDATE
    to prevent race conditions when multiple concurrent requests attempt to
    register devices and bypass tier limits.

    SECURITY: Uses database row-level locks to ensure device count is accurate
    even under high concurrency. This prevents the TOCTOU vulnerability where
    a user could register more devices than their tier allows by sending
    concurrent requests.

    Args:
        request: Device registration request
        current_user: Currently authenticated user
        db: Database session

    Returns:
        DeviceResponse with registered device information

    Raises:
        HTTPException: If device limit exceeded or device already registered
        OperationalError: On deadlock (caller should retry)
    """
    # Use nested transaction for atomic operation with proper rollback on error
    async with db.begin_nested():
        # CRITICAL: Lock ALL user's devices with SELECT FOR UPDATE
        # This prevents concurrent transactions from reading/modifying these rows
        # until this transaction completes, ensuring accurate device count
        lock_stmt = (
            select(Device)
            .where(
                Device.user_id == current_user.id,
                Device.is_active == True,
            )
            .with_for_update()  # PostgreSQL: FOR UPDATE lock, SQLite: no-op (single writer)
        )

        result = await db.execute(lock_stmt)
        active_devices = result.scalars().all()
        active_device_count = len(active_devices)

        # Check if device with this UUID already exists (within the lock)
        existing_device = next(
            (d for d in active_devices if d.device_uuid == request.device_uuid),
            None
        )

        if existing_device:
            # Device already registered to this user - update and return
            existing_device.device_name = request.device_name
            existing_device.platform = request.platform
            existing_device.hostname = request.hostname
            existing_device.update_last_seen()
            await db.flush()
            await db.refresh(existing_device)

            logger.info(
                "device_updated",
                user_id=current_user.id,
                device_id=existing_device.id,
                device_uuid=request.device_uuid,
            )

            return DeviceResponse.model_validate(existing_device)

        # Any other row with this UUID (also lock it). Active or not: device_uuid
        # is globally unique, so another user's active device must be a 409 too,
        # not an IntegrityError on insert.
        uuid_stmt = (
            select(Device)
            .where(Device.device_uuid == request.device_uuid)
            .with_for_update()
        )
        uuid_result = await db.execute(uuid_stmt)
        uuid_device = uuid_result.scalar_one_or_none()

        if uuid_device and uuid_device.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Device already registered to another user",
            )

        # Check device limit (within the lock, so count is guaranteed accurate)
        device_limit = get_device_limit(current_user.tier)

        if active_device_count >= device_limit:
            # Build upgrade suggestion
            upgrade_suggestions = {
                "free": "Upgrade to Starter for 2 devices",
                "starter": "Upgrade to Pro for 3 devices",
                "pro": "Upgrade to Enterprise for unlimited devices",
            }
            upgrade_msg = upgrade_suggestions.get(current_user.tier, "")

            # Build detailed error message
            tier_display = current_user.tier.capitalize()
            error_message = (
                f"Device limit reached ({active_device_count}/{device_limit} for {tier_display} tier). "
                f"{upgrade_msg}, or deactivate an existing device."
            )

            # Include list of current devices (limit to 10 to avoid leaking too much info)
            devices_list = [
                {
                    "id": device.id,
                    "device_name": device.device_name,
                    "platform": device.platform,
                    # Don't include full hostname for security
                    "last_seen": device.last_seen.isoformat(),
                    "created_at": device.created_at.isoformat(),
                }
                for device in active_devices[:10]
            ]

            logger.warning(
                "device_limit_reached",
                user_id=current_user.id,
                tier=current_user.tier,
                limit=device_limit,
                current=active_device_count,
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "message": error_message,
                    "error": "device_limit_reached",
                    "tier": current_user.tier,
                    "limit": device_limit,
                    "current": active_device_count,
                    "devices": devices_list,
                    "actions": {
                        "deactivate": "DELETE /devices/{device_id} to free up a slot",
                        "upgrade": upgrade_msg if upgrade_msg else None,
                    },
                },
            )

        if uuid_device:
            # Reactivate user's own inactive device (after the limit check, so
            # reactivation can't exceed the tier's device limit)
            uuid_device.is_active = True
            uuid_device.device_name = request.device_name
            uuid_device.platform = request.platform
            uuid_device.hostname = request.hostname
            uuid_device.update_last_seen()
            await db.flush()
            await db.refresh(uuid_device)

            logger.info(
                "device_reactivated",
                user_id=current_user.id,
                device_id=uuid_device.id,
                device_uuid=request.device_uuid,
            )

            return DeviceResponse.model_validate(uuid_device)

        # Create new device (within the lock, so count check is still valid)
        new_device = Device(
            user_id=current_user.id,
            device_uuid=request.device_uuid,
            device_name=request.device_name,
            platform=request.platform,
            hostname=request.hostname,
            is_active=True,
        )
        new_device.update_last_seen()

        db.add(new_device)
        await db.flush()
        await db.refresh(new_device)

    # Commit the transaction (nested transaction auto-commits on exit)
    await db.commit()

    logger.info(
        "device_registered",
        user_id=current_user.id,
        device_id=new_device.id,
        device_uuid=request.device_uuid,
        tier=current_user.tier,
        device_count=active_device_count + 1,
    )

    return DeviceResponse.model_validate(new_device)


@router.post("/register", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def register_device(
    request: DeviceCreate,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> DeviceResponse:
    """Register a new CLI device for the current user with race condition protection.

    Enforces device limits based on user's subscription tier:
    - Free: 1 device
    - Starter: 2 devices
    - Pro: 3 devices
    - Enterprise: 500 devices

    SECURITY: Uses database row-level locking (SELECT FOR UPDATE) to prevent
    race conditions where concurrent requests could bypass device limits.
    Implements automatic retry on deadlock with exponential backoff.

    Args:
        request: Device registration request
        current_user: Currently authenticated user
        db: Database session

    Returns:
        DeviceResponse with registered device information

    Raises:
        HTTPException: If device limit exceeded or device already registered
    """
    # Maximum retry attempts for deadlock scenarios
    MAX_RETRIES = 3

    for attempt in range(MAX_RETRIES):
        try:
            return await _register_device_impl(request, current_user, db)
        except OperationalError as e:
            # Check if this is a deadlock error
            error_str = str(e).lower()
            is_deadlock = "deadlock" in error_str or "lock timeout" in error_str

            # Only retry on deadlock, and only if we have attempts left
            if is_deadlock and attempt < MAX_RETRIES - 1:
                # Exponential backoff: 50ms, 100ms, 200ms
                backoff_ms = 50 * (2 ** attempt)
                await asyncio.sleep(backoff_ms / 1000.0)

                logger.warning(
                    "device_registration_deadlock_retry",
                    user_id=current_user.id,
                    attempt=attempt + 1,
                    max_retries=MAX_RETRIES,
                    backoff_ms=backoff_ms,
                )
                continue

            # Not a deadlock or out of retries - propagate error
            logger.error(
                "device_registration_database_error",
                user_id=current_user.id,
                error=str(e),
                is_deadlock=is_deadlock,
            )
            raise

    # Should never reach here, but satisfy type checker
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to register device after multiple retries",
    )


@router.get("", response_model=DeviceListResponse)
async def list_devices(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
    include_inactive: bool = False,
) -> DeviceListResponse:
    """List all devices for the current user.

    Args:
        current_user: Currently authenticated user
        db: Database session
        include_inactive: Whether to include inactive devices (default: False)

    Returns:
        DeviceListResponse with list of devices and metadata
    """
    # Build query
    stmt = select(Device).where(Device.user_id == current_user.id)

    if not include_inactive:
        stmt = stmt.where(Device.is_active == True)

    stmt = stmt.order_by(Device.created_at.desc())

    # Execute query
    result = await db.execute(stmt)
    devices = result.scalars().all()

    # Count active devices
    active_count = sum(1 for d in devices if d.is_active)

    # Get device limit
    device_limit = get_device_limit(current_user.tier)

    return DeviceListResponse(
        devices=[DeviceResponse.model_validate(d) for d in devices],
        total=len(devices),
        active_count=active_count,
        device_limit=device_limit,
    )


# Declared before /{device_id}, which would otherwise capture "limit" (422).
@router.get("/limit", response_model=DeviceLimitInfo)
async def get_device_limit_info(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> DeviceLimitInfo:
    """Get device limit information for the current user's tier.

    Shows current active device count versus the tier limit.

    Args:
        current_user: Currently authenticated user
        db: Database session

    Returns:
        DeviceLimitInfo with limit and usage information
    """
    # Count active devices for user
    stmt = select(func.count()).select_from(Device).where(
        Device.user_id == current_user.id,
        Device.is_active == True,
    )
    result = await db.execute(stmt)
    active_count = result.scalar_one()

    # Get device limit for user's tier
    limit = get_device_limit(current_user.tier)

    # Calculate remaining slots
    remaining = max(0, limit - active_count)
    can_add = active_count < limit

    return DeviceLimitInfo(
        tier=current_user.tier,  # type: ignore
        limit=limit,
        current=active_count,
        remaining=remaining,
        can_add=can_add,
    )


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: int,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> DeviceResponse:
    """Get details for a specific device.

    Args:
        device_id: Device ID to retrieve
        current_user: Currently authenticated user
        db: Database session

    Returns:
        DeviceResponse with device information

    Raises:
        HTTPException: If device not found or doesn't belong to user
    """
    stmt = select(Device).where(
        Device.id == device_id,
        Device.user_id == current_user.id,
    )
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    return DeviceResponse.model_validate(device)


@router.patch("/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: int,
    request: DeviceUpdate,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> DeviceResponse:
    """Update device information.

    Args:
        device_id: Device ID to update
        request: Device update request
        current_user: Currently authenticated user
        db: Database session

    Returns:
        DeviceResponse with updated device information

    Raises:
        HTTPException: If device not found or doesn't belong to user
    """
    stmt = select(Device).where(
        Device.id == device_id,
        Device.user_id == current_user.id,
    )
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    # Update fields if provided
    if request.device_name is not None:
        device.device_name = request.device_name

    if request.is_active is not None:
        device.is_active = request.is_active

    await db.commit()
    await db.refresh(device)

    return DeviceResponse.model_validate(device)


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def deactivate_device(
    device_id: int,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Deactivate (soft delete) a device.

    Sets device as inactive rather than deleting from database.

    Args:
        device_id: Device ID to deactivate
        current_user: Currently authenticated user
        db: Database session

    Raises:
        HTTPException: If device not found or doesn't belong to user
    """
    stmt = select(Device).where(
        Device.id == device_id,
        Device.user_id == current_user.id,
    )
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    # Soft delete by marking inactive
    device.is_active = False
    await db.commit()


@router.post("/{device_id}/ping", response_model=DeviceResponse)
async def ping_device(
    device_id: int,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> DeviceResponse:
    """Update device's last_seen timestamp (heartbeat).

    Used by CLI to signal activity and keep device active.

    Args:
        device_id: Device ID to ping
        current_user: Currently authenticated user
        db: Database session

    Returns:
        DeviceResponse with updated device information

    Raises:
        HTTPException: If device not found or doesn't belong to user
    """
    stmt = select(Device).where(
        Device.id == device_id,
        Device.user_id == current_user.id,
    )
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    # Update last_seen timestamp
    device.update_last_seen()
    await db.commit()
    await db.refresh(device)

    return DeviceResponse.model_validate(device)
