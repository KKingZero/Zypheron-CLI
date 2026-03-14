"""Examples of using device binding enforcement in API endpoints.

This file demonstrates how to use the device validation dependencies
to protect endpoints and ensure they're only accessible from registered devices.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies import OptionalDevice, ValidatedDevice
from app.routers.auth import CurrentUser

# Example router
router = APIRouter(prefix="/examples", tags=["Examples"])


# EXAMPLE 1: Strict device binding (CLI-only endpoint)
@router.get("/cli-only")
async def cli_only_endpoint(
    current_user: CurrentUser,
    device: ValidatedDevice,  # This enforces device binding
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Example endpoint that requires a validated device.

    This endpoint can ONLY be accessed from registered, active devices.
    Web users will get a 400 error (missing header).

    Use this for:
    - Scan operations (CLI-initiated)
    - Device-specific features
    - Operations that require device context
    """
    return {
        "message": "Success! This request came from a validated device",
        "user": {
            "id": current_user.id,
            "email": current_user.email,
            "tier": current_user.tier,
        },
        "device": {
            "id": device.id,
            "name": device.device_name,
            "platform": device.platform,
            "hostname": device.hostname,
        },
    }


# EXAMPLE 2: Optional device binding (Hybrid endpoint)
@router.get("/hybrid")
async def hybrid_endpoint(
    current_user: CurrentUser,
    device: OptionalDevice,  # Device is optional
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Example endpoint that works with or without a device.

    This endpoint can be accessed from:
    - CLI (with X-Device-UUID header) - device will be validated
    - Web (without header) - device will be None

    Use this for:
    - User profile endpoints
    - Data retrieval that works from both web and CLI
    - Features available in both interfaces
    """
    if device:
        return {
            "message": "Request from CLI device",
            "source": "cli",
            "user": current_user.email,
            "device": device.device_name,
        }
    else:
        return {
            "message": "Request from web (no device)",
            "source": "web",
            "user": current_user.email,
        }


# EXAMPLE 3: Manual device validation (custom logic)
@router.post("/custom-device-check")
async def custom_device_validation(
    current_user: CurrentUser,
    device: OptionalDevice,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Example with custom device-based logic.

    You can use OptionalDevice and then implement custom logic
    based on whether a device is present.
    """
    # Custom business logic based on device presence
    if device:
        # CLI users get additional features
        return {
            "features": ["scan", "export", "webhooks", "realtime"],
            "message": "Full feature set available from CLI",
            "device_id": device.id,
        }
    else:
        # Web users get limited features
        return {
            "features": ["view", "export"],
            "message": "Limited features from web",
        }


# EXAMPLE 4: Device required for tier-based features
@router.post("/premium-scan")
async def premium_scan_endpoint(
    current_user: CurrentUser,
    device: ValidatedDevice,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Example of combining device validation with tier checks.

    This shows how to:
    1. Require a valid device (CLI-only)
    2. Check user tier for feature access
    3. Track device usage
    """
    # Check if user has access to premium scans
    allowed_tiers = ["pro", "enterprise"]
    if current_user.tier not in allowed_tiers:
        from fastapi import HTTPException, status

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "tier_required",
                "message": f"Premium scans require Pro or Enterprise tier",
                "current_tier": current_user.tier,
                "required_tiers": allowed_tiers,
            },
        )

    # Initiate scan (device is validated and active)
    return {
        "scan_id": "scan_123",
        "status": "initiated",
        "user_tier": current_user.tier,
        "device": device.device_name,
        "message": "Premium scan started from validated device",
    }


"""
USAGE IN YOUR ROUTERS:

1. For CLI-only endpoints (require device):
   Add `device: ValidatedDevice` parameter

2. For hybrid endpoints (optional device):
   Add `device: OptionalDevice` parameter

3. For web-only endpoints:
   Don't add any device parameter

SECURITY BENEFITS:

✓ Prevents access from deactivated devices
✓ Enforces device limits (users can't bypass by using unregistered devices)
✓ Tracks device activity (last_seen updated on each request)
✓ Prevents device UUID spoofing (validates ownership)
✓ Clear error messages guide users to register devices

ERROR RESPONSES:

400 - Missing X-Device-UUID header (when using ValidatedDevice)
403 - Device not registered
403 - Device belongs to another user
403 - Device has been deactivated

CLIENT IMPLEMENTATION:

CLI clients should include the header in all requests:

```python
headers = {
    "Authorization": f"Bearer {access_token}",
    "X-Device-UUID": device_uuid,  # From device registration
}

response = requests.get(
    "https://api.example.com/examples/cli-only",
    headers=headers
)
```

TESTING:

# Test with valid device
curl -H "Authorization: Bearer TOKEN" \\
     -H "X-Device-UUID: valid-uuid-here" \\
     https://api.example.com/examples/cli-only

# Test without device (should fail for strict endpoints)
curl -H "Authorization: Bearer TOKEN" \\
     https://api.example.com/examples/cli-only

# Test with deactivated device (should fail)
curl -H "Authorization: Bearer TOKEN" \\
     -H "X-Device-UUID: deactivated-uuid" \\
     https://api.example.com/examples/cli-only
"""
