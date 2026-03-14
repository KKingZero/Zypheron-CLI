# Device Binding Enforcement - Quick Start

## Summary

Device binding is now fully implemented with tier-based limits:
- **Free**: 1 device
- **Starter**: 2 devices
- **Pro**: 3 devices
- **Enterprise**: Unlimited devices

## Key Files Modified/Created

### Modified Files
1. `/app/schemas/device.py` - Updated DEVICE_LIMITS (Enterprise = unlimited)
2. `/app/routers/devices.py` - Enhanced error messages, added `/devices/limit` endpoint

### New Files
1. `/app/dependencies/device.py` - Device validation dependencies
2. `/app/dependencies/__init__.py` - Package exports
3. `/app/examples/device_binding_usage.py` - Usage examples
4. `/DEVICE_BINDING_GUIDE.md` - Comprehensive documentation
5. `/tests/test_device_binding.py` - Test suite

## Quick Implementation Guide

### Step 1: Protect an Endpoint (CLI-only)

```python
from app.dependencies import ValidatedDevice
from app.routers.auth import CurrentUser

@router.post("/scan")
async def initiate_scan(
    current_user: CurrentUser,
    device: ValidatedDevice,  # Add this parameter
) -> dict:
    # Device is now validated and active
    return {
        "scan_id": "...",
        "device": device.device_name
    }
```

### Step 2: Create Hybrid Endpoint (CLI + Web)

```python
from app.dependencies import OptionalDevice

@router.get("/results")
async def get_results(
    current_user: CurrentUser,
    device: OptionalDevice,  # Optional device
) -> dict:
    if device:
        # CLI request
        return {"source": "cli", "device": device.device_name}
    else:
        # Web request
        return {"source": "web"}
```

### Step 3: Update CLI Client

```python
# Include device UUID in all requests
headers = {
    "Authorization": f"Bearer {access_token}",
    "X-Device-UUID": device_uuid  # Required for protected endpoints
}
```

## API Endpoints

### Device Registration
```bash
POST /devices/register
{
  "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "device_name": "Work Laptop",
  "platform": "linux",
  "hostname": "dev-machine-01"
}
```

### Check Limit Status
```bash
GET /devices/limit

Response:
{
  "tier": "free",
  "limit": 1,
  "current": 1,
  "remaining": 0,
  "can_add": false
}
```

### List Devices
```bash
GET /devices

Response:
{
  "devices": [...],
  "total": 1,
  "active_count": 1,
  "device_limit": 1
}
```

### Deactivate Device
```bash
DELETE /devices/{device_id}
```

## Error Responses

### Device Limit Reached (403)
```json
{
  "detail": {
    "message": "Device limit reached (1/1 for Free tier). Upgrade to Starter for 2 devices, or deactivate an existing device.",
    "error": "device_limit_reached",
    "tier": "free",
    "limit": 1,
    "current": 1,
    "devices": [
      {
        "id": 5,
        "device_name": "Home PC",
        "platform": "win32",
        "hostname": "home-desktop",
        "last_seen": "2026-01-02T15:20:00Z",
        "created_at": "2026-01-01T09:00:00Z"
      }
    ],
    "actions": {
      "deactivate": "DELETE /devices/{device_id} to free up a slot",
      "upgrade": "Upgrade to Starter for 2 devices"
    }
  }
}
```

### Missing Device Header (400)
```json
{
  "detail": {
    "error": "missing_device_header",
    "message": "X-Device-UUID header is required for this endpoint",
    "hint": "Register your device first using POST /devices/register"
  }
}
```

### Device Not Registered (403)
```json
{
  "detail": {
    "error": "device_not_registered",
    "message": "This device is not registered to your account",
    "hint": "Register your device using POST /devices/register"
  }
}
```

### Device Deactivated (403)
```json
{
  "detail": {
    "error": "device_deactivated",
    "message": "This device has been deactivated",
    "hint": "Reactivate your device by registering it again with POST /devices/register"
  }
}
```

## Testing Checklist

- [ ] Register device successfully
- [ ] Hit device limit for each tier
- [ ] Deactivate device to free slot
- [ ] Reactivate deactivated device
- [ ] Access protected endpoint with valid device
- [ ] Access protected endpoint without header (should fail)
- [ ] Access with deactivated device (should fail)
- [ ] Access with another user's device UUID (should fail)
- [ ] Check `/devices/limit` endpoint
- [ ] Verify error messages are helpful

## Security Features

✅ Tier-based device limits enforced
✅ Device ownership validation (prevents UUID spoofing)
✅ Active/inactive status checking
✅ Automatic last_seen timestamp updates
✅ Detailed error messages with actionable guidance
✅ Device list in error response (helps users choose which to deactivate)
✅ Soft delete (preserves audit trail)
✅ Enterprise tier has unlimited devices

## Common Use Cases

### 1. Enforce CLI-only access
```python
device: ValidatedDevice
```

### 2. Support both CLI and Web
```python
device: OptionalDevice
if device:
    # CLI logic
else:
    # Web logic
```

### 3. Track device activity
```python
# last_seen is automatically updated by ValidatedDevice dependency
```

### 4. Tier-based feature access
```python
if current_user.tier not in ["pro", "enterprise"]:
    raise HTTPException(403, detail="Premium feature")
```

## Migration Path for Existing Endpoints

1. Identify endpoints that should require device validation
2. Add `from app.dependencies import ValidatedDevice`
3. Add `device: ValidatedDevice` parameter
4. Update CLI client to include `X-Device-UUID` header
5. Test with valid/invalid/deactivated devices

## Next Steps

1. Review `/DEVICE_BINDING_GUIDE.md` for detailed documentation
2. Check `/app/examples/device_binding_usage.py` for code examples
3. Run tests in `/tests/test_device_binding.py`
4. Update CLI client to include device UUID header
5. Add device validation to appropriate endpoints

## Support

For detailed information, see:
- `/DEVICE_BINDING_GUIDE.md` - Complete documentation
- `/app/examples/device_binding_usage.py` - Code examples
- `/app/dependencies/device.py` - Implementation details
