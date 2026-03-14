# Device Binding Enforcement Guide

## Overview

The Zypheron API implements comprehensive device binding enforcement to control CLI access based on subscription tiers. Each user can register a limited number of devices, and all CLI operations require a valid, active device registration.

## Device Limits by Tier

| Tier       | Max Devices | Notes |
|------------|-------------|-------|
| Free       | 1           | Single device only |
| Starter    | 2           | Two devices (e.g., work + home) |
| Pro        | 3           | Three devices |
| Enterprise | Unlimited   | No device limit |

These limits are enforced at device registration time and are defined in `/app/schemas/device.py`.

## Architecture

### Core Components

1. **Device Model** (`/app/models/device.py`)
   - Stores device registrations with UUID, name, platform, hostname
   - Tracks `last_seen` for activity monitoring
   - Supports soft-delete via `is_active` flag

2. **Device Schemas** (`/app/schemas/device.py`)
   - `DeviceCreate`: Registration request
   - `DeviceResponse`: Device information
   - `DeviceLimitInfo`: Current usage vs limit
   - `DEVICE_LIMITS`: Tier-based limits configuration

3. **Device Router** (`/app/routers/devices.py`)
   - Registration with limit enforcement
   - Device listing and management
   - Deactivation (free up slots)
   - Limit checking endpoint

4. **Device Dependencies** (`/app/dependencies/device.py`)
   - `ValidatedDevice`: Strict device validation (CLI-only)
   - `OptionalDevice`: Optional device validation (hybrid endpoints)
   - Automatic last_seen updates

## API Endpoints

### POST /devices/register

Register a new CLI device. Enforces tier-based device limits.

**Request:**
```json
{
  "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "device_name": "Work Laptop",
  "platform": "linux",
  "hostname": "dev-machine-01"
}
```

**Success Response (201):**
```json
{
  "id": 1,
  "user_id": 42,
  "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "device_name": "Work Laptop",
  "platform": "linux",
  "hostname": "dev-machine-01",
  "last_seen": "2026-01-03T10:30:00Z",
  "is_active": true,
  "created_at": "2026-01-03T10:30:00Z",
  "updated_at": "2026-01-03T10:30:00Z"
}
```

**Error Response - Limit Reached (403):**
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

**Behavior:**
- If device UUID already exists and is inactive: Reactivates it
- If device UUID exists and belongs to current user: Updates device info
- If device UUID exists and belongs to another user: Returns 409 Conflict
- If at device limit: Returns detailed 403 error with device list

### GET /devices

List all registered devices for the current user.

**Query Parameters:**
- `include_inactive` (boolean): Include deactivated devices (default: false)

**Response:**
```json
{
  "devices": [
    {
      "id": 1,
      "device_name": "Work Laptop",
      "platform": "linux",
      "last_seen": "2026-01-03T10:30:00Z",
      "is_active": true,
      ...
    }
  ],
  "total": 1,
  "active_count": 1,
  "device_limit": 2
}
```

### GET /devices/limit

Check current device usage versus tier limit.

**Response:**
```json
{
  "tier": "starter",
  "limit": 2,
  "current": 1,
  "remaining": 1,
  "can_add": true
}
```

### GET /devices/{device_id}

Get details for a specific device. Only returns devices owned by the current user.

### DELETE /devices/{device_id}

Deactivate a device (soft delete). Frees up a device slot.

**Response:** 204 No Content

**Security:** Users can only deactivate their own devices.

### PATCH /devices/{device_id}

Update device information (name, active status).

**Request:**
```json
{
  "device_name": "New Name",
  "is_active": true
}
```

### POST /devices/{device_id}/ping

Update device's last_seen timestamp (heartbeat). Use for activity tracking.

## Device Binding Dependencies

Use these dependencies in your API endpoints to enforce device validation.

### ValidatedDevice - Strict Validation (CLI-only)

```python
from app.dependencies import ValidatedDevice

@router.post("/scan")
async def initiate_scan(
    current_user: CurrentUser,
    device: ValidatedDevice,  # Requires valid device
) -> dict:
    # This endpoint is CLI-only
    # Device is guaranteed to be registered, active, and owned by user
    return {"scan_id": "...", "device": device.device_name}
```

**Enforces:**
- X-Device-UUID header must be present (400 if missing)
- Device must exist (403 if not found)
- Device must belong to current user (403 if ownership mismatch)
- Device must be active (403 if deactivated)
- Automatically updates last_seen timestamp

**Error Responses:**

```json
// Missing header
{
  "detail": {
    "error": "missing_device_header",
    "message": "X-Device-UUID header is required for this endpoint",
    "hint": "Register your device first using POST /devices/register"
  }
}

// Not registered
{
  "detail": {
    "error": "device_not_registered",
    "message": "This device is not registered to your account",
    "hint": "Register your device using POST /devices/register"
  }
}

// Deactivated
{
  "detail": {
    "error": "device_deactivated",
    "message": "This device has been deactivated",
    "hint": "Reactivate your device by registering it again with POST /devices/register"
  }
}
```

### OptionalDevice - Hybrid Endpoints

```python
from app.dependencies import OptionalDevice

@router.get("/profile")
async def get_profile(
    current_user: CurrentUser,
    device: OptionalDevice,  # Optional device
) -> dict:
    # Works from both web and CLI
    if device:
        # CLI access
        return {"source": "cli", "device": device.device_name}
    else:
        # Web access
        return {"source": "web"}
```

**Behavior:**
- If X-Device-UUID header present: Validates device (same checks as ValidatedDevice)
- If header missing: Returns None (no error)
- Use for endpoints that work from both web and CLI

## Security Features

### 1. Prevent Unauthorized Device Access

All device operations verify user ownership:
```python
if device.user_id != current_user.id:
    raise HTTPException(status_code=403, detail="Device not authorized")
```

### 2. Enforce Tier Limits

Registration automatically checks and enforces limits:
- Counts active devices for user
- Compares against tier limit
- Blocks registration if at limit
- Provides actionable error messages

### 3. Device Activity Tracking

Every validated request updates `last_seen`:
```python
device.update_last_seen()
await db.commit()
```

Use this for:
- Detecting inactive devices
- Audit trails
- Usage analytics

### 4. Soft Delete (Deactivation)

Devices are never hard-deleted:
- Preserves audit trail
- Can be reactivated by re-registering
- Doesn't count against device limit when inactive

### 5. UUID Spoofing Prevention

Device UUID validation ensures:
- Device exists in database
- Device belongs to requesting user
- Device is active

Cannot bypass by using another user's UUID.

## Client Implementation

### CLI Device Registration Flow

```python
import uuid
import requests

# 1. Generate or load device UUID (persistent per installation)
device_uuid = str(uuid.uuid4())  # Save this to config file

# 2. Register device
response = requests.post(
    "https://api.zypheron.com/devices/register",
    headers={"Authorization": f"Bearer {access_token}"},
    json={
        "device_uuid": device_uuid,
        "device_name": "My Laptop",
        "platform": "linux",
        "hostname": "dev-machine"
    }
)

if response.status_code == 403:
    error = response.json()["detail"]
    if error["error"] == "device_limit_reached":
        # Show user their current devices
        print(f"Device limit reached ({error['current']}/{error['limit']})")
        print("Current devices:")
        for dev in error["devices"]:
            print(f"  - {dev['device_name']} (ID: {dev['id']})")
        print(f"\nDeactivate a device: DELETE /devices/{{id}}")
        print(f"Or {error['actions']['upgrade']}")
    sys.exit(1)

device_data = response.json()
print(f"Device registered: {device_data['device_name']}")
```

### Include Header in All Requests

```python
# Store device UUID in config
config = {
    "access_token": "...",
    "device_uuid": "..."
}

# Include in all API requests
headers = {
    "Authorization": f"Bearer {config['access_token']}",
    "X-Device-UUID": config["device_uuid"]
}

# Make API calls
response = requests.post(
    "https://api.zypheron.com/scan",
    headers=headers,
    json={"target": "example.com"}
)
```

## Testing

### Test Scenarios

#### 1. Test Free Tier Limit (1 device)

```bash
# Register first device - should succeed
curl -X POST https://api.zypheron.com/devices/register \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "device_uuid": "device-1",
    "device_name": "Device 1",
    "platform": "linux"
  }'

# Try to register second device - should fail with 403
curl -X POST https://api.zypheron.com/devices/register \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "device_uuid": "device-2",
    "device_name": "Device 2",
    "platform": "darwin"
  }'
```

#### 2. Test Device Deactivation

```bash
# List devices to get ID
curl https://api.zypheron.com/devices \
  -H "Authorization: Bearer $TOKEN"

# Deactivate a device
curl -X DELETE https://api.zypheron.com/devices/1 \
  -H "Authorization: Bearer $TOKEN"

# Register new device - should now succeed
curl -X POST https://api.zypheron.com/devices/register \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "device_uuid": "device-2",
    "device_name": "Device 2",
    "platform": "darwin"
  }'
```

#### 3. Test Device Validation

```bash
# Try to access protected endpoint without device header - should fail
curl https://api.zypheron.com/protected-endpoint \
  -H "Authorization: Bearer $TOKEN"

# With valid device UUID - should succeed
curl https://api.zypheron.com/protected-endpoint \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Device-UUID: device-1"

# With deactivated device UUID - should fail
curl https://api.zypheron.com/protected-endpoint \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Device-UUID: deactivated-uuid"

# With another user's device UUID - should fail
curl https://api.zypheron.com/protected-endpoint \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Device-UUID: other-users-uuid"
```

#### 4. Test Limit Check Endpoint

```bash
curl https://api.zypheron.com/devices/limit \
  -H "Authorization: Bearer $TOKEN"

# Response:
# {
#   "tier": "free",
#   "limit": 1,
#   "current": 1,
#   "remaining": 0,
#   "can_add": false
# }
```

## Migration Guide

If you have existing endpoints that should enforce device binding:

### 1. Import Dependencies

```python
from app.dependencies import ValidatedDevice, OptionalDevice
```

### 2. Add Parameter to Endpoint

```python
# Before (no device validation)
@router.post("/scan")
async def scan(current_user: CurrentUser):
    ...

# After (strict device validation)
@router.post("/scan")
async def scan(current_user: CurrentUser, device: ValidatedDevice):
    ...

# Or for hybrid endpoints
@router.get("/results")
async def results(current_user: CurrentUser, device: OptionalDevice):
    if device:
        # CLI specific logic
    else:
        # Web specific logic
```

### 3. Update Client Code

Ensure CLI clients include the X-Device-UUID header in all requests.

## Database Schema

```sql
CREATE TABLE devices (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    device_uuid VARCHAR(255) UNIQUE NOT NULL,
    device_name VARCHAR(255) NOT NULL,
    platform VARCHAR(50),
    hostname VARCHAR(255),
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_devices_user_id ON devices(user_id);
CREATE INDEX idx_devices_device_uuid ON devices(device_uuid);
```

## Error Handling Best Practices

### Client-Side Error Handling

```python
def register_device(device_uuid, device_name, platform):
    response = requests.post(url, json={...})

    if response.status_code == 403:
        error = response.json()["detail"]

        if error["error"] == "device_limit_reached":
            # Show device list and upgrade options
            show_device_management_ui(error["devices"])
            suggest_upgrade(error["tier"], error["actions"]["upgrade"])

        elif error["error"] == "device_not_authorized":
            # Device belongs to another user
            show_error("This device is registered to another account")

    elif response.status_code == 409:
        # Device already registered
        show_info("Device already registered and active")
```

## Monitoring and Analytics

Track device metrics:
- Active devices per user
- Device registrations over time
- Device deactivations
- Last seen timestamps for inactive device detection

Example queries:

```sql
-- Users at device limit
SELECT u.id, u.email, u.tier, COUNT(d.id) as device_count
FROM users u
JOIN devices d ON u.id = d.user_id
WHERE d.is_active = TRUE
GROUP BY u.id, u.email, u.tier
HAVING COUNT(d.id) >= CASE
    WHEN u.tier = 'free' THEN 1
    WHEN u.tier = 'starter' THEN 2
    WHEN u.tier = 'pro' THEN 3
    ELSE 999999
END;

-- Inactive devices (not seen in 30 days)
SELECT * FROM devices
WHERE last_seen < NOW() - INTERVAL '30 days'
AND is_active = TRUE;
```

## Troubleshooting

### Issue: "Device limit reached" but user has no devices

**Cause:** User has deactivated devices that need cleanup.

**Solution:** Include `include_inactive=true` when listing devices, or clean up old deactivated devices.

### Issue: Device reactivation not working

**Cause:** Re-registering with same UUID should reactivate.

**Solution:** Ensure device registration endpoint handles reactivation:
```python
if existing_device and not existing_device.is_active:
    existing_device.is_active = True
```

### Issue: Last seen not updating

**Cause:** Device validation dependency not used on endpoint.

**Solution:** Add `ValidatedDevice` or `OptionalDevice` dependency to auto-update last_seen.

## Future Enhancements

Potential improvements:
1. Device name auto-generation from hostname
2. Device fingerprinting (beyond UUID)
3. Automatic device deactivation after X days of inactivity
4. Device transfer between users (enterprise)
5. Device usage analytics dashboard
6. Rate limiting per device
7. Device-specific permissions

## Support

For issues or questions:
- Check error response `hint` field for guidance
- Review device list with `GET /devices`
- Check limit status with `GET /devices/limit`
- Contact support with device_id for investigation
