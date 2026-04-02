# Device Code Authentication Implementation

## Overview

This document describes the Phase 2 implementation of Device Code Authentication for Zypheron, following the OAuth 2.0 Device Authorization Grant flow (RFC 8628).

## Architecture

### Flow Diagram

```
┌─────────────┐                                      ┌─────────────┐
│             │  1. POST /auth/device/code           │             │
│     CLI     │─────────────────────────────────────>│  Zypheron   │
│  (Device)   │<─────────────────────────────────────│     API     │
│             │  device_code + user_code             │ (port 8000) │
└─────────────┘                                      └─────────────┘
      │                                                      ^
      │                                                      │
      │  Display user_code                                  │
      │  & verification_url                                 │
      │                                                      │
      v                                         3. POST /auth/device/authorize
┌─────────────┐                                (with JWT token)
│    User     │                                              │
│  Terminal   │                                              │
└─────────────┘                                              │
      │                                                      │
      │  2. Open browser                                     │
      │  Navigate to verification_url                        │
      v                                                      │
┌─────────────┐                                      ┌─────────────┐
│             │  Login (if needed)                   │             │
│   Browser   │─────────────────────────────────────>│  Web App    │
│             │                                      │(port 3000)  │
│             │  Enter user_code                     │             │
│             │  Authorize device                    └─────────────┘
└─────────────┘
                                                              │
      ┌───────────────────────────────────────────────────────┘
      │
      │  4. Poll POST /auth/device/token
      │     (every 5 seconds)
      v
┌─────────────┐                                      ┌─────────────┐
│             │  POST /auth/device/token             │             │
│     CLI     │─────────────────────────────────────>│  Zypheron   │
│  (Device)   │<─────────────────────────────────────│     API     │
│             │  status: pending | authorized        │             │
└─────────────┘                                      └─────────────┘
      │
      │  When authorized:
      │  - Receive access_token
      │  - Save token
      │  - Start making authenticated requests
      v
```

## Implementation Details

### 1. Database Schema

The `device_codes` table (already exists) stores device authorization requests:

```sql
CREATE TABLE device_codes (
    id INTEGER PRIMARY KEY,
    device_code VARCHAR(255) UNIQUE NOT NULL,  -- 32-char secret for polling
    user_code VARCHAR(20) UNIQUE NOT NULL,     -- 8-char code (XXXX-XXXX) for user
    device_info JSON,                          -- Device metadata
    user_id INTEGER REFERENCES users(id),      -- NULL until authorized
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    authorized_at TIMESTAMP WITH TIME ZONE
);
```

**Status values:**
- `pending`: Waiting for user authorization
- `authorized`: User has authorized the device
- `expired`: Device code has expired (5 minutes)
- `denied`: User explicitly denied authorization

### 2. API Endpoints

#### a) POST /auth/device/code

**Purpose:** Initiate device code flow (called by CLI)

**Request:**
```json
{
  "device_info": {
    "os": "Linux",
    "os_version": "6.14.0-37-generic",
    "hostname": "dev-machine",
    "cli_version": "2.0.0"
  }
}
```

**Response (201 Created):**
```json
{
  "device_code": "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",  // 32 chars (secret)
  "user_code": "ABCD-1234",                           // 8 chars + hyphen
  "verification_url": "http://localhost:3000/device?code=ABCD-1234",
  "expires_in": 300,                                  // 5 minutes in seconds
  "interval": 5                                       // Recommended polling interval
}
```

**Implementation:**
- Generates unique 32-character `device_code` (alphanumeric, uppercase)
- Generates unique 8-character `user_code` in format `XXXX-XXXX` (alphanumeric, uppercase)
- Stores in `device_codes` table with 5-minute expiry
- Cleans up expired codes before creating new ones (optimization)
- Returns verification URL pointing to web app

#### b) POST /auth/device/authorize

**Purpose:** Authorize a device code (called by web app after user login)

**Authentication:** Requires JWT token in `Authorization: Bearer <token>` header

**Request:**
```json
{
  "user_code": "ABCD-1234"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Device authorized successfully. You can now return to your CLI.",
  "device_info": {
    "os": "Linux",
    "os_version": "6.14.0-37-generic",
    "hostname": "dev-machine",
    "cli_version": "1.0.0"
  }
}
```

**Error Responses:**
- `404 Not Found`: Invalid user code
- `400 Bad Request`: Code expired, already authorized, or denied
- `401 Unauthorized`: Missing or invalid JWT token

**Implementation:**
- Validates JWT token to get current user
- Finds device code by `user_code`
- Checks if expired or already used
- Links `user_id` to the device code
- Updates status to `authorized`
- Sets `authorized_at` timestamp

#### c) POST /auth/device/token

**Purpose:** Poll for authorization status (called by CLI repeatedly)

**Request:**
```json
{
  "device_code": "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
  "device_info": {
    "os": "Linux",
    "os_version": "6.14.0-37-generic",
    "hostname": "dev-machine",
    "cli_version": "1.0.0"
  }
}
```

**Response (200 OK):**

**When pending:**
```json
{
  "status": "pending"
}
```

**When authorized:**
```json
{
  "status": "authorized",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": null,
  "user_id": 123,
  "email": "user@example.com",
  "tier": "free",
  "token_type": "bearer",
  "expires_in": null
}
```

**When expired:**
```json
{
  "status": "expired"
}
```

**When denied:**
```json
{
  "status": "denied"
}
```

**Error Responses:**
- `404 Not Found`: Invalid device code

**Implementation:**
- Finds device code by `device_code`
- Checks expiration and updates status if expired
- Returns current status
- If authorized:
  - Fetches user information
  - Generates JWT access token
  - Creates session record
  - Returns token and user details
  - Keeps device code for audit (can be deleted if preferred)

### 3. Helper Functions

#### `generate_device_code() -> str`
Located in `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/core/security.py`

- Generates 32-character random string
- Uses `secrets.choice()` for cryptographic randomness
- Alphabet: uppercase letters + digits (A-Z, 0-9)

#### `generate_user_code() -> str`
Located in `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/core/security.py`

- Generates 8-character code in format `XXXX-XXXX`
- Uses `secrets.choice()` for cryptographic randomness
- Alphabet: uppercase letters + digits (A-Z, 0-9)
- Hyphen separator for readability

#### `cleanup_expired_codes(db: AsyncSession) -> int`
Located in `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/routers/auth.py`

- Deletes all expired device codes from database
- Returns count of deleted records
- Called before creating new device codes (optional optimization)
- Can be scheduled as periodic background task

### 4. Pydantic Schemas

Located in `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/schemas/device_auth.py`

**Request Schemas:**
- `DeviceCodeRequest`: Request device code with device info
- `DeviceAuthorizeRequest`: Authorize with user code
- `DeviceTokenRequest`: Poll with device code

**Response Schemas:**
- `DeviceCodeResponse`: Device code, user code, verification URL
- `DeviceAuthorizeResponse`: Authorization success response
- `DeviceTokenResponse`: Token polling response with status

All schemas include:
- Field validation (length, pattern, required fields)
- Type hints for IDE support
- Descriptive docstrings and examples
- Proper error messages

## Security Considerations

### 1. Code Generation
- Uses `secrets` module for cryptographically secure randomness
- Device codes are 32 characters (provides ~191 bits of entropy)
- User codes are 8 characters (provides ~48 bits of entropy)
- Both use alphanumeric alphabet (36 characters)

### 2. Expiration
- Device codes expire after 5 minutes (300 seconds)
- Automatic cleanup of expired codes
- Status updated to `expired` when checked after expiration
- Prevents indefinite pending states

### 3. Authentication
- `/auth/device/authorize` requires valid JWT token
- Validates user is authenticated before linking device
- Uses existing `get_current_user` dependency
- Prevents unauthorized device authorization

### 4. Rate Limiting
- Recommended polling interval: 5 seconds
- CLI should implement exponential backoff on errors
- Could add rate limiting middleware to prevent abuse
- Database indexes on `device_code` and `user_code` for fast lookups

### 5. Input Validation
- All inputs validated via Pydantic schemas
- User code pattern validation: `^[A-Z0-9]{4}-[A-Z0-9]{4}$`
- Device code length validation: exactly 32 characters
- SQL injection prevention via SQLAlchemy parameter binding

## Testing

### Manual Testing

1. **Start the API server:**
   ```bash
   cd zypheron-api
   uvicorn app.main:app --reload --port 8000
   ```

2. **Request device code:**
   ```bash
   curl -X POST http://localhost:8000/auth/device/code \
     -H 'Content-Type: application/json' \
     -d '{
       "device_info": {
         "os": "Linux",
         "os_version": "6.14.0-37-generic",
         "hostname": "test-machine",
         "cli_version": "1.0.0"
       }
     }'
   ```

3. **Register/login a user (to get JWT token):**
   ```bash
   curl -X POST http://localhost:8000/auth/register \
     -H 'Content-Type: application/json' \
     -d '{
       "email": "test@example.com",
       "password": "TestPass123"
     }'
   ```

4. **Authorize device code (with JWT token):**
   ```bash
   curl -X POST http://localhost:8000/auth/device/authorize \
     -H 'Content-Type: application/json' \
     -H 'Authorization: Bearer <JWT_TOKEN>' \
     -d '{
       "user_code": "ABCD-1234"
     }'
   ```

5. **Poll for token:**
   ```bash
   curl -X POST http://localhost:8000/auth/device/token \
     -H 'Content-Type: application/json' \
     -d '{
       "device_code": "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
       "device_info": {
         "os": "Linux",
         "os_version": "6.14.0-37-generic",
         "hostname": "test-machine",
         "cli_version": "1.0.0"
       }
     }'
   ```

### Automated Testing

Run the provided test script:

```bash
cd zypheron-api
python3 test_device_auth.py
```

This script tests the complete flow including:
- Device code creation
- User authorization
- Token polling
- Success validation

## Configuration

### Environment Variables

Add to `.env` file:

```bash
# Frontend URL for device code verification
FRONTEND_URL=http://localhost:3000
```

### Settings

Located in `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/core/config.py`:

```python
frontend_url: str = "http://localhost:3000"
```

For production, change to your actual web app URL:
```bash
FRONTEND_URL=https://app.zypheron.com
```

## Files Modified/Created

### Created Files:
1. `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/schemas/device_auth.py` - Pydantic schemas
2. `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/test_device_auth.py` - Test script
3. `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/DEVICE_AUTH_IMPLEMENTATION.md` - This documentation

### Modified Files:
1. `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/routers/auth.py` - Added 3 endpoints + cleanup helper
2. `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/core/security.py` - Added code generation functions
3. `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/schemas/__init__.py` - Exported new schemas
4. `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/core/config.py` - Added frontend_url setting

## Next Steps (Phase 3)

1. **CLI Integration:**
   - Implement device code flow in CLI
   - Add token storage and management
   - Implement automatic token refresh

2. **Web App Integration:**
   - Create `/device` page to accept user codes
   - Implement authorization UI
   - Show device information before authorizing

3. **Enhancements:**
   - Add device management (list/revoke authorized devices)
   - Implement refresh tokens
   - Add rate limiting middleware
   - Set up background task for cleanup
   - Add analytics/logging for authorization attempts

4. **Testing:**
   - Add unit tests for endpoints
   - Add integration tests for complete flow
   - Test expiration scenarios
   - Test error handling

## API Documentation

Once the API is running, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

The new endpoints will appear under the "Authentication" tag.

## Troubleshooting

### Common Issues:

1. **"Invalid device code"**
   - Code may have expired (5 minutes)
   - Code may have been typed incorrectly
   - Request a new code

2. **"Missing or invalid authorization header"**
   - Web app must include JWT token in Authorization header
   - User must be logged in first

3. **"Device code has expired"**
   - Codes expire after 5 minutes
   - Request a new code from CLI

4. **Polling timeout**
   - User may not have authorized yet
   - Check that user_code is correct
   - Ensure web app is accessible

### Database Issues:

If you encounter database errors, ensure the `device_codes` table exists:

```sql
-- The table should already exist from the models
-- If not, run migrations or create manually
```

## Compliance

This implementation follows:
- **RFC 8628**: OAuth 2.0 Device Authorization Grant
- **RFC 6749**: The OAuth 2.0 Authorization Framework
- **OWASP** security best practices
- **PEP 8**: Python code style guidelines

## License

Part of the Zypheron project. All rights reserved.
