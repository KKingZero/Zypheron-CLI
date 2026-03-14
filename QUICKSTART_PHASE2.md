# Phase 2: Device Code Authentication - Quick Start Guide

## What Was Implemented

Phase 2 adds OAuth 2.0 Device Code authentication to Zypheron API, allowing CLI users to authenticate by entering a code on the web app.

**Status:** ✅ COMPLETE

---

## Quick Test (5 minutes)

### 1. Start the API Server

```bash
cd "/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api"
uvicorn app.main:app --reload --port 8000
```

### 2. Run the Test Script

In a new terminal:

```bash
cd "/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api"
python3 test_device_auth.py
```

Expected output:
```
================================================================================
DEVICE CODE AUTHENTICATION FLOW TEST
================================================================================

Step 1: Creating test user...
Created user: test_1234567890@example.com
JWT Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

Step 2: Creating device code...
User Code: ABCD-1234

Step 3: Authorizing device code (as logged-in user)...
Success: True
Message: Device authorized successfully. You can now return to your CLI.

Step 4: Polling for token (should succeed immediately)...
Status: authorized
Access Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
User ID: 123
Email: test_1234567890@example.com
Tier: free

================================================================================
COMPLETE FLOW TEST SUCCESSFUL!
================================================================================
```

---

## Three New Endpoints

### 1. POST /auth/device/code (CLI)

Request device code:
```bash
curl -X POST http://localhost:8000/auth/device/code \
  -H 'Content-Type: application/json' \
  -d '{"device_info": {"os": "Linux", "cli_version": "1.0.0"}}'
```

Response:
```json
{
  "device_code": "K7P9M2X5Q8W3N1V4C6Z0R9Y2T5H8J3",
  "user_code": "ABCD-1234",
  "verification_url": "http://localhost:3000/device?code=ABCD-1234",
  "expires_in": 300,
  "interval": 5
}
```

### 2. POST /auth/device/authorize (Web App)

Authorize device (requires JWT):
```bash
# First login to get JWT token
curl -X POST http://localhost:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email": "user@example.com", "password": "TestPass123"}'

# Then authorize
curl -X POST http://localhost:8000/auth/device/authorize \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_JWT_TOKEN' \
  -d '{"user_code": "ABCD-1234"}'
```

### 3. POST /auth/device/token (CLI)

Poll for authorization:
```bash
curl -X POST http://localhost:8000/auth/device/token \
  -H 'Content-Type: application/json' \
  -d '{
    "device_code": "K7P9M2X5Q8W3N1V4C6Z0R9Y2T5H8J3",
    "device_info": {"os": "Linux", "cli_version": "1.0.0"}
  }'
```

When authorized:
```json
{
  "status": "authorized",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user_id": 123,
  "email": "user@example.com",
  "tier": "free",
  "token_type": "bearer"
}
```

---

## Files Created

```
Zypheron-CLI-Production/
├── PHASE_2_SUMMARY.md              ⭐ Implementation summary
├── PHASE_2_FILES.txt               ⭐ File listing
├── QUICKSTART_PHASE2.md            ⭐ This guide
└── zypheron-api/
    ├── DEVICE_AUTH_IMPLEMENTATION.md   ⭐ Full technical docs
    ├── DEVICE_AUTH_API_REFERENCE.md    ⭐ API reference
    ├── test_device_auth.py             ⭐ Test script
    └── app/
        ├── core/
        │   ├── config.py              ✏️ Added frontend_url
        │   └── security.py            ✏️ Added code generators
        ├── routers/
        │   └── auth.py                ✏️ Added 3 endpoints
        └── schemas/
            ├── __init__.py            ✏️ Exported new schemas
            └── device_auth.py         ⭐ Pydantic schemas
```

---

## Key Features

1. **Secure Code Generation**
   - 32-char device codes (secret)
   - 8-char user codes (XXXX-XXXX format)
   - Cryptographically secure random generation

2. **Automatic Expiration**
   - Codes expire after 5 minutes
   - Automatic cleanup of expired codes

3. **Complete Validation**
   - Pydantic schemas for all requests
   - Type-safe with proper error messages

4. **Production Ready**
   - JWT authentication
   - Comprehensive error handling
   - Database indexed for performance

---

## Configuration

Add to `.env` (if it doesn't exist, create it):

```bash
# Frontend URL for device verification
FRONTEND_URL=http://localhost:3000
```

For production:
```bash
FRONTEND_URL=https://app.zypheron.com
```

---

## API Documentation

Once the server is running, visit:

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

Look for the three new endpoints under "Authentication" tag.

---

## Flow Diagram

```
CLI                           API                          Web App
│                             │                              │
│ 1. Request device code      │                              │
├────────────────────────────>│                              │
│<────────────────────────────┤                              │
│   device_code + user_code   │                              │
│                             │                              │
│ Display: "Enter ABCD-1234   │                              │
│  at localhost:3000/device"  │                              │
│                             │                              │
│                             │  2. User enters code         │
│                             │<─────────────────────────────┤
│                             │                              │
│                             │  3. Authorize (with JWT)     │
│                             │<─────────────────────────────┤
│                             ├─────────────────────────────>│
│                             │     success: true            │
│                             │                              │
│ 4. Poll every 5 seconds     │                              │
├────────────────────────────>│                              │
│<────────────────────────────┤                              │
│   status: pending           │                              │
│                             │                              │
│ 5. Poll again               │                              │
├────────────────────────────>│                              │
│<────────────────────────────┤                              │
│   status: authorized        │                              │
│   + access_token            │                              │
│                             │                              │
│ 6. Use token for requests   │                              │
├────────────────────────────>│                              │
│                             │                              │
```

---

## Next Steps

### For CLI Integration (Phase 3)

The CLI should:

1. Call `POST /auth/device/code`
2. Display user_code and verification_url
3. Poll `POST /auth/device/token` every 5 seconds
4. Save access_token when status is "authorized"
5. Use token for authenticated API requests

Example CLI flow:
```python
# 1. Request device code
response = requests.post("http://localhost:8000/auth/device/code",
    json={"device_info": get_device_info()})
data = response.json()

# 2. Display to user
print(f"Visit: {data['verification_url']}")
print(f"Enter code: {data['user_code']}")

# 3. Poll for authorization
while True:
    response = requests.post("http://localhost:8000/auth/device/token",
        json={"device_code": data['device_code'], "device_info": get_device_info()})
    result = response.json()

    if result['status'] == 'authorized':
        save_token(result['access_token'])
        break
    elif result['status'] in ['expired', 'denied']:
        print(f"Authorization {result['status']}")
        break

    time.sleep(5)
```

### For Web App Integration (Phase 4)

The web app should:

1. Create a `/device` page that accepts `?code=XXXX-XXXX`
2. Show login form if user not authenticated
3. After login, display device info and ask for confirmation
4. Call `POST /auth/device/authorize` with user's JWT token
5. Show success message

---

## Troubleshooting

### API won't start
```bash
# Check if port 8000 is in use
lsof -i :8000

# Try a different port
uvicorn app.main:app --reload --port 8001
```

### Test script fails
```bash
# Install dependencies
pip install httpx

# Check API is running
curl http://localhost:8000/docs
```

### Database errors
```bash
# The device_codes table should already exist
# If not, check app/models/device_code.py
```

---

## Documentation

- **Full Implementation:** `zypheron-api/DEVICE_AUTH_IMPLEMENTATION.md`
- **API Reference:** `zypheron-api/DEVICE_AUTH_API_REFERENCE.md`
- **Summary:** `PHASE_2_SUMMARY.md`
- **File List:** `PHASE_2_FILES.txt`

---

## Support

All endpoints follow OAuth 2.0 Device Authorization Grant (RFC 8628).

For questions or issues, refer to the comprehensive documentation in the files above.

---

**Status:** ✅ READY FOR INTEGRATION

**Next Phase:** CLI Implementation (Phase 3)
