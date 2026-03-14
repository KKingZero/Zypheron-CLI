# Device Code Authentication - API Quick Reference

## Endpoints Summary

| Endpoint | Method | Auth Required | Called By | Purpose |
|----------|--------|---------------|-----------|---------|
| `/auth/device/code` | POST | No | CLI | Request device code |
| `/auth/device/authorize` | POST | Yes (JWT) | Web App | Authorize device |
| `/auth/device/token` | POST | No | CLI | Poll for token |

---

## 1. POST /auth/device/code

**Initiate device authorization flow**

### Request
```bash
curl -X POST http://localhost:8000/auth/device/code \
  -H 'Content-Type: application/json' \
  -d '{
    "device_info": {
      "os": "Linux",
      "os_version": "6.14.0-37-generic",
      "hostname": "dev-machine",
      "cli_version": "1.0.0"
    }
  }'
```

### Response (201 Created)
```json
{
  "device_code": "K7P9M2X5Q8W3N1V4C6Z0R9Y2T5H8J3",
  "user_code": "ABCD-1234",
  "verification_url": "http://localhost:3000/device?code=ABCD-1234",
  "expires_in": 300,
  "interval": 5
}
```

### Response Fields
- `device_code` (string): 32-char secret for polling (keep private)
- `user_code` (string): 8-char code for user to enter (XXXX-XXXX format)
- `verification_url` (string): URL for user to visit and authorize
- `expires_in` (integer): Seconds until expiration (300 = 5 minutes)
- `interval` (integer): Recommended polling interval in seconds (5)

### CLI Flow
1. Call this endpoint
2. Display `user_code` and `verification_url` to user
3. Start polling `/auth/device/token` with `device_code`

---

## 2. POST /auth/device/authorize

**Authorize a device (called by web app after user login)**

### Request
```bash
curl -X POST http://localhost:8000/auth/device/authorize \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' \
  -d '{
    "user_code": "ABCD-1234"
  }'
```

### Response (200 OK)
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

### Error Responses

#### 401 Unauthorized
```json
{
  "detail": "Missing or invalid authorization header"
}
```

#### 404 Not Found
```json
{
  "detail": "Invalid device code. Please check the code and try again."
}
```

#### 400 Bad Request (Expired)
```json
{
  "detail": "Device code has expired. Please request a new code from your CLI."
}
```

#### 400 Bad Request (Already Used)
```json
{
  "detail": "Device code has already been authorized."
}
```

### Web App Flow
1. User logs in (receives JWT token)
2. User navigates to `/device?code=XXXX-XXXX`
3. Web app calls this endpoint with user's JWT token
4. Show success message to user

---

## 3. POST /auth/device/token

**Poll for authorization status**

### Request
```bash
curl -X POST http://localhost:8000/auth/device/token \
  -H 'Content-Type: application/json' \
  -d '{
    "device_code": "K7P9M2X5Q8W3N1V4C6Z0R9Y2T5H8J3",
    "device_info": {
      "os": "Linux",
      "os_version": "6.14.0-37-generic",
      "hostname": "dev-machine",
      "cli_version": "1.0.0"
    }
  }'
```

### Response - Pending (200 OK)
```json
{
  "status": "pending"
}
```

**Action:** Continue polling every 5 seconds

### Response - Authorized (200 OK)
```json
{
  "status": "authorized",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJpYXQiOjE3MDk5Mzc2MDB9.abc123...",
  "refresh_token": null,
  "user_id": 123,
  "email": "user@example.com",
  "tier": "free",
  "token_type": "bearer",
  "expires_in": null
}
```

**Action:** Stop polling, save `access_token`, start using API

### Response - Expired (200 OK)
```json
{
  "status": "expired"
}
```

**Action:** Stop polling, inform user, request new device code

### Response - Denied (200 OK)
```json
{
  "status": "denied"
}
```

**Action:** Stop polling, inform user that authorization was denied

### Error Response - Invalid Code (404 Not Found)
```json
{
  "detail": "Invalid device code."
}
```

### CLI Polling Logic
```python
import time
import requests

def poll_for_token(device_code, device_info, max_attempts=60):
    """Poll for authorization with 5-second intervals."""
    url = "http://localhost:8000/auth/device/token"
    interval = 5  # seconds

    for attempt in range(1, max_attempts + 1):
        response = requests.post(url, json={
            "device_code": device_code,
            "device_info": device_info
        })

        if response.status_code != 200:
            print(f"Error: {response.json()}")
            return None

        data = response.json()
        status = data["status"]

        if status == "authorized":
            # Success! Save the token
            return data["access_token"]
        elif status == "pending":
            # Keep waiting
            print(f"Waiting for authorization... ({attempt}/{max_attempts})")
            time.sleep(interval)
        elif status in ["expired", "denied"]:
            # Failed
            print(f"Authorization {status}")
            return None

    print("Polling timeout")
    return None
```

---

## Complete Example Flow

### 1. CLI Requests Device Code

```bash
curl -X POST http://localhost:8000/auth/device/code \
  -H 'Content-Type: application/json' \
  -d '{"device_info": {"os": "Linux", "cli_version": "1.0.0"}}'
```

**Response:**
```json
{
  "device_code": "K7P9M2X5Q8W3N1V4C6Z0R9Y2T5H8J3",
  "user_code": "ABCD-1234",
  "verification_url": "http://localhost:3000/device?code=ABCD-1234",
  "expires_in": 300,
  "interval": 5
}
```

### 2. CLI Displays to User

```
To authenticate, please visit:
  http://localhost:3000/device?code=ABCD-1234

And enter this code:
  ABCD-1234

Waiting for authorization...
```

### 3. User Opens Browser and Logs In

```bash
# User registers or logs in
curl -X POST http://localhost:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123"
  }'
```

**Response:**
```json
{
  "user": {...},
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

### 4. Web App Authorizes Device

```bash
curl -X POST http://localhost:8000/auth/device/authorize \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' \
  -d '{"user_code": "ABCD-1234"}'
```

**Response:**
```json
{
  "success": true,
  "message": "Device authorized successfully. You can now return to your CLI.",
  "device_info": {"os": "Linux", "cli_version": "1.0.0"}
}
```

### 5. CLI Polls and Receives Token

```bash
curl -X POST http://localhost:8000/auth/device/token \
  -H 'Content-Type: application/json' \
  -d '{
    "device_code": "K7P9M2X5Q8W3N1V4C6Z0R9Y2T5H8J3",
    "device_info": {"os": "Linux", "cli_version": "1.0.0"}
  }'
```

**Response:**
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

### 6. CLI Uses Token for Authenticated Requests

```bash
curl -X GET http://localhost:8000/auth/me \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
```

---

## Status Codes

| Code | Meaning | When |
|------|---------|------|
| 200 | OK | Successful poll (all statuses) |
| 201 | Created | Device code created successfully |
| 400 | Bad Request | Invalid input, expired code, already used |
| 401 | Unauthorized | Missing or invalid JWT token |
| 404 | Not Found | Invalid device_code or user_code |
| 500 | Internal Server Error | Server error (code generation failed) |

---

## Timing Specifications

- **Device code expiry:** 5 minutes (300 seconds)
- **Recommended polling interval:** 5 seconds
- **Maximum polling duration:** 5 minutes (60 attempts × 5 seconds)

---

## Security Notes

1. **device_code** is secret - never show to user
2. **user_code** is public - safe to display
3. Codes expire after 5 minutes
4. Authorization requires JWT token
5. Each device_code can only be authorized once
6. Use HTTPS in production

---

## Testing with curl

### Quick Test Script

```bash
#!/bin/bash

# 1. Request device code
RESPONSE=$(curl -s -X POST http://localhost:8000/auth/device/code \
  -H 'Content-Type: application/json' \
  -d '{"device_info": {"os": "Linux"}}')

DEVICE_CODE=$(echo $RESPONSE | jq -r '.device_code')
USER_CODE=$(echo $RESPONSE | jq -r '.user_code')
VERIFICATION_URL=$(echo $RESPONSE | jq -r '.verification_url')

echo "Device Code: $DEVICE_CODE"
echo "User Code: $USER_CODE"
echo "Verification URL: $VERIFICATION_URL"
echo ""

# 2. Register user
USER_RESPONSE=$(curl -s -X POST http://localhost:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123"
  }')

JWT_TOKEN=$(echo $USER_RESPONSE | jq -r '.access_token')
echo "JWT Token: ${JWT_TOKEN:0:50}..."
echo ""

# 3. Authorize device
curl -X POST http://localhost:8000/auth/device/authorize \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d "{\"user_code\": \"$USER_CODE\"}"
echo ""

# 4. Poll for token
curl -X POST http://localhost:8000/auth/device/token \
  -H 'Content-Type: application/json' \
  -d "{
    \"device_code\": \"$DEVICE_CODE\",
    \"device_info\": {\"os\": \"Linux\"}
  }"
```

---

## Next Steps

After implementing these endpoints:

1. **CLI Integration:** Update CLI to use device code flow
2. **Web App:** Create `/device` page for code entry
3. **Testing:** Write comprehensive tests
4. **Monitoring:** Add logging and analytics
5. **Production:** Enable HTTPS, add rate limiting

---

## Support

For issues or questions, refer to:
- Full documentation: `DEVICE_AUTH_IMPLEMENTATION.md`
- Test script: `test_device_auth.py`
- API docs: http://localhost:8000/docs
