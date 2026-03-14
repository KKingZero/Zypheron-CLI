# Zypheron API Testing Guide

Quick reference for testing API endpoints with curl.

## Setup

1. Start the server:
```bash
./run.sh
# Or: uvicorn app.main:app --reload
```

2. Server will be available at: `http://localhost:8000`
3. API docs at: `http://localhost:8000/docs`

---

## Authentication Flow

### 1. Register New User

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123"
  }'
```

Response:
```json
{
  "user": {
    "id": 1,
    "email": "test@example.com",
    "tier": "free",
    "is_active": true,
    "is_verified": false,
    "created_at": "2025-01-15T10:00:00Z"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

Save the `access_token` for subsequent requests.

### 2. Login Existing User

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123"
  }'
```

### 3. Get Current User

```bash
export TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

curl http://localhost:8000/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Logout

```bash
curl -X POST http://localhost:8000/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

---

## Device Management

### 1. Register Device

```bash
curl -X POST http://localhost:8000/devices/register \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "device_name": "MacBook Pro",
    "platform": "darwin",
    "hostname": "johns-mbp.local"
  }'
```

Response:
```json
{
  "id": 1,
  "user_id": 1,
  "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "device_name": "MacBook Pro",
  "platform": "darwin",
  "hostname": "johns-mbp.local",
  "last_seen": "2025-01-15T10:05:00Z",
  "is_active": true,
  "created_at": "2025-01-15T10:05:00Z"
}
```

### 2. List Devices

```bash
# Active devices only
curl http://localhost:8000/devices \
  -H "Authorization: Bearer $TOKEN"

# Include inactive devices
curl "http://localhost:8000/devices?include_inactive=true" \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Get Device by ID

```bash
curl http://localhost:8000/devices/1 \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Update Device

```bash
curl -X PATCH http://localhost:8000/devices/1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "device_name": "MacBook Pro (Work)"
  }'
```

### 5. Deactivate Device

```bash
curl -X DELETE http://localhost:8000/devices/1 \
  -H "Authorization: Bearer $TOKEN"
```

### 6. Ping Device (Heartbeat)

```bash
curl -X POST http://localhost:8000/devices/1/ping \
  -H "Authorization: Bearer $TOKEN"
```

### 7. Test Device Limit

Try registering more devices than tier allows:

```bash
# Free tier allows 1 device, this should fail:
curl -X POST http://localhost:8000/devices/register \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "device_uuid": "550e8400-e29b-41d4-a716-446655440001",
    "device_name": "Linux Desktop",
    "platform": "linux"
  }'
```

Expected error (403):
```json
{
  "detail": {
    "message": "Device limit reached for free tier",
    "limit": 1,
    "current": 1,
    "upgrade_required": true
  }
}
```

---

## License Management

### 1. Validate License

```bash
curl http://localhost:8000/license/validate \
  -H "Authorization: Bearer $TOKEN"
```

Response:
```json
{
  "is_valid": true,
  "tier": "free",
  "status": "active",
  "valid_until": null,
  "days_remaining": null,
  "features": {
    "tier": "free",
    "token_limit": 0,
    "tokens_included": false,
    "rate_limit": 10,
    "max_devices": 1,
    "available_providers": ["openai", "anthropic", "grok", "deepseek"],
    "features": {
      "byok_required": true,
      "caching": false,
      "priority_support": false,
      "advanced_scanning": false,
      "websocket_streaming": true
    },
    "cache_enabled": false,
    "cache_ttl_minutes": 0
  }
}
```

### 2. Get License Features

```bash
curl http://localhost:8000/license/features \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Get License Details

```bash
curl http://localhost:8000/license \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Get All Tiers (Public)

```bash
curl http://localhost:8000/license/tiers
```

Returns feature comparison for all tiers (useful for pricing page).

### 5. Initiate Upgrade (TODO - Stripe)

```bash
curl -X POST http://localhost:8000/license/upgrade/pro \
  -H "Authorization: Bearer $TOKEN"
```

Expected: 501 Not Implemented (Stripe not configured yet)

---

## Token Usage Tracking

### 1. Get Usage Summary

```bash
# Current month
curl http://localhost:8000/tokens/usage \
  -H "Authorization: Bearer $TOKEN"

# Specific period
curl "http://localhost:8000/tokens/usage?period=week" \
  -H "Authorization: Bearer $TOKEN"
```

Periods: `day`, `week`, `month`, `all`

### 2. Get Remaining Tokens

```bash
curl http://localhost:8000/tokens/remaining \
  -H "Authorization: Bearer $TOKEN"
```

Response:
```json
{
  "tokens_remaining": 0,
  "token_limit": 0,
  "tier": "free",
  "byok_enabled": true
}
```

### 3. Get Quota Info

```bash
curl http://localhost:8000/tokens/quota \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Get Usage History

```bash
# First page, 50 items
curl http://localhost:8000/tokens/history \
  -H "Authorization: Bearer $TOKEN"

# Pagination
curl "http://localhost:8000/tokens/history?page=2&page_size=20" \
  -H "Authorization: Bearer $TOKEN"

# Filter by provider
curl "http://localhost:8000/tokens/history?provider=openai" \
  -H "Authorization: Bearer $TOKEN"
```

---

## WebSocket Testing

### Using websocat

```bash
# Install websocat
brew install websocat  # macOS
# Or: cargo install websocat

# Connect to scan stream
websocat "ws://localhost:8000/ws/scans/test_user_123"
```

### Using JavaScript

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/scans/test_user_123');

ws.onopen = () => {
  console.log('Connected to scan stream');
  ws.send('Hello from client');
};

ws.onmessage = (event) => {
  console.log('Received:', event.data);
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};

ws.onclose = () => {
  console.log('Disconnected');
};
```

---

## Health Check

```bash
curl http://localhost:8000/health
```

Response:
```json
{
  "status": "healthy",
  "service": "Zypheron API",
  "version": "0.1.0",
  "environment": "development"
}
```

---

## Error Handling Examples

### Invalid Credentials (401)

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "WrongPassword123"
  }'
```

### Missing Authorization (401)

```bash
curl http://localhost:8000/auth/me
```

### Invalid Token (401)

```bash
curl http://localhost:8000/auth/me \
  -H "Authorization: Bearer invalid_token_here"
```

### Weak Password (422)

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test2@example.com",
    "password": "weak"
  }'
```

### Resource Not Found (404)

```bash
curl http://localhost:8000/devices/999 \
  -H "Authorization: Bearer $TOKEN"
```

---

## Complete Test Flow

```bash
#!/bin/bash
# Complete API test flow

BASE_URL="http://localhost:8000"

# 1. Register
echo "1. Registering user..."
REGISTER_RESPONSE=$(curl -s -X POST $BASE_URL/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "TestPass123"
  }')

TOKEN=$(echo $REGISTER_RESPONSE | jq -r '.access_token')
echo "Token: $TOKEN"

# 2. Get current user
echo -e "\n2. Getting current user..."
curl -s $BASE_URL/auth/me \
  -H "Authorization: Bearer $TOKEN" | jq

# 3. Register device
echo -e "\n3. Registering device..."
curl -s -X POST $BASE_URL/devices/register \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "device_uuid": "test-device-uuid-123",
    "device_name": "Test Device",
    "platform": "linux"
  }' | jq

# 4. List devices
echo -e "\n4. Listing devices..."
curl -s $BASE_URL/devices \
  -H "Authorization: Bearer $TOKEN" | jq

# 5. Validate license
echo -e "\n5. Validating license..."
curl -s $BASE_URL/license/validate \
  -H "Authorization: Bearer $TOKEN" | jq

# 6. Get quota
echo -e "\n6. Getting quota info..."
curl -s $BASE_URL/tokens/quota \
  -H "Authorization: Bearer $TOKEN" | jq

# 7. Logout
echo -e "\n7. Logging out..."
curl -s -X POST $BASE_URL/auth/logout \
  -H "Authorization: Bearer $TOKEN"

echo -e "\nTest flow complete!"
```

Save as `test_flow.sh`, make executable, and run:

```bash
chmod +x test_flow.sh
./test_flow.sh
```

---

## Interactive API Docs

For interactive testing, visit the Swagger UI:

**http://localhost:8000/docs**

Features:
- Try out all endpoints directly
- Auto-populated schemas
- Authorization token management
- Request/response examples

Or use ReDoc for documentation:

**http://localhost:8000/redoc**
