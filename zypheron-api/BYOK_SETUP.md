# BYOK (Bring Your Own Key) Setup Guide

## Overview

The BYOK (Bring Your Own Key) feature allows users to use their own API keys for AI providers instead of consuming tokens from the Zypheron platform. This provides:

- **Unlimited Usage**: Bypass monthly token limits
- **Cost Control**: Use your own API budget
- **Privacy**: Direct communication with AI providers
- **Flexibility**: Support for multiple providers

## Supported Providers

- **OpenAI** (GPT-4, GPT-3.5, etc.)
- **Anthropic** (Claude models)
- **Google Gemini**
- **DeepSeek**
- **Grok** (xAI)

## Setup Instructions

### 1. Generate Encryption Key

The BYOK feature requires a Fernet encryption key to securely store user API keys. Generate one using:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

This will output something like:
```
7xK8vQ2mP9nL4wB6hD3jR5sT1cF0gY8uE2oA7iM6kN4=
```

### 2. Add to Environment Variables

Add the encryption key to your `.env` file:

```bash
# BYOK (Bring Your Own Key) Configuration
BYOK_ENCRYPTION_KEY=7xK8vQ2mP9nL4wB6hD3jR5sT1cF0gY8uE2oA7iM6kN4=
```

**SECURITY WARNING**:
- Never commit the encryption key to version control
- Store it securely (use secrets manager in production)
- If the key is lost, encrypted API keys cannot be recovered
- Changing the key will invalidate all stored API keys

### 3. Run Database Migration

The BYOK feature adds a new `user_api_keys` table. Initialize it with:

```bash
# The table will be created automatically on next startup
python -m app.main
```

Or manually trigger database initialization:

```python
from app.core.database import init_db
import asyncio

asyncio.run(init_db())
```

## API Endpoints

### 1. Add a New API Key

**Endpoint**: `POST /byok/keys`

**Request**:
```json
{
  "provider": "openai",
  "api_key": "sk-proj-abc123..."
}
```

**Response**:
```json
{
  "id": 1,
  "provider": "openai",
  "key_masked": "...c123",
  "is_valid": false,
  "last_validated_at": null,
  "last_used_at": null,
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Provider-Specific Key Formats**:
- **OpenAI**: Must start with `sk-` or `sk-proj-`
- **Anthropic**: Must start with `sk-ant-`
- **Gemini**: Alphanumeric key (typically 39 chars)
- **DeepSeek**: Must start with `sk-`
- **Grok**: 20+ character key

### 2. List User's API Keys

**Endpoint**: `GET /byok/keys`

**Response**:
```json
{
  "keys": [
    {
      "id": 1,
      "provider": "openai",
      "key_masked": "...c123",
      "is_valid": true,
      "last_validated_at": "2024-01-15T11:00:00Z",
      "last_used_at": "2024-01-15T12:30:00Z",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1
}
```

### 3. Validate an API Key

**Endpoint**: `POST /byok/keys/{key_id}/validate`

**Response**:
```json
{
  "is_valid": true,
  "message": "OpenAI API key validated successfully",
  "provider": "openai",
  "validated_at": "2024-01-15T11:00:00Z"
}
```

This endpoint makes a test API call to the provider to verify the key works.

### 4. Delete an API Key

**Endpoint**: `DELETE /byok/keys/{key_id}`

**Response**:
```json
{
  "success": true,
  "message": "openai API key deleted successfully"
}
```

## Usage Flow

### For Users (via CLI or Web App):

1. **Add API Key**:
   ```bash
   curl -X POST https://api.zypheron.com/byok/keys \
     -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "provider": "openai",
       "api_key": "sk-proj-abc123..."
     }'
   ```

2. **Validate the Key**:
   ```bash
   curl -X POST https://api.zypheron.com/byok/keys/1/validate \
     -H "Authorization: Bearer YOUR_JWT_TOKEN"
   ```

3. **Use AI Services**: Once validated, requests to AI proxy will automatically use the user's key

4. **Check Usage**:
   ```bash
   curl https://api.zypheron.com/byok/keys \
     -H "Authorization: Bearer YOUR_JWT_TOKEN"
   ```

### Integration with AI Proxy

When a user makes an AI request, the system should:

1. Check if user has a valid BYOK key for the requested provider
2. If yes, use their key (no token deduction)
3. If no, use platform API keys and deduct tokens

**Example Integration** (in `ai_proxy.py`):

```python
from app.models.user_api_key import UserAPIKey
from app.core.encryption import decrypt_api_key

# Check for BYOK key
stmt = select(UserAPIKey).where(
    UserAPIKey.user_id == current_user.id,
    UserAPIKey.provider == provider,
    UserAPIKey.is_valid == True
)
result = await db.execute(stmt)
user_key = result.scalar_one_or_none()

if user_key:
    # Use user's API key (BYOK mode)
    api_key = decrypt_api_key(user_key.encrypted_key)
    user_key.update_last_used()
    await db.commit()
    # No token deduction
else:
    # Use platform API keys
    api_key = get_platform_api_key(provider)
    # Deduct tokens from user's quota
    await deduct_tokens(current_user.id, tokens_used)
```

## Security Considerations

### Encryption

- **Algorithm**: Fernet (AES-128-CBC + HMAC)
- **Key Storage**: Environment variables (production: secrets manager)
- **Data at Rest**: All API keys encrypted in database
- **Data in Transit**: HTTPS only

### Key Validation

Keys are validated by making actual API calls to providers:
- **OpenAI**: `GET /v1/models`
- **Anthropic**: `POST /v1/messages` (minimal request)
- **Gemini**: `GET /v1beta/models`
- **DeepSeek**: `GET /v1/models`
- **Grok**: `GET /v1/models`

### Input Validation

- Provider-specific format validation
- Length checks (min 20, max 500 chars)
- Prefix validation (e.g., `sk-` for OpenAI)
- Sanitization before storage

### Access Control

- All endpoints require authentication (JWT token)
- Users can only manage their own keys
- Keys are masked in responses (show only last 4 chars)
- Full keys never returned via API

## Database Schema

```sql
CREATE TABLE user_api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    provider VARCHAR(50) NOT NULL,
    encrypted_key TEXT NOT NULL,
    key_masked VARCHAR(50) NOT NULL,
    is_valid BOOLEAN NOT NULL DEFAULT FALSE,
    last_validated_at TIMESTAMP,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (user_id, provider)
);

CREATE INDEX idx_user_provider_unique ON user_api_keys(user_id, provider);
CREATE INDEX idx_user_valid ON user_api_keys(user_id, is_valid);
```

## Environment Variables Reference

```bash
# BYOK Configuration (Required)
BYOK_ENCRYPTION_KEY=<your-fernet-key-here>

# Example: Full .env configuration
BYOK_ENCRYPTION_KEY=7xK8vQ2mP9nL4wB6hD3jR5sT1cF0gY8uE2oA7iM6kN4=
```

## Troubleshooting

### Error: "BYOK_ENCRYPTION_KEY not set"

**Solution**: Add the encryption key to your `.env` file:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Copy output to .env
```

### Error: "Decryption failed: Invalid token or encryption key changed"

**Cause**: The encryption key was changed after keys were stored.

**Solution**:
1. Keys encrypted with the old key cannot be recovered
2. Users must re-add their API keys
3. Never change the encryption key in production

### Error: "Invalid [Provider] API key"

**Cause**: API key format validation failed.

**Solution**: Check that your key matches the expected format:
- OpenAI: `sk-...` or `sk-proj-...`
- Anthropic: `sk-ant-...`
- Gemini: Alphanumeric
- DeepSeek: `sk-...`

### Key Validation Fails

**Possible Causes**:
1. API key is invalid or expired
2. Network connectivity issues
3. Provider API is down
4. Rate limiting

**Solution**:
1. Verify key works directly with provider
2. Check network connectivity
3. Wait and retry if rate limited

## Production Checklist

- [ ] Set `BYOK_ENCRYPTION_KEY` in production environment
- [ ] Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)
- [ ] Enable HTTPS for all API endpoints
- [ ] Implement key rotation strategy
- [ ] Set up monitoring for failed validations
- [ ] Configure rate limiting for validation endpoints
- [ ] Backup encryption keys securely
- [ ] Document key recovery process
- [ ] Implement audit logging for key operations
- [ ] Set up alerts for encryption errors

## API Testing

### Using cURL

```bash
# Set variables
API_URL="http://localhost:8000"
JWT_TOKEN="your-jwt-token-here"

# Add OpenAI key
curl -X POST "$API_URL/byok/keys" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"provider": "openai", "api_key": "sk-proj-..."}'

# List keys
curl "$API_URL/byok/keys" \
  -H "Authorization: Bearer $JWT_TOKEN"

# Validate key
curl -X POST "$API_URL/byok/keys/1/validate" \
  -H "Authorization: Bearer $JWT_TOKEN"

# Delete key
curl -X DELETE "$API_URL/byok/keys/1" \
  -H "Authorization: Bearer $JWT_TOKEN"
```

### Using Python

```python
import httpx

API_URL = "http://localhost:8000"
JWT_TOKEN = "your-jwt-token-here"
headers = {"Authorization": f"Bearer {JWT_TOKEN}"}

# Add key
response = httpx.post(
    f"{API_URL}/byok/keys",
    headers=headers,
    json={
        "provider": "openai",
        "api_key": "sk-proj-..."
    }
)
print(response.json())

# List keys
response = httpx.get(f"{API_URL}/byok/keys", headers=headers)
print(response.json())

# Validate key
key_id = 1
response = httpx.post(
    f"{API_URL}/byok/keys/{key_id}/validate",
    headers=headers
)
print(response.json())
```

## Support

For issues or questions:
- Documentation: `/docs` endpoint (Swagger UI)
- GitHub Issues: [Project Repository]
- Email: support@zypheron.com
