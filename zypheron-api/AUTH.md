# Authentication

Zypheron API supports three authentication methods: device code flow (for CLI), GitHub OAuth (for web), and BYOK key management.

## Device Code Authentication

The CLI uses OAuth 2.0 Device Authorization Grant (RFC 8628) to authenticate without a browser login on the CLI itself.

### Flow

1. CLI requests a device code from the API
2. User visits the verification URL and enters the code
3. User logs in via web app and authorizes the device
4. CLI polls until authorized, then receives a JWT token

### Endpoints

| Endpoint | Method | Auth | Called By |
|----------|--------|------|-----------|
| `/auth/device/code` | POST | No | CLI |
| `/auth/device/authorize` | POST | JWT | Web App |
| `/auth/device/token` | POST | No | CLI (polling) |

### 1. Request Device Code

```bash
curl -X POST http://localhost:8000/auth/device/code \
  -H 'Content-Type: application/json' \
  -d '{"device_info": {"os": "Linux", "cli_version": "2.0.0"}}'
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

- `device_code`: Secret for polling (never show to user)
- `user_code`: Display to user (XXXX-XXXX format)
- Codes expire after 5 minutes

### 2. Authorize Device (Web App)

```bash
curl -X POST http://localhost:8000/auth/device/authorize \
  -H 'Authorization: Bearer <jwt_token>' \
  -H 'Content-Type: application/json' \
  -d '{"user_code": "ABCD-1234"}'
```

### 3. Poll for Token (CLI)

```bash
curl -X POST http://localhost:8000/auth/device/token \
  -H 'Content-Type: application/json' \
  -d '{"device_code": "K7P9M2X5Q8W3N1V4C6Z0R9Y2T5H8J3", "device_info": {"os": "Linux"}}'
```

Poll every 5 seconds. Possible `status` values: `pending`, `authorized`, `expired`, `denied`.

On `authorized`, the response includes `access_token`, `user_id`, `email`, and `tier`.

## GitHub OAuth

### Setup

1. Register an OAuth App at [GitHub Developer Settings](https://github.com/settings/developers)
   - Callback URL: `http://localhost:8000/auth/github/callback`
2. Add to `.env`:

```bash
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
BASE_URL=http://localhost:8000
FRONTEND_URL=http://localhost:3000
```

For production, set `BASE_URL` and `FRONTEND_URL` to your domains and use `ENVIRONMENT=production` for HTTPS-only cookies.

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/github` | GET | Initiates OAuth flow (redirects to GitHub) |
| `/auth/github/callback` | GET | Handles callback, returns JWT + user info |

### Security

- CSRF protection via state parameter in HttpOnly cookie (10-minute expiry)
- GitHub access token used only to fetch profile, never stored
- Accounts auto-link when email matches an existing user
- Private GitHub emails handled (falls back to any verified email)

### Account Types

| Type | Description |
|------|-------------|
| GitHub OAuth only | Created via GitHub signup; `password_hash` is NULL |
| Email + GitHub linked | Email/password account later linked to GitHub |
| Email only | Traditional registration, no GitHub fields |

## BYOK (Bring Your Own Key)

Users can store their own AI provider API keys for direct provider access without consuming platform tokens.

### Setup

Generate a Fernet encryption key and add to `.env`:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# .env
BYOK_ENCRYPTION_KEY=<generated_key>
```

The `user_api_keys` table is created automatically on startup.

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/byok/keys` | POST | Add a new API key |
| `/byok/keys` | GET | List user's keys (masked) |
| `/byok/keys/{id}/validate` | POST | Validate key with provider |
| `/byok/keys/{id}` | DELETE | Delete a key |

### Supported Key Formats

| Provider | Prefix |
|----------|--------|
| OpenAI | `sk-` or `sk-proj-` |
| Anthropic | `sk-ant-` |
| Gemini | Alphanumeric (~39 chars) |
| DeepSeek | `sk-` |
| Grok | 20+ chars |

### Security

- Keys encrypted at rest with Fernet (AES-128-CBC + HMAC)
- Keys masked in API responses (last 4 chars only)
- Full keys never returned via API
- All endpoints require JWT authentication
- Users can only manage their own keys

### Integration with AI Proxy

When a user makes an AI request, the system checks for a valid BYOK key for the requested provider. If found, the user's key is used and no tokens are deducted.

## General Auth Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/register` | POST | Register with email/password |
| `/auth/login` | POST | Login, receive JWT |
| `/auth/logout` | POST | Invalidate session |
| `/auth/me` | GET | Get current user info |

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "GitHub OAuth not configured" | Set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` in `.env` |
| "Invalid state parameter" | Restart OAuth flow (cookie expired or CSRF blocked) |
| "No verified email found" | Verify an email in GitHub settings |
| "BYOK_ENCRYPTION_KEY not set" | Generate and add Fernet key to `.env` |
| "Decryption failed" | Encryption key changed; users must re-add their API keys |
