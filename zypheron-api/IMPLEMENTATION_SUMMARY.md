# AI Proxy License Validation Implementation Summary

## Overview
Implemented proper license validation and BYOK (Bring Your Own Key) logic in the AI proxy router with correct business logic for tier-based access control and token consumption.

## Implementation Details

### 1. Authentication Required
- **ALL** `/ai/chat` requests now require authentication
- Users must include JWT token in `Authorization: Bearer <token>` header
- Unauthenticated requests return `401 Unauthorized`

### 2. Tier-Based Feature Access (Payment Required)

#### Free Tier
- Can ONLY use Ollama (local models)
- NO access to cloud AI providers (OpenAI, Anthropic, Grok, DeepSeek)
- Attempting to use cloud providers returns `403 Forbidden` with message:
  ```
  Cloud AI providers require Starter tier or higher.
  Free tier can only use Ollama (local models).
  Upgrade your plan to access OpenAI, Anthropic, Grok, and DeepSeek.
  ```

#### Paid Tiers (Starter/Pro/Enterprise)
- Full access to ALL providers including:
  - OpenAI (GPT-4, GPT-3.5, etc.)
  - Anthropic (Claude)
  - Grok (xAI)
  - DeepSeek
  - Ollama (local models)

### 3. Token Consumption & BYOK Bypass

#### BYOK (Bring Your Own Key) Flow
1. User adds their own API key via BYOK management endpoints
2. Key is encrypted with Fernet symmetric encryption and stored in `user_api_keys` table
3. When making AI requests:
   - System checks for valid BYOK key for the requested provider
   - If found: Decrypts and uses user's key
   - **NO token deduction** from user's quota
   - Only updates `last_used_at` timestamp on BYOK key
4. Benefits:
   - Unlimited usage (no token limits)
   - User pays provider directly
   - Full control over API costs

#### Platform Keys Flow
1. User has NO BYOK key for the provider
2. System uses platform-managed API keys
3. Before request:
   - Checks user's token quota for current billing period
   - If quota exceeded: Returns `402 Payment Required` with message:
     ```
     Insufficient tokens. You've used X of your Y monthly tokens.
     Add a BYOK (Bring Your Own Key) to bypass token limits, or upgrade your plan.
     ```
4. After successful request:
   - Deducts tokens from user's quota
   - Creates `TokenUsage` record for billing/analytics
   - Updates `UserQuota.tokens_used_period`

### 4. Token Limits by Tier

| Tier       | Monthly Token Limit | Cloud AI Access |
|------------|--------------------:|:---------------:|
| Free       |                   0 | No (Ollama only)|
| Starter    |           1,000,000 | Yes             |
| Pro        |           3,000,000 | Yes             |
| Enterprise |          15,000,000 | Yes             |

### 5. Key Functions Added

#### `get_current_user_optional()`
- Dependency that extracts user from JWT token
- Returns `User | None` (optional authentication)
- Used in `/ai/chat` endpoint

#### `check_license_and_byok()`
- Core business logic function
- Checks user's tier against requested provider
- Returns tuple: `(decrypted_api_key | None, is_byok: bool)`
- Raises `HTTPException` if:
  - Free tier trying to use cloud providers (403)
  - Insufficient tokens when using platform keys (402)

#### `_create_default_quota()`
- Creates `UserQuota` record for new users
- Sets token limits based on tier
- Calculates billing period (monthly)

#### `update_token_usage()`
- Called after successful API request (platform keys only)
- Creates `TokenUsage` record
- Updates `UserQuota.tokens_used_period`
- Tracks: user, provider, model, tokens, timestamp, prompt_hash

#### `update_byok_last_used()`
- Called after successful API request (BYOK only)
- Updates `UserAPIKey.last_used_at` timestamp
- No token deduction

### 6. Updated Endpoints

#### `POST /ai/chat`
**Changes:**
- Added authentication requirement (was optional before)
- Added `current_user` dependency
- Added `db` dependency for database access
- Integrated license checking before provider access
- Integrated token tracking after request completion
- Updated documentation with tier restrictions

**Request Flow:**
1. Authenticate user (401 if missing)
2. Auto-select provider if not specified
3. Check license tier & BYOK status (403 if restricted, 402 if no tokens)
4. Decrypt BYOK key if available
5. Check cache (only for platform keys, non-streaming)
6. Execute AI request
7. Update token usage (platform) or BYOK timestamp
8. Cache response (platform keys only)
9. Return response

**Error Codes:**
- `401`: Authentication required
- `402`: Insufficient tokens (upgrade or add BYOK)
- `403`: Tier upgrade required (Free tier trying to use cloud AI)
- `429`: Rate limit exceeded
- `503`: Service unavailable

### 7. Security Enhancements

#### API Key Protection
- BYOK keys stored encrypted with Fernet (AES-128-CBC)
- Decryption only happens at request time
- Never logged or exposed in responses
- Sanitized from error messages

#### Input Validation
- All user inputs validated via Pydantic schemas
- Provider names validated against allowed list
- Token limits enforced before request execution

#### Proper Error Messages
- Clear, actionable error messages
- No sensitive data leakage
- Guidance on how to resolve (upgrade, add BYOK, etc.)

### 8. Database Integration

#### Tables Used
- `users`: User account and tier information
- `user_api_keys`: Encrypted BYOK keys
- `user_quota`: Token quotas and usage tracking
- `token_usage`: Detailed usage logs per request
- `sessions`: JWT token validation

#### Queries Added
- Check for valid BYOK key by user_id + provider
- Get/create user quota by user_id
- Insert token usage records
- Update BYOK last_used timestamp

### 9. Logging Improvements

#### New Log Events
- `ollama_access`: User accessing Ollama (always allowed)
- `byok_key_found`: BYOK key found and decrypted
- `byok_key_decryption_failed`: Decryption error
- `platform_key_access`: Using platform keys with remaining tokens
- `quota_created`: New quota record created
- `token_usage_updated`: Tokens deducted from quota
- `byok_last_used_updated`: BYOK timestamp updated
- `ai_chat_success_byok`: Successful BYOK request
- `ai_chat_success_platform`: Successful platform key request

#### Enhanced Existing Logs
- Added `user_id` to all AI request logs
- Added `tier` to platform key request logs
- Added `tokens_remaining` to quota checks

### 10. Caching Strategy

#### When to Cache
- Non-streaming requests only
- Platform keys only (NOT BYOK)
- Identical prompts (SHA-256 hash match)

#### Cache TTL by Content Type
- CVE/vulnerability queries: 24 hours
- General security questions: 6 hours
- Other prompts: 1 hour

#### Why NOT Cache BYOK
- User is paying for their own API usage
- Should get fresh responses every time
- Avoids quota/billing confusion

## Testing Recommendations

### Test Cases to Validate

1. **Free Tier Restrictions**
   - ✅ Free user can access Ollama
   - ✅ Free user gets 403 for OpenAI/Anthropic/Grok/DeepSeek
   - ✅ Error message explains upgrade needed

2. **Paid Tier Access**
   - ✅ Starter/Pro/Enterprise can access all providers
   - ✅ Token deduction works correctly
   - ✅ Quota exceeded returns 402

3. **BYOK Flow**
   - ✅ Valid BYOK key bypasses token limits
   - ✅ BYOK requests don't deduct tokens
   - ✅ Last_used timestamp updates
   - ✅ BYOK requests not cached

4. **Platform Keys Flow**
   - ✅ Token deduction after each request
   - ✅ Quota tracking accurate
   - ✅ Cache works for identical prompts

5. **Authentication**
   - ✅ No token = 401 error
   - ✅ Invalid token = 401 error
   - ✅ Valid token = allowed

## Files Modified

1. **`/app/routers/ai_proxy.py`** (PRIMARY)
   - Added imports for DB models, auth, encryption
   - Added `get_current_user_optional()` dependency
   - Added `check_license_and_byok()` core logic
   - Added `_create_default_quota()` helper
   - Added `update_token_usage()` tracking
   - Added `update_byok_last_used()` tracking
   - Updated `chat_completion()` endpoint
   - Updated `_handle_complete_chat()` for token tracking
   - Updated `_handle_streaming_chat()` for token tracking

2. **`/app/schemas/ai_proxy.py`**
   - Added "ollama" to `ChatCompletionRequest.provider` literal
   - Added "ollama" to `ValidateKeyRequest.provider` literal

3. **`/app/models/user_api_key.py`**
   - Added "ollama" to `ProviderType` literal

## Migration Notes

### Database Changes Needed
None - all tables already exist. Implementation uses existing schema:
- `user_api_keys` (BYOK storage)
- `user_quota` (token tracking)
- `token_usage` (usage logs)
- `users` (tier information)
- `sessions` (authentication)

### Configuration Required
Ensure these environment variables are set:
- `BYOK_ENCRYPTION_KEY`: Fernet key for encrypting BYOK keys
  - Generate: `python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`

## API Documentation Updates

### Endpoint: `POST /ai/chat`

**Authentication:** Required (was optional before)
```
Authorization: Bearer <jwt_token>
```

**Request Body:**
```json
{
  "messages": [
    {"role": "user", "content": "Hello"}
  ],
  "provider": "openai",  // or "anthropic", "grok", "deepseek", "ollama"
  "model": "gpt-4o",
  "temperature": 0.7,
  "stream": false,
  "user_api_key": null  // Optional: override BYOK with inline key
}
```

**Response Codes:**
- `200`: Success
- `401`: Authentication required
- `402`: Insufficient tokens (upgrade or add BYOK)
- `403`: Tier upgrade required (Free tier, cloud provider)
- `429`: Rate limit exceeded
- `503`: Service unavailable

**Free Tier Example (Ollama):**
```bash
curl -X POST https://api.example.com/ai/chat \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [{"role": "user", "content": "Hello"}],
    "provider": "ollama",
    "model": "llama3"
  }'
```

**Free Tier Example (Cloud - REJECTED):**
```bash
curl -X POST https://api.example.com/ai/chat \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [{"role": "user", "content": "Hello"}],
    "provider": "openai",
    "model": "gpt-4"
  }'

# Response: 403 Forbidden
# {
#   "detail": "Cloud AI providers require Starter tier or higher. Free tier can only use Ollama (local models). Upgrade your plan to access OpenAI, Anthropic, Grok, and DeepSeek."
# }
```

## Summary

The implementation successfully enforces the business logic:

1. **Feature Access = Tier-Based**
   - Free tier: Ollama only
   - Paid tiers: All providers

2. **Token Consumption = BYOK Bypass**
   - BYOK: No token deduction, unlimited usage
   - Platform keys: Token deduction, quota enforcement

3. **Security & Scalability**
   - Encrypted BYOK storage
   - Proper authentication
   - Token tracking for billing
   - Usage analytics

4. **User Experience**
   - Clear error messages
   - Guidance on upgrades
   - Transparent quota usage
   - Cache optimization
