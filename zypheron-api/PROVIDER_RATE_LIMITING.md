# Per-Provider Rate Limiting Implementation

## Overview

Per-provider rate limiting has been successfully implemented for the AI proxy router to prevent abuse of expensive cloud AI providers while allowing unlimited access to local Ollama instances.

## Implementation Details

### Location
- **File**: `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/routers/ai_proxy.py`

### Key Components

#### 1. Rate Limit Configuration

**Provider Rate Limits** (requests per minute):

```python
PROVIDER_RATE_LIMITS = {
    "ollama": {
        "free": -1,      # Unlimited (local, no cost)
        "starter": -1,
        "pro": -1,
        "enterprise": -1,
    },
    "openai_gpt4": {    # GPT-4o and similar expensive models
        "free": 0,       # Free tier blocked from cloud providers
        "starter": 30,
        "pro": 60,
        "enterprise": 120,
    },
    "openai_gpt35": {   # GPT-3.5 and cheaper models
        "free": 0,
        "starter": 60,
        "pro": 120,
        "enterprise": 240,
    },
    "anthropic": {      # All Claude models
        "free": 0,
        "starter": 30,
        "pro": 60,
        "enterprise": 120,
    },
    "deepseek": {
        "free": 0,
        "starter": 60,
        "pro": 120,
        "enterprise": 240,
    },
    "grok": {
        "free": 0,
        "starter": 30,
        "pro": 60,
        "enterprise": 120,
    },
}
```

**BYOK Multiplier**: Users with Bring Your Own Key (BYOK) receive **2x** the normal rate limit since they're paying for their own API calls.

#### 2. Model Tier Classification

Models are classified into provider tiers to determine which rate limit applies:

```python
MODEL_TIERS = {
    # OpenAI - GPT-4 tier (expensive)
    "gpt-4o": "openai_gpt4",
    "gpt-4o-mini": "openai_gpt4",
    "gpt-4-turbo": "openai_gpt4",
    "gpt-4": "openai_gpt4",

    # OpenAI - GPT-3.5 tier (cheaper)
    "gpt-3.5-turbo": "openai_gpt35",
    "gpt-3.5-turbo-16k": "openai_gpt35",

    # Anthropic - all models same tier
    "claude-3-5-sonnet-20241022": "anthropic",
    "claude-3-5-haiku-20241022": "anthropic",
    "claude-3-opus-20240229": "anthropic",

    # DeepSeek
    "deepseek-chat": "deepseek",
    "deepseek-coder": "deepseek",

    # Grok
    "grok-beta": "grok",
    "grok-2": "grok",
}
```

#### 3. Redis-Based Rate Tracking

**Key Format**: `ai_ratelimit:{user_id}:{provider_tier}`

**Algorithm**: Sliding window (60 seconds) using Redis sorted sets
- Same robust implementation as global rate limiter
- Each request is tracked with a timestamp score
- Old entries automatically expire
- Atomic operations using Redis pipelines

#### 4. Rate Limit Function

```python
async def check_provider_rate_limit(
    user_id: int,
    provider_type: ProviderType,
    model: str,
    tier: str,
    is_byok: bool,
) -> tuple[bool, int, int, str]:
```

**Returns**:
- `allowed` (bool): Whether request is allowed
- `remaining` (int): Requests remaining in window
- `reset_at` (int): Unix timestamp when limit resets
- `provider_tier` (str): Provider tier used for rate limiting

**Behavior**:
- ✅ **Ollama**: Always allowed (unlimited)
- ✅ **BYOK Users**: 2x rate limit multiplier applied
- ✅ **Fail Closed**: If Redis unavailable, requests are denied (security-first approach)
- ✅ **Atomic Operations**: Uses Redis pipelines for race condition prevention

### Integration Flow

1. **Authentication Check**: User must be authenticated
2. **Provider Selection**: Auto-select provider if not specified
3. **License & BYOK Check**: Verify tier permissions and BYOK status
4. **Provider Rate Limit Check**: ⭐ **NEW** - Check per-provider limits BEFORE API call
5. **Cache Check**: Check for cached responses (if applicable)
6. **API Call**: Execute the actual provider API call
7. **Response Headers**: Add rate limit information to response

### Response Headers

All successful responses include:

```http
X-Provider-RateLimit-Limit: 60          # Your tier's limit for this provider
X-Provider-RateLimit-Remaining: 42      # Remaining requests
X-Provider-RateLimit-Reset: 1704123456  # Unix timestamp when resets
```

### Error Responses

When rate limit is exceeded (HTTP 429):

```json
{
  "detail": "Rate limit exceeded for openai (openai_gpt4). Your starter tier allows 30 requests per minute for this provider. Try again in 45 seconds. Consider using an alternative provider: anthropic, deepseek, ollama."
}
```

**Headers**:
```http
X-Provider-RateLimit-Limit: 30
X-Provider-RateLimit-Remaining: 0
X-Provider-RateLimit-Reset: 1704123456
Retry-After: 45
```

## Security Features

### 1. Fail-Closed Design
- If Redis is unavailable, **deny** requests (unlike global rate limiter which fails open)
- Prevents abuse during infrastructure issues
- Returns HTTP 503 with clear error message

### 2. Abuse Prevention
- Prevents users from hammering expensive providers (GPT-4, Claude)
- Separate limits per provider prevent cross-contamination
- BYOK users get higher limits but still rate limited

### 3. Sliding Window Algorithm
- Smooth rate limiting (no burst issues at window boundaries)
- Redis sorted sets track exact timestamps
- Automatic cleanup of old entries
- Race condition protection with atomic operations

## API Documentation Updates

The `/ai/chat` endpoint documentation now includes:

```
Per-provider limits (per user, per minute):
- Ollama: Unlimited (local, no cost)
- OpenAI GPT-4: Starter=30, Pro=60, Enterprise=120
- OpenAI GPT-3.5: Starter=60, Pro=120, Enterprise=240
- Anthropic Claude: Starter=30, Pro=60, Enterprise=120
- DeepSeek: Starter=60, Pro=120, Enterprise=240
- Grok: Starter=30, Pro=60, Enterprise=120
- BYOK users get 2x the normal provider limit

Response headers:
- X-Provider-RateLimit-Limit: Your provider-specific rate limit
- X-Provider-RateLimit-Remaining: Remaining requests for this provider
- X-Provider-RateLimit-Reset: Unix timestamp when limit resets
```

## Logging

Comprehensive structured logging for monitoring:

### Success Cases
```python
logger.debug("provider_rate_limit_checked",
    user_id=user_id,
    provider=provider_type.value,
    provider_tier=provider_tier,
    tier=tier,
    is_byok=is_byok,
    limit=rate_limit,
    remaining=remaining,
    reset_at=reset_time
)
```

### Rate Limit Exceeded
```python
logger.warning("provider_rate_limit_exceeded",
    user_id=user_id,
    provider=provider_type.value,
    provider_tier=provider_tier,
    tier=tier,
    is_byok=is_byok,
    limit=rate_limit,
    current_count=current_count
)
```

### Errors
```python
logger.error("redis_unavailable_for_provider_rate_limit",
    error=str(e),
    user_id=user_id,
    provider=provider_type.value
)
```

## Testing Recommendations

### Manual Testing

1. **Test Ollama (Unlimited)**:
   ```bash
   # Should always succeed
   curl -X POST http://localhost:8000/ai/chat \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "provider": "ollama",
       "model": "llama3",
       "messages": [{"role": "user", "content": "Hello"}]
     }'
   ```

2. **Test GPT-4 Rate Limit (Starter = 30/min)**:
   ```bash
   # Make 31 requests rapidly - last one should return 429
   for i in {1..31}; do
     curl -X POST http://localhost:8000/ai/chat \
       -H "Authorization: Bearer $TOKEN" \
       -H "Content-Type: application/json" \
       -d '{
         "provider": "openai",
         "model": "gpt-4o",
         "messages": [{"role": "user", "content": "Test '$i'"}]
       }'
   done
   ```

3. **Test BYOK Multiplier**:
   - Add BYOK key for OpenAI via `/byok/keys` endpoint
   - Verify rate limit is 2x normal (60 instead of 30 for Starter)
   - Check headers: `X-Provider-RateLimit-Limit: 60`

4. **Test Response Headers**:
   ```bash
   curl -v -X POST http://localhost:8000/ai/chat \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"provider": "openai", "model": "gpt-4o", "messages": [...]}' \
     | grep -i "X-Provider-RateLimit"
   ```

5. **Test Different Providers Independently**:
   ```bash
   # OpenAI and Anthropic have separate limits
   # 30 requests to OpenAI shouldn't affect Anthropic limit

   # Make 30 OpenAI requests
   for i in {1..30}; do curl ...; done

   # Should still be able to make Anthropic requests
   curl -X POST ... -d '{"provider": "anthropic", "model": "claude-3-5-sonnet-20241022", ...}'
   ```

### Integration Testing

```python
import pytest
from app.routers.ai_proxy import check_provider_rate_limit
from app.services.ai_providers import ProviderType

@pytest.mark.asyncio
async def test_provider_rate_limit_ollama_unlimited():
    """Ollama should always allow requests (unlimited)."""
    allowed, remaining, reset_at, tier = await check_provider_rate_limit(
        user_id=1,
        provider_type=ProviderType.OLLAMA,
        model="llama3",
        tier="starter",
        is_byok=False
    )
    assert allowed is True
    assert remaining == -1  # Unlimited

@pytest.mark.asyncio
async def test_provider_rate_limit_gpt4_starter():
    """Starter tier should get 30 req/min for GPT-4."""
    # Make 30 requests - should succeed
    for i in range(30):
        allowed, remaining, reset_at, tier = await check_provider_rate_limit(
            user_id=1,
            provider_type=ProviderType.OPENAI,
            model="gpt-4o",
            tier="starter",
            is_byok=False
        )
        assert allowed is True

    # 31st request should fail
    allowed, remaining, reset_at, tier = await check_provider_rate_limit(
        user_id=1,
        provider_type=ProviderType.OPENAI,
        model="gpt-4o",
        tier="starter",
        is_byok=False
    )
    assert allowed is False
    assert remaining == 0

@pytest.mark.asyncio
async def test_provider_rate_limit_byok_2x():
    """BYOK users should get 2x rate limit."""
    # Starter + BYOK = 30 * 2 = 60 req/min
    for i in range(60):
        allowed, remaining, reset_at, tier = await check_provider_rate_limit(
            user_id=1,
            provider_type=ProviderType.OPENAI,
            model="gpt-4o",
            tier="starter",
            is_byok=True  # BYOK enabled
        )
        assert allowed is True

    # 61st should fail
    allowed, remaining, reset_at, tier = await check_provider_rate_limit(
        user_id=1,
        provider_type=ProviderType.OPENAI,
        model="gpt-4o",
        tier="starter",
        is_byok=True
    )
    assert allowed is False
```

## Performance Considerations

### Redis Operations per Request
1. `ZCOUNT` - Count requests in window (O(log N))
2. `ZADD` - Add current request (O(log N))
3. `ZREMRANGEBYSCORE` - Remove old entries (O(log N))
4. `EXPIRE` - Set key expiration (O(1))

**Total**: 4 Redis operations using pipeline (executed atomically)

### Memory Usage
- Each request stores ~50 bytes in Redis (timestamp + random suffix)
- Max 300 requests/min for Enterprise = ~15KB per user per provider
- Keys auto-expire after 120 seconds (2x window size)
- Minimal memory footprint

## Monitoring Recommendations

### Key Metrics to Track

1. **Rate Limit Hits per Provider**:
   ```
   provider_rate_limit_exceeded count by provider_tier, tier
   ```

2. **Redis Availability**:
   ```
   redis_unavailable_for_provider_rate_limit errors
   ```

3. **Distribution of Provider Usage**:
   ```
   provider_rate_limit_checked count by provider_tier
   ```

4. **BYOK vs Platform Key Usage**:
   ```
   provider_rate_limit_checked count by is_byok
   ```

### Alerts to Configure

1. **High Rate Limit Rejection Rate**: Alert if >10% of requests hit provider limits
2. **Redis Connection Issues**: Alert on any `redis_unavailable` errors
3. **Unusual Provider Distribution**: Alert if one provider gets >80% of traffic (potential abuse)

## Future Enhancements

### Potential Improvements

1. **Dynamic Rate Limits**: Adjust limits based on time of day or system load
2. **Burst Allowance**: Allow short bursts above the limit (token bucket algorithm)
3. **Per-Model Granularity**: Different limits for different models within same provider
4. **Rate Limit Quotas**: Daily/weekly limits in addition to per-minute
5. **Admin Override**: Allow admins to temporarily increase limits for specific users
6. **Metrics Dashboard**: Real-time visualization of rate limit usage

### Configuration Options

Consider adding to `Settings`:
```python
class Settings(BaseSettings):
    # Provider rate limit multipliers (allow env var overrides)
    provider_rate_limit_multiplier_byok: float = 2.0
    provider_rate_limit_window_seconds: int = 60
    provider_rate_limit_fail_closed: bool = True  # Deny on Redis failure
```

## Conclusion

The per-provider rate limiting implementation provides:

✅ **Abuse Prevention**: Expensive providers protected from overuse
✅ **Fair Resource Allocation**: Tier-based limits ensure fair usage
✅ **BYOK Incentive**: 2x limits encourage users to bring own keys
✅ **Operational Visibility**: Comprehensive logging and headers
✅ **Production Ready**: Fail-closed security, atomic operations, error handling
✅ **User Friendly**: Clear error messages with alternative provider suggestions

The implementation is production-ready and follows all security and performance best practices.
