# Token Tracking System - Implementation Guide

## Overview

The Token Tracking System provides comprehensive token usage monitoring, quota enforcement, and caching for the Zypheron API. It enables:

- Accurate token counting using tiktoken
- Per-user quota tracking and enforcement
- Usage analytics and history
- Response caching for cost optimization
- Tier-based limits with upgrade prompts

## Architecture

### Components

1. **Database Models** (`app/models/token_usage.py`)
   - `TokenUsage`: Individual usage records with provider/model tracking
   - `UserQuota`: Denormalized quota table for fast lookups

2. **Token Tracking Service** (`app/services/token_tracking.py`)
   - Token counting with tiktoken integration
   - Usage recording and retrieval
   - Quota checking and management
   - SHA-256 prompt hashing

3. **Cache Service** (`app/services/cache.py`)
   - Abstract cache interface
   - Redis backend (production)
   - In-memory fallback (development)
   - TTL management for prompts and vulnerability descriptions

4. **API Router** (`app/routers/tokens.py`)
   - GET `/tokens/usage` - Usage summary with period filter
   - GET `/tokens/remaining` - Remaining quota
   - GET `/tokens/quota` - Comprehensive quota info
   - GET `/tokens/history` - Paginated usage history

5. **Middleware** (`app/middleware/token_check.py`)
   - Pre-request quota validation
   - 429 responses with upgrade prompts
   - Automatic tier detection

## Token Limits by Tier

```python
Free:       0 tokens/month (BYOK only)
Starter:    1,000,000 tokens/month
Pro:        3,000,000 tokens/month
Enterprise: 15,000,000 tokens/month (shared pool per 5 users)
```

## Cache Strategy

### Cache Keys
- **AI Responses**: `ai_response:{sha256_hash}`
- **Vulnerability Descriptions**: `vuln_desc:{vuln_id}`

### TTL Configuration
- **Prompts**: 15 minutes (900 seconds)
- **Vulnerability Descriptions**: 1 hour (3600 seconds)

### Prompt Hashing
```python
from app.services.token_tracking import TokenTrackingService

# SHA-256 hash for exact match caching
prompt_hash = TokenTrackingService.hash_prompt(prompt_text)
```

## Usage Examples

### 1. Initialize User Quota (On Registration)

```python
from app.services.token_tracking import TokenTrackingService
from app.core.database import get_db

async def on_user_registration(user_id: int, tier: str):
    async with get_db() as db:
        service = TokenTrackingService(db)

        quota = await service.initialize_user_quota(
            user_id=user_id,
            tier=tier,
            byok_enabled=False,
        )

        await db.commit()
```

### 2. Count Tokens Before AI Request

```python
from app.services.token_tracking import TokenTrackingService

# Count tokens in prompt
prompt = "Analyze this code for security vulnerabilities..."
model = "gpt-4"

token_count = TokenTrackingService.count_tokens(prompt, model)
print(f"Prompt contains {token_count} tokens")
```

### 3. Check Quota Before Request

```python
async def before_ai_request(user_id: int, db: AsyncSession) -> bool:
    service = TokenTrackingService(db)

    has_quota = await service.check_quota(user_id)

    if not has_quota:
        # Return 429 or upgrade prompt
        remaining = await service.get_remaining_tokens(user_id)
        raise QuotaExceededError(f"No tokens remaining")

    return True
```

### 4. Record Usage After AI Request

```python
async def after_ai_request(
    user_id: int,
    tokens_used: int,
    provider: str,
    model: str,
    prompt: str,
    db: AsyncSession,
):
    service = TokenTrackingService(db)

    # Hash the prompt for cache key
    prompt_hash = service.hash_prompt(prompt)

    # Record usage
    usage = await service.record_usage(
        user_id=user_id,
        tokens_used=tokens_used,
        provider=provider,
        model=model,
        prompt_hash=prompt_hash,
        endpoint="/api/scan/code",
    )

    await db.commit()
```

### 5. Cache AI Response

```python
from app.services.cache import get_cache_service

async def handle_ai_request(prompt: str):
    cache = get_cache_service()
    service = TokenTrackingService(db)

    # Generate cache key
    prompt_hash = service.hash_prompt(prompt)

    # Check cache first
    cached = await cache.get_cached_response(prompt_hash)
    if cached:
        return cached

    # Make AI request
    response = await ai_provider.complete(prompt)

    # Cache the response (15 min TTL)
    await cache.cache_response(prompt_hash, response)

    return response
```

### 6. Get Usage Analytics

```python
async def get_user_analytics(user_id: int, db: AsyncSession):
    service = TokenTrackingService(db)

    # Get monthly usage
    monthly_usage = await service.get_usage(user_id, period="month")

    # Get breakdown by provider
    by_provider = await service.get_usage_by_provider(user_id, period="month")

    # Get quota info
    quota_info = await service.get_quota_info(user_id)

    return {
        "monthly_usage": monthly_usage,
        "by_provider": by_provider,
        "quota": quota_info,
    }
```

## API Endpoints

### GET /tokens/usage

Get usage summary for the current user.

**Query Parameters:**
- `period` (optional): "day" | "week" | "month" | "all" (default: "month")

**Response:**
```json
{
  "total_tokens": 250000,
  "period": "month",
  "by_provider": {
    "openai": 150000,
    "anthropic": 100000
  }
}
```

### GET /tokens/remaining

Get remaining token quota.

**Response:**
```json
{
  "tokens_remaining": 750000,
  "token_limit": 1000000,
  "tier": "starter",
  "byok_enabled": false
}
```

### GET /tokens/quota

Get comprehensive quota information.

**Response:**
```json
{
  "tier": "starter",
  "tokens_used": 250000,
  "token_limit": 1000000,
  "tokens_remaining": 750000,
  "percentage_used": 25.0,
  "period_start": "2025-01-01T00:00:00+00:00",
  "period_end": "2025-02-01T00:00:00+00:00",
  "byok_enabled": false
}
```

### GET /tokens/history

Get paginated usage history.

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `page_size` (optional): Items per page, max 100 (default: 50)
- `provider` (optional): Filter by provider

**Response:**
```json
{
  "items": [
    {
      "id": 123,
      "user_id": 1,
      "tokens_used": 1500,
      "provider": "openai",
      "model": "gpt-4",
      "prompt_hash": "a3f2...",
      "endpoint": "/api/scan/code",
      "created_at": "2025-01-15T10:30:00+00:00"
    }
  ],
  "total": 150,
  "page": 1,
  "page_size": 50,
  "total_pages": 3
}
```

## Middleware Integration

The `TokenQuotaMiddleware` automatically checks quotas before AI requests.

### Setup in main.py

```python
from fastapi import FastAPI
from app.middleware import add_token_quota_middleware

app = FastAPI()

# Add token quota middleware
add_token_quota_middleware(app)
```

### Protected Endpoints

The middleware automatically protects these endpoint patterns:
- `/api/ai/*` - AI proxy endpoints
- `/api/scan/*` - Vulnerability scanning
- `/api/analyze/*` - Code analysis

### 429 Response Format

When quota is exceeded:

```json
{
  "error": "quota_exceeded",
  "message": "Monthly token quota exceeded",
  "details": {
    "tier": "starter",
    "tokens_used": 1000000,
    "token_limit": 1000000,
    "period_end": "2025-02-01T00:00:00+00:00"
  },
  "upgrade_message": "You've reached your Starter tier limit. Upgrade to Pro ($29/month) for 3,000,000 tokens/month and priority support."
}
```

**Headers:**
- `X-RateLimit-Limit`: Token limit for tier
- `X-RateLimit-Remaining`: 0
- `X-RateLimit-Reset`: Period end timestamp
- `Retry-After`: Seconds until quota reset

## Database Migrations

### Create Tables

```python
from app.core.database import init_db

# Initialize all tables including token_usage and user_quota
await init_db()
```

### Indexes

The system creates optimized indexes for:
- User ID + Created At (quota checks)
- User ID + Provider + Created At (analytics)
- Prompt Hash (cache lookups)

## Cache Backend Configuration

### Redis (Production)

```bash
# .env
REDIS_URL=redis://localhost:6379/0
REDIS_ENABLED=true
```

### In-Memory (Development)

```bash
# .env
REDIS_ENABLED=false
```

The system automatically falls back to in-memory cache if Redis is unavailable.

## Model Support

### Supported Models

The system includes accurate token counting for:

**OpenAI:**
- GPT-4, GPT-4 Turbo (cl100k_base)
- GPT-4o, GPT-4o-mini (o200k_base)
- GPT-3.5 Turbo (cl100k_base)

**Anthropic:**
- Claude 3 Opus, Sonnet, Haiku
- Claude 3.5 Sonnet

**Other:**
- Grok Beta
- DeepSeek Chat/Coder

Unknown models default to `cl100k_base` encoding.

## Billing Period Management

### Reset Quota on Period End

```python
async def reset_monthly_quotas():
    """Cron job to reset quotas at period end"""
    from app.core.database import get_db_context
    from app.models.user_quota import UserQuota
    from sqlalchemy import select

    async with get_db_context() as db:
        # Get all quotas where period has ended
        now = datetime.now(timezone.utc)
        stmt = select(UserQuota).where(UserQuota.period_end <= now)
        result = await db.execute(stmt)
        quotas = result.scalars().all()

        # Reset each quota
        for quota in quotas:
            service = TokenTrackingService(db)
            await service.reset_period_usage(quota.user_id)

        await db.commit()
```

## Performance Considerations

### Query Optimization

1. **Denormalized Quotas**: `UserQuota` table avoids expensive aggregations
2. **Indexed Queries**: All common queries use composite indexes
3. **Cache Layer**: Reduces redundant AI API calls
4. **Async Operations**: Full async/await support

### Scalability

- Handles millions of usage records per user
- Efficient pagination for history queries
- Redis clustering support for distributed caching
- Database connection pooling with SQLAlchemy

## Security

### Prompt Hashing
- SHA-256 ensures collision resistance
- Hashes are deterministic for cache hits
- Full prompts never stored in cache keys

### Data Protection
- Token usage data is user-scoped
- No cross-user data leakage
- Cascade delete on user removal

## Monitoring

### Key Metrics to Track

1. **Cache Hit Rate**: `cache_hits / total_requests`
2. **Quota Utilization**: `tokens_used / token_limit`
3. **Provider Distribution**: Tokens by provider
4. **429 Rate**: Quota exceeded responses

### Logging

```python
import logging

logger = logging.getLogger("app.services.token_tracking")
logger.info(f"User {user_id} used {tokens_used} tokens")
```

## Testing

### Unit Tests

```python
import pytest
from app.services.token_tracking import TokenTrackingService

@pytest.mark.asyncio
async def test_count_tokens():
    text = "Hello, world!"
    model = "gpt-4"

    count = TokenTrackingService.count_tokens(text, model)
    assert count > 0

@pytest.mark.asyncio
async def test_quota_check(db_session):
    service = TokenTrackingService(db_session)

    # Initialize quota
    await service.initialize_user_quota(
        user_id=1,
        tier="starter",
    )

    # Should have quota
    has_quota = await service.check_quota(1)
    assert has_quota is True
```

## Troubleshooting

### Issue: Cache not working

**Check:**
1. Redis connection: `REDIS_URL` in .env
2. Redis service running: `redis-cli ping`
3. Falls back to in-memory if Redis unavailable

### Issue: Incorrect token counts

**Solution:**
- Verify model name matches `MODEL_ENCODINGS`
- Unknown models use cl100k_base
- Update encoding map for new models

### Issue: Quota not enforcing

**Check:**
1. Middleware registered: `add_token_quota_middleware(app)`
2. Endpoint matches pattern in `AI_ENDPOINTS`
3. `UserQuota` record exists for user

## Future Enhancements

1. **Enterprise Pools**: Shared quota tracking across teams
2. **Cost Tracking**: Convert tokens to USD cost estimates
3. **Alerts**: Email/Slack notifications at 80% quota
4. **Rate Limiting**: Per-minute/hour limits alongside monthly
5. **Analytics Dashboard**: Usage trends and projections

## Support

For issues or questions:
- Check logs: `app/logs/token_tracking.log`
- Database queries: Monitor slow query log
- Redis status: `redis-cli info stats`

---

**Version:** 1.0.0
**Last Updated:** 2025-12-19
**Maintained by:** Zypheron Team
