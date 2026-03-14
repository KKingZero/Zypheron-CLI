# Token Tracking System - Implementation Summary

## Overview

Successfully implemented a comprehensive Token Tracking System for the Zypheron API with the following capabilities:

- Accurate token counting using tiktoken for all major AI providers
- Per-user quota tracking and enforcement with tier-based limits
- High-performance caching with Redis and in-memory fallback
- RESTful API endpoints for usage monitoring and analytics
- Automatic quota checking middleware with upgrade prompts
- SHA-256 prompt hashing for exact-match cache lookups

## Files Created

### 1. Database Models
**File:** `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/models/token_usage.py`

**Models:**
- `TokenUsage`: Records individual API calls with token consumption
- `UserQuota`: Denormalized quota table for fast lookups

**Key Features:**
- Foreign key relationships with User model
- Composite indexes for efficient querying
- Support for BYOK (Bring Your Own Key) users
- Enterprise pool tracking for shared quotas
- Automatic timestamps with timezone support

### 2. Token Tracking Service
**File:** `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/services/token_tracking.py`

**Core Methods:**
```python
# Token counting
TokenTrackingService.count_tokens(text: str, model: str) -> int

# Usage recording
await service.record_usage(
    user_id=1,
    tokens_used=1500,
    provider="openai",
    model="gpt-4",
    prompt_hash="abc123...",
)

# Quota checking
has_quota = await service.check_quota(user_id=1)
remaining = await service.get_remaining_tokens(user_id=1)

# Analytics
usage = await service.get_usage(user_id=1, period="month")
by_provider = await service.get_usage_by_provider(user_id=1)
quota_info = await service.get_quota_info(user_id=1)
```

**Supported Models:**
- OpenAI: GPT-4, GPT-4 Turbo, GPT-4o, GPT-3.5 Turbo
- Anthropic: Claude 3 (Opus, Sonnet, Haiku), Claude 3.5 Sonnet
- Grok: Grok Beta
- DeepSeek: Chat and Coder models

### 3. Cache Service
**File:** `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/services/cache.py`

**Architecture:**
- Abstract `CacheBackend` interface
- `RedisCacheBackend` for production (with auto-reconnect)
- `InMemoryCacheBackend` for development (with TTL support)
- Automatic fallback if Redis is unavailable

**Cache Methods:**
```python
cache = get_cache_service()

# Cache AI responses
await cache.cache_response(prompt_hash, response, ttl=900)
cached = await cache.get_cached_response(prompt_hash)

# Cache vulnerability descriptions
await cache.cache_vuln_description(vuln_id, description, ttl=3600)
cached = await cache.get_cached_vuln_description(vuln_id)
```

**TTL Configuration:**
- Prompts: 15 minutes (900 seconds)
- Vulnerability Descriptions: 1 hour (3600 seconds)

### 4. API Router
**File:** `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/routers/tokens.py`

**Endpoints:**

#### GET /tokens/usage
Get usage summary for current period
- Query param: `period` (day/week/month/all)
- Returns: Total tokens + breakdown by provider

#### GET /tokens/remaining
Get remaining quota
- Returns: Tokens remaining, limit, tier, BYOK status

#### GET /tokens/quota
Get comprehensive quota info
- Returns: Usage, limits, percentage, billing period

#### GET /tokens/history
Get paginated usage history
- Query params: `page`, `page_size`, `provider`
- Returns: Paginated usage records with metadata

### 5. Schemas
**File:** `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/schemas/tokens.py`

**Response Models:**
- `TokenUsageResponse`: Individual usage record
- `UsageSummaryResponse`: Period summary with provider breakdown
- `QuotaInfoResponse`: Comprehensive quota information
- `RemainingTokensResponse`: Remaining quota details
- `UsageHistoryResponse`: Paginated history with metadata

### 6. Middleware
**File:** `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-api/app/middleware/token_check.py`

**Functionality:**
- Intercepts requests to AI endpoints (`/api/ai/*`, `/api/scan/*`, `/api/analyze/*`)
- Validates user quota before processing
- Returns 429 with tier-specific upgrade message if quota exceeded
- Includes rate limit headers (X-RateLimit-*)

**Usage:**
```python
from app.middleware import add_token_quota_middleware

app = FastAPI()
add_token_quota_middleware(app)
```

## Token Limits by Tier

| Tier       | Monthly Limit  | Notes                              |
|------------|----------------|------------------------------------|
| Free       | 0              | BYOK only                          |
| Starter    | 1,000,000      | Individual quota                   |
| Pro        | 3,000,000      | Individual quota                   |
| Enterprise | 15,000,000     | Shared pool per 5 users            |

## Integration Guide

### 1. Initialize User Quota (On Registration)

Add to user registration flow:

```python
from app.services.token_tracking import TokenTrackingService

# In registration handler
async def register_user(email: str, tier: str, db: AsyncSession):
    # ... create user ...

    # Initialize token quota
    service = TokenTrackingService(db)
    await service.initialize_user_quota(
        user_id=new_user.id,
        tier=tier,
        byok_enabled=False,
    )

    await db.commit()
```

### 2. AI Request Flow with Caching

```python
from app.services.cache import get_cache_service
from app.services.token_tracking import TokenTrackingService

async def ai_completion(
    prompt: str,
    model: str,
    user_id: int,
    db: AsyncSession,
):
    cache = get_cache_service()
    token_service = TokenTrackingService(db)

    # 1. Generate cache key
    prompt_hash = token_service.hash_prompt(prompt)

    # 2. Check cache
    cached_response = await cache.get_cached_response(prompt_hash)
    if cached_response:
        return cached_response

    # 3. Count tokens
    input_tokens = token_service.count_tokens(prompt, model)

    # 4. Check quota (middleware already checked, but double-check)
    has_quota = await token_service.check_quota(user_id)
    if not has_quota:
        raise HTTPException(status_code=429, detail="Quota exceeded")

    # 5. Make AI request
    response = await ai_provider.complete(prompt, model)

    # 6. Count output tokens
    output_tokens = token_service.count_tokens(response["text"], model)
    total_tokens = input_tokens + output_tokens

    # 7. Record usage
    await token_service.record_usage(
        user_id=user_id,
        tokens_used=total_tokens,
        provider="openai",
        model=model,
        prompt_hash=prompt_hash,
        endpoint="/api/ai/completions",
    )

    # 8. Cache response
    await cache.cache_response(
        prompt_hash=prompt_hash,
        response=response,
        ttl=900,  # 15 minutes
    )

    await db.commit()
    return response
```

### 3. Add Middleware to Main App

In `main.py`:

```python
from fastapi import FastAPI
from app.middleware import add_token_quota_middleware
from app.routers import tokens_router

app = FastAPI(title="Zypheron API")

# Add middleware (checks quota before AI requests)
add_token_quota_middleware(app)

# Include token endpoints
app.include_router(tokens_router)
```

### 4. Database Migration

```python
from app.core.database import init_db

# Create all tables including token_usage and user_quota
await init_db()
```

## Configuration

### Environment Variables

```bash
# Redis Cache (Optional for dev, recommended for prod)
REDIS_URL=redis://localhost:6379/0
REDIS_ENABLED=true

# Cache TTL (seconds)
CACHE_TTL_PROMPT=900        # 15 minutes
CACHE_TTL_VULN_DESC=3600    # 1 hour

# Token Limits (monthly)
TOKEN_LIMIT_FREE=0
TOKEN_LIMIT_STARTER=1000000
TOKEN_LIMIT_PRO=3000000
TOKEN_LIMIT_ENTERPRISE=15000000
```

## Database Schema

### token_usage Table

```sql
CREATE TABLE token_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tokens_used BIGINT NOT NULL,
    provider VARCHAR(50) NOT NULL,
    model VARCHAR(100) NOT NULL,
    prompt_hash VARCHAR(64),
    endpoint VARCHAR(100),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_created (user_id, created_at),
    INDEX idx_user_provider_created (user_id, provider, created_at),
    INDEX idx_prompt_hash (prompt_hash)
);
```

### user_quota Table

```sql
CREATE TABLE user_quota (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tier VARCHAR(20) NOT NULL DEFAULT 'free',
    period_start TIMESTAMP NOT NULL,
    period_end TIMESTAMP NOT NULL,
    tokens_used_period BIGINT NOT NULL DEFAULT 0,
    token_limit BIGINT NOT NULL,
    byok_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    enterprise_pool_id VARCHAR(36),
    updated_at TIMESTAMP NOT NULL
);
```

## API Response Examples

### GET /tokens/usage?period=month

```json
{
  "total_tokens": 250000,
  "period": "month",
  "by_provider": {
    "openai": 150000,
    "anthropic": 80000,
    "grok": 20000
  }
}
```

### GET /tokens/quota

```json
{
  "tier": "starter",
  "tokens_used": 250000,
  "token_limit": 1000000,
  "tokens_remaining": 750000,
  "percentage_used": 25.0,
  "period_start": "2025-12-01T00:00:00+00:00",
  "period_end": "2026-01-01T00:00:00+00:00",
  "byok_enabled": false
}
```

### 429 Quota Exceeded Response

```json
{
  "error": "quota_exceeded",
  "message": "Monthly token quota exceeded",
  "details": {
    "tier": "starter",
    "tokens_used": 1000000,
    "token_limit": 1000000,
    "period_end": "2026-01-01T00:00:00+00:00"
  },
  "upgrade_message": "You've reached your Starter tier limit. Upgrade to Pro ($29/month) for 3,000,000 tokens/month and priority support."
}
```

## Performance Optimizations

### 1. Denormalized Quotas
- `UserQuota` table stores current period usage
- Avoids expensive SUM aggregations on every request
- Updated incrementally on each usage record

### 2. Composite Indexes
- `(user_id, created_at)`: Fast quota checks
- `(user_id, provider, created_at)`: Analytics queries
- `(prompt_hash)`: Cache lookups

### 3. Cache Layer
- SHA-256 hashing for exact prompt matches
- Reduces redundant AI API calls
- Configurable TTL per use case

### 4. Async Architecture
- Full async/await throughout
- Non-blocking database operations
- Efficient connection pooling

## Testing

### Unit Test Example

```python
import pytest
from app.services.token_tracking import TokenTrackingService

@pytest.mark.asyncio
async def test_token_counting():
    text = "Analyze this code for security vulnerabilities"
    model = "gpt-4"

    count = TokenTrackingService.count_tokens(text, model)
    assert count > 0
    assert isinstance(count, int)

@pytest.mark.asyncio
async def test_quota_enforcement(db_session):
    service = TokenTrackingService(db_session)

    # Initialize with starter tier (1M tokens)
    await service.initialize_user_quota(
        user_id=1,
        tier="starter",
    )

    # Use 999,999 tokens
    await service.record_usage(
        user_id=1,
        tokens_used=999_999,
        provider="openai",
        model="gpt-4",
    )

    # Should still have quota
    assert await service.check_quota(1) is True

    # Use 2 more tokens (now at 1,000,001)
    await service.record_usage(
        user_id=1,
        tokens_used=2,
        provider="openai",
        model="gpt-4",
    )

    # Quota should be exceeded
    assert await service.check_quota(1) is False
```

## Monitoring Metrics

### Key Metrics to Track

1. **Cache Hit Rate**: `cache_hits / (cache_hits + cache_misses)`
2. **Average Tokens per Request**: `total_tokens / total_requests`
3. **Quota Utilization**: `avg(tokens_used / token_limit)`
4. **429 Rate**: `quota_exceeded_responses / total_ai_requests`
5. **Provider Distribution**: Percentage by provider
6. **Top Users**: Users with highest token consumption

## Dependencies

All required packages already in `pyproject.toml`:
- `tiktoken>=0.5.2` - Token counting
- `redis>=5.0.1` - Cache backend
- `sqlalchemy[asyncio]>=2.0.25` - Database ORM
- `fastapi>=0.109.0` - API framework
- `pydantic>=2.5.0` - Data validation

## Next Steps

1. **Add to Main App**: Import and register middleware + router in `main.py`
2. **Database Migration**: Run `init_db()` to create tables
3. **Initialize Quotas**: Add quota initialization to user registration
4. **Integrate AI Proxy**: Use `TokenTrackingService` in AI endpoints
5. **Set Up Redis**: Configure Redis for production caching
6. **Add Monitoring**: Track metrics in observability platform

## Security Considerations

- SHA-256 prompt hashing (collision-resistant)
- User-scoped data access (no cross-user leakage)
- Cascade delete on user removal
- JWT token validation in middleware
- SQL injection protection via SQLAlchemy ORM

## Production Readiness

The implementation includes:
- ✅ Comprehensive error handling
- ✅ Async/await throughout
- ✅ Database connection pooling
- ✅ Redis auto-reconnect
- ✅ In-memory fallback for development
- ✅ Proper indexes for performance
- ✅ Type hints for maintainability
- ✅ Docstrings for all public methods
- ✅ Tier-based upgrade messaging
- ✅ Rate limit headers (RFC 6585)

---

**Implementation Date:** 2025-12-19
**Version:** 1.0.0
**Status:** Production Ready
