# Token Tracking System - Quick Reference

## Import Statements

```python
from app.services.token_tracking import TokenTrackingService
from app.services.cache import get_cache_service
from app.middleware import add_token_quota_middleware
```

## Common Operations

### Count Tokens
```python
tokens = TokenTrackingService.count_tokens("Your text here", "gpt-4")
```

### Hash Prompt (for cache key)
```python
hash_key = TokenTrackingService.hash_prompt("Your prompt here")
```

### Check Quota
```python
service = TokenTrackingService(db)
has_quota = await service.check_quota(user_id)
```

### Record Usage
```python
await service.record_usage(
    user_id=1,
    tokens_used=1500,
    provider="openai",
    model="gpt-4",
    prompt_hash=hash_key,
)
```

### Get Usage Stats
```python
# Total usage
usage = await service.get_usage(user_id, period="month")

# By provider
by_provider = await service.get_usage_by_provider(user_id, period="month")

# Remaining tokens
remaining = await service.get_remaining_tokens(user_id)
```

### Cache Operations
```python
cache = get_cache_service()

# Cache response
await cache.cache_response(prompt_hash, response, ttl=900)

# Get cached
cached = await cache.get_cached_response(prompt_hash)
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/tokens/usage` | GET | Usage summary (query: `?period=month`) |
| `/tokens/remaining` | GET | Remaining quota |
| `/tokens/quota` | GET | Full quota info |
| `/tokens/history` | GET | Paginated history (query: `?page=1&page_size=50`) |

## Token Limits

```python
Free:       0 tokens/month (BYOK only)
Starter:    1,000,000 tokens/month
Pro:        3,000,000 tokens/month
Enterprise: 15,000,000 tokens/month (shared)
```

## Cache TTL

```python
Prompts:                900 seconds (15 min)
Vulnerability Descs:    3600 seconds (1 hour)
```

## Middleware Setup

```python
from fastapi import FastAPI
from app.middleware import add_token_quota_middleware

app = FastAPI()
add_token_quota_middleware(app)
```

Protected endpoint patterns:
- `/api/ai/*`
- `/api/scan/*`
- `/api/analyze/*`

## Database Tables

### token_usage
- `user_id`: FK to users
- `tokens_used`: BigInt
- `provider`: openai/anthropic/grok/deepseek
- `model`: Model name
- `prompt_hash`: SHA-256 (optional)
- `created_at`: Timestamp

### user_quota
- `user_id`: PK, FK to users
- `tier`: free/starter/pro/enterprise
- `tokens_used_period`: Current usage
- `token_limit`: Tier limit
- `period_start`, `period_end`: Billing period
- `byok_enabled`: Boolean

## Error Responses

### 429 Quota Exceeded
```json
{
  "error": "quota_exceeded",
  "message": "Monthly token quota exceeded",
  "details": { ... },
  "upgrade_message": "Tier-specific upgrade prompt"
}
```

Headers:
- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`
- `Retry-After`

## File Locations

```
app/
├── models/token_usage.py          # TokenUsage, UserQuota
├── services/
│   ├── token_tracking.py         # TokenTrackingService
│   └── cache.py                  # CacheService
├── routers/tokens.py             # API endpoints
├── schemas/tokens.py             # Response models
└── middleware/token_check.py     # TokenQuotaMiddleware
```

## Supported Models

**OpenAI:** gpt-4, gpt-4-turbo, gpt-4o, gpt-3.5-turbo
**Anthropic:** claude-3-opus, claude-3-sonnet, claude-3-haiku, claude-3.5-sonnet
**Grok:** grok-beta
**DeepSeek:** deepseek-chat, deepseek-coder

## Environment Variables

```bash
REDIS_URL=redis://localhost:6379/0
REDIS_ENABLED=true
CACHE_TTL_PROMPT=900
CACHE_TTL_VULN_DESC=3600
TOKEN_LIMIT_FREE=0
TOKEN_LIMIT_STARTER=1000000
TOKEN_LIMIT_PRO=3000000
TOKEN_LIMIT_ENTERPRISE=15000000
```
