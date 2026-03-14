# Token Usage Synchronization Implementation

Comprehensive token tracking and synchronization between the AI proxy and license system with provider-specific cost multipliers, Redis caching, and usage alerts.

## Overview

This implementation provides advanced token usage tracking with:

- **Separate tracking** of prompt and completion tokens
- **Provider-specific cost multipliers** for accurate billing
- **Redis caching** for fast monthly quota checks
- **Automated usage alerts** at 80% and 100% thresholds
- **Historical usage tracking** with monthly aggregation
- **Detailed breakdowns** by provider and model

## Architecture

### Components

1. **TokenSyncService** (`/app/services/token_sync.py`)
   - Core service for token synchronization
   - Applies provider cost multipliers
   - Manages Redis cache and database persistence
   - Triggers usage alerts

2. **Enhanced TokenUsage Model** (`/app/models/token_usage.py`)
   - Added `prompt_tokens` field (raw count)
   - Added `completion_tokens` field (raw count)
   - Existing `tokens_used` now stores normalized tokens

3. **Updated AI Proxy** (`/app/routers/ai_proxy.py`)
   - Integrated with TokenSyncService
   - Tracks prompt/completion tokens separately
   - Includes usage metadata in responses

4. **New API Endpoints** (`/app/routers/tokens.py`)
   - `GET /tokens/breakdown` - Usage by provider/model
   - `GET /tokens/monthly-history` - Historical usage
   - `GET /tokens/quota-detailed` - Quota with alert flags

## Provider Cost Multipliers

Token costs are normalized relative to OpenAI GPT-4o (baseline = 1.0):

| Provider | Model | Multiplier | Notes |
|----------|-------|------------|-------|
| OpenAI | GPT-4o | 1.0 | Baseline |
| OpenAI | GPT-4o-mini | 0.5 | 50% cheaper |
| OpenAI | GPT-3.5-turbo | 0.5 | 50% cheaper |
| Anthropic | Claude Opus | 1.2 | 20% more expensive |
| Anthropic | Claude Sonnet | 1.2 | 20% more expensive |
| Anthropic | Claude Haiku | 0.8 | 20% cheaper |
| DeepSeek | All models | 0.3 | 70% cheaper |
| Grok | All models | 1.0 | Same as GPT-4o |
| Ollama | All models | 0.0 | Free (local) |

### How It Works

```python
# Example: User makes request with 1000 prompt + 500 completion tokens
raw_tokens = 1500
provider = "anthropic"
model = "claude-3-5-sonnet"

# Apply multiplier (1.2 for Claude)
normalized_tokens = 1500 * 1.2 = 1800

# Store both values
TokenUsage:
  prompt_tokens: 1000        # Raw count
  completion_tokens: 500     # Raw count
  tokens_used: 1800          # Normalized for billing
```

## Redis Caching Strategy

### Cache Keys

```
tokens:{user_id}:{year}:{month}     # Monthly aggregate
alert:{user_id}:{year}:{month}:{threshold}  # Alert sent flags
```

### Benefits

1. **Fast Quota Checks** - O(1) lookup instead of database aggregation
2. **Reduced DB Load** - Quota checks don't hit database
3. **Automatic Cleanup** - TTL of 35 days (1 month + buffer)

### Flow

```
Request → Check Redis for monthly usage → If miss, query DB → Update Redis
          ↓
       Update Redis counter (+tokens_used)
          ↓
       Update UserQuota table
```

## Usage Alerts

### Thresholds

- **80% Warning** - User approaching quota limit
- **100% Critical** - User has exhausted quota

### Alert Logic

1. After each token usage update, check percentage
2. If threshold crossed, check Redis flag
3. If alert not sent this period, log warning
4. Set Redis flag to prevent duplicate alerts
5. (Optional) Send webhook notification

### Implementation

```python
# Check if user crossed 80% threshold
if usage_percentage >= 0.80:
    alert_key = f"alert:{user_id}:{year}:{month}:80"
    was_set = redis.set(alert_key, "1", ex=7*86400, nx=True)

    if was_set:
        # First time crossing threshold this period
        logger.warning("token_usage_alert", threshold="WARNING", ...)
        # await send_webhook_notification(...)
```

## Monthly Billing Period Reset

### Automatic Reset

The `reset_billing_period()` method handles:

1. Update `period_start` and `period_end` to new month
2. Reset `tokens_used_period` to 0
3. Clear Redis cache for new billing period
4. Log reset event

### Trigger Points

- Subscription renewal (Stripe webhook)
- Manual reset via admin API
- Scheduled job (cron/celery)

Example:
```python
sync_service = TokenSyncService(db)
await sync_service.reset_billing_period(user_id=123)
```

## API Endpoints

### 1. Get Usage Breakdown

```http
GET /tokens/breakdown
Authorization: Bearer {jwt_token}
```

Response:
```json
{
  "by_provider": {
    "openai": {
      "gpt-4o": 50000,
      "gpt-3.5-turbo": 25000
    },
    "anthropic": {
      "claude-3-opus": 30000
    }
  },
  "total_tokens": 105000,
  "period_start": "2025-01-01T00:00:00Z",
  "period_end": "2025-02-01T00:00:00Z"
}
```

### 2. Get Monthly History

```http
GET /tokens/monthly-history?months=12
Authorization: Bearer {jwt_token}
```

Response:
```json
[
  {
    "month": "2025-01-01T00:00:00Z",
    "total_tokens": 150000,
    "request_count": 450
  },
  {
    "month": "2024-12-01T00:00:00Z",
    "total_tokens": 125000,
    "request_count": 380
  }
]
```

### 3. Get Detailed Quota

```http
GET /tokens/quota-detailed
Authorization: Bearer {jwt_token}
```

Response:
```json
{
  "tokens_used": 850000,
  "token_limit": 1000000,
  "tokens_remaining": 150000,
  "percentage_used": 85.0,
  "alert_warning": true,
  "alert_critical": false,
  "tier": "pro",
  "period_start": "2025-01-01T00:00:00Z",
  "period_end": "2025-02-01T00:00:00Z"
}
```

## Response Headers for Usage Alerts

When a user approaches or exceeds quota limits, the API should include headers:

```http
X-Token-Usage: 850000
X-Token-Limit: 1000000
X-Token-Remaining: 150000
X-Token-Alert: warning  # or "critical"
```

## Database Schema Changes

### Migration Required

Run the migration script to add new columns:

```bash
cd /home/zero/Downloads/Zypheron\ project/Zypheron-CLI-Production/zypheron-api
python scripts/migrate_add_token_fields.py
```

### Schema Changes

**token_usage table:**
```sql
-- New columns
ALTER TABLE token_usage
ADD COLUMN prompt_tokens BIGINT NOT NULL DEFAULT 0;

ALTER TABLE token_usage
ADD COLUMN completion_tokens BIGINT NOT NULL DEFAULT 0;

-- Existing columns
-- id, user_id, tokens_used (now normalized), provider, model,
-- prompt_hash, endpoint, created_at
```

### Backward Compatibility

- Existing records will have `prompt_tokens = 0` and `completion_tokens = 0`
- This is acceptable as historical breakdown is optional
- New records will have full detail

## Integration with AI Proxy

### Before (Old Code)

```python
await update_token_usage(
    user=current_user,
    provider_type=provider_type,
    model=response.model,
    tokens_used=response.total_tokens,  # Single value
    db=db,
)
```

### After (New Code)

```python
await update_token_usage(
    user=current_user,
    provider_type=provider_type,
    model=response.model,
    prompt_tokens=response.prompt_tokens,       # Separate
    completion_tokens=response.completion_tokens, # Separate
    db=db,
)
```

### Streaming Support

For streaming responses, tokens are accumulated from metadata:

```python
prompt_tokens_accumulated = 0
completion_tokens_accumulated = 0

async for chunk in stream:
    if chunk.metadata:
        prompt_tokens_accumulated = chunk.metadata.get("prompt_tokens", 0)
        completion_tokens_accumulated = chunk.metadata.get("completion_tokens", 0)
```

## Testing

### Unit Tests

```python
async def test_cost_multiplier():
    """Test provider cost multipliers."""
    # OpenAI GPT-4o (baseline)
    assert TokenSyncService.get_cost_multiplier("openai", "gpt-4o") == 1.0

    # Anthropic (20% more expensive)
    assert TokenSyncService.get_cost_multiplier("anthropic", "claude-3-opus") == 1.2

    # DeepSeek (70% cheaper)
    assert TokenSyncService.get_cost_multiplier("deepseek", "deepseek-chat") == 0.3

    # Ollama (free)
    assert TokenSyncService.get_cost_multiplier("ollama", "llama3") == 0.0

async def test_usage_tracking():
    """Test token usage recording."""
    service = TokenSyncService(db)

    usage, normalized = await service.record_usage(
        user_id=1,
        provider="anthropic",
        model="claude-3-opus",
        prompt_tokens=1000,
        completion_tokens=500,
    )

    assert usage.prompt_tokens == 1000
    assert usage.completion_tokens == 500
    assert normalized == 1800  # 1500 * 1.2
```

### Integration Tests

```python
async def test_ai_proxy_integration():
    """Test full flow from AI request to token tracking."""
    response = await client.post(
        "/ai/chat",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "provider": "anthropic",
            "model": "claude-3-opus",
            "messages": [{"role": "user", "content": "Hello"}],
        },
    )

    assert response.status_code == 200

    # Check usage was recorded
    usage = await get_latest_usage(user_id=1)
    assert usage.provider == "anthropic"
    assert usage.prompt_tokens > 0
    assert usage.completion_tokens > 0
```

## Monitoring and Observability

### Structured Logging

All operations use structured logging:

```python
logger.info(
    "token_usage_recorded",
    user_id=user.id,
    provider="anthropic",
    model="claude-3-opus",
    prompt_tokens=1000,
    completion_tokens=500,
    normalized_tokens=1800,
    usage_id=42,
)
```

### Key Metrics to Track

1. **Token consumption rate** - Tokens/hour by provider
2. **Cost multiplier impact** - Normalized vs raw token delta
3. **Cache hit rate** - Redis hits / total quota checks
4. **Alert frequency** - How often users hit 80%/100%
5. **Billing period resets** - Successful resets per month

### Alerts to Configure

- Redis connection failures
- Database write failures during token sync
- Unusual spike in token usage
- Failed billing period resets
- High percentage of users hitting quota

## Deployment Checklist

- [ ] Run database migration script
- [ ] Verify Redis is configured and accessible
- [ ] Update environment variables (Redis URL)
- [ ] Deploy new code (token_sync.py, updated models, routes)
- [ ] Restart API server
- [ ] Monitor logs for token_usage_recorded events
- [ ] Verify new endpoints return data
- [ ] Test quota enforcement with test user
- [ ] Configure webhook for usage alerts (optional)

## Configuration

### Environment Variables

```bash
# Redis (required for caching)
REDIS_ENABLED=true
REDIS_URL=redis://localhost:6379

# OR
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_password
REDIS_SSL=true  # For Upstash/managed Redis

# Token limits (already configured)
TOKEN_LIMIT_FREE=0
TOKEN_LIMIT_STARTER=1000000
TOKEN_LIMIT_PRO=3000000
TOKEN_LIMIT_ENTERPRISE=15000000
```

## Troubleshooting

### Issue: Redis cache not updating

**Symptoms:** Quota checks show stale data

**Solution:**
1. Check Redis connectivity: `redis-cli ping`
2. Verify REDIS_ENABLED=true in .env
3. Check logs for "redis_cache_update_failed"
4. Ensure Redis has sufficient memory

### Issue: Token multipliers not applied

**Symptoms:** All providers charged equally

**Solution:**
1. Check TokenSyncService.PROVIDER_COST_MULTIPLIERS
2. Verify provider name matches enum values
3. Check logs for "token_normalization" entries
4. Ensure using TokenSyncService, not old code

### Issue: Alerts not triggering

**Symptoms:** No alerts at 80%/100%

**Solution:**
1. Check Redis connectivity for alert flags
2. Verify _check_usage_alerts is called after record_usage
3. Check logs for "token_usage_alert" entries
4. Ensure quota.token_limit > 0

## Future Enhancements

### Webhook Notifications

Implement `_send_webhook_notification()` to notify external systems:

```python
async def _send_webhook_notification(
    user_id: int,
    threshold: str,
    quota: UserQuota,
) -> None:
    """Send webhook when usage threshold crossed."""
    webhook_url = settings.usage_alert_webhook_url
    if not webhook_url:
        return

    payload = {
        "user_id": user_id,
        "threshold": threshold,
        "tokens_used": quota.tokens_used_period,
        "token_limit": quota.token_limit,
        "percentage": quota.tokens_used_period / quota.token_limit * 100,
        "tier": quota.tier,
    }

    async with httpx.AsyncClient() as client:
        await client.post(webhook_url, json=payload)
```

### Dynamic Cost Multipliers

Load multipliers from database or external config for easy updates:

```python
# Store in database
class ProviderCostConfig(Base):
    provider: str
    model: str
    multiplier: float

# Load on startup
PROVIDER_COST_MULTIPLIERS = await load_cost_config()
```

### Enterprise Pool Sharing

For enterprise licenses with shared quotas:

```python
# Group users by enterprise_pool_id
# Aggregate usage across all pool members
# Check quota against pool limit instead of individual
```

## Files Created/Modified

### New Files
- `/app/services/token_sync.py` - Core synchronization service
- `/scripts/migrate_add_token_fields.py` - Database migration
- `/TOKEN_SYNC_IMPLEMENTATION.md` - This documentation

### Modified Files
- `/app/models/token_usage.py` - Added prompt_tokens, completion_tokens
- `/app/routers/tokens.py` - Added breakdown, history, quota-detailed endpoints
- `/app/schemas/tokens.py` - Added response models for new endpoints
- `/app/routers/ai_proxy.py` - Integrated TokenSyncService

## Support

For questions or issues:
1. Check logs for structured error messages
2. Review this documentation
3. Check Redis and database connectivity
4. Verify environment configuration
5. Contact the development team

---

**Last Updated:** 2025-01-03
**Version:** 1.0.0
