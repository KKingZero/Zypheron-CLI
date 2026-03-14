# Token Synchronization Quick Reference

Quick reference guide for token usage synchronization system.

## Installation & Setup

### 1. Run Migration

```bash
cd /path/to/zypheron-api
python scripts/migrate_add_token_fields.py
```

### 2. Verify Redis

```bash
# Check Redis connection
redis-cli ping
# Should return: PONG

# Or use test script
./scripts/test-redis.sh
```

### 3. Restart API

```bash
./run.sh
```

## Provider Cost Multipliers

| Provider | Model | Multiplier |
|----------|-------|------------|
| OpenAI GPT-4o | gpt-4o | 1.0 |
| OpenAI GPT-3.5 | gpt-3.5-turbo | 0.5 |
| Anthropic Claude | claude-* | 1.2 |
| DeepSeek | deepseek-* | 0.3 |
| Grok | grok-* | 1.0 |
| Ollama | * | 0.0 (free) |

## API Endpoints

### Get Usage Breakdown
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/tokens/breakdown
```

### Get Monthly History
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/tokens/monthly-history?months=6"
```

### Get Detailed Quota
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/tokens/quota-detailed
```

## Redis Cache Keys

```
tokens:{user_id}:{year}:{month}           # Monthly usage aggregate
alert:{user_id}:{year}:{month}:{threshold} # Alert sent flag
```

### Manual Operations

```bash
# Check user's monthly usage
redis-cli GET "tokens:123:2025:1"

# Clear usage cache for user 123 in Jan 2025
redis-cli DEL "tokens:123:2025:1"

# Check if alert was sent
redis-cli GET "alert:123:2025:1:80"
```

## Usage Examples

### Record Token Usage

```python
from app.services.token_sync import TokenSyncService

service = TokenSyncService(db)

usage, normalized = await service.record_usage(
    user_id=123,
    provider="anthropic",
    model="claude-3-opus",
    prompt_tokens=1000,
    completion_tokens=500,
    prompt_hash="abc123...",
    endpoint="/ai/chat",
)

print(f"Raw tokens: 1500")
print(f"Normalized: {normalized}")  # 1800 (1500 * 1.2)
```

### Check Monthly Usage

```python
# Fast: Uses Redis cache
usage = await service.get_monthly_usage(user_id=123)
print(f"Used this month: {usage}")
```

### Get Usage Breakdown

```python
breakdown = await service.get_usage_breakdown(user_id=123)

# Output: {
#   "openai": {"gpt-4o": 50000},
#   "anthropic": {"claude-3-opus": 30000}
# }
```

### Reset Billing Period

```python
await service.reset_billing_period(user_id=123)
# Resets usage to 0, updates period_start/end
```

### Get Quota with Alerts

```python
quota_info = await service.get_quota_with_alerts(user_id=123)

if quota_info["alert_warning"]:
    print("⚠️ User at 80% quota")

if quota_info["alert_critical"]:
    print("🚨 User exceeded quota")
```

## Alert Thresholds

| Threshold | Percentage | Action |
|-----------|-----------|---------|
| WARNING | 80% | Log warning, set Redis flag |
| CRITICAL | 100% | Block requests, log critical |

## Database Schema

### token_usage Table

```sql
id                  INTEGER PRIMARY KEY
user_id             INTEGER NOT NULL
tokens_used         BIGINT NOT NULL  -- Normalized tokens
prompt_tokens       BIGINT NOT NULL  -- Raw prompt tokens
completion_tokens   BIGINT NOT NULL  -- Raw completion tokens
provider            VARCHAR(50) NOT NULL
model               VARCHAR(100) NOT NULL
prompt_hash         VARCHAR(64)
endpoint            VARCHAR(100)
created_at          TIMESTAMP WITH TIME ZONE
```

## Logging

### Key Log Events

```python
# Token usage recorded
logger.info("token_usage_recorded",
    user_id=123,
    provider="anthropic",
    normalized_tokens=1800,
)

# Usage alert triggered
logger.warning("token_usage_alert",
    user_id=123,
    threshold="WARNING",
    usage_percentage=85.0,
)

# Redis cache updated
logger.debug("redis_cache_updated",
    user_id=123,
    tokens_added=1800,
)

# Billing period reset
logger.info("billing_period_reset",
    user_id=123,
    new_period_start="2025-02-01",
)
```

## Troubleshooting

### Redis Not Updating

```bash
# Check Redis status
systemctl status redis
# Or
redis-cli ping

# Check connection in Python
python -c "
from app.core.redis_client import get_redis_client
import asyncio
async def test():
    client = await get_redis_client()
    print(f'Available: {client.is_available}')
asyncio.run(test())
"
```

### Token Multipliers Wrong

```python
# Test multiplier calculation
from app.services.token_sync import TokenSyncService

multiplier = TokenSyncService.get_cost_multiplier("anthropic", "claude-3-opus")
print(f"Multiplier: {multiplier}")  # Should be 1.2

normalized = TokenSyncService.calculate_normalized_tokens(
    provider="anthropic",
    model="claude-3-opus",
    prompt_tokens=1000,
    completion_tokens=500,
)
print(f"Normalized: {normalized}")  # Should be 1800
```

### Alerts Not Triggering

```bash
# Check if alert flag exists
redis-cli GET "alert:123:2025:1:80"

# Delete to re-trigger
redis-cli DEL "alert:123:2025:1:80"

# Check quota info
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/tokens/quota-detailed | jq
```

## Testing

### Quick Test Script

```python
import asyncio
from app.core.database import get_db
from app.services.token_sync import TokenSyncService

async def test_token_sync():
    async for db in get_db():
        service = TokenSyncService(db)

        # Record usage
        usage, normalized = await service.record_usage(
            user_id=1,
            provider="anthropic",
            model="claude-3-opus",
            prompt_tokens=1000,
            completion_tokens=500,
        )

        print(f"✓ Usage recorded: {usage.id}")
        print(f"  Raw tokens: 1500")
        print(f"  Normalized: {normalized}")

        # Check monthly usage
        monthly = await service.get_monthly_usage(user_id=1)
        print(f"✓ Monthly usage: {monthly}")

        # Get breakdown
        breakdown = await service.get_usage_breakdown(user_id=1)
        print(f"✓ Breakdown: {breakdown}")

        # Get quota with alerts
        quota = await service.get_quota_with_alerts(user_id=1)
        print(f"✓ Quota: {quota['tokens_used']}/{quota['token_limit']}")
        print(f"  Alert warning: {quota['alert_warning']}")

        break

asyncio.run(test_token_sync())
```

## Performance Tips

### 1. Use Redis for Quota Checks

```python
# Fast: Uses Redis O(1)
usage = await service.get_monthly_usage(user_id)

# Slow: Queries database
stmt = select(func.sum(TokenUsage.tokens_used))...
```

### 2. Batch Updates

For high-volume scenarios:

```python
# Instead of committing each usage
await service.record_usage(...)
await db.commit()  # Slow

# Batch multiple operations
for request in batch:
    await service.record_usage(...)
await db.commit()  # Once per batch
```

### 3. Monitor Redis Memory

```bash
# Check memory usage
redis-cli INFO memory

# Check key count
redis-cli DBSIZE

# Clear old keys (run monthly)
redis-cli --scan --pattern "tokens:*:2024:*" | xargs redis-cli DEL
```

## Response Headers (Optional)

Add usage info to response headers:

```python
response.headers["X-Token-Usage"] = str(quota["tokens_used"])
response.headers["X-Token-Limit"] = str(quota["token_limit"])
response.headers["X-Token-Remaining"] = str(quota["tokens_remaining"])

if quota["alert_warning"]:
    response.headers["X-Token-Alert"] = "warning"
if quota["alert_critical"]:
    response.headers["X-Token-Alert"] = "critical"
```

## Monitoring Queries

### Users Near Quota

```sql
SELECT
    user_id,
    tier,
    tokens_used_period,
    token_limit,
    (tokens_used_period::float / token_limit * 100) as percentage
FROM user_quota
WHERE tokens_used_period >= token_limit * 0.8
ORDER BY percentage DESC;
```

### Top Consumers This Month

```sql
SELECT
    u.email,
    uq.tier,
    uq.tokens_used_period,
    uq.token_limit
FROM user_quota uq
JOIN users u ON u.id = uq.user_id
ORDER BY uq.tokens_used_period DESC
LIMIT 20;
```

### Usage by Provider

```sql
SELECT
    provider,
    COUNT(*) as request_count,
    SUM(tokens_used) as total_tokens,
    AVG(tokens_used) as avg_tokens_per_request
FROM token_usage
WHERE created_at >= date_trunc('month', NOW())
GROUP BY provider
ORDER BY total_tokens DESC;
```

## Scheduled Tasks

### Monthly Reset Job

```python
# Run on 1st of each month
from app.services.token_sync import TokenSyncService

async def reset_all_users():
    """Reset billing period for all users."""
    async for db in get_db():
        service = TokenSyncService(db)

        # Get all users with active quotas
        quotas = await db.execute(select(UserQuota))

        for quota in quotas.scalars():
            await service.reset_billing_period(quota.user_id)

        await db.commit()
        break
```

### Cache Cleanup Job

```bash
#!/bin/bash
# Clean up expired cache keys (run weekly)

# Remove tokens from months older than 2 months ago
CUTOFF_MONTH=$(date -d "2 months ago" +%Y:%m)

redis-cli --scan --pattern "tokens:*:*:*" |
while read key; do
    MONTH=$(echo $key | cut -d: -f3-4)
    if [[ "$MONTH" < "$CUTOFF_MONTH" ]]; then
        redis-cli DEL "$key"
    fi
done
```

---

**Quick Links:**
- [Full Implementation Guide](./TOKEN_SYNC_IMPLEMENTATION.md)
- [API Reference](./README.md)
- [Token Tracking Guide](./TOKEN_TRACKING_GUIDE.md)
