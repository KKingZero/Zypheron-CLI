# Rate Limiting

Redis-backed rate limiting with tier-based limits, sliding window algorithm, and per-provider controls. When Redis is unavailable, the global rate limiter fails open (allows requests) while the per-provider limiter fails closed (denies requests to protect paid APIs).

## Global Rate Limits

| Tier | Requests/Minute |
|------|-----------------|
| Free | 10 |
| Starter | 60 |
| Pro | 120 |
| Enterprise | 300 |

Unauthenticated requests use the Free tier limit, keyed by IP address.

### Exempt Paths

`/`, `/health`, `/docs`, `/redoc`, `/openapi.json` are exempt from rate limiting.

### Response Headers

All non-exempt responses include:

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1704295260
```

When rate limited (HTTP 429), a `Retry-After` header is also included.

## Per-Provider Rate Limits (AI Proxy)

Provider-specific limits apply per user, per minute on `/ai/chat`:

| Provider Tier | Free | Starter | Pro | Enterprise |
|--------------|------|---------|-----|------------|
| Ollama | Unlimited | Unlimited | Unlimited | Unlimited |
| OpenAI GPT-4 | Blocked | 30 | 60 | 120 |
| OpenAI GPT-3.5 | Blocked | 60 | 120 | 240 |
| Anthropic Claude | Blocked | 30 | 60 | 120 |
| DeepSeek | Blocked | 60 | 120 | 240 |
| Grok | Blocked | 30 | 60 | 120 |

**BYOK multiplier:** Users with their own API key get **2x** the normal provider limit.

### Model Tier Mapping

Models are grouped into provider tiers:

- `openai_gpt4`: gpt-4o, gpt-4o-mini, gpt-4-turbo, gpt-4
- `openai_gpt35`: gpt-3.5-turbo, gpt-3.5-turbo-16k
- `anthropic`: claude-3-5-sonnet, claude-3-5-haiku, claude-3-opus
- `deepseek`: deepseek-chat, deepseek-coder
- `grok`: grok-beta, grok-2

### Per-Provider Response Headers

```http
X-Provider-RateLimit-Limit: 60
X-Provider-RateLimit-Remaining: 42
X-Provider-RateLimit-Reset: 1704123456
```

## Configuration

```bash
# Enable Redis-based rate limiting
REDIS_ENABLED=true
REDIS_URL=redis://localhost:6379

# Or individual settings
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_password
REDIS_DB=0
```

Priority: `REDIS_URL` > individual settings > defaults (localhost:6379).

## How It Works

Both global and per-provider limiters use a **sliding window** algorithm backed by Redis sorted sets:

1. Add current request timestamp to sorted set
2. Remove timestamps older than 60 seconds
3. Count remaining entries
4. Allow or reject based on tier limit

Key format:
- Global: `ratelimit:{user_id}` or `ratelimit:{ip_address}`
- Per-provider: `ai_ratelimit:{user_id}:{provider_tier}`

Keys auto-expire after 120 seconds (2x window).

## IP Address Handling

For proxied deployments, the middleware checks `X-Forwarded-For` (first IP), then `X-Real-IP`, then direct client IP.

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP $remote_addr;
```

## Error Handling

| Scenario | Global Limiter | Provider Limiter |
|----------|---------------|-----------------|
| Redis unavailable | Fail open (allow) | Fail closed (deny, HTTP 503) |
| User tier lookup fails | Default to Free | Default to Free |
| Redis operation error | Allow request | Deny request |

## Testing

```bash
# Manual test: send 15 rapid requests
for i in {1..15}; do
  curl -i http://localhost:8000/auth/me -H "Authorization: Bearer $TOKEN"
done

# Run rate limit test script
python test_rate_limit.py
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Rate limiting not active | Check `REDIS_ENABLED=true` and Redis is running |
| Wrong limits applied | Check user tier in database; decode JWT to verify user_id |
| Headers missing | Test a non-exempt path (not /health, /docs) |

## Key Files

- Global middleware: `app/middleware/rate_limiter.py`
- Provider limits: `app/routers/ai_proxy.py`
- Redis client: `app/core/redis_client.py`
- Config: `app/core/config.py`
