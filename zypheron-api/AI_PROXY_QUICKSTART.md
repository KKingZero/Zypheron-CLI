# AI Proxy Service - Quick Start Guide

## What Was Built

A production-ready AI Proxy Service with:
- **4 AI Providers**: OpenAI, Anthropic (Claude), Grok, DeepSeek
- **Load Balancing**: Automatic key rotation and failover
- **Security**: Comprehensive security controls (see AI_PROXY_SECURITY.md)
- **Streaming**: Real-time streaming responses
- **Caching**: Response caching for identical prompts
- **BYOK**: Bring Your Own Key support

## File Structure

```
zypheron-api/
├── app/
│   ├── services/
│   │   ├── ai_providers/           # AI provider clients (1,537 lines)
│   │   │   ├── __init__.py         # Exports
│   │   │   ├── base.py             # Abstract base class (447 lines)
│   │   │   ├── openai_client.py    # OpenAI implementation (242 lines)
│   │   │   ├── anthropic_client.py # Anthropic implementation (310 lines)
│   │   │   ├── grok_client.py      # Grok implementation (251 lines)
│   │   │   └── deepseek_client.py  # DeepSeek implementation (251 lines)
│   │   └── load_balancer.py        # Key pool manager (507 lines)
│   ├── routers/
│   │   └── ai_proxy.py             # API endpoints (606 lines)
│   └── schemas/
│       └── ai_proxy.py             # Request/response models (191 lines)
├── AI_PROXY_README.md              # Full documentation
├── AI_PROXY_SECURITY.md            # Security analysis
└── AI_PROXY_QUICKSTART.md          # This file

Total: 2,841 lines of production code
```

## Installation

### 1. Dependencies Already Installed
All required dependencies are in `pyproject.toml`:
- `httpx>=0.26.0` - HTTP client
- `tenacity>=8.2.3` - Retry logic
- `structlog>=24.1.0` - Structured logging
- `pydantic>=2.5.0` - Validation
- `fastapi>=0.109.0` - API framework

### 2. Configure API Keys

Edit `.env` file (or create from `.env.example`):

```bash
# OpenAI
OPENAI_API_KEYS=["sk-proj-...", "sk-proj-..."]

# Anthropic
ANTHROPIC_API_KEYS=["sk-ant-..."]

# Grok (optional)
GROK_API_KEYS=["xai-..."]

# DeepSeek (optional)
DEEPSEEK_API_KEYS=["sk-..."]
```

**Important**: Use JSON array format `["key1", "key2"]`, not comma-separated.

### 3. Update Main App

Add AI proxy router to your FastAPI app (if not already done):

```python
# In app/main.py or wherever you create the FastAPI app
from app.routers import ai_proxy_router

app = FastAPI(title="Zypheron API")

# Include routers
app.include_router(ai_proxy_router)  # Adds /ai/* endpoints
```

### 4. Start Server

```bash
cd /home/zero/Downloads/Zypheron\ project/Zypheron-CLI-Production/zypheron-api

# Development
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production
uvicorn app.main:app --workers 4 --host 0.0.0.0 --port 8000
```

## Quick Test

### Test Provider Availability
```bash
curl http://localhost:8000/ai/providers
```

Expected response:
```json
{
  "providers": [
    {
      "name": "openai",
      "available": true,
      "models": ["gpt-4o", "gpt-4o-mini"],
      "supports_streaming": true
    }
  ],
  "total_count": 1
}
```

### Test Chat Completion
```bash
curl -X POST http://localhost:8000/ai/chat \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      {"role": "user", "content": "Say hello"}
    ]
  }'
```

Expected response:
```json
{
  "provider": "openai",
  "model": "gpt-4o-mini",
  "content": "Hello! How can I help you today?",
  "usage": {
    "prompt_tokens": 10,
    "completion_tokens": 8,
    "total_tokens": 18
  },
  "latency_ms": 342,
  "cached": false,
  "finish_reason": "stop"
}
```

### Test Streaming
```bash
curl -X POST http://localhost:8000/ai/chat \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [{"role": "user", "content": "Count to 5"}],
    "stream": true
  }'
```

Expected response (SSE format):
```
data: {"type":"content","content":"1"}

data: {"type":"content","content":", 2"}

data: {"type":"content","content":", 3"}

data: {"type":"done","metadata":{"total_tokens":15}}
```

### Test BYOK (Bring Your Own Key)
```bash
curl -X POST http://localhost:8000/ai/chat \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [{"role": "user", "content": "Hello"}],
    "provider": "openai",
    "user_api_key": "sk-your-own-key"
  }'
```

## API Endpoints Summary

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ai/chat` | POST | Chat completion (streaming or non-streaming) |
| `/ai/providers` | GET | List available providers |
| `/ai/validate-key` | POST | Validate user's API key |
| `/ai/health` | GET | Health check for key pools |

## Common Use Cases

### 1. Auto-Select Provider
```python
import httpx

response = httpx.post(
    "http://localhost:8000/ai/chat",
    json={
        "messages": [
            {"role": "user", "content": "What is Python?"}
        ]
    }
)
print(response.json()["content"])
```

### 2. Specific Provider and Model
```python
response = httpx.post(
    "http://localhost:8000/ai/chat",
    json={
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Explain quantum computing"}
        ],
        "provider": "anthropic",
        "model": "claude-3-5-sonnet-20241022",
        "temperature": 0.3,
        "max_tokens": 1000
    }
)
```

### 3. Streaming Response
```python
with httpx.stream(
    "POST",
    "http://localhost:8000/ai/chat",
    json={
        "messages": [{"role": "user", "content": "Write a story"}],
        "stream": True
    }
) as response:
    for line in response.iter_lines():
        if line.startswith("data: "):
            data = json.loads(line[6:])
            if data["type"] == "content":
                print(data["content"], end="", flush=True)
```

### 4. BYOK with Custom Settings
```python
response = httpx.post(
    "http://localhost:8000/ai/chat",
    json={
        "messages": [{"role": "user", "content": "Hello"}],
        "provider": "openai",
        "model": "gpt-4o",
        "user_api_key": "sk-your-key",
        "temperature": 0.9,
        "max_tokens": 500
    }
)
```

## Load Balancing in Action

### How It Works

1. **Initial Request**: First key from pool
2. **Round-Robin**: Next request uses next key
3. **Failure Detection**: 3 consecutive failures = unhealthy
4. **Cooldown**: Unhealthy keys excluded for 60s (configurable)
5. **Recovery**: Auto-recovery after cooldown
6. **Failover**: Automatic retry with next healthy key

### Example with 3 Keys

```bash
# Configure 3 OpenAI keys
OPENAI_API_KEYS=["sk-key1", "sk-key2", "sk-key3"]
```

Request sequence:
- Request 1 → Key 1
- Request 2 → Key 2
- Request 3 → Key 3
- Request 4 → Key 1 (round-robin)
- Key 2 fails 3 times → Marked unhealthy
- Request 5 → Key 3 (Key 2 skipped)
- Request 6 → Key 1
- Wait 60s → Key 2 recovers
- Request 7 → Key 2 (back in rotation)

## Error Handling

### Client Errors
```json
{
  "detail": "Invalid request format"
}
```

### Rate Limit
```json
{
  "detail": "Rate limit exceeded"
}
```
Response includes `Retry-After` header.

### Invalid Key (BYOK)
```json
{
  "detail": "Authentication failed: Invalid API key"
}
```

### Service Unavailable
```json
{
  "detail": "Provider openai not available - no healthy keys"
}
```

## Monitoring

### Check Health
```bash
curl http://localhost:8000/ai/health
```

Response:
```json
{
  "status": "healthy",
  "providers": {
    "openai": {
      "provider": "openai",
      "total_keys": 3,
      "healthy_keys": 3,
      "unhealthy_keys": 0,
      "total_failures": 0
    },
    "anthropic": {
      "provider": "anthropic",
      "total_keys": 2,
      "healthy_keys": 2,
      "unhealthy_keys": 0,
      "total_failures": 0
    }
  }
}
```

### Log Monitoring

Look for these log events:
- `ai_chat_request` - New chat request
- `ai_chat_success` - Successful completion
- `ai_provider_error` - Provider error
- `load_balancer_key_failed` - Key failure
- `api_key_unhealthy` - Key marked unhealthy
- `api_key_recovered` - Key recovered

## Security Checklist

Before deploying to production:

- [ ] API keys in `.env` file (not in code)
- [ ] `.env` file in `.gitignore`
- [ ] Strong JWT secret (`openssl rand -hex 32`)
- [ ] HTTPS enabled on server
- [ ] Rate limiting configured
- [ ] Different keys for dev/staging/prod
- [ ] Regular key rotation plan
- [ ] Monitoring and alerting set up
- [ ] Logs reviewed for key leakage

## Troubleshooting

### "No AI providers available"
**Cause**: No API keys configured.
**Solution**: Add keys to `.env` file in JSON array format.

### "Invalid JSON in API keys"
**Cause**: Wrong format in `.env`.
**Solution**: Use `["key1", "key2"]` not `"key1,key2"`.

### "All keys unhealthy"
**Cause**: All keys failed multiple times.
**Solution**:
1. Check provider status
2. Verify keys are valid
3. Wait for cooldown period (60s)
4. Check logs for error details

### High latency
**Cause**: Provider latency or network issues.
**Solution**:
1. Check `latency_ms` in responses
2. Monitor provider status pages
3. Consider adding more providers
4. Adjust timeout if needed

### Streaming not working
**Cause**: Nginx buffering or proxy issues.
**Solution**: Add to nginx config:
```nginx
proxy_buffering off;
proxy_cache off;
```

## Next Steps

1. **Read Full Documentation**: See `AI_PROXY_README.md`
2. **Security Review**: See `AI_PROXY_SECURITY.md`
3. **Configure Caching**: Set up Redis for production
4. **Add Monitoring**: Set up log aggregation and metrics
5. **Token Tracking**: Integrate with token tracking service
6. **Rate Limiting**: Implement user-based rate limiting

## Support

For issues or questions:
1. Check logs for detailed error messages
2. Review `AI_PROXY_README.md` for detailed docs
3. Review `AI_PROXY_SECURITY.md` for security best practices
4. Check provider status pages for outages

## Summary

You now have a production-ready AI Proxy Service with:
- ✅ 4 AI providers (OpenAI, Anthropic, Grok, DeepSeek)
- ✅ Automatic load balancing and failover
- ✅ Streaming support
- ✅ BYOK support
- ✅ Comprehensive security
- ✅ Response caching
- ✅ Health monitoring

Start the server and test with `curl` or your favorite HTTP client!
