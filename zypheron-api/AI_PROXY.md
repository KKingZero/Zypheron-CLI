# AI Proxy

The AI proxy provides a unified interface for multiple AI providers with load balancing, failover, caching, and BYOK (Bring Your Own Key) support.

## Supported Providers

| Provider | Models | API Format |
|----------|--------|------------|
| OpenAI | GPT-4o, GPT-4o-mini, GPT-4-turbo | OpenAI-compatible |
| Anthropic | Claude 3.5 Sonnet, Claude 3.5 Haiku | Custom Anthropic |
| Grok (xAI) | Grok-beta | OpenAI-compatible |
| DeepSeek | deepseek-chat, deepseek-coder | OpenAI-compatible |
| Ollama | Any local model | OpenAI-compatible |

## Configuration

Add API keys to `.env` in JSON array format:

```bash
OPENAI_API_KEYS=["sk-key1", "sk-key2"]
ANTHROPIC_API_KEYS=["sk-ant-key1"]
GROK_API_KEYS=["xai-key1"]
DEEPSEEK_API_KEYS=["ds-key1"]

# Ollama (enabled by default, no key needed)
ENABLE_OLLAMA=true
OLLAMA_BASE_URL=http://localhost:11434

# Cache TTL
CACHE_TTL_PROMPT=900
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ai/chat` | POST | Chat completion (streaming or non-streaming) |
| `/ai/providers` | GET | List available providers and models |
| `/ai/validate-key` | POST | Validate a user's API key (BYOK) |
| `/ai/health` | GET | Health check for key pools |

### POST /ai/chat

```bash
curl -X POST http://localhost:8000/ai/chat \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [{"role": "user", "content": "Hello"}],
    "provider": "openai",
    "model": "gpt-4o-mini",
    "temperature": 0.7,
    "max_tokens": 1000,
    "stream": false,
    "user_api_key": null
  }'
```

Response:

```json
{
  "provider": "openai",
  "model": "gpt-4o-mini",
  "content": "Hello! How can I help you?",
  "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
  "latency_ms": 342,
  "cached": false,
  "finish_reason": "stop"
}
```

Streaming response (SSE):

```
data: {"type":"content","content":"Hello"}
data: {"type":"done","metadata":{"finish_reason":"stop","total_tokens":18}}
```

### BYOK Usage

Pass `user_api_key` in the request to use your own key. BYOK requests bypass the response cache and are not deducted from platform token quotas.

## Load Balancing

Keys are rotated round-robin within each provider pool. Failed keys are marked unhealthy and placed in cooldown:

| Error Type | Action | Cooldown |
|------------|--------|----------|
| Rate Limit (429) | Rotate to next key | retry-after header or 300s |
| Invalid Key (401) | Rotate | 24 hours |
| Quota Exceeded (402) | Rotate | 300s |
| Server Error (5xx) | Retry same key | None (transient) |

Keys automatically recover after their cooldown period.

## Caching

Responses are cached by SHA-256 hash of (provider, model, messages, temperature, max_tokens). Cache TTL defaults to 15 minutes. BYOK and streaming requests bypass the cache.

## Security

- API keys are never logged or exposed in error messages
- Regex-based scrubbing removes key patterns from errors
- Input validation: max 100k chars/message, max 100 messages/request
- 30-second default request timeout (60s for Ollama)
- HTTPS enforced for all provider connections
- No redirect following (SSRF prevention)
- Rate limiting per user tier when Redis is enabled

## Architecture

```
app/services/ai_providers/
  base.py              # Abstract base class
  openai_client.py     # OpenAI implementation
  anthropic_client.py  # Anthropic implementation
  grok_client.py       # Grok implementation
  deepseek_client.py   # DeepSeek implementation
  ollama_client.py     # Ollama implementation
app/services/load_balancer.py  # Key pool manager
app/routers/ai_proxy.py       # API endpoints
app/schemas/ai_proxy.py       # Pydantic models
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "No AI providers available" | Add API keys to `.env` in JSON array format |
| "Invalid JSON in API keys" | Use `["key1", "key2"]` not `"key1,key2"` |
| "All keys unhealthy" | Check provider status, verify keys, wait for cooldown |
| High latency | Check `latency_ms`, monitor provider status |
| Streaming not working | Disable nginx buffering: `proxy_buffering off;` |
