# AI Proxy Service Documentation

## Overview

The AI Proxy Service provides a unified, secure interface for interacting with multiple AI providers (OpenAI, Anthropic, Grok, DeepSeek) with built-in load balancing, automatic failover, and comprehensive security features.

## Architecture

### Components

1. **AI Provider Clients** (`app/services/ai_providers/`)
   - Abstract base class with security and performance patterns
   - Provider-specific implementations (OpenAI, Anthropic, Grok, DeepSeek)
   - Standardized response format across all providers
   - Streaming and non-streaming support

2. **Load Balancer** (`app/services/load_balancer.py`)
   - Round-robin key selection per provider
   - Automatic key health tracking
   - Circuit breaker pattern for failed keys
   - Failover with exponential backoff

3. **API Router** (`app/routers/ai_proxy.py`)
   - Unified chat completion endpoint
   - Provider listing and key validation
   - Request/response caching
   - Comprehensive error handling

4. **Schemas** (`app/schemas/ai_proxy.py`)
   - Input validation with Pydantic v2
   - Response models
   - Error responses

## Security Features

### API Key Protection
- **Never logged**: API keys are never written to logs
- **Memory isolation**: Keys stored securely in memory
- **BYOK support**: Users can provide their own keys
- **Key rotation**: Automatic rotation through key pool
- **Error sanitization**: API keys scrubbed from error messages

### Input Validation
- **Size limits**: Max 100k characters per message, 100 messages per request
- **Type validation**: Strict type checking for all fields
- **Content sanitization**: Prompts sanitized before logging
- **Injection prevention**: No command or format string injection vectors

### Request Security
- **Timeouts**: 30-second default timeout (configurable)
- **Rate limiting**: Per-user rate limits based on plan
- **HTTPS only**: All provider connections use HTTPS
- **No redirects**: Explicit redirect handling disabled

### Error Handling
- **No information leakage**: Generic error messages to users
- **Detailed logging**: Full error context in logs (without keys)
- **Retryable classification**: Errors marked as retryable or not
- **Circuit breaking**: Failed keys automatically excluded

## API Endpoints

### POST /ai/chat

Unified chat completion endpoint supporting all providers.

**Request:**
```json
{
  "messages": [
    {
      "role": "user",
      "content": "What is the capital of France?"
    }
  ],
  "provider": "openai",  // Optional: auto-select if omitted
  "model": "gpt-4o-mini",  // Optional: provider default if omitted
  "temperature": 0.7,
  "max_tokens": 1000,
  "stream": false,
  "user_api_key": null  // Optional: BYOK
}
```

**Response (non-streaming):**
```json
{
  "provider": "openai",
  "model": "gpt-4o-mini",
  "content": "The capital of France is Paris.",
  "usage": {
    "prompt_tokens": 15,
    "completion_tokens": 8,
    "total_tokens": 23
  },
  "latency_ms": 342,
  "cached": false,
  "finish_reason": "stop"
}
```

**Response (streaming):**
Server-Sent Events (SSE) format:
```
data: {"type":"content","content":"The"}

data: {"type":"content","content":" capital"}

data: {"type":"done","metadata":{"finish_reason":"stop","total_tokens":23}}
```

### GET /ai/providers

List available AI providers and their models.

**Response:**
```json
{
  "providers": [
    {
      "name": "openai",
      "available": true,
      "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],
      "supports_streaming": true
    },
    {
      "name": "anthropic",
      "available": true,
      "models": ["claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022"],
      "supports_streaming": true
    }
  ],
  "total_count": 2
}
```

### POST /ai/validate-key

Validate a user's API key (BYOK).

**Request:**
```json
{
  "provider": "openai",
  "api_key": "sk-..."
}
```

**Response:**
```json
{
  "provider": "openai",
  "valid": true,
  "message": "API key is valid"
}
```

### GET /ai/health

Health check for AI proxy service.

**Response:**
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
    }
  }
}
```

## Configuration

Add API keys to your `.env` file:

```bash
# OpenAI keys (comma-separated for multiple keys)
OPENAI_API_KEYS=["sk-key1", "sk-key2", "sk-key3"]

# Anthropic keys
ANTHROPIC_API_KEYS=["sk-ant-key1", "sk-ant-key2"]

# Grok keys
GROK_API_KEYS=["xai-key1"]

# DeepSeek keys
DEEPSEEK_API_KEYS=["ds-key1"]

# Cache settings
CACHE_TTL_PROMPT=900  # 15 minutes
```

## Load Balancing

### Round-Robin Selection
Keys are selected in round-robin order within each provider pool.

### Health Tracking
Each key tracks:
- **Consecutive failures**: Count of sequential failures
- **Total failures**: Lifetime failure count
- **Cooldown period**: Time until unhealthy key is retried
- **Health status**: Healthy/unhealthy

### Failure Handling

| Error Type | Action | Cooldown |
|------------|--------|----------|
| Rate Limit (429) | Mark unhealthy, rotate | retry-after header or 300s |
| Invalid Key (401) | Mark unhealthy, rotate | 24 hours |
| Quota Exceeded (402) | Mark unhealthy, rotate | 300s |
| Server Error (5xx) | Retry same key | None (transient) |
| Timeout | Retry same key | None (transient) |

### Automatic Recovery
- Keys automatically recover after cooldown period
- Consecutive failures reset on success
- Health status checked before each selection

## Caching

### Cache Key Generation
Cache keys are SHA-256 hashes of:
- Provider
- Model
- Messages (full conversation)
- Temperature
- Max tokens

### Cache Behavior
- **Exact match only**: Different prompts = different cache keys
- **TTL**: 15 minutes (configurable)
- **BYOK bypass**: User keys bypass cache
- **Streaming bypass**: Streaming requests bypass cache

### Future: Redis Integration
When Redis is enabled:
- Distributed caching across instances
- Shared cache between users (identical prompts)
- Automatic expiration

## Error Handling

### Client Errors (4xx)
- **400 Bad Request**: Invalid request format
- **401 Unauthorized**: Invalid API key
- **402 Quota Exceeded**: Usage limit exceeded
- **429 Too Many Requests**: Rate limit exceeded

### Server Errors (5xx)
- **500 Internal Server Error**: Unexpected error
- **503 Service Unavailable**: Provider unavailable or retryable error

### Error Response Format
```json
{
  "error": "RateLimitError",
  "message": "Rate limit exceeded",
  "provider": "openai",
  "retryable": true
}
```

## Provider-Specific Notes

### OpenAI
- **API Format**: OpenAI-compatible
- **Streaming**: SSE with `data: [DONE]` terminator
- **Models**: GPT-4, GPT-3.5 families
- **Base URL**: `https://api.openai.com/v1`

### Anthropic (Claude)
- **API Format**: Custom Anthropic format
- **Message conversion**: System messages extracted separately
- **Streaming**: SSE with event types
- **Models**: Claude 3 family
- **Base URL**: `https://api.anthropic.com/v1`
- **Required**: `max_tokens` parameter (defaults to 4096)

### Grok (xAI)
- **API Format**: OpenAI-compatible
- **Streaming**: SSE with `data: [DONE]` terminator
- **Models**: Grok-beta
- **Base URL**: `https://api.x.ai/v1`

### DeepSeek
- **API Format**: OpenAI-compatible
- **Streaming**: SSE with `data: [DONE]` terminator
- **Models**: deepseek-chat, deepseek-coder
- **Base URL**: `https://api.deepseek.com/v1`

## Performance Optimization

### HTTP Client
- **Connection pooling**: Max 10 connections per provider
- **Keep-alive**: Max 5 keep-alive connections
- **Timeout**: 30 seconds default
- **No redirects**: Security and performance

### Memory Management
- **Async operations**: All I/O is non-blocking
- **Resource cleanup**: Automatic client closure
- **Context managers**: RAII pattern for providers

### Request Optimization
- **Streaming**: Reduces time-to-first-byte
- **Parallel failover**: Fast rotation on errors
- **Connection reuse**: HTTP connection pooling

## Usage Examples

### Basic Chat (Auto-select Provider)
```python
import httpx

response = httpx.post(
    "http://localhost:8000/ai/chat",
    json={
        "messages": [
            {"role": "user", "content": "Hello!"}
        ]
    }
)
print(response.json())
```

### Specific Provider and Model
```python
response = httpx.post(
    "http://localhost:8000/ai/chat",
    json={
        "messages": [
            {"role": "user", "content": "Explain quantum computing"}
        ],
        "provider": "anthropic",
        "model": "claude-3-5-sonnet-20241022",
        "temperature": 0.3
    }
)
```

### Streaming Response
```python
import httpx

with httpx.stream(
    "POST",
    "http://localhost:8000/ai/chat",
    json={
        "messages": [{"role": "user", "content": "Write a poem"}],
        "stream": True
    }
) as response:
    for line in response.iter_lines():
        if line.startswith("data: "):
            print(line[6:])  # Remove "data: " prefix
```

### BYOK (Bring Your Own Key)
```python
response = httpx.post(
    "http://localhost:8000/ai/chat",
    json={
        "messages": [{"role": "user", "content": "Hello"}],
        "provider": "openai",
        "user_api_key": "sk-your-own-key"
    }
)
```

### Validate User Key
```python
response = httpx.post(
    "http://localhost:8000/ai/validate-key",
    json={
        "provider": "openai",
        "api_key": "sk-test-key"
    }
)
print(response.json()["valid"])  # True or False
```

## Monitoring and Logging

### Structured Logging
All logs use structlog with consistent fields:
```json
{
  "event": "ai_chat_request",
  "provider": "openai",
  "model": "gpt-4o-mini",
  "message_count": 3,
  "stream": false,
  "has_user_key": false,
  "timestamp": "2025-12-19T19:45:00Z"
}
```

### Key Metrics to Monitor
- **Request latency**: `latency_ms` in responses
- **Error rates**: By provider and error type
- **Key health**: Healthy vs unhealthy keys
- **Cache hit rate**: Cached responses percentage
- **Token usage**: Per user and provider

### Health Checks
```bash
# Check service health
curl http://localhost:8000/ai/health

# Check available providers
curl http://localhost:8000/ai/providers
```

## Security Checklist

- [ ] API keys stored in environment variables, not code
- [ ] API keys never logged or exposed in errors
- [ ] Input validation on all user inputs
- [ ] Rate limiting enabled per user plan
- [ ] Timeouts configured on all requests
- [ ] Error messages sanitized
- [ ] HTTPS enforced for all provider connections
- [ ] No redirect following
- [ ] Prompt sanitization before logging
- [ ] BYOK keys validated before use

## Troubleshooting

### No Providers Available
**Cause**: No API keys configured for any provider.
**Solution**: Add API keys to `.env` file.

### All Keys Unhealthy
**Cause**: All keys failed and are in cooldown.
**Solution**: Check provider status, verify keys are valid, wait for cooldown.

### Rate Limit Errors
**Cause**: Provider rate limits exceeded.
**Solution**: Add more keys to pool, upgrade provider plan, or implement user-side rate limiting.

### High Latency
**Cause**: Provider latency or network issues.
**Solution**: Monitor `latency_ms`, consider timeout adjustments, check provider status.

### Invalid Key Errors with BYOK
**Cause**: User provided invalid API key.
**Solution**: Use `/ai/validate-key` endpoint to test before use.

## Future Enhancements

- [ ] Redis caching for distributed deployments
- [ ] Advanced routing (cost optimization, latency optimization)
- [ ] Token usage tracking integration
- [ ] Request queuing for rate limit management
- [ ] Provider failover on model availability
- [ ] Cost estimation per request
- [ ] A/B testing framework for models
- [ ] Custom model mappings
