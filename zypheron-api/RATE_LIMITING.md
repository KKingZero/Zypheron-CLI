# Redis-based Rate Limiting Implementation

## Overview

This implementation provides production-ready, Redis-backed rate limiting for the Zypheron API with tier-based limits, sliding window algorithm, and graceful fallback.

## Features

- **Tier-based Rate Limits**: Different limits for Free, Starter, Pro, and Enterprise tiers
- **Sliding Window Algorithm**: Smooth rate limiting without burst allowances
- **Redis-backed**: Distributed rate limiting for multi-instance deployments
- **Graceful Fallback**: Continues operating when Redis is unavailable
- **Standard Headers**: Returns X-RateLimit-* headers in all responses
- **Security**: No internal details exposed in error messages

## Architecture

### Components

1. **RedisClient** (`app/core/redis_client.py`)
   - Connection pool management
   - Health checks and monitoring
   - Automatic reconnection
   - Graceful error handling

2. **RateLimitMiddleware** (`app/middleware/rate_limiter.py`)
   - Request interception
   - User authentication extraction
   - Tier-based limit application
   - Sliding window implementation
   - Response header injection

3. **Configuration** (`app/core/config.py`)
   - Environment-based settings
   - Redis connection parameters
   - Tier limit configuration

## Rate Limits by Tier

| Tier       | Requests/Minute |
|------------|-----------------|
| Free       | 10              |
| Starter    | 60              |
| Pro        | 120             |
| Enterprise | 300             |

## Configuration

### Environment Variables

#### Redis URL (Recommended)

```bash
# Production (Upstash, Redis Cloud, etc.)
REDIS_URL=rediss://default:PASSWORD@HOST:PORT

# Development (Local Redis)
REDIS_URL=redis://localhost:6379
```

#### Individual Redis Settings (Alternative)

```bash
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_password
REDIS_DB=0
REDIS_SSL=true
```

#### Enable/Disable Rate Limiting

```bash
# Enable Redis-based rate limiting
REDIS_ENABLED=true

# Disable rate limiting (development only)
REDIS_ENABLED=false
```

### Configuration Priority

1. `REDIS_URL` (highest priority - used if set)
2. Individual settings (`REDIS_HOST`, `REDIS_PORT`, etc.)
3. Defaults (localhost:6379)

## Implementation Details

### Sliding Window Algorithm

The middleware uses a Redis Sorted Set to implement a sliding window:

```python
# Key structure: ratelimit:{user_id} or ratelimit:{ip_address}
# Score: Unix timestamp
# Member: {timestamp}:{random_suffix}

1. Add current request timestamp to sorted set
2. Remove timestamps outside the window (60 seconds)
3. Count remaining timestamps
4. Compare count with tier limit
5. Allow or reject request
```

### Rate Limit Keys

- **Authenticated Users**: `ratelimit:{user_id}`
  - Uses user ID from JWT token
  - Looks up tier from database
  - Applies tier-specific limit

- **Unauthenticated Requests**: `ratelimit:{ip_address}`
  - Uses client IP address
  - Applies Free tier limit (10 req/min)
  - Checks X-Forwarded-For for proxied requests

### Response Headers

All responses (except exempt paths) include:

```http
X-RateLimit-Limit: 60          # Maximum requests per window
X-RateLimit-Remaining: 45      # Requests remaining in current window
X-RateLimit-Reset: 1704295260  # Unix timestamp when limit resets
```

When rate limited (429 response):

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1704295260
Retry-After: 30                 # Seconds until retry allowed
```

### Exempt Paths

The following paths are exempt from rate limiting:

- `/` (root)
- `/health` (health check)
- `/docs` (Swagger UI)
- `/redoc` (ReDoc UI)
- `/openapi.json` (OpenAPI schema)

These paths are typically used for monitoring, documentation, and health checks.

## Usage

### Basic Setup

1. **Install Redis** (if not using cloud provider)

```bash
# macOS
brew install redis
brew services start redis

# Ubuntu/Debian
sudo apt install redis-server
sudo systemctl start redis

# Docker
docker run -d -p 6379:6379 redis:7-alpine
```

2. **Configure Environment Variables**

```bash
# .env file
REDIS_URL=redis://localhost:6379
REDIS_ENABLED=true
```

3. **Start the API**

```bash
uvicorn app.main:app --reload
```

The rate limiting middleware is automatically registered and will:
- Connect to Redis on startup
- Apply rate limits to all non-exempt paths
- Add rate limit headers to all responses
- Gracefully handle Redis connection failures

### Testing

Run the test suite:

```bash
# Start the API
uvicorn app.main:app

# In another terminal, run tests
python test_rate_limit.py
```

Or test manually with curl:

```bash
# Test unauthenticated request
for i in {1..15}; do
  curl -i http://localhost:8000/health
  echo "---"
done

# Test authenticated request
TOKEN="your_jwt_token_here"
for i in {1..15}; do
  curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8000/health
  echo "---"
done
```

## Production Deployment

### Recommended Redis Providers

1. **Upstash** (Serverless, Edge-optimized)
   - Global replication
   - Per-request usage accounting
   - TLS by default
   - Perfect for serverless deployments

2. **Redis Cloud** (Managed Redis)
   - High availability
   - Automatic failover
   - Multi-zone replication

3. **AWS ElastiCache** (AWS-native)
   - VPC integration
   - Automatic backups
   - Multi-AZ support

### Production Configuration

```bash
# Use TLS for production
REDIS_URL=rediss://default:PASSWORD@HOST:PORT

# Enable Redis
REDIS_ENABLED=true

# SSL enabled by default
REDIS_SSL=true
```

### Monitoring

Monitor these metrics in production:

1. **Rate Limit Hit Rate**
   - Number of 429 responses
   - Identify potential abusive traffic

2. **Redis Connection Health**
   - Connection pool utilization
   - Failed health checks
   - Reconnection events

3. **Response Times**
   - Impact of Redis lookups on latency
   - Cache hit/miss ratios

### High Availability

For high availability deployments:

1. **Redis Cluster**: Use Redis Cluster for automatic sharding and failover
2. **Sentinel**: Use Redis Sentinel for automatic failover
3. **Replica Sets**: Configure read replicas for better performance

### Scaling Considerations

- **Connection Pool**: Default pool size is 20 connections
  - Increase for high-traffic deployments
  - Monitor pool exhaustion

- **Sorted Set Size**: Each user's rate limit key maintains a sorted set
  - Automatically cleaned up (removes old entries)
  - TTL set to 2x window size (120 seconds)

- **Memory Usage**: Approximately 200 bytes per active user
  - 10,000 active users ≈ 2MB memory

## Error Handling

### Redis Unavailable

When Redis is unavailable:

1. Middleware logs warning
2. All requests are allowed (fail-open)
3. No rate limit headers are added
4. Application continues functioning

```python
# Logs:
WARNING:app.middleware.rate_limiter:Redis unavailable - rate limiting disabled
```

### Database Errors

When user tier lookup fails:

1. Defaults to Free tier (most restrictive)
2. Logs error for investigation
3. Continues processing request

### Redis Errors

Individual Redis operations handle errors gracefully:

- GET/SET failures: Return None/False
- Connection timeouts: Mark connection unhealthy
- Pipeline errors: Log and allow request

## Security Considerations

### DoS Protection

Rate limiting provides basic DoS protection:

- Per-user limits prevent single user abuse
- Per-IP limits protect against unauthenticated attacks
- Sliding window prevents burst attacks

### Information Disclosure

Error messages are generic and don't expose:

- Internal Redis details
- User tier information
- System architecture
- Rate limit implementation details

### IP Address Handling

For proxied/load-balanced deployments:

1. Checks `X-Forwarded-For` header
2. Takes first IP in chain (original client)
3. Falls back to `X-Real-IP`
4. Finally uses direct client IP

Configure your reverse proxy correctly:

```nginx
# Nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP $remote_addr;
```

## Troubleshooting

### Rate Limiting Not Working

1. **Check Redis Connection**
   ```bash
   redis-cli ping
   ```

2. **Check Environment Variables**
   ```bash
   echo $REDIS_URL
   echo $REDIS_ENABLED
   ```

3. **Check Logs**
   ```bash
   # Look for Redis connection messages
   grep -i redis app.log
   ```

### Headers Not Appearing

1. **Check Exempt Paths**
   - `/health`, `/`, `/docs` are exempt
   - Test with a different endpoint

2. **Check Middleware Registration**
   - Ensure middleware is added in main.py
   - Verify import statements

### Wrong Rate Limits Applied

1. **Check User Tier**
   ```sql
   SELECT id, email, tier FROM users WHERE id = ?;
   ```

2. **Check JWT Token**
   ```python
   # Decode token to verify user_id
   from app.core.security import decode_access_token
   payload = decode_access_token(token)
   print(payload)
   ```

3. **Check Configuration**
   ```python
   from app.core.config import get_settings
   settings = get_settings()
   print(f"Free: {settings.rate_limit_free}")
   print(f"Starter: {settings.rate_limit_starter}")
   ```

## Future Enhancements

Potential improvements for future iterations:

1. **Distributed Tracing**: Add OpenTelemetry tracing for rate limit operations
2. **Metrics Export**: Export rate limit metrics to Prometheus/Grafana
3. **Dynamic Limits**: Adjust limits based on system load
4. **Whitelist/Blacklist**: IP-based whitelist for trusted clients
5. **Custom Headers**: Support for custom rate limit headers
6. **Multiple Windows**: Support for different time windows (hourly, daily)
7. **Burst Allowance**: Allow short bursts above limit
8. **Cost-based Limiting**: Rate limit based on compute cost, not request count

## References

- [Redis Sorted Sets](https://redis.io/docs/data-types/sorted-sets/)
- [FastAPI Middleware](https://fastapi.tiangolo.com/advanced/middleware/)
- [RFC 6585 - 429 Too Many Requests](https://tools.ietf.org/html/rfc6585#section-4)
- [Upstash Redis](https://upstash.com/docs/redis)
