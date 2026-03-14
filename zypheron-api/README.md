# Zypheron API

FastAPI backend for Zypheron - AI-powered vulnerability scanning and security analysis.

## Features

- **Authentication**: Email/password and GitHub OAuth support
- **Device Management**: UUID-based CLI device registration with tier-based limits
- **License Management**: Subscription tiers with Stripe billing (monthly + annual)
- **Stripe Billing**: Checkout, billing portal, subscription reactivation, webhook processing with idempotency
- **AI Proxy**: Multi-provider load balancer with caching, quota tracking, and BYOK support
- **Token Tracking**: Usage monitoring and quota enforcement
- **Monitoring**: Prometheus metrics, health checks with component status
- **Rate Limiting**: Redis-backed Lua script rate limiting per tier
- **Real-time Updates**: WebSocket support for scan streaming
- **Database**: SQLite for dev, PostgreSQL/Supabase for production
- **Security**: Open redirect prevention, error sanitization, JWT 7-day expiry, webhook idempotency

## Tech Stack

- **Framework**: FastAPI (async/await)
- **Database**: SQLAlchemy 2.0+ (async) - PostgreSQL (prod) / SQLite (dev)
- **Cache**: Redis (response caching, rate limiting, webhook idempotency)
- **Auth**: JWT tokens (HS256, 7-day expiry) with session management
- **Payments**: Stripe (subscriptions, webhooks, billing portal)
- **Monitoring**: Prometheus metrics middleware
- **Validation**: Pydantic v2 schemas
- **Containers**: Docker/Podman with docker-compose

## Quick Start

### Option 1: Docker/Podman (Recommended)

```bash
# Start full stack (API + Postgres + Redis + pgAdmin + Prometheus)
podman-compose up -d

# Or with Docker
docker-compose up -d
```

Services available at:
- **API**: http://localhost:8000
- **Swagger Docs**: http://localhost:8000/docs
- **pgAdmin**: http://localhost:5050
- **Prometheus**: http://localhost:9090

### Option 2: Local Development

```bash
# Install dependencies
poetry install

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Run development server (auto-reload)
poetry run uvicorn app.main:app --reload
```

### Running Tests

```bash
# In container (recommended - includes Postgres + Redis)
podman-compose --profile test up test-runner

# Locally (requires running Postgres + Redis)
poetry run pytest

# With coverage
poetry run pytest --cov=app
```

## API Endpoints

### Authentication (`/auth`)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/register` | Register with email/password |
| `POST` | `/auth/login` | Login and get JWT token |
| `GET` | `/auth/github` | Initiate GitHub OAuth flow |
| `GET` | `/auth/github/callback` | GitHub OAuth callback |
| `POST` | `/auth/logout` | Invalidate current session |
| `GET` | `/auth/me` | Get current user info |

### Devices (`/devices`)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/devices/register` | Register new CLI device |
| `GET` | `/devices` | List user's devices |
| `GET` | `/devices/{id}` | Get device details |
| `PATCH` | `/devices/{id}` | Update device |
| `DELETE` | `/devices/{id}` | Deactivate device |
| `POST` | `/devices/{id}/ping` | Update last_seen (heartbeat) |

### License (`/license`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/license` | Get license details |
| `GET` | `/license/validate` | Validate current license |
| `GET` | `/license/features` | Get available features for tier |
| `GET` | `/license/tiers` | Get all tier configurations |
| `GET` | `/license/prices` | Get all tiers with monthly/annual pricing |
| `POST` | `/license/upgrade/{tier}` | Initiate Stripe checkout session |
| `POST` | `/license/portal` | Get Stripe billing portal URL |
| `POST` | `/license/reactivate` | Reactivate a cancelled-but-active subscription |
| `POST` | `/license/cancel` | Cancel subscription (end of period) |
| `POST` | `/license/refresh` | Sync license from Stripe |

### Token Usage (`/tokens`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/tokens/usage` | Get usage summary |
| `GET` | `/tokens/remaining` | Get remaining quota |
| `GET` | `/tokens/quota` | Get comprehensive quota info |
| `GET` | `/tokens/history` | Get paginated usage history |

### AI Proxy (`/ai`)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/ai/chat` | Proxied chat completion (load balanced) |
| `POST` | `/ai/keys` | Store BYOK API key (encrypted at rest) |
| `GET` | `/ai/keys` | List user's stored provider keys |
| `DELETE` | `/ai/keys/{provider}` | Delete a stored BYOK key |

### Webhooks

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/webhooks/stripe` | Stripe webhook receiver (signature verified) |

### Monitoring

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check with component status (DB, Redis, Stripe) |
| `GET` | `/metrics` | Prometheus metrics (IP allowlist + bearer token auth) |

### WebSocket

| Method | Path | Description |
|--------|------|-------------|
| `WS` | `/ws/scans/{user_id}` | Real-time scan updates |

## Subscription Tiers

| Feature | Free | Starter | Pro | Enterprise |
|---------|------|---------|-----|------------|
| **Monthly price** | $0 | $29/mo | $149/mo | $499/seat/mo |
| **Annual price** | $0 | $261/yr (25% off) | $1,341/yr (25% off) | $4,491/seat/yr (25% off) |
| **Tokens/month** | 0 (BYOK) | 1M | 3M | 15M (per 5 users) |
| **Rate limit** | 10/min | 60/min | 120/min | 300/min |
| **Devices** | 1 | 2 | 3 | 500 |
| **API Keys** | BYOK only | Included | Included | Included |
| **Response Caching** | No | Yes | Yes | Yes |
| **Support** | Community | Email | Priority | Dedicated |

## Monitoring

### Prometheus Metrics

The `/metrics` endpoint exposes:

- `http_requests_total` - HTTP requests by method, path, status
- `http_request_duration_seconds` - Request latency histogram
- `ai_requests_total` - AI proxy requests by provider, model
- `cache_hits_total` / `cache_misses_total` - Cache effectiveness
- `rate_limit_exceeded_total` - Rate limit violations

Access requires IP allowlist and/or `METRICS_SECRET_TOKEN` bearer token.

### Health Check

`GET /health` returns component-level status:

```json
{
  "status": "healthy",
  "components": {
    "database": "healthy",
    "redis": "healthy",
    "stripe": "healthy"
  }
}
```

## Security

### Implemented Protections

- **Open redirect prevention**: `ALLOWED_REDIRECT_DOMAINS` allowlist for all redirect URLs (Stripe checkout/portal returns)
- **Webhook idempotency**: Redis (48h TTL) + in-memory OrderedDict fallback (10K cap, LRU eviction)
- **Error sanitization**: No stack traces or internal paths in production error responses
- **JWT 7-day expiry**: Tokens expire after `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` (default 10080)
- **Rate limiting**: Redis Lua scripts for atomic per-user rate limiting by tier
- **BYOK encryption**: AES-256-GCM encryption for user API keys stored at rest
- **Metrics auth**: IP allowlist + bearer token for `/metrics` endpoint
- **Port binding**: Docker services bound to `127.0.0.1` by default

### Password Requirements

- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit

## Testing

### Test Files

Tests are in the `tests/` directory and cover all code review fixes plus integration scenarios:

- Stripe webhook lifecycle tests (create, update, delete, payment success/failure)
- Subscription endpoint tests (checkout, portal, reactivate, cancel, prices)
- AI proxy tests (load balancer, caching, quota, BYOK)
- Security fix validation tests (open redirect, error sanitization, JWT expiry, idempotency)
- Rate limiting tests
- Health check and metrics tests

### Running Tests

```bash
# Containerized (recommended - full stack with Postgres + Redis)
podman-compose --profile test up test-runner

# Local
poetry run pytest

# Specific test file
poetry run pytest tests/test_webhook_fixes.py -v

# With coverage report
poetry run pytest --cov=app --cov-report=html
```

## Production Deployment

### Environment Variables

See `.env.example` for all configuration options. Key production settings:

```bash
ENVIRONMENT=production
DEBUG=false
JWT_SECRET_KEY=<strong-random-secret>
DATABASE_TYPE=postgresql
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_SERVICE_KEY=<service-key>
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
REDIS_URL=redis://:password@redis-host:6379/0
METRICS_SECRET_TOKEN=<metrics-bearer-token>
ALLOWED_REDIRECT_DOMAINS=zypheron.com,app.zypheron.com
```

### Docker/Podman

```bash
# Production stack
podman-compose up -d

# View logs
podman-compose logs -f api
```

### Manual

```bash
# With Gunicorn + Uvicorn workers
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

## TODO / Future Enhancements

- [ ] Complete GitHub OAuth implementation
- [ ] Email verification system
- [ ] Password reset flow
- [ ] Database migrations (Alembic)
- [ ] Admin dashboard endpoints
- [ ] Usage analytics and reporting
- [ ] Celery for background tasks
- [ ] WebSocket authentication and authorization
- [ ] Scan result storage and retrieval endpoints

## License

Proprietary - Zypheron Project
