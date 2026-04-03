# Zypheron API

FastAPI backend for Zypheron. Local-first and self-hostable by default. Supports the OSS CLI with authentication, device registration, AI proxy, token tracking, and real-time scan updates.

## Quick Start

```bash
cd zypheron-api
cp .env.example .env
openssl rand -hex 32  # Generate JWT secret, add to .env as JWT_SECRET_KEY
```

Set minimum environment variables in `.env`:

```bash
DEBUG=true
ENVIRONMENT=development
JWT_SECRET_KEY=<your-generated-secret>
DATABASE_TYPE=sqlite
DATABASE_URL=sqlite+aiosqlite:///./zypheron.db
```

Install and run:

```bash
# With Poetry
poetry install
./run.sh

# Or with pip
pip install -e .
uvicorn app.main:app --reload
```

Verify:

```bash
curl http://localhost:8000/health
```

- API docs: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- Health: http://localhost:8000/health

## API Areas

### Authentication (`/auth`)

- `POST /auth/register` - Create account
- `POST /auth/login` - Login, receive JWT
- `POST /auth/logout` - Invalidate session
- `GET /auth/me` - Current user info
- `GET /auth/github` - GitHub OAuth flow
- Device code flow for CLI authentication

### Devices (`/devices`)

- Register, list, update, delete, heartbeat

### AI Proxy (`/ai`)

- `POST /ai/chat` - Proxied chat completion (streaming supported)
- `GET /ai/providers` - List available providers
- `POST /ai/validate-key` - Validate BYOK key
- `GET /ai/health` - Provider health status

### BYOK (`/byok`)

- Store, list, validate, delete user API keys

### Tokens & Usage (`/tokens`)

- Usage summary, remaining quota, usage history

### Monitoring

- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics (when configured)

### WebSocket

- `WS /ws/scans/{user_id}` - Real-time scan updates

## Infrastructure

| Component | Default | Optional |
|-----------|---------|----------|
| Database | SQLite | PostgreSQL, Supabase |
| Cache / Rate Limiting | None | Redis |
| Metrics | None | Prometheus |

## Prerequisites

- Python 3.11+
- Poetry or pip
- SQLite (included, no setup)
- Docker (optional, for PostgreSQL/Redis)

## Testing

```bash
# Run all tests
poetry run pytest

# Run specific test files
poetry run pytest tests/test_auth.py
poetry run pytest tests/test_devices.py
poetry run pytest tests/test_tokens.py
```

### Smoke Test

1. Start the server
2. `curl http://localhost:8000/health`
3. Register a user via `/auth/register`
4. Login and check `/auth/me`
5. Register a device
6. Verify `/tokens/usage` works for the authenticated user

## Security

- Redirect validation and error sanitization
- JWT with configurable expiry
- Rate limiting (Redis-backed, tier-based)
- Fernet encryption for stored provider keys
- API key scrubbing in logs and error messages
- Input validation (size limits, type checking)
- Optional metrics auth

## Documentation

| File | Topic |
|------|-------|
| [DATABASE.md](DATABASE.md) | SQLite/PostgreSQL setup, migration, management |
| [REDIS.md](REDIS.md) | Redis setup, configuration, common commands |
| [AI_PROXY.md](AI_PROXY.md) | AI proxy setup, providers, load balancing |
| [AUTH.md](AUTH.md) | Device auth, GitHub OAuth, BYOK setup |
| [RATE_LIMITING.md](RATE_LIMITING.md) | Global and per-provider rate limits |
| [KEY_ROTATION.md](KEY_ROTATION.md) | Encryption key rotation procedure |
| [OLLAMA.md](OLLAMA.md) | Local LLM provider setup |
| [app/websocket/README.md](app/websocket/README.md) | WebSocket implementation |

## See Also

- [../README.md](../README.md) - Project root
- [../docs/AI_GUIDE.md](../docs/AI_GUIDE.md) - AI usage guide
- [../docs/INSTALL.md](../docs/INSTALL.md) - Installation guide
