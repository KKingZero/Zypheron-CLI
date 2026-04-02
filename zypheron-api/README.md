# Zypheron API

FastAPI service components for Zypheron.

This service should be treated as local-first and self-hostable by default. It exists to support the OSS CLI, not as a hosted commercial product layer.

## Current Scope

The active API scope is:

- authentication and session flows
- device registration
- AI proxy and provider key handling
- token and usage tracking for runtime visibility
- monitoring and health endpoints
- real-time scan updates over WebSocket

Optional infrastructure:

- SQLite by default
- PostgreSQL optional
- Redis optional
- Prometheus optional

## Quick Start

```bash
cp .env.example .env
python3 -m venv .venv
source .venv/bin/activate
../scripts/setup_api_test_env.sh --allow-online
uvicorn app.main:app --reload
```

Useful endpoints:

- API: `http://localhost:8000`
- Docs: `http://localhost:8000/docs`
- Health: `http://localhost:8000/health`
- AI health: `http://localhost:8000/ai/health`

## API Areas

### Authentication

- `/auth/register`
- `/auth/login`
- `/auth/logout`
- `/auth/me`
- GitHub OAuth endpoints when configured

### Devices

- register, list, update, delete, heartbeat

### AI

- proxied chat completion
- BYOK provider key storage
- provider key listing and deletion

### Tokens and usage

- usage summary
- remaining quota
- usage history

### Monitoring

- `/health`
- `/metrics`

### WebSocket

- real-time scan updates

## Notes

- Some legacy API paths may still exist in the repository for historical reasons, but they are not part of the intended OSS product direction.
- Prefer the CLI/runtime docs in the repo root and `docs/` for the main product path.

## Testing

```bash
../scripts/setup_api_test_env.sh --allow-online
source .venv/bin/activate
pytest -v
```

## Security

Implemented protections include:

- redirect validation
- webhook idempotency helpers where still needed
- error sanitization
- JWT expiry
- rate limiting when Redis is enabled
- encryption for stored provider keys
- optional metrics auth

## See Also

- [../README.md](../README.md)
- [../docs/AI_GUIDE.md](../docs/AI_GUIDE.md)
- [../docs/INSTALL.md](../docs/INSTALL.md)
