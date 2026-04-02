# Zypheron API Setup Guide

Setup instructions for the local-first FastAPI backend used by Zypheron.

## Purpose

This service supports the OSS CLI with:

- authentication and session handling
- device registration
- token and usage visibility
- websocket updates for scan activity
- optional local or self-hosted service integrations

## Prerequisites

- Python 3.11+
- Poetry or pip
- SQLite for the default local path
- PostgreSQL, Redis, and Prometheus only if you need those optional paths

## Install

```bash
cd zypheron-api
poetry install
```

Or:

```bash
pip install -e .
```

## Minimal Configuration

```bash
cp .env.example .env
openssl rand -hex 32
```

Set at minimum:

```bash
DEBUG=true
ENVIRONMENT=development
JWT_SECRET_KEY=your-generated-secret
DATABASE_TYPE=sqlite
DATABASE_URL=sqlite+aiosqlite:///./zypheron.db
```

## Start

```bash
./run.sh
```

Or:

```bash
uvicorn app.main:app --reload
```

## Verify

```bash
curl http://localhost:8000/health
```

Open:

- `http://localhost:8000/docs`
- `http://localhost:8000/redoc`

## Main API Areas

### `/auth`

- register
- login
- logout
- current-user lookup

### `/devices`

- register a CLI device
- list known devices
- update device metadata
- mark activity

### `/tokens`

- usage summary
- remaining budget or quota view
- usage history

### `/ws`

- real-time scan updates

## Local Defaults

- SQLite is the default database.
- Redis and Prometheus are optional.
- Local development should work without external hosted services.

## Suggested Smoke Test

1. Start the server.
2. Hit `/health`.
3. Register a user.
4. Log in and fetch `/auth/me`.
5. Register a device.
6. Verify `/tokens/usage` returns successfully for the authenticated user.

## Related Docs

- `README.md`
- `QUICK_START.md`
- `API_TESTING.md`
- `BUILD_SUMMARY.md`
