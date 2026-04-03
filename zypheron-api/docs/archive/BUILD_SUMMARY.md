# Zypheron API - Build Summary

## Current State

`zypheron-api/` is the repository's FastAPI backend for local or self-hosted use.
It should be read as support infrastructure for the OSS CLI.

## Main Areas

### Core

- `app/core/` for configuration, database setup, and security helpers
- `app/main.py` for startup, routing, health checks, and middleware wiring

### Models

- users
- devices
- sessions
- token usage and related usage-tracking tables

### Routers

- `auth.py`
- `devices.py`
- `tokens.py`
- websocket and scan-related routes

### Runtime Support

- local SQLite by default
- optional PostgreSQL support
- optional Redis and Prometheus paths
- websocket support for scan progress and related updates

## What To Verify

1. `poetry install`
2. `cp .env.example .env`
3. set `JWT_SECRET_KEY`
4. start with `./run.sh` or `uvicorn app.main:app --reload`
5. hit `/health`
6. confirm `/docs` loads

## Related Docs

- `README.md`
- `QUICK_START.md`
- `SETUP_GUIDE.md`
- `API_TESTING.md`
