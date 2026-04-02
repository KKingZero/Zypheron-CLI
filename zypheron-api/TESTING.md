# Zypheron API Testing

## Purpose

This file documents the current local testing paths for `zypheron-api/`.

## Common Commands

```bash
cd zypheron-api
poetry run pytest
```

Run a focused subset:

```bash
poetry run pytest tests/test_auth.py
poetry run pytest tests/test_devices.py
poetry run pytest tests/test_tokens.py
```

## Local Validation Flow

1. Install dependencies with Poetry.
2. Copy `.env.example` to `.env`.
3. Start the API locally.
4. Run the relevant pytest subset.
5. Perform a quick `/health` and `/docs` smoke test.

## Notes

- Prefer SQLite for local test setup unless a specific test requires another backend.
- Treat optional services like Redis as additive, not required, for local verification.
- Keep tests safe for offline or constrained environments where possible.
