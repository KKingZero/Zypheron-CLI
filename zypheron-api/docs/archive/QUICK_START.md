# Zypheron API - Quick Start

Get the local API running quickly for development or self-hosted use.

## 1. Install Dependencies

```bash
cd zypheron-api
poetry install
```

Or with pip:

```bash
pip install -e .
```

## 2. Configure Environment

```bash
cp .env.example .env
openssl rand -hex 32
```

Set at minimum:

```bash
DEBUG=true
ENVIRONMENT=development
JWT_SECRET_KEY=your-generated-secret-key-here
DATABASE_TYPE=sqlite
DATABASE_URL=sqlite+aiosqlite:///./zypheron.db
```

## 3. Start the Server

```bash
./run.sh
```

Or:

```bash
uvicorn app.main:app --reload
```

## 4. Verify It

```bash
curl http://localhost:8000/health
```

Then open:

- `http://localhost:8000/docs`
- `http://localhost:8000/redoc`

## Core Endpoints

- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`
- `POST /devices/register`
- `GET /devices`
- `GET /tokens/usage`
- `WS /ws/scans/{user_id}`

## Notes

- SQLite is the default local database.
- PostgreSQL, Redis, and Prometheus are optional.
- This API should be treated as self-hosted support infrastructure for the OSS CLI.

## Next Steps

- Read `SETUP_GUIDE.md` for fuller configuration notes.
- Read `API_TESTING.md` for example requests.
- Read `BUILD_SUMMARY.md` for the current backend architecture summary.
