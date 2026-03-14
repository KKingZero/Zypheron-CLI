# Zypheron API - Quick Start

Get the API running in 3 minutes.

## Step 1: Install Dependencies

```bash
cd zypheron-api
poetry install
```

Or with pip:
```bash
pip install fastapi sqlalchemy[asyncio] pydantic-settings uvicorn aiosqlite python-jose[cryptography] passlib[bcrypt]
```

## Step 2: Configure Environment

```bash
# Copy example config
cp .env.example .env

# Generate secure secret
openssl rand -hex 32

# Edit .env and set:
# JWT_SECRET_KEY=<output from above>
```

Minimal `.env`:
```bash
DEBUG=true
ENVIRONMENT=development
JWT_SECRET_KEY=your-generated-secret-key-here
DATABASE_TYPE=sqlite
DATABASE_URL=sqlite+aiosqlite:///./zypheron.db
```

## Step 3: Start Server

```bash
./run.sh
```

Or:
```bash
uvicorn app.main:app --reload
```

## Step 4: Test It

Visit: http://localhost:8000/docs

Or test with curl:

```bash
# Health check
curl http://localhost:8000/health

# Register user
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass123"}'

# Save the access_token from response
export TOKEN="<your-access-token>"

# Get current user
curl http://localhost:8000/auth/me \
  -H "Authorization: Bearer $TOKEN"

# Register device
curl -X POST http://localhost:8000/devices/register \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_uuid":"test-123","device_name":"My Device","platform":"linux"}'

# Check license
curl http://localhost:8000/license/validate \
  -H "Authorization: Bearer $TOKEN"
```

## That's It!

Your API is now running at:
- **API**: http://localhost:8000
- **Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Next Steps

- Read `API_TESTING.md` for complete endpoint examples
- Read `SETUP_GUIDE.md` for detailed configuration
- Read `README.md` for full documentation
- Read `BUILD_SUMMARY.md` for implementation details

## Common Issues

**Port 8000 in use?**
```bash
lsof -ti:8000 | xargs kill -9
```

**Import errors?**
```bash
poetry install
# or
pip install -e .
```

**Database errors?**
```bash
rm zypheron.db
uvicorn app.main:app --reload
```

## Subscription Tiers

| Tier | Devices | Tokens/mo | Rate Limit |
|------|---------|-----------|------------|
| Free | 1 | 0 (BYOK) | 10/min |
| Starter | 2 | 1M | 60/min |
| Pro | 3 | 3M | 120/min |
| Enterprise | 500 | 15M | 300/min |

## Key Endpoints

- `POST /auth/register` - Create account
- `POST /auth/login` - Get JWT token
- `GET /auth/me` - Current user info
- `POST /devices/register` - Register CLI device
- `GET /devices` - List devices
- `GET /license/validate` - Check license
- `GET /tokens/usage` - Usage stats
- `WS /ws/scans/{user_id}` - Real-time updates

## Done!

Start building your Zypheron CLI integration.
