# Zypheron API Setup Guide

Complete setup instructions for the Zypheron FastAPI backend.

## What's Been Created

### Core Infrastructure
- **FastAPI application** with async/await patterns
- **SQLAlchemy 2.0+** async database layer
- **JWT authentication** with session management
- **WebSocket support** for real-time scan updates
- **Pydantic v2 schemas** for validation
- **CORS middleware** configured

### Database Models
1. **User** - Authentication and profile (`app/models/user.py`)
   - Email/password + GitHub OAuth support
   - Tier tracking
   - Relationships to devices, licenses, sessions

2. **Device** - CLI device registration (`app/models/device.py`)
   - UUID-based identification
   - Tier-based device limits
   - Activity tracking

3. **License** - Subscription management (`app/models/license.py`)
   - Stripe integration ready
   - Tier and status tracking
   - Validity period management

4. **Session** - Auth token tracking (`app/models/session.py`)
   - JWT storage and validation
   - Logout support
   - Activity tracking

5. **TokenUsage** - API usage tracking (`app/models/token_usage.py`)
   - Per-request token consumption
   - Provider and model tracking
   - Prompt hashing for deduplication

### API Endpoints

#### Authentication (`/auth`)
- `POST /auth/register` - Email/password registration
- `POST /auth/login` - Login with credentials
- `GET /auth/github` - GitHub OAuth (placeholder)
- `GET /auth/github/callback` - OAuth callback (placeholder)
- `POST /auth/logout` - Session invalidation
- `GET /auth/me` - Current user info

#### Devices (`/devices`)
- `POST /devices/register` - Register CLI device
- `GET /devices` - List user devices
- `GET /devices/{id}` - Get device details
- `PATCH /devices/{id}` - Update device
- `DELETE /devices/{id}` - Deactivate device
- `POST /devices/{id}/ping` - Heartbeat

#### License (`/license`)
- `GET /license/validate` - Validate license
- `GET /license/features` - Get tier features
- `GET /license` - License details
- `POST /license/refresh` - Sync from Stripe (placeholder)
- `GET /license/tiers` - All tier configurations
- `POST /license/upgrade/{tier}` - Initiate upgrade (placeholder)
- `POST /license/cancel` - Cancel subscription (placeholder)

#### Token Usage (`/tokens`)
- `GET /tokens/usage` - Usage summary
- `GET /tokens/remaining` - Remaining quota
- `GET /tokens/quota` - Comprehensive quota info
- `GET /tokens/history` - Paginated usage history

#### WebSocket
- `WS /ws/scans/{user_id}` - Real-time scan updates

### Pydantic Schemas
- **Auth schemas** - Registration, login, token responses
- **Device schemas** - Device creation, updates, responses
- **License schemas** - License validation, features, tier info
- **Token schemas** - Usage tracking, quota information

## Installation

### 1. Prerequisites
- Python 3.11+
- pip or Poetry
- (Optional) PostgreSQL for production
- (Optional) Redis for caching

### 2. Install Dependencies

Using Poetry (recommended):
```bash
cd zypheron-api
poetry install
```

Using pip:
```bash
cd zypheron-api
pip install -e .
```

### 3. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Generate secure JWT secret
openssl rand -hex 32

# Edit .env and set at minimum:
# - JWT_SECRET_KEY (from above)
# - DEBUG=true (for development)
# - ENVIRONMENT=development
```

Minimal `.env` for local development:
```bash
DEBUG=true
ENVIRONMENT=development
JWT_SECRET_KEY=your-generated-secret-here
DATABASE_TYPE=sqlite
DATABASE_URL=sqlite+aiosqlite:///./zypheron.db
```

### 4. Start the Server

Using the run script:
```bash
chmod +x run.sh
./run.sh
```

Or directly with uvicorn:
```bash
uvicorn app.main:app --reload
```

Or with Python:
```bash
python -m app.main
```

### 5. Verify Installation

Check health endpoint:
```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "Zypheron API",
  "version": "0.1.0",
  "environment": "development"
}
```

Visit API docs:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Quick Test

### 1. Register a User

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123"
  }'
```

Save the `access_token` from the response.

### 2. Get Current User

```bash
export TOKEN="<your-access-token>"

curl http://localhost:8000/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Register a Device

```bash
curl -X POST http://localhost:8000/devices/register \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "device_uuid": "test-uuid-123",
    "device_name": "My Test Device",
    "platform": "linux"
  }'
```

### 4. Check License

```bash
curl http://localhost:8000/license/validate \
  -H "Authorization: Bearer $TOKEN"
```

## Subscription Tiers

| Feature | Free | Starter | Pro | Enterprise |
|---------|------|---------|-----|------------|
| Monthly Tokens | 0 (BYOK) | 1M | 3M | 15M |
| Rate Limit | 10/min | 60/min | 120/min | 300/min |
| Max Devices | 1 | 2 | 3 | 500 |
| API Keys | BYOK | Included | Included | Included |
| Caching | No | Yes | Yes | Yes |
| Support | Community | Email | Priority | Dedicated |

## Database Schema

The database is automatically initialized on first startup via `init_db()` in the lifespan manager.

Tables created:
- `users` - User accounts
- `devices` - Registered devices
- `licenses` - Subscription licenses
- `sessions` - Active auth sessions
- `token_usage` - Token consumption tracking
- `user_quota` - Quota denormalization table

## Security Features

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit

### JWT Tokens
- HS256 algorithm
- Session-based validation
- Configurable expiry (default: no expiry until logout)

### Device Management
- UUID-based identification
- Tier-based limits enforced
- Activity tracking

## Development Workflow

### Project Structure
```
zypheron-api/
├── app/
│   ├── core/          # Config, database, security
│   ├── models/        # SQLAlchemy models
│   ├── schemas/       # Pydantic schemas
│   ├── routers/       # API endpoints
│   ├── services/      # Business logic
│   └── main.py        # FastAPI app
├── tests/             # Test suite
├── .env               # Environment config
├── .env.example       # Example config
├── pyproject.toml     # Dependencies
└── README.md          # Documentation
```

### Adding a New Endpoint

1. Create route in `app/routers/`
2. Define schemas in `app/schemas/`
3. Add to router exports
4. Include router in `app/main.py`

Example:
```python
# app/routers/myrouter.py
from fastapi import APIRouter, Depends
from app.routers.auth import CurrentUser

router = APIRouter(prefix="/myendpoint", tags=["MyEndpoint"])

@router.get("/")
async def my_endpoint(current_user: CurrentUser):
    return {"message": "Hello from my endpoint"}

# app/main.py
from app.routers import myrouter
app.include_router(myrouter.router)
```

### Database Changes

Models are auto-created on startup. For production, use migrations:

```bash
# Install Alembic
poetry add alembic

# Initialize
alembic init alembic

# Create migration
alembic revision --autogenerate -m "Description"

# Apply migration
alembic upgrade head
```

## Production Deployment

### Environment Configuration

```bash
# Production .env
ENVIRONMENT=production
DEBUG=false
JWT_SECRET_KEY=<strong-secret-key>

# PostgreSQL/Supabase
DATABASE_TYPE=postgresql
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_SERVICE_KEY=<service-key>

# Stripe (optional)
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...

# GitHub OAuth (optional)
GITHUB_CLIENT_ID=<client-id>
GITHUB_CLIENT_SECRET=<client-secret>
```

### Running in Production

```bash
# With Gunicorn + Uvicorn workers
gunicorn app.main:app \
  -w 4 \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000

# Or with Uvicorn
uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 4
```

### CORS Configuration

Update `app/main.py` with production origins:

```python
allowed_origins = [
    "https://yourdomain.com",
    "https://app.yourdomain.com",
]
```

## Next Steps

### Immediate TODOs
1. Configure JWT_SECRET_KEY in .env
2. Test all endpoints with API_TESTING.md guide
3. Set up GitHub OAuth credentials (optional)
4. Set up Stripe credentials (optional)

### Future Enhancements
- Complete GitHub OAuth implementation
- Complete Stripe integration (checkout, webhooks)
- Add Redis caching layer
- Implement rate limiting middleware
- Add email verification system
- Password reset flow
- Admin dashboard endpoints
- Scan result storage endpoints
- AI provider proxy with load balancing

## Troubleshooting

### Database Errors

If you see database errors, delete the database and restart:
```bash
rm zypheron.db
uvicorn app.main:app --reload
```

### Import Errors

Ensure all dependencies are installed:
```bash
poetry install
# or
pip install -e .
```

### Port Already in Use

Kill process on port 8000:
```bash
lsof -ti:8000 | xargs kill -9
```

Or use a different port:
```bash
uvicorn app.main:app --port 8001
```

## Resources

- **API Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **Testing Guide**: See `API_TESTING.md`
- **Main README**: See `README.md`

## Support

For issues or questions:
1. Check the API docs at `/docs`
2. Review `API_TESTING.md` for examples
3. Check logs for error details
4. Verify `.env` configuration

---

**Zypheron API** - AI-powered vulnerability scanning backend
