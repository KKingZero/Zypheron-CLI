# Zypheron v0.2.0-beta: Backend API & Freemium Infrastructure

This release introduces the **zypheron-api** backend service, implementing Phase 2 of the production freemium model. This is a major step toward the full Zypheron platform with licensing, AI proxy, and token tracking capabilities.

## What's New

### Backend API (`zypheron-api/`)

A complete FastAPI backend service ready for production deployment:

#### Authentication & Authorization
- **Email/Password authentication** with bcrypt password hashing
- **GitHub OAuth** integration (placeholder ready for credentials)
- **JWT tokens** with configurable expiry (default: no expiry until logout)
- **Session management** with secure logout

#### Device Management
- **UUID-based device registration** for license enforcement
- **Tier-based device limits**:
  - Free: 1 device
  - Starter: 2 devices
  - Pro: 3 devices
  - Enterprise: 500 devices

#### License System
- **License validation API** for CLI integration
- **Feature gating** by subscription tier
- **Stripe integration** placeholders for payment processing
- **Tier features endpoint** for dynamic feature checks

#### AI Proxy Service
- **Unified API** for 4 AI providers:
  - OpenAI (GPT-4, GPT-3.5)
  - Anthropic (Claude 3.5)
  - Grok (xAI)
  - DeepSeek
- **Load balancer** with round-robin key selection
- **Automatic failover** on rate limits or errors
- **Health tracking** with circuit breaker pattern
- **BYOK support** for free tier users
- **Streaming responses** via Server-Sent Events

#### Token Tracking
- **Accurate token counting** using tiktoken
- **Usage tracking** by provider and billing period
- **Quota enforcement** middleware with upgrade prompts
- **Redis caching** (optional, with in-memory fallback)
- **Cache strategy**: SHA-256 hash of prompts for exact matches

### Database
- **SQLite** for development (zero-config)
- **Supabase/PostgreSQL** ready for production
- **Async SQLAlchemy 2.0** with full type hints

## API Endpoints

| Route | Description |
|-------|-------------|
| `POST /auth/register` | Register new user |
| `POST /auth/login` | Login with email/password |
| `GET /auth/me` | Get current user |
| `POST /devices/register` | Register device |
| `GET /license/validate` | Validate license |
| `GET /license/features` | Get tier features |
| `GET /tokens/usage` | Get token usage |
| `GET /tokens/quota` | Get quota info |
| `POST /ai/chat` | Unified AI chat endpoint |
| `GET /ai/providers` | List available providers |
| `WS /ws/scans/{user_id}` | Real-time scan updates |

## Quick Start

```bash
cd zypheron-api
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
# Edit .env with your JWT_SECRET_KEY
uvicorn app.main:app --reload
# Visit http://localhost:8000/docs
```

## Configuration

Key environment variables:
- `JWT_SECRET_KEY` - Secret for JWT signing (required)
- `DATABASE_TYPE` - `sqlite` or `postgresql`
- `SUPABASE_URL` / `SUPABASE_KEY` - For production database
- `OPENAI_API_KEYS` - JSON array of API keys for load balancing
- `ANTHROPIC_API_KEYS` - Claude API keys
- `REDIS_URL` - Optional Redis for caching

## Pricing Tiers

| Tier | Monthly | Tokens | Devices | Key Features |
|------|---------|--------|---------|--------------|
| **Free** | $0 | BYOK only | 1 | Recon, scanning, basic reports |
| **Starter** | $20 | 1M | 2 | + Cloud AI + Exploitation |
| **Pro** | $40 | 3M | 3 | + Higher token allocation |
| **Enterprise** | $500/device | 15M/5 users | 500 | + Local exploits + Teams + Compliance |

## What's Next (Phase 3-7)

- [ ] Go CLI licensing module integration
- [ ] Feature gate middleware in CLI
- [ ] Stripe webhook handling
- [ ] TUI dashboard with Bubbletea
- [ ] OSCP benchmark testing
- [ ] Production deployment to Railway

## Breaking Changes

None - this is a new addition to the codebase.

## Files Added

```
zypheron-api/
├── app/
│   ├── core/           # Config, database, security
│   ├── models/         # User, Device, License, TokenUsage, Session
│   ├── schemas/        # Pydantic validation schemas
│   ├── routers/        # auth, devices, license, tokens, ai_proxy
│   ├── services/       # token_tracking, cache, load_balancer
│   │   └── ai_providers/  # OpenAI, Anthropic, Grok, DeepSeek clients
│   ├── middleware/     # Token quota enforcement
│   └── main.py         # FastAPI app + WebSocket
├── pyproject.toml      # Dependencies
├── .env.example        # Configuration template
└── run.sh              # Development server script
```

## Contributors

- Zypheron Development Team
- Claude Opus 4.5 (AI pair programming)

---

**Full Changelog**: https://github.com/KKingZero/Cobra-AI/compare/809f3d4...3d917fc
