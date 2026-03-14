# Zypheron Backend, Enterprise & Electron Integration Plan

> **Phase 2 Implementation**
> **Stack**: Python + FastAPI | Railway/Render | SQLite shared auth
> **Status**: Planning

---

## Executive Summary

This document covers the remaining implementation phases:
- **Phase 1**: Backend API Server (FastAPI)
- **Phase 5**: Enterprise Features (Teams, Compliance, Audit)
- **Phase 6**: Electron Desktop Integration

Based on your requirements:
- Backend: **Python + FastAPI**
- Hosting: **Railway/Render**
- Auth sharing: **Local SQLite database**
- Team roles: **Owner/Admin/Member**
- AI Proxy: **Simple passthrough + Load balancing**
- Offline: **Default 30 days**, configurable (24h, 7d, 30d, 90d, never)

---

## Phase 0: Supabase Cloud Database Setup

### Step 1: Create Supabase Project

1. Go to [supabase.com](https://supabase.com) and sign up/login
2. Click **"New Project"**
3. Configure:
   - **Name**: `zypheron-production`
   - **Database Password**: Generate a strong password (save this!)
   - **Region**: Choose closest to your users
4. Wait for project to provision (~2 minutes)

### Step 2: Get Your API Keys

From your Supabase dashboard → **Settings** → **API**:

```bash
# Save these - you'll need them for the backend
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIs...   # Public key (for client)
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIs... # Secret key (for backend)
```

### Step 3: Run Database Schema

Go to **SQL Editor** in Supabase dashboard and run this schema:

```sql
-- ============================================================
-- ZYPHERON DATABASE SCHEMA
-- Run this in Supabase SQL Editor
-- ============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- PROFILES TABLE (extends Supabase auth.users)
-- ============================================================
CREATE TABLE public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    display_name TEXT,

    -- Stripe integration
    stripe_customer_id TEXT UNIQUE,

    -- Subscription info
    tier TEXT DEFAULT 'free' CHECK (tier IN ('free', 'starter', 'pro', 'enterprise')),

    -- Token tracking
    tokens_used BIGINT DEFAULT 0,
    tokens_remaining BIGINT DEFAULT 0,
    tokens_limit BIGINT DEFAULT 0,
    tokens_reset_date TIMESTAMP WITH TIME ZONE,

    -- Team membership (for enterprise)
    team_id UUID,
    team_role TEXT CHECK (team_role IN ('owner', 'admin', 'member')),

    -- Settings
    offline_days INT DEFAULT 30,
    default_ai_provider TEXT DEFAULT 'claude',

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================
-- SUBSCRIPTIONS TABLE
-- ============================================================
CREATE TABLE public.subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,

    -- Stripe data
    stripe_subscription_id TEXT UNIQUE NOT NULL,
    stripe_price_id TEXT NOT NULL,
    stripe_product_id TEXT,

    -- Status
    status TEXT NOT NULL CHECK (status IN (
        'active', 'past_due', 'canceled', 'incomplete',
        'incomplete_expired', 'trialing', 'unpaid', 'paused'
    )),

    -- Billing period
    current_period_start TIMESTAMP WITH TIME ZONE,
    current_period_end TIMESTAMP WITH TIME ZONE,
    cancel_at_period_end BOOLEAN DEFAULT FALSE,
    canceled_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================
-- TEAMS TABLE (Enterprise)
-- ============================================================
CREATE TABLE public.teams (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    owner_id UUID NOT NULL REFERENCES public.profiles(id),

    -- Billing
    stripe_subscription_id TEXT,
    seats_purchased INT DEFAULT 1,

    -- Token pool for team
    tokens_pool BIGINT DEFAULT 0,

    -- Settings
    offline_days_policy INT DEFAULT 30,
    require_sso BOOLEAN DEFAULT FALSE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add foreign key for team membership
ALTER TABLE public.profiles
ADD CONSTRAINT fk_team
FOREIGN KEY (team_id) REFERENCES public.teams(id) ON DELETE SET NULL;

-- ============================================================
-- TEAM INVITATIONS TABLE
-- ============================================================
CREATE TABLE public.team_invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID NOT NULL REFERENCES public.teams(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT DEFAULT 'member' CHECK (role IN ('admin', 'member')),
    invited_by UUID NOT NULL REFERENCES public.profiles(id),
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    accepted_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(team_id, email)
);

-- ============================================================
-- DEVICES TABLE
-- ============================================================
CREATE TABLE public.devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    device_name TEXT,
    platform TEXT,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(user_id, device_id)
);

-- ============================================================
-- USAGE LOGS TABLE
-- ============================================================
CREATE TABLE public.usage_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    team_id UUID REFERENCES public.teams(id) ON DELETE SET NULL,

    -- Usage details
    action TEXT NOT NULL,
    tokens_used INT DEFAULT 0,
    ai_provider TEXT,
    feature TEXT,

    -- Request metadata
    request_id TEXT,
    model TEXT,
    prompt_tokens INT,
    completion_tokens INT,

    -- Additional data
    metadata JSONB DEFAULT '{}',

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================
-- AUDIT LOGS TABLE (Enterprise)
-- ============================================================
CREATE TABLE public.audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID NOT NULL REFERENCES public.teams(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.profiles(id),

    -- Action details
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,

    -- Context
    details JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    device_id UUID REFERENCES public.devices(id),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================
-- API KEYS TABLE (BYOK - Bring Your Own Key)
-- ============================================================
CREATE TABLE public.user_api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,

    -- Encrypted key (encrypt with user-specific key or use Supabase Vault)
    encrypted_key TEXT NOT NULL,
    key_hint TEXT, -- Last 4 characters for display

    -- Metadata
    is_valid BOOLEAN DEFAULT TRUE,
    last_used TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(user_id, provider)
);

-- ============================================================
-- DEVICE AUTH CODES TABLE (for CLI login flow)
-- ============================================================
CREATE TABLE public.device_auth_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code TEXT UNIQUE NOT NULL,
    user_id UUID REFERENCES public.profiles(id),
    device_id TEXT NOT NULL,

    -- Status
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'authorized', 'expired', 'used')),

    -- Timestamps
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    authorized_at TIMESTAMP WITH TIME ZONE,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================
CREATE INDEX idx_profiles_stripe_customer ON public.profiles(stripe_customer_id);
CREATE INDEX idx_profiles_team ON public.profiles(team_id);
CREATE INDEX idx_profiles_tier ON public.profiles(tier);

CREATE INDEX idx_subscriptions_user ON public.subscriptions(user_id);
CREATE INDEX idx_subscriptions_stripe ON public.subscriptions(stripe_subscription_id);
CREATE INDEX idx_subscriptions_status ON public.subscriptions(status);

CREATE INDEX idx_teams_owner ON public.teams(owner_id);

CREATE INDEX idx_devices_user ON public.devices(user_id);
CREATE INDEX idx_devices_last_seen ON public.devices(last_seen);

CREATE INDEX idx_usage_logs_user ON public.usage_logs(user_id);
CREATE INDEX idx_usage_logs_team ON public.usage_logs(team_id);
CREATE INDEX idx_usage_logs_date ON public.usage_logs(created_at);
CREATE INDEX idx_usage_logs_action ON public.usage_logs(action);

CREATE INDEX idx_audit_logs_team ON public.audit_logs(team_id);
CREATE INDEX idx_audit_logs_user ON public.audit_logs(user_id);
CREATE INDEX idx_audit_logs_date ON public.audit_logs(created_at);
CREATE INDEX idx_audit_logs_action ON public.audit_logs(action);

CREATE INDEX idx_device_auth_codes_code ON public.device_auth_codes(code);
CREATE INDEX idx_device_auth_codes_status ON public.device_auth_codes(status);

-- ============================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================

-- Enable RLS on all tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.usage_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_auth_codes ENABLE ROW LEVEL SECURITY;

-- Profiles: Users can read/update their own profile
CREATE POLICY "Users can view own profile" ON public.profiles
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can update own profile" ON public.profiles
    FOR UPDATE USING (auth.uid() = id);

-- Subscriptions: Users can view their own subscriptions
CREATE POLICY "Users can view own subscriptions" ON public.subscriptions
    FOR SELECT USING (auth.uid() = user_id);

-- Teams: Team members can view their team
CREATE POLICY "Team members can view team" ON public.teams
    FOR SELECT USING (
        id IN (SELECT team_id FROM public.profiles WHERE id = auth.uid())
        OR owner_id = auth.uid()
    );

-- Team owners/admins can update team
CREATE POLICY "Team admins can update team" ON public.teams
    FOR UPDATE USING (
        owner_id = auth.uid()
        OR id IN (
            SELECT team_id FROM public.profiles
            WHERE id = auth.uid() AND team_role IN ('owner', 'admin')
        )
    );

-- Devices: Users can manage their own devices
CREATE POLICY "Users can manage own devices" ON public.devices
    FOR ALL USING (auth.uid() = user_id);

-- Usage logs: Users can view their own usage
CREATE POLICY "Users can view own usage" ON public.usage_logs
    FOR SELECT USING (auth.uid() = user_id);

-- Audit logs: Team admins/owners can view
CREATE POLICY "Team admins can view audit logs" ON public.audit_logs
    FOR SELECT USING (
        team_id IN (
            SELECT team_id FROM public.profiles
            WHERE id = auth.uid() AND team_role IN ('owner', 'admin')
        )
    );

-- API Keys: Users can manage their own keys
CREATE POLICY "Users can manage own API keys" ON public.user_api_keys
    FOR ALL USING (auth.uid() = user_id);

-- ============================================================
-- FUNCTIONS & TRIGGERS
-- ============================================================

-- Auto-create profile on user signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.profiles (id, email)
    VALUES (NEW.id, NEW.email);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Update updated_at timestamp
CREATE OR REPLACE FUNCTION public.update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_profiles_updated_at
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

CREATE TRIGGER update_subscriptions_updated_at
    BEFORE UPDATE ON public.subscriptions
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

CREATE TRIGGER update_teams_updated_at
    BEFORE UPDATE ON public.teams
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- Reset tokens on subscription renewal
CREATE OR REPLACE FUNCTION public.reset_user_tokens(p_user_id UUID, p_tier TEXT)
RETURNS VOID AS $$
DECLARE
    v_token_limit BIGINT;
BEGIN
    -- Set token limit based on tier
    v_token_limit := CASE p_tier
        WHEN 'starter' THEN 1000000
        WHEN 'pro' THEN 3000000
        WHEN 'enterprise' THEN 15000000
        ELSE 0
    END;

    UPDATE public.profiles
    SET
        tokens_remaining = v_token_limit,
        tokens_used = 0,
        tokens_limit = v_token_limit,
        tokens_reset_date = NOW() + INTERVAL '1 month'
    WHERE id = p_user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Deduct tokens function (called by backend)
CREATE OR REPLACE FUNCTION public.deduct_tokens(p_user_id UUID, p_tokens INT)
RETURNS BIGINT AS $$
DECLARE
    v_remaining BIGINT;
BEGIN
    UPDATE public.profiles
    SET
        tokens_remaining = tokens_remaining - p_tokens,
        tokens_used = tokens_used + p_tokens
    WHERE id = p_user_id
    RETURNING tokens_remaining INTO v_remaining;

    RETURN v_remaining;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================
-- INITIAL DATA (Optional - run after schema)
-- ============================================================

-- You can add test data here if needed
-- INSERT INTO ...
```

### Step 4: Configure Authentication

In Supabase dashboard → **Authentication** → **Providers**:

1. **Email** (enabled by default)
   - Enable "Confirm email" for production
   - Customize email templates

2. **OAuth Providers** (optional but recommended):
   - **GitHub**: Add Client ID and Secret
   - **Google**: Add Client ID and Secret

3. **URL Configuration** (Authentication → URL Configuration):
   ```
   Site URL: https://zypheron.io
   Redirect URLs:
     - https://zypheron.io/auth/callback
     - http://localhost:3000/auth/callback (for development)
   ```

### Step 5: Set Up Stripe

1. **Create Stripe Account** at [stripe.com](https://stripe.com)

2. **Create Products** in Stripe Dashboard → Products:

   | Product | Price | Price ID |
   |---------|-------|----------|
   | Zypheron Starter | $20/month | `price_starter_xxx` |
   | Zypheron Pro | $40/month | `price_pro_xxx` |
   | Zypheron Enterprise | $80/month per seat | `price_enterprise_xxx` |

3. **Get API Keys** from Developers → API Keys:
   ```bash
   STRIPE_SECRET_KEY=sk_live_xxx  # or sk_test_xxx for testing
   STRIPE_PUBLISHABLE_KEY=pk_live_xxx
   ```

4. **Set Up Webhook** in Developers → Webhooks:
   - Endpoint URL: `https://api.zypheron.io/api/billing/webhook`
   - Events to listen:
     - `customer.subscription.created`
     - `customer.subscription.updated`
     - `customer.subscription.deleted`
     - `invoice.paid`
     - `invoice.payment_failed`
   - Save the webhook signing secret: `STRIPE_WEBHOOK_SECRET=whsec_xxx`

### Step 6: Environment Variables

Create `.env` file for your backend:

```bash
# Application
APP_NAME=Zypheron API
DEBUG=false
SECRET_KEY=your-256-bit-secret-key-here  # Generate: openssl rand -hex 32

# Supabase
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIs...
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIs...

# Stripe
STRIPE_SECRET_KEY=sk_live_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx
STRIPE_PRICE_STARTER=price_xxx
STRIPE_PRICE_PRO=price_xxx
STRIPE_PRICE_ENTERPRISE=price_xxx

# AI Providers (for proxy - your master keys)
ANTHROPIC_API_KEY=sk-ant-xxx
OPENAI_API_KEY=sk-xxx
GEMINI_API_KEY=xxx

# Frontend URL (for redirects)
FRONTEND_URL=https://zypheron.io

# Rate Limits (requests per minute)
RATE_LIMIT_FREE=10
RATE_LIMIT_STARTER=60
RATE_LIMIT_PRO=120
RATE_LIMIT_ENTERPRISE=300
```

### Database Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                     SUPABASE (Cloud - PostgreSQL)                    │
│                     Source of Truth for All Data                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │   profiles   │  │subscriptions │  │    teams     │              │
│  │──────────────│  │──────────────│  │──────────────│              │
│  │ id (auth.uid)│  │ user_id      │  │ id           │              │
│  │ email        │  │ stripe_id    │  │ owner_id     │              │
│  │ tier         │  │ status       │  │ seats        │              │
│  │ tokens_*     │  │ period_end   │  │ tokens_pool  │              │
│  │ team_id ─────┼──┼──────────────┼──► │              │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│         │                                    │                       │
│         │         ┌──────────────┐          │                       │
│         │         │   devices    │          │                       │
│         └────────►│──────────────│          │                       │
│                   │ user_id      │          │                       │
│                   │ device_id    │          │                       │
│                   │ last_seen    │          │                       │
│                   └──────────────┘          │                       │
│                                             │                       │
│  ┌──────────────┐  ┌──────────────┐        │                       │
│  │  usage_logs  │  │  audit_logs  │◄───────┘                       │
│  │──────────────│  │──────────────│  (Enterprise only)             │
│  │ user_id      │  │ team_id      │                                │
│  │ tokens_used  │  │ user_id      │                                │
│  │ ai_provider  │  │ action       │                                │
│  │ timestamp    │  │ details      │                                │
│  └──────────────┘  └──────────────┘                                │
│                                                                      │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   │ API Calls (FastAPI backend)
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     LOCAL SQLITE (User's Machine)                    │
│                     Cache for Offline Operation                      │
├─────────────────────────────────────────────────────────────────────┤
│  ~/.zypheron/zypheron.db                                            │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │ auth_session │  │license_cache │  │ token_usage  │              │
│  │──────────────│  │──────────────│  │──────────────│              │
│  │ access_token │  │ license_json │  │ action       │              │
│  │ refresh_token│  │ cached_at    │  │ tokens       │              │
│  │ user_id      │  │              │  │ synced=0/1   │              │
│  │ email        │  │              │  │              │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│                                                                      │
│  Syncs with Supabase:                                               │
│  • On login (download license)                                      │
│  • On token usage (upload usage, update balance)                    │
│  • Periodically (refresh license cache)                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Backend API Server

### Technology Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                     Backend Architecture                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  FastAPI Application                      │   │
│  │                                                           │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │   │
│  │  │   Routes    │  │  Services   │  │ Middleware  │      │   │
│  │  │  - /auth    │  │  - Stripe   │  │  - Auth     │      │   │
│  │  │  - /license │  │  - Supabase │  │  - RateLimit│      │   │
│  │  │  - /usage   │  │  - AI Proxy │  │  - CORS     │      │   │
│  │  │  - /teams   │  │  - Teams    │  │  - Logging  │      │   │
│  │  │  - /ai      │  │  - Audit    │  │             │      │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘      │   │
│  │                                                           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│              ┌───────────────┼───────────────┐                  │
│              │               │               │                  │
│              ▼               ▼               ▼                  │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│  │   Supabase    │  │    Stripe     │  │  AI Providers │       │
│  │   Database    │  │   Payments    │  │    Proxy      │       │
│  └───────────────┘  └───────────────┘  └───────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
api-server/
├── app/
│   ├── __init__.py
│   ├── main.py                    # FastAPI app entry point
│   ├── config.py                  # Configuration settings
│   │
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── auth.py                # Authentication endpoints
│   │   ├── license.py             # License validation
│   │   ├── usage.py               # Token usage tracking
│   │   ├── teams.py               # Enterprise team management
│   │   ├── billing.py             # Stripe webhooks
│   │   └── ai_proxy.py            # AI provider proxy
│   │
│   ├── services/
│   │   ├── __init__.py
│   │   ├── stripe_service.py      # Stripe integration
│   │   ├── supabase_service.py    # Database operations
│   │   ├── ai_proxy_service.py    # AI provider routing
│   │   ├── team_service.py        # Team management
│   │   └── audit_service.py       # Audit logging
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py                # User models
│   │   ├── license.py             # License models
│   │   ├── team.py                # Team models
│   │   └── usage.py               # Usage models
│   │
│   ├── middleware/
│   │   ├── __init__.py
│   │   ├── auth.py                # JWT authentication
│   │   ├── rate_limit.py          # Rate limiting
│   │   └── logging.py             # Request logging
│   │
│   └── utils/
│       ├── __init__.py
│       ├── jwt.py                 # JWT utilities
│       └── validators.py          # Input validation
│
├── tests/
│   ├── __init__.py
│   ├── test_auth.py
│   ├── test_license.py
│   └── test_teams.py
│
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── railway.toml                   # Railway deployment config
└── render.yaml                    # Render deployment config
```

### Core Implementation

#### 1. Main Application (app/main.py)

```python
"""
Zypheron API Server

FastAPI backend for license management, billing, and AI proxy.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from app.config import settings
from app.routers import auth, license, usage, teams, billing, ai_proxy
from app.middleware.rate_limit import RateLimitMiddleware
from app.services.supabase_service import init_supabase


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management."""
    # Startup
    logger.info("Starting Zypheron API Server...")
    await init_supabase()
    yield
    # Shutdown
    logger.info("Shutting down Zypheron API Server...")


app = FastAPI(
    title="Zypheron API",
    description="Backend API for Zypheron CLI licensing and AI services",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting
app.add_middleware(RateLimitMiddleware)

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(license.router, prefix="/api/license", tags=["License"])
app.include_router(usage.router, prefix="/api/usage", tags=["Usage"])
app.include_router(teams.router, prefix="/api/teams", tags=["Teams"])
app.include_router(billing.router, prefix="/api/billing", tags=["Billing"])
app.include_router(ai_proxy.router, prefix="/api/ai", tags=["AI Proxy"])


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "1.0.0"}
```

#### 2. Configuration (app/config.py)

```python
"""Application configuration."""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings from environment variables."""

    # Application
    APP_NAME: str = "Zypheron API"
    DEBUG: bool = False
    SECRET_KEY: str

    # Supabase
    SUPABASE_URL: str
    SUPABASE_KEY: str
    SUPABASE_SERVICE_KEY: str  # For admin operations

    # Stripe
    STRIPE_SECRET_KEY: str
    STRIPE_WEBHOOK_SECRET: str
    STRIPE_PRICE_STARTER: str
    STRIPE_PRICE_PRO: str
    STRIPE_PRICE_ENTERPRISE: str

    # AI Providers (for proxy)
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    GEMINI_API_KEY: str = ""

    # Rate Limits
    RATE_LIMIT_FREE: int = 10       # requests per minute
    RATE_LIMIT_STARTER: int = 60
    RATE_LIMIT_PRO: int = 120
    RATE_LIMIT_ENTERPRISE: int = 300

    # Token Limits
    TOKENS_STARTER: int = 1_000_000
    TOKENS_PRO: int = 3_000_000
    TOKENS_ENTERPRISE: int = 15_000_000

    # Offline License Duration Options (days)
    OFFLINE_OPTIONS: list = [1, 7, 30, 90, -1]  # -1 = never expire
    OFFLINE_DEFAULT: int = 30

    # CORS
    ALLOWED_ORIGINS: list = [
        "http://localhost:3000",
        "https://zypheron.io",
        "https://app.zypheron.io"
    ]

    class Config:
        env_file = ".env"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
```

#### 3. Authentication Router (app/routers/auth.py)

```python
"""Authentication endpoints."""

from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, EmailStr
import jwt

from app.config import settings
from app.services.supabase_service import supabase
from app.utils.jwt import create_access_token, create_refresh_token, verify_token


router = APIRouter()


class LoginRequest(BaseModel):
    email: EmailStr
    password: Optional[str] = None
    magic_link_token: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict


class DeviceLoginRequest(BaseModel):
    device_code: str


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """
    Authenticate user and return tokens.

    Supports password and magic link authentication.
    """
    if request.magic_link_token:
        # Verify magic link token
        user = await verify_magic_link(request.magic_link_token)
    elif request.password:
        # Password authentication via Supabase
        response = supabase.auth.sign_in_with_password({
            "email": request.email,
            "password": request.password
        })
        user = response.user
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either password or magic_link_token required"
        )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    # Get user profile with subscription info
    profile = await get_user_profile(user.id)

    # Create tokens
    access_token = create_access_token(user.id, profile)
    refresh_token = create_refresh_token(user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=3600,
        user={
            "id": user.id,
            "email": user.email,
            "tier": profile.get("tier", "free"),
            "tokens_remaining": profile.get("tokens_remaining", 0)
        }
    )


@router.post("/device-login")
async def device_login(request: DeviceLoginRequest):
    """
    CLI device authentication flow.

    Called after user completes browser auth to link CLI.
    """
    # Verify device code and get pending auth
    pending = await get_pending_device_auth(request.device_code)
    if not pending:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device code not found or expired"
        )

    user_id = pending["user_id"]
    profile = await get_user_profile(user_id)

    access_token = create_access_token(user_id, profile)
    refresh_token = create_refresh_token(user_id)

    # Mark device code as used
    await mark_device_code_used(request.device_code)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=3600,
        user=profile
    )


@router.post("/refresh")
async def refresh_tokens(refresh_token: str):
    """Refresh access token."""
    payload = verify_token(refresh_token, token_type="refresh")
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    user_id = payload["sub"]
    profile = await get_user_profile(user_id)

    new_access_token = create_access_token(user_id, profile)

    return {
        "access_token": new_access_token,
        "token_type": "bearer",
        "expires_in": 3600
    }


@router.post("/logout")
async def logout(request: Request):
    """Logout and invalidate tokens."""
    # Add token to blacklist (implement token blacklist in Redis/DB)
    return {"message": "Logged out successfully"}


@router.post("/magic-link")
async def send_magic_link(email: EmailStr):
    """Send magic link to email."""
    # Generate magic link token
    token = create_magic_link_token(email)

    # Send email (implement email service)
    await send_magic_link_email(email, token)

    return {"message": "Magic link sent to email"}


# Helper functions (implement these)
async def verify_magic_link(token: str):
    """Verify magic link token and return user."""
    pass


async def get_user_profile(user_id: str) -> dict:
    """Get user profile with subscription info."""
    response = supabase.table("profiles").select("*").eq("id", user_id).single().execute()
    return response.data


async def get_pending_device_auth(device_code: str) -> dict:
    """Get pending device authentication."""
    pass


async def mark_device_code_used(device_code: str):
    """Mark device code as used."""
    pass


def create_magic_link_token(email: str) -> str:
    """Create magic link token."""
    pass


async def send_magic_link_email(email: str, token: str):
    """Send magic link email."""
    pass
```

#### 4. License Router (app/routers/license.py)

```python
"""License validation and management."""

from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import jwt

from app.config import settings
from app.middleware.auth import get_current_user
from app.services.supabase_service import supabase


router = APIRouter()


class LicenseResponse(BaseModel):
    user_id: str
    email: str
    tier: str
    features: List[str]
    tokens_remaining: int
    tokens_used: int
    tokens_limit: int
    reset_date: Optional[str]
    expires_at: str
    issued_at: str
    device_id: Optional[str]
    team_id: Optional[str]
    team_role: Optional[str]
    offline_days: int


class LicenseTokenResponse(BaseModel):
    license_token: str
    expires_at: str


# Feature definitions per tier
TIER_FEATURES = {
    "free": [],
    "starter": ["cloud_ai", "autopent", "exploitation", "post_exploitation"],
    "pro": ["cloud_ai", "autopent", "exploitation", "post_exploitation"],
    "enterprise": [
        "cloud_ai", "autopent", "exploitation", "post_exploitation",
        "teams", "compliance", "audit_logs", "api_access", "sso"
    ]
}

TIER_TOKENS = {
    "free": 0,
    "starter": 1_000_000,
    "pro": 3_000_000,
    "enterprise": 15_000_000
}


@router.get("", response_model=LicenseResponse)
async def get_license(user: dict = Depends(get_current_user)):
    """Get current license information."""
    user_id = user["id"]

    # Get profile with subscription
    profile = supabase.table("profiles").select("*").eq("id", user_id).single().execute()
    profile_data = profile.data

    # Get subscription details
    subscription = supabase.table("subscriptions").select("*").eq("user_id", user_id).single().execute()
    sub_data = subscription.data if subscription.data else {}

    tier = profile_data.get("tier", "free")
    offline_days = profile_data.get("offline_days", settings.OFFLINE_DEFAULT)

    # Calculate reset date (next billing date)
    reset_date = None
    if sub_data.get("current_period_end"):
        reset_date = sub_data["current_period_end"]

    return LicenseResponse(
        user_id=user_id,
        email=user["email"],
        tier=tier,
        features=TIER_FEATURES.get(tier, []),
        tokens_remaining=profile_data.get("tokens_remaining", 0),
        tokens_used=profile_data.get("tokens_used", 0),
        tokens_limit=TIER_TOKENS.get(tier, 0),
        reset_date=reset_date,
        expires_at=(datetime.utcnow() + timedelta(days=offline_days)).isoformat(),
        issued_at=datetime.utcnow().isoformat(),
        device_id=user.get("device_id"),
        team_id=profile_data.get("team_id"),
        team_role=profile_data.get("team_role"),
        offline_days=offline_days
    )


@router.post("/refresh", response_model=LicenseTokenResponse)
async def refresh_license(
    device_id: str,
    user: dict = Depends(get_current_user)
):
    """
    Refresh license and return signed JWT for offline use.

    The license token is cached locally by CLI/Electron for offline validation.
    """
    user_id = user["id"]

    # Get current license
    license_info = await get_license(user)

    # Create signed license token (JWT)
    license_token = jwt.encode(
        {
            "sub": user_id,
            "email": license_info.email,
            "tier": license_info.tier,
            "features": license_info.features,
            "tokens_remaining": license_info.tokens_remaining,
            "tokens_limit": license_info.tokens_limit,
            "reset_date": license_info.reset_date,
            "device_id": device_id,
            "team_id": license_info.team_id,
            "team_role": license_info.team_role,
            "offline_days": license_info.offline_days,
            "iat": datetime.utcnow().timestamp(),
            "exp": (datetime.utcnow() + timedelta(days=license_info.offline_days)).timestamp()
        },
        settings.SECRET_KEY,
        algorithm="HS256"
    )

    # Register device
    await register_device(user_id, device_id)

    return LicenseTokenResponse(
        license_token=license_token,
        expires_at=license_info.expires_at
    )


@router.put("/offline-duration")
async def update_offline_duration(
    days: int,
    user: dict = Depends(get_current_user)
):
    """
    Update offline license duration (Enterprise only).

    Options: 1 (24h), 7, 30, 90, -1 (never)
    """
    # Check enterprise tier
    profile = supabase.table("profiles").select("tier").eq("id", user["id"]).single().execute()
    if profile.data.get("tier") != "enterprise":
        raise HTTPException(
            status_code=403,
            detail="Offline duration configuration requires Enterprise plan"
        )

    if days not in settings.OFFLINE_OPTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid duration. Options: {settings.OFFLINE_OPTIONS}"
        )

    supabase.table("profiles").update({"offline_days": days}).eq("id", user["id"]).execute()

    return {"message": f"Offline duration updated to {days} days"}


async def register_device(user_id: str, device_id: str):
    """Register a device for the user."""
    supabase.table("devices").upsert({
        "user_id": user_id,
        "device_id": device_id,
        "last_seen": datetime.utcnow().isoformat()
    }).execute()
```

#### 5. AI Proxy Router (app/routers/ai_proxy.py)

```python
"""
AI Provider Proxy

Routes AI requests through Zypheron servers with:
- Unified token counting
- Load balancing across API keys
- User doesn't need their own keys
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import httpx
from loguru import logger

from app.config import settings
from app.middleware.auth import get_current_user
from app.services.ai_proxy_service import AIProxyService


router = APIRouter()
ai_proxy = AIProxyService()


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    provider: str = "claude"
    model: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 4096
    stream: bool = False


class ChatResponse(BaseModel):
    content: str
    provider: str
    model: str
    usage: Dict[str, int]
    tokens_remaining: int


@router.post("/chat", response_model=ChatResponse)
async def proxy_chat(
    request: ChatRequest,
    user: dict = Depends(get_current_user)
):
    """
    Proxy chat request to AI provider.

    - Validates license for cloud AI
    - Checks token balance
    - Routes to provider
    - Tracks usage
    """
    user_id = user["id"]
    tier = user.get("tier", "free")

    # Check cloud AI access
    if tier == "free":
        raise HTTPException(
            status_code=403,
            detail="Cloud AI requires a paid subscription. Use Ollama locally or upgrade."
        )

    # Get user's token balance
    tokens_remaining = user.get("tokens_remaining", 0)

    # Estimate tokens needed
    estimated_tokens = ai_proxy.estimate_tokens(request.messages, request.max_tokens)

    if tokens_remaining < estimated_tokens:
        raise HTTPException(
            status_code=402,
            detail=f"Insufficient tokens. Need ~{estimated_tokens}, have {tokens_remaining}"
        )

    # Make request to AI provider
    try:
        response = await ai_proxy.chat(
            provider=request.provider,
            messages=[m.dict() for m in request.messages],
            model=request.model,
            temperature=request.temperature,
            max_tokens=request.max_tokens
        )
    except Exception as e:
        logger.error(f"AI proxy error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    # Deduct tokens
    actual_tokens = response.get("usage", {}).get("total_tokens", estimated_tokens)
    new_balance = await ai_proxy.deduct_tokens(user_id, actual_tokens)

    return ChatResponse(
        content=response["content"],
        provider=request.provider,
        model=response.get("model", request.model or "default"),
        usage=response.get("usage", {"total_tokens": actual_tokens}),
        tokens_remaining=new_balance
    )


@router.get("/providers")
async def list_providers(user: dict = Depends(get_current_user)):
    """List available AI providers for user's tier."""
    tier = user.get("tier", "free")

    if tier == "free":
        return {
            "available": ["ollama"],
            "locked": ["claude", "openai", "gemini", "deepseek", "grok", "kimi"],
            "message": "Cloud AI providers require a paid subscription"
        }

    return {
        "available": ["claude", "openai", "gemini", "deepseek", "grok", "kimi", "ollama"],
        "locked": [],
        "default": "claude"
    }
```

#### 6. Stripe Billing Router (app/routers/billing.py)

```python
"""Stripe billing webhooks and portal."""

from fastapi import APIRouter, Request, HTTPException, Depends
import stripe
from loguru import logger

from app.config import settings
from app.middleware.auth import get_current_user
from app.services.stripe_service import StripeService


router = APIRouter()
stripe.api_key = settings.STRIPE_SECRET_KEY
stripe_service = StripeService()


@router.post("/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events."""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Handle events
    event_type = event["type"]
    data = event["data"]["object"]

    logger.info(f"Stripe webhook: {event_type}")

    if event_type == "customer.subscription.created":
        await stripe_service.handle_subscription_created(data)

    elif event_type == "customer.subscription.updated":
        await stripe_service.handle_subscription_updated(data)

    elif event_type == "customer.subscription.deleted":
        await stripe_service.handle_subscription_cancelled(data)

    elif event_type == "invoice.paid":
        await stripe_service.handle_invoice_paid(data)

    elif event_type == "invoice.payment_failed":
        await stripe_service.handle_payment_failed(data)

    return {"received": True}


@router.post("/create-checkout-session")
async def create_checkout_session(
    price_id: str,
    user: dict = Depends(get_current_user)
):
    """Create Stripe checkout session for subscription."""
    user_id = user["id"]
    email = user["email"]

    # Get or create Stripe customer
    customer_id = await stripe_service.get_or_create_customer(user_id, email)

    # Create checkout session
    session = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription",
        success_url=f"{settings.FRONTEND_URL}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{settings.FRONTEND_URL}/billing/cancel",
        metadata={"user_id": user_id}
    )

    return {"checkout_url": session.url}


@router.post("/portal-session")
async def create_portal_session(user: dict = Depends(get_current_user)):
    """Create Stripe customer portal session."""
    customer_id = user.get("stripe_customer_id")

    if not customer_id:
        raise HTTPException(status_code=400, detail="No billing account found")

    session = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=f"{settings.FRONTEND_URL}/account"
    )

    return {"portal_url": session.url}
```

---

## Phase 5: Enterprise Features

### Team Management

#### Team Roles & Permissions

```python
# app/models/team.py

from enum import Enum


class TeamRole(str, Enum):
    OWNER = "owner"      # Full control, billing
    ADMIN = "admin"      # Manage members, view all
    MEMBER = "member"    # Use features, view own


ROLE_PERMISSIONS = {
    TeamRole.OWNER: [
        "manage_billing",
        "manage_team",
        "invite_members",
        "remove_members",
        "change_roles",
        "view_audit_logs",
        "manage_compliance",
        "allocate_tokens",
        "all_features"
    ],
    TeamRole.ADMIN: [
        "invite_members",
        "remove_members",
        "view_audit_logs",
        "manage_compliance",
        "allocate_tokens",
        "all_features"
    ],
    TeamRole.MEMBER: [
        "view_own_usage",
        "use_features"
    ]
}
```

#### Team Router (app/routers/teams.py)

```python
"""Enterprise team management."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime

from app.middleware.auth import get_current_user, require_enterprise
from app.services.team_service import TeamService
from app.services.audit_service import AuditService


router = APIRouter()
team_service = TeamService()
audit_service = AuditService()


class CreateTeamRequest(BaseModel):
    name: str


class InviteMemberRequest(BaseModel):
    email: EmailStr
    role: str = "member"


class TeamMemberResponse(BaseModel):
    user_id: str
    email: str
    role: str
    tokens_allocated: int
    joined_at: str


class TeamResponse(BaseModel):
    id: str
    name: str
    owner_id: str
    seats_purchased: int
    seats_used: int
    tokens_pool: int
    members: List[TeamMemberResponse]
    created_at: str


@router.post("", response_model=TeamResponse)
async def create_team(
    request: CreateTeamRequest,
    user: dict = Depends(require_enterprise)
):
    """Create a new team (Enterprise only)."""
    team = await team_service.create_team(
        name=request.name,
        owner_id=user["id"]
    )

    await audit_service.log(
        team_id=team["id"],
        user_id=user["id"],
        action="team_created",
        details={"name": request.name}
    )

    return team


@router.get("/{team_id}", response_model=TeamResponse)
async def get_team(
    team_id: str,
    user: dict = Depends(get_current_user)
):
    """Get team details."""
    # Verify membership
    if not await team_service.is_member(team_id, user["id"]):
        raise HTTPException(status_code=403, detail="Not a team member")

    return await team_service.get_team(team_id)


@router.post("/{team_id}/invite")
async def invite_member(
    team_id: str,
    request: InviteMemberRequest,
    user: dict = Depends(get_current_user)
):
    """Invite a member to the team."""
    # Check permission
    if not await team_service.can_invite(team_id, user["id"]):
        raise HTTPException(status_code=403, detail="No permission to invite")

    invitation = await team_service.invite_member(
        team_id=team_id,
        email=request.email,
        role=request.role,
        invited_by=user["id"]
    )

    await audit_service.log(
        team_id=team_id,
        user_id=user["id"],
        action="member_invited",
        details={"email": request.email, "role": request.role}
    )

    return invitation


@router.delete("/{team_id}/members/{member_id}")
async def remove_member(
    team_id: str,
    member_id: str,
    user: dict = Depends(get_current_user)
):
    """Remove a member from the team."""
    if not await team_service.can_remove(team_id, user["id"], member_id):
        raise HTTPException(status_code=403, detail="No permission to remove")

    await team_service.remove_member(team_id, member_id)

    await audit_service.log(
        team_id=team_id,
        user_id=user["id"],
        action="member_removed",
        details={"member_id": member_id}
    )

    return {"message": "Member removed"}


@router.put("/{team_id}/members/{member_id}/role")
async def change_member_role(
    team_id: str,
    member_id: str,
    role: str,
    user: dict = Depends(get_current_user)
):
    """Change a member's role."""
    if not await team_service.can_change_role(team_id, user["id"]):
        raise HTTPException(status_code=403, detail="No permission to change roles")

    await team_service.change_role(team_id, member_id, role)

    await audit_service.log(
        team_id=team_id,
        user_id=user["id"],
        action="role_changed",
        details={"member_id": member_id, "new_role": role}
    )

    return {"message": f"Role changed to {role}"}


@router.put("/{team_id}/members/{member_id}/tokens")
async def allocate_tokens(
    team_id: str,
    member_id: str,
    tokens: int,
    user: dict = Depends(get_current_user)
):
    """Allocate tokens to a team member."""
    if not await team_service.can_allocate_tokens(team_id, user["id"]):
        raise HTTPException(status_code=403, detail="No permission to allocate tokens")

    await team_service.allocate_tokens(team_id, member_id, tokens)

    await audit_service.log(
        team_id=team_id,
        user_id=user["id"],
        action="tokens_allocated",
        details={"member_id": member_id, "tokens": tokens}
    )

    return {"message": f"Allocated {tokens} tokens"}


@router.get("/{team_id}/audit-logs")
async def get_audit_logs(
    team_id: str,
    limit: int = 100,
    offset: int = 0,
    user: dict = Depends(get_current_user)
):
    """Get team audit logs (Admin/Owner only)."""
    if not await team_service.can_view_audit(team_id, user["id"]):
        raise HTTPException(status_code=403, detail="No permission to view audit logs")

    logs = await audit_service.get_logs(team_id, limit, offset)
    return {"logs": logs, "total": len(logs)}
```

### Audit Logging Service

```python
# app/services/audit_service.py

"""Enterprise audit logging service."""

from datetime import datetime
from typing import Dict, List, Optional
from loguru import logger

from app.services.supabase_service import supabase


class AuditService:
    """
    Audit logging for enterprise compliance.

    Tracks all team activities for SOC2, PCI-DSS, HIPAA compliance.
    """

    async def log(
        self,
        team_id: str,
        user_id: str,
        action: str,
        details: Optional[Dict] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ):
        """
        Log an audit event.

        Args:
            team_id: Team ID
            user_id: User who performed the action
            action: Action type (e.g., "member_invited", "scan_executed")
            details: Additional details as JSON
            resource_type: Type of resource affected
            resource_id: ID of resource affected
            ip_address: Client IP address
        """
        entry = {
            "team_id": team_id,
            "user_id": user_id,
            "action": action,
            "details": details or {},
            "resource_type": resource_type,
            "resource_id": resource_id,
            "ip_address": ip_address,
            "created_at": datetime.utcnow().isoformat()
        }

        try:
            supabase.table("audit_logs").insert(entry).execute()
            logger.debug(f"Audit log: {action} by {user_id}")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    async def get_logs(
        self,
        team_id: str,
        limit: int = 100,
        offset: int = 0,
        action_filter: Optional[str] = None,
        user_filter: Optional[str] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None
    ) -> List[Dict]:
        """Get audit logs with filters."""
        query = supabase.table("audit_logs").select("*").eq("team_id", team_id)

        if action_filter:
            query = query.eq("action", action_filter)
        if user_filter:
            query = query.eq("user_id", user_filter)
        if from_date:
            query = query.gte("created_at", from_date)
        if to_date:
            query = query.lte("created_at", to_date)

        query = query.order("created_at", desc=True).range(offset, offset + limit - 1)

        response = query.execute()
        return response.data

    async def export_logs(
        self,
        team_id: str,
        format: str = "json",
        from_date: Optional[str] = None,
        to_date: Optional[str] = None
    ) -> str:
        """Export audit logs for compliance reporting."""
        logs = await self.get_logs(
            team_id,
            limit=10000,
            from_date=from_date,
            to_date=to_date
        )

        if format == "json":
            import json
            return json.dumps(logs, indent=2)
        elif format == "csv":
            import csv
            import io
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=logs[0].keys() if logs else [])
            writer.writeheader()
            writer.writerows(logs)
            return output.getvalue()

        return str(logs)
```

---

## Phase 6: Electron Desktop Integration

### Shared SQLite Database

The CLI and Electron app share a SQLite database for authentication state.

Location: `~/.zypheron/zypheron.db`

#### Schema (already implemented in CLI)

```sql
-- Auth session (single row, shared between CLI and Electron)
CREATE TABLE auth_session (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- License cache
CREATE TABLE license_cache (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    license_json TEXT NOT NULL,
    cached_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Token usage (synced with server)
CREATE TABLE token_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    tokens INTEGER NOT NULL,
    provider TEXT,
    feature TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    synced INTEGER DEFAULT 0
);
```

### Electron Main Process Integration

```typescript
// electron-app/src/main/auth-bridge.ts

import Database from 'better-sqlite3';
import { app } from 'electron';
import * as path from 'path';
import * as os from 'os';

interface AuthSession {
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
  userId: string;
  email: string;
}

interface License {
  tier: string;
  features: string[];
  tokensRemaining: number;
  tokensUsed: number;
  resetDate: string;
  expiresAt: string;
}

class AuthBridge {
  private db: Database.Database;
  private dbPath: string;

  constructor() {
    this.dbPath = path.join(os.homedir(), '.zypheron', 'zypheron.db');
    this.db = new Database(this.dbPath);
    this.initSchema();
  }

  private initSchema(): void {
    // Schema already created by CLI, but ensure it exists
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS auth_session (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        access_token TEXT NOT NULL,
        refresh_token TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        user_id TEXT NOT NULL,
        email TEXT NOT NULL,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS license_cache (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        license_json TEXT NOT NULL,
        cached_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
  }

  getSession(): AuthSession | null {
    const row = this.db.prepare(
      'SELECT * FROM auth_session WHERE id = 1'
    ).get() as any;

    if (!row) return null;

    return {
      accessToken: row.access_token,
      refreshToken: row.refresh_token,
      expiresAt: new Date(row.expires_at),
      userId: row.user_id,
      email: row.email
    };
  }

  saveSession(session: AuthSession): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO auth_session
      (id, access_token, refresh_token, expires_at, user_id, email, updated_at)
      VALUES (1, ?, ?, ?, ?, ?, datetime('now'))
    `).run(
      session.accessToken,
      session.refreshToken,
      session.expiresAt.toISOString(),
      session.userId,
      session.email
    );
  }

  getLicense(): License | null {
    const row = this.db.prepare(
      'SELECT license_json FROM license_cache WHERE id = 1'
    ).get() as any;

    if (!row) return null;

    return JSON.parse(row.license_json);
  }

  saveLicense(license: License): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO license_cache
      (id, license_json, cached_at)
      VALUES (1, ?, datetime('now'))
    `).run(JSON.stringify(license));
  }

  clearSession(): void {
    this.db.prepare('DELETE FROM auth_session').run();
    this.db.prepare('DELETE FROM license_cache').run();
  }

  isAuthenticated(): boolean {
    const session = this.getSession();
    if (!session) return false;

    // Check if token is expired
    return new Date() < session.expiresAt;
  }
}

export const authBridge = new AuthBridge();
```

### Electron Renderer Integration

```typescript
// electron-app/src/renderer/hooks/useAuth.ts

import { useState, useEffect } from 'react';

interface AuthState {
  isAuthenticated: boolean;
  user: {
    email: string;
    tier: string;
    tokensRemaining: number;
  } | null;
  loading: boolean;
}

export function useAuth() {
  const [auth, setAuth] = useState<AuthState>({
    isAuthenticated: false,
    user: null,
    loading: true
  });

  useEffect(() => {
    // Check auth state from shared database
    const checkAuth = async () => {
      try {
        const session = await window.electron.getSession();
        const license = await window.electron.getLicense();

        if (session && license) {
          setAuth({
            isAuthenticated: true,
            user: {
              email: session.email,
              tier: license.tier,
              tokensRemaining: license.tokensRemaining
            },
            loading: false
          });
        } else {
          setAuth({ isAuthenticated: false, user: null, loading: false });
        }
      } catch (error) {
        console.error('Auth check failed:', error);
        setAuth({ isAuthenticated: false, user: null, loading: false });
      }
    };

    checkAuth();

    // Watch for changes from CLI
    const interval = setInterval(checkAuth, 5000);
    return () => clearInterval(interval);
  }, []);

  const login = async () => {
    // Open browser for OAuth
    await window.electron.openExternal('https://zypheron.io/auth/desktop');
  };

  const logout = async () => {
    await window.electron.clearSession();
    setAuth({ isAuthenticated: false, user: null, loading: false });
  };

  return { ...auth, login, logout };
}
```

---

## Deployment Configuration

### Railway (railway.toml)

```toml
[build]
builder = "DOCKERFILE"
dockerfilePath = "Dockerfile"

[deploy]
numReplicas = 1
healthcheckPath = "/health"
healthcheckTimeout = 10

[env]
PYTHON_VERSION = "3.11"
```

### Render (render.yaml)

```yaml
services:
  - type: web
    name: zypheron-api
    env: docker
    dockerfilePath: ./Dockerfile
    healthCheckPath: /health
    envVars:
      - key: SECRET_KEY
        generateValue: true
      - key: SUPABASE_URL
        sync: false
      - key: SUPABASE_KEY
        sync: false
      - key: STRIPE_SECRET_KEY
        sync: false
      - key: STRIPE_WEBHOOK_SECRET
        sync: false
```

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ ./app/

# Run with uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### requirements.txt

```
fastapi==0.109.0
uvicorn[standard]==0.27.0
pydantic==2.5.3
pydantic-settings==2.1.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
stripe==7.10.0
supabase==2.3.4
httpx==0.26.0
loguru==0.7.2
python-multipart==0.0.6
```

---

## Next Steps

1. [ ] Review and approve this plan
2. [ ] Set up Supabase project
3. [ ] Set up Stripe account with products
4. [ ] Deploy API server to Railway/Render
5. [ ] Test auth flow between CLI and API
6. [ ] Implement Electron auth integration
7. [ ] Build compliance reporting templates
8. [ ] End-to-end testing

---

**Document Version**: 1.0
**Last Updated**: January 2025
**Author**: Claude (AI Assistant)
