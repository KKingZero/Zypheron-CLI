# Zypheron CLI - Freemium Production Implementation Plan

> **Status**: Planning Phase
> **Target**: Production-ready freemium SaaS model
> **Architecture**: Closed-source binary with Stripe billing integration
> **Desktop App**: Electron app integration (shared authentication)

---

## Executive Summary

Transform Zypheron into a freemium penetration testing platform with:
- **Free tier**: Local scanning + self-hosted AI (Ollama) - limited features
- **Paid tiers**: Cloud AI + Exploitation/Autopent features
- **Enterprise**: Team management, compliance reporting, priority support

---

## Pricing Structure

| Tier | Price | AI Tokens | Features |
|------|-------|-----------|----------|
| **Free** | $0/month | 0 (self-hosted only) | Scanning, recon, OSINT, basic analysis |
| **Starter** | $29/month | 1M tokens | + Cloud AI + Exploitation/Autopent |
| **Pro** | $149/month | 5M tokens | + All Starter features + Priority |
| **Enterprise** | $499/month/user | 25M tokens/user | + Team mgmt + Compliance + Priority support |

**Token Policy**: Monthly allocation, no rollover. Tokens reset on billing date.

---

## Feature Matrix

### FREE Tier Features

```
INCLUDED (FREE):
[x] Network Scanning (nmap, masscan, rustscan)
[x] Web Application Scanning (nikto, nuclei)
[x] SQL Injection Testing (sqlmap)
[x] Directory Fuzzing (gobuster, ffuf)
[x] Subdomain Enumeration (subfinder, amass)
[x] OSINT Operations
[x] Bruteforce Attacks (hydra)
[x] Reconnaissance
[x] Self-hosted AI Analysis (Ollama only)
[x] Basic Vulnerability Reports
[x] Tool Management
[x] Tab Completion

LOCKED (Requires Paid):
[ ] Cloud AI Providers (Claude, OpenAI, Gemini, DeepSeek, Grok, Kimi)
[ ] Autopent Engine (Automated Penetration Testing)
[ ] Exploitation Module
[ ] Post-Exploitation Features
[ ] Attack Chain Planning
[ ] AI Decision Engine
[ ] Credential Vault (secure storage)
[ ] Autonomous Orchestrator
```

### PAID Tier Features (Starter/Pro/Enterprise)

```
STARTER ($29/month - 1M tokens):
[x] All FREE features
[x] Cloud AI Providers (7 providers)
[x] Autopent Engine
[x] Exploitation Module
[x] Post-Exploitation
[x] Attack Chain Planning
[x] AI Decision Engine
[x] Interactive Exploitation Prompts
[x] Advanced Vulnerability Analysis
[x] CVE Enrichment
[x] ML Vulnerability Prediction

PRO ($149/month - 5M tokens):
[x] All Starter features
[x] Higher token allocation (5M)
[x] Priority support

ENTERPRISE ($499/month/user - 25M tokens/user):
[x] All Pro features
[x] Team Management (users, roles, permissions)
[x] Shared Projects & Workspaces
[x] Audit Logging
[x] Compliance Reporting (SOC2, PCI-DSS, HIPAA, ISO 27001)
[x] Priority Support Channel
[x] Custom Branding (white-label reports)
[x] SSO/SAML Integration
[x] API Access for CI/CD Integration
```

---

## Technical Architecture

### 1. Authentication & Licensing System

```
┌─────────────────────────────────────────────────────────────────┐
│                    Zypheron Auth Architecture                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│  │  CLI Binary  │     │ Electron App │     │  Web Portal  │    │
│  └──────┬───────┘     └──────┬───────┘     └──────┬───────┘    │
│         │                    │                    │             │
│         └────────────────────┼────────────────────┘             │
│                              │                                   │
│                              ▼                                   │
│                    ┌─────────────────┐                          │
│                    │  Zypheron API   │                          │
│                    │   (Your Server) │                          │
│                    └────────┬────────┘                          │
│                              │                                   │
│         ┌────────────────────┼────────────────────┐             │
│         ▼                    ▼                    ▼             │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐       │
│  │   Stripe    │     │  Supabase   │     │  AI Proxy   │       │
│  │  Payments   │     │  Auth/DB    │     │  Service    │       │
│  └─────────────┘     └─────────────┘     └─────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2. License Validation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     License Check Flow                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. CLI Startup                                                  │
│     └─> Check ~/.zypheron/license.json                          │
│         └─> If missing/expired: prompt login or free mode        │
│                                                                  │
│  2. Feature Access Request                                       │
│     └─> Check feature against tier                               │
│         └─> FREE: Allow if in free list                         │
│         └─> PAID: Validate license + token balance               │
│             └─> If valid: Execute + deduct tokens               │
│             └─> If invalid: Show upgrade prompt                  │
│                                                                  │
│  3. Token Deduction (for AI calls)                               │
│     └─> Pre-request: Check balance                               │
│     └─> Post-request: Deduct actual tokens used                  │
│     └─> Sync with server every N requests or on app close        │
│                                                                  │
│  4. Offline Mode                                                 │
│     └─> Cache license for 7 days                                 │
│     └─> Token tracking stored locally, synced when online        │
│     └─> Paid features work offline with cached license           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3. Directory Structure Changes

```
zypheron-cli-production/
├── FREEMIUM_IMPLEMENTATION_PLAN.md   # This file
├── LICENSE                            # Proprietary EULA
├── README.md                          # Updated for freemium
│
├── zypheron-go/                       # Go CLI (closed source binary)
│   ├── internal/
│   │   ├── licensing/                 # NEW: License management
│   │   │   ├── license.go            # License validation
│   │   │   ├── features.go           # Feature gate definitions
│   │   │   ├── tokens.go             # Token tracking
│   │   │   └── offline.go            # Offline mode handling
│   │   ├── billing/                   # NEW: Stripe integration
│   │   │   ├── stripe.go             # Stripe API client
│   │   │   ├── subscription.go       # Subscription management
│   │   │   └── usage.go              # Usage reporting
│   │   ├── auth/                      # NEW: Authentication
│   │   │   ├── auth.go               # Login/logout
│   │   │   ├── session.go            # Session management
│   │   │   └── device.go             # Device registration
│   │   └── commands/
│   │       ├── login.go              # NEW: zypheron login
│   │       ├── account.go            # NEW: zypheron account
│   │       └── upgrade.go            # NEW: zypheron upgrade
│   │
│   └── cmd/zypheron/
│       └── main.go                    # Add license checks
│
├── zypheron-ai/                       # Python AI Engine
│   ├── licensing/                     # NEW: License verification
│   │   ├── __init__.py
│   │   ├── validator.py              # Validate requests
│   │   └── token_counter.py          # Count AI tokens
│   │
│   ├── autopent/                      # Gated behind paid tier
│   └── providers/                     # Cloud providers gated
│
├── api-server/                        # NEW: Backend API
│   ├── src/
│   │   ├── routes/
│   │   │   ├── auth.ts               # Authentication endpoints
│   │   │   ├── billing.ts            # Stripe webhook handlers
│   │   │   ├── license.ts            # License validation
│   │   │   ├── usage.ts              # Token usage tracking
│   │   │   └── teams.ts              # Enterprise team management
│   │   ├── services/
│   │   │   ├── stripe.ts             # Stripe service
│   │   │   ├── supabase.ts           # Database service
│   │   │   └── ai-proxy.ts           # AI provider proxy
│   │   └── middleware/
│   │       ├── auth.ts               # Auth middleware
│   │       └── rate-limit.ts         # Rate limiting
│   │
│   ├── package.json
│   └── Dockerfile
│
└── docs/
    ├── PRICING.md                     # Pricing documentation
    ├── ENTERPRISE.md                  # Enterprise features
    └── API.md                         # API documentation
```

---

## Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)

#### 1.1 Backend API Server
```
Tasks:
[ ] Set up Node.js/Express or Go API server
[ ] Configure Supabase for auth + database
[ ] Implement Stripe integration
    [ ] Product creation (Free, Starter, Pro, Enterprise)
    [ ] Subscription management
    [ ] Webhook handlers (subscription.created, .updated, .cancelled)
    [ ] Usage-based billing for tokens
[ ] Create database schema:
    - users (id, email, stripe_customer_id, tier, created_at)
    - subscriptions (id, user_id, stripe_sub_id, status, current_period_end)
    - usage (id, user_id, tokens_used, tokens_remaining, reset_date)
    - teams (id, name, owner_id, created_at) [Enterprise]
    - team_members (team_id, user_id, role)
    - audit_logs (id, team_id, user_id, action, timestamp) [Enterprise]
    - devices (id, user_id, device_hash, last_seen, name)
```

#### 1.2 License System
```
Tasks:
[ ] Design license token format (JWT with claims)
    {
      "sub": "user_id",
      "tier": "starter|pro|enterprise",
      "tokens_remaining": 1000000,
      "features": ["cloud_ai", "autopent", "exploitation"],
      "team_id": null | "team_uuid",
      "exp": unix_timestamp,
      "device_id": "device_hash"
    }
[ ] Implement license caching (7-day offline validity)
[ ] Create license refresh mechanism
[ ] Add device binding (limit concurrent devices per tier)
    - Free: 1 device
    - Starter: 2 devices
    - Pro: 3 devices
    - Enterprise: Unlimited (per user)
```

### Phase 2: CLI Integration (Week 2-3)

#### 2.1 Authentication Commands
```go
// New commands to add:
zypheron login              // OAuth/magic link login
zypheron logout             // Clear session
zypheron account            // Show account info + usage
zypheron account usage      // Detailed token usage
zypheron upgrade            // Open upgrade page
zypheron billing            // Open billing portal
```

#### 2.2 Feature Gating Implementation
```go
// internal/licensing/features.go

type Feature string

const (
    FeatureCloudAI      Feature = "cloud_ai"
    FeatureAutopent     Feature = "autopent"
    FeatureExploitation Feature = "exploitation"
    FeatureTeams        Feature = "teams"
    FeatureCompliance   Feature = "compliance"
    FeatureAuditLogs    Feature = "audit_logs"
)

var TierFeatures = map[string][]Feature{
    "free": {},
    "starter": {FeatureCloudAI, FeatureAutopent, FeatureExploitation},
    "pro": {FeatureCloudAI, FeatureAutopent, FeatureExploitation},
    "enterprise": {FeatureCloudAI, FeatureAutopent, FeatureExploitation,
                   FeatureTeams, FeatureCompliance, FeatureAuditLogs},
}

func (l *License) HasFeature(f Feature) bool {
    features := TierFeatures[l.Tier]
    for _, feat := range features {
        if feat == f {
            return true
        }
    }
    return false
}
```

#### 2.3 Token Tracking
```go
// internal/licensing/tokens.go

type TokenTracker struct {
    Used       int64
    Remaining  int64
    ResetDate  time.Time
    LastSync   time.Time
}

func (t *TokenTracker) Deduct(tokens int64) error {
    if t.Remaining < tokens {
        return ErrInsufficientTokens
    }
    t.Used += tokens
    t.Remaining -= tokens
    return nil
}

func (t *TokenTracker) SyncWithServer() error {
    // POST to API server with usage
    // Update local cache with server response
}
```

### Phase 3: AI Provider Gating (Week 3-4)

#### 3.1 Cloud AI Proxy
```
Architecture:
- Users with BYOK (Bring Your Own Key): Direct connection allowed
- Paid users without keys: Route through Zypheron AI Proxy
- Free users: Only Ollama (local) allowed

Proxy Benefits:
- Unified token counting across all providers
- No API key exposure to client
- Usage analytics
- Rate limiting per tier
```

#### 3.2 Provider Manager Updates
```python
# zypheron-ai/providers/manager.py

class AIProviderManager:
    def __init__(self, license: License):
        self.license = license
        self.providers = {}
        self._initialize_providers()

    def _initialize_providers(self):
        # Ollama always available (free)
        self.providers[AIProvider.OLLAMA] = OllamaProvider()

        # Cloud providers only for paid tiers
        if self.license.has_feature("cloud_ai"):
            if self.license.has_byok("claude"):
                self.providers[AIProvider.CLAUDE] = ClaudeProvider(
                    api_key=self.license.get_byok("claude")
                )
            elif self.license.tier in ["starter", "pro", "enterprise"]:
                self.providers[AIProvider.CLAUDE] = ProxiedClaudeProvider(
                    proxy_url=ZYPHERON_AI_PROXY,
                    license_token=self.license.token
                )
            # ... repeat for other providers

    def chat(self, messages, provider=None, **kwargs):
        if provider != "ollama" and not self.license.has_feature("cloud_ai"):
            raise FeatureLockedError(
                "Cloud AI requires a paid subscription. "
                "Upgrade at: https://zypheron.io/upgrade\n"
                "Or use: zypheron chat --provider ollama"
            )
        # ... rest of implementation
```

### Phase 4: Autopent/Exploitation Gating (Week 4-5)

#### 4.1 Exploitation Module Gate
```go
// internal/commands/exploit.go

func ExploitCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "exploit",
        Short: "Automated exploitation (Paid feature)",
        PreRunE: func(cmd *cobra.Command, args []string) error {
            license := licensing.GetLicense()
            if !license.HasFeature(licensing.FeatureExploitation) {
                return &licensing.FeatureLockedError{
                    Feature: "Exploitation",
                    Message: `
╔═══════════════════════════════════════════════════════════════╗
║  EXPLOITATION - PAID FEATURE                                   ║
╠═══════════════════════════════════════════════════════════════╣
║                                                                 ║
║  Automated exploitation requires a paid subscription.           ║
║                                                                 ║
║  Included in:                                                   ║
║    • Starter ($29/month) - 1M AI tokens                        ║
║    • Pro ($149/month) - 5M AI tokens                           ║
║    • Enterprise ($499/month/user) - 25M tokens                 ║
║                                                                 ║
║  Upgrade: zypheron upgrade                                      ║
║  Or visit: https://zypheron.io/pricing                         ║
║                                                                 ║
╚═══════════════════════════════════════════════════════════════╝`,
                }
            }
            return nil
        },
        // ... rest of command
    }
    return cmd
}
```

#### 4.2 Autopent Engine Gate
```python
# zypheron-ai/autopent/autopent_engine.py

class AutoPentEngine:
    def __init__(self, license: License):
        self.license = license
        self._validate_license()

    def _validate_license(self):
        if not self.license.has_feature("autopent"):
            raise FeatureLockedError(
                "AutoPent engine requires a paid subscription.\n"
                "Upgrade at: https://zypheron.io/upgrade"
            )

    async def run(self, target, scope, **kwargs):
        # Check tokens before each AI call
        estimated_tokens = self._estimate_tokens(target, scope)
        if self.license.tokens_remaining < estimated_tokens:
            raise InsufficientTokensError(
                f"This operation requires ~{estimated_tokens:,} tokens. "
                f"You have {self.license.tokens_remaining:,} remaining.\n"
                "Purchase more: zypheron upgrade"
            )
        # ... rest of implementation
```

### Phase 5: Enterprise Features (Week 5-6)

#### 5.1 Team Management
```
Database Schema:
- teams
    - id: UUID
    - name: String
    - owner_id: UUID (FK users)
    - stripe_subscription_id: String
    - seats_purchased: Int
    - created_at: Timestamp

- team_members
    - team_id: UUID (FK teams)
    - user_id: UUID (FK users)
    - role: Enum(owner, admin, member)
    - invited_at: Timestamp
    - accepted_at: Timestamp

API Endpoints:
POST   /api/teams              - Create team
GET    /api/teams/:id          - Get team details
PUT    /api/teams/:id          - Update team
DELETE /api/teams/:id          - Delete team
POST   /api/teams/:id/invite   - Invite member
DELETE /api/teams/:id/members/:user_id - Remove member
PUT    /api/teams/:id/members/:user_id/role - Change role
```

#### 5.2 Audit Logging
```python
# zypheron-ai/compliance/audit_logger.py

class AuditLogger:
    def __init__(self, license: License):
        self.license = license
        self.team_id = license.team_id

    async def log(self, action: str, details: dict):
        if not self.license.has_feature("audit_logs"):
            return  # Silently skip for non-enterprise

        entry = {
            "team_id": self.team_id,
            "user_id": self.license.user_id,
            "action": action,
            "details": details,
            "timestamp": datetime.utcnow().isoformat(),
            "ip_address": get_client_ip(),
            "device_id": self.license.device_id
        }
        await self._send_to_server(entry)

# Usage in commands:
audit_logger.log("exploit_executed", {
    "target": target,
    "exploit": exploit_name,
    "result": "success"
})
```

#### 5.3 Compliance Reporting
```
Enterprise-only Reports:
- SOC2 audit trail export
- PCI-DSS compliance scans with attestation
- HIPAA security assessment templates
- ISO 27001 control mapping
- Custom compliance frameworks

Report Features:
- Executive summary with risk scores
- Detailed findings with remediation steps
- Evidence collection (screenshots, logs)
- Trend analysis over time
- Export formats: PDF, HTML, JSON, CSV
```

### Phase 6: Electron Desktop Integration (Week 6-7)

#### 6.1 Shared Authentication
```
Flow:
1. User logs in via Electron app
2. App stores auth token securely (keychain)
3. CLI detects Electron auth token
4. Shared session between CLI and Electron

Implementation:
- Electron: Store token in system keychain
- CLI: Check keychain for existing session
- Both: Use same API endpoints
- Sync: Token refresh handled by whichever app is active
```

#### 6.2 IPC Communication
```typescript
// electron-app/src/main/cli-bridge.ts

import { ipcMain } from 'electron';
import { spawn } from 'child_process';

class CLIBridge {
    async executeCommand(command: string, args: string[]): Promise<string> {
        return new Promise((resolve, reject) => {
            const proc = spawn('zypheron', [command, ...args]);
            let output = '';

            proc.stdout.on('data', (data) => {
                output += data.toString();
                // Stream to renderer process
                mainWindow.webContents.send('cli-output', data.toString());
            });

            proc.on('close', (code) => {
                if (code === 0) resolve(output);
                else reject(new Error(`CLI exited with code ${code}`));
            });
        });
    }
}
```

---

## Database Schema (Supabase)

```sql
-- Users table (extends Supabase auth.users)
CREATE TABLE public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id),
    email TEXT NOT NULL,
    display_name TEXT,
    stripe_customer_id TEXT UNIQUE,
    tier TEXT DEFAULT 'free' CHECK (tier IN ('free', 'starter', 'pro', 'enterprise')),
    tokens_used BIGINT DEFAULT 0,
    tokens_remaining BIGINT DEFAULT 0,
    tokens_reset_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Subscriptions
CREATE TABLE public.subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id),
    stripe_subscription_id TEXT UNIQUE NOT NULL,
    stripe_price_id TEXT NOT NULL,
    status TEXT NOT NULL,
    current_period_start TIMESTAMP WITH TIME ZONE,
    current_period_end TIMESTAMP WITH TIME ZONE,
    cancel_at_period_end BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Teams (Enterprise)
CREATE TABLE public.teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    owner_id UUID REFERENCES public.profiles(id),
    stripe_subscription_id TEXT,
    seats_purchased INT DEFAULT 1,
    tokens_pool BIGINT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Team Members
CREATE TABLE public.team_members (
    team_id UUID REFERENCES public.teams(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
    role TEXT DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
    tokens_allocated BIGINT DEFAULT 0,
    invited_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    accepted_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (team_id, user_id)
);

-- Devices
CREATE TABLE public.devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id),
    device_hash TEXT NOT NULL,
    device_name TEXT,
    platform TEXT,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, device_hash)
);

-- Usage Logs
CREATE TABLE public.usage_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id),
    team_id UUID REFERENCES public.teams(id),
    action TEXT NOT NULL,
    tokens_used INT DEFAULT 0,
    ai_provider TEXT,
    feature TEXT,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit Logs (Enterprise)
CREATE TABLE public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id UUID REFERENCES public.teams(id),
    user_id UUID REFERENCES public.profiles(id),
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    details JSONB,
    ip_address INET,
    device_id UUID REFERENCES public.devices(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- BYOK (Bring Your Own Key)
CREATE TABLE public.user_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id),
    provider TEXT NOT NULL,
    encrypted_key TEXT NOT NULL,  -- Encrypted with user's key
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, provider)
);

-- Row Level Security
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.usage_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- Indexes
CREATE INDEX idx_usage_logs_user_date ON public.usage_logs(user_id, created_at);
CREATE INDEX idx_audit_logs_team_date ON public.audit_logs(team_id, created_at);
CREATE INDEX idx_devices_user ON public.devices(user_id);
```

---

## Stripe Configuration

### Products & Prices

```javascript
// stripe-setup.js

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

async function setupProducts() {
    // Starter Plan
    const starter = await stripe.products.create({
        name: 'Zypheron Starter',
        description: 'Cloud AI + Exploitation features - 1M tokens/month',
        metadata: {
            tier: 'starter',
            tokens: '1000000'
        }
    });

    await stripe.prices.create({
        product: starter.id,
        unit_amount: 2900, // $29.00
        currency: 'usd',
        recurring: { interval: 'month' },
        metadata: { tier: 'starter' }
    });

    // Pro Plan
    const pro = await stripe.products.create({
        name: 'Zypheron Pro',
        description: 'Cloud AI + Exploitation features - 5M tokens/month + Priority',
        metadata: {
            tier: 'pro',
            tokens: '5000000'
        }
    });

    await stripe.prices.create({
        product: pro.id,
        unit_amount: 14900, // $149.00
        currency: 'usd',
        recurring: { interval: 'month' },
        metadata: { tier: 'pro' }
    });

    // Enterprise Plan (per seat)
    const enterprise = await stripe.products.create({
        name: 'Zypheron Enterprise',
        description: 'Team features + 25M tokens/user/month',
        metadata: {
            tier: 'enterprise',
            tokens_per_seat: '25000000'
        }
    });

    await stripe.prices.create({
        product: enterprise.id,
        unit_amount: 49900, // $499.00 per seat
        currency: 'usd',
        recurring: { interval: 'month' },
        metadata: { tier: 'enterprise', billing_scheme: 'per_seat' }
    });
}
```

### Webhook Handlers

```typescript
// api-server/src/routes/billing.ts

app.post('/webhooks/stripe', async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const event = stripe.webhooks.constructEvent(req.body, sig, WEBHOOK_SECRET);

    switch (event.type) {
        case 'customer.subscription.created':
        case 'customer.subscription.updated':
            await handleSubscriptionUpdate(event.data.object);
            break;

        case 'customer.subscription.deleted':
            await handleSubscriptionCancelled(event.data.object);
            break;

        case 'invoice.paid':
            await handleInvoicePaid(event.data.object);
            break;

        case 'invoice.payment_failed':
            await handlePaymentFailed(event.data.object);
            break;
    }

    res.json({ received: true });
});

async function handleSubscriptionUpdate(subscription) {
    const userId = await getUserByStripeCustomer(subscription.customer);
    const tier = subscription.items.data[0].price.metadata.tier;
    const tokens = getTierTokens(tier);

    await supabase.from('profiles').update({
        tier,
        tokens_remaining: tokens,
        tokens_reset_date: new Date(subscription.current_period_end * 1000)
    }).eq('id', userId);
}
```

---

## API Endpoints

### Authentication

```
POST /api/auth/login
    Body: { email, password } or { magic_link_token }
    Response: { access_token, refresh_token, user }

POST /api/auth/refresh
    Body: { refresh_token }
    Response: { access_token }

POST /api/auth/logout
    Headers: Authorization: Bearer <token>
    Response: { success: true }

GET /api/auth/me
    Headers: Authorization: Bearer <token>
    Response: { user, subscription, usage }
```

### License

```
GET /api/license
    Headers: Authorization: Bearer <token>
    Response: {
        tier: "starter",
        features: ["cloud_ai", "autopent", "exploitation"],
        tokens_remaining: 950000,
        tokens_used: 50000,
        reset_date: "2025-02-01T00:00:00Z",
        expires_at: "2025-01-14T00:00:00Z"  // 7-day license validity
    }

POST /api/license/refresh
    Headers: Authorization: Bearer <token>
    Response: { license_token: "jwt..." }
```

### Usage

```
POST /api/usage/report
    Headers: Authorization: Bearer <token>
    Body: {
        actions: [
            { action: "ai_chat", tokens: 1500, provider: "claude", timestamp: "..." },
            { action: "exploit", tokens: 0, feature: "exploitation", timestamp: "..." }
        ]
    }
    Response: { tokens_remaining: 948500 }

GET /api/usage/history
    Headers: Authorization: Bearer <token>
    Query: ?from=2025-01-01&to=2025-01-31
    Response: { usage: [...], total_tokens: 150000 }
```

### Teams (Enterprise)

```
POST /api/teams
    Body: { name: "Acme Security Team" }
    Response: { team }

POST /api/teams/:id/invite
    Body: { email: "newmember@acme.com", role: "member" }
    Response: { invitation }

GET /api/teams/:id/audit-logs
    Query: ?from=2025-01-01&limit=100
    Response: { logs: [...] }
```

---

## CLI Commands (New)

```bash
# Authentication
zypheron login                    # Open browser for OAuth login
zypheron login --email            # Email magic link login
zypheron logout                   # Clear session
zypheron whoami                   # Show current user

# Account Management
zypheron account                  # Show account summary
zypheron account usage            # Detailed usage stats
zypheron account devices          # List registered devices
zypheron account devices remove   # Remove a device

# Billing
zypheron upgrade                  # Open upgrade page
zypheron billing                  # Open Stripe billing portal

# Teams (Enterprise)
zypheron team                     # Show team info
zypheron team members             # List team members
zypheron team invite <email>      # Invite member
zypheron team remove <user>       # Remove member
zypheron team audit-log           # View audit log

# API Keys (BYOK)
zypheron config set-key <provider>    # Add your own API key
zypheron config remove-key <provider> # Remove API key
zypheron config list-keys             # List configured keys
```

---

## User Experience Flows

### Free User Attempting Paid Feature

```
$ zypheron exploit target.com

╔═══════════════════════════════════════════════════════════════╗
║                    FEATURE LOCKED                              ║
╠═══════════════════════════════════════════════════════════════╣
║                                                                 ║
║  The 'exploit' command requires a paid subscription.           ║
║                                                                 ║
║  Your current plan: FREE                                        ║
║                                                                 ║
║  Upgrade options:                                               ║
║    Starter  $29/mo  →  1M AI tokens + Exploitation             ║
║    Pro      $149/mo →  5M AI tokens + Priority Support         ║
║                                                                 ║
║  Upgrade now: zypheron upgrade                                  ║
║  Or try: zypheron scan target.com (available in FREE)          ║
║                                                                 ║
╚═══════════════════════════════════════════════════════════════╝
```

### Token Exhaustion

```
$ zypheron chat "Analyze this vulnerability report"

╔═══════════════════════════════════════════════════════════════╗
║                 INSUFFICIENT TOKENS                            ║
╠═══════════════════════════════════════════════════════════════╣
║                                                                 ║
║  This request requires approximately 2,500 tokens.             ║
║  Your remaining balance: 1,200 tokens                          ║
║                                                                 ║
║  Options:                                                       ║
║    1. Wait for reset: 3 days (Jan 1, 2025)                     ║
║    2. Upgrade plan: zypheron upgrade                           ║
║    3. Use local AI: zypheron chat --provider ollama "..."      ║
║                                                                 ║
╚═══════════════════════════════════════════════════════════════╝
```

### First Login

```
$ zypheron login

╔═══════════════════════════════════════════════════════════════╗
║              WELCOME TO ZYPHERON                               ║
╚═══════════════════════════════════════════════════════════════╝

Opening browser for authentication...

[Browser opens to https://zypheron.io/auth/cli]

Waiting for authentication... ✓

╔═══════════════════════════════════════════════════════════════╗
║  Successfully logged in!                                       ║
║                                                                 ║
║  User: harrison@example.com                                     ║
║  Plan: Starter ($29/month)                                     ║
║  Tokens: 1,000,000 remaining                                   ║
║  Resets: Jan 15, 2025                                          ║
║                                                                 ║
║  Quick start:                                                   ║
║    zypheron scan <target>         # Security scan              ║
║    zypheron chat "question"       # AI assistant               ║
║    zypheron exploit <target>      # Automated exploitation     ║
║                                                                 ║
╚═══════════════════════════════════════════════════════════════╝
```

---

## Security Considerations

### License Token Security
- JWT signed with RS256 (asymmetric)
- Short expiry (7 days) with refresh
- Device binding to prevent sharing
- Revocation via server-side blacklist

### API Key Security (BYOK)
- Encrypted at rest with user-derived key
- Never transmitted to Zypheron servers
- Used client-side only

### Binary Protection
- Stripped symbols
- UPX compression (optional)
- Anti-debugging measures
- License validation in multiple places

### Rate Limiting
```
Free:      10 requests/minute
Starter:   60 requests/minute
Pro:       120 requests/minute
Enterprise: 300 requests/minute
```

---

## Migration Path

### From Current Cobra-AI Users
1. Existing users get 30-day grace period
2. Prompt to create account on first run
3. Import existing configurations
4. No data loss during transition

### From Free Version
1. Account creation optional for free features
2. Prompt upgrade when hitting locked features
3. Seamless upgrade path via CLI

---

## Monitoring & Analytics

### Metrics to Track
- Daily/Monthly Active Users (DAU/MAU)
- Token consumption patterns
- Feature usage breakdown
- Conversion rates (free → paid)
- Churn rate by tier
- Average revenue per user (ARPU)

### Tools
- Stripe Dashboard (revenue)
- Supabase Dashboard (database)
- PostHog or Mixpanel (product analytics)
- Sentry (error tracking)

---

## Timeline Summary

| Phase | Duration | Deliverables |
|-------|----------|--------------|
| **Phase 1** | Week 1-2 | Backend API, Stripe, Database |
| **Phase 2** | Week 2-3 | CLI auth, feature gating |
| **Phase 3** | Week 3-4 | AI provider gating, proxy |
| **Phase 4** | Week 4-5 | Autopent/exploit gating |
| **Phase 5** | Week 5-6 | Enterprise features |
| **Phase 6** | Week 6-7 | Electron integration |
| **Phase 7** | Week 7-8 | Testing, polish, launch |

---

## Next Steps

1. [ ] Review and approve this plan
2. [ ] Set up Stripe account and products
3. [ ] Set up Supabase project
4. [ ] Begin Phase 1 implementation
5. [ ] Create web portal for account management
6. [ ] Design Electron app integration points

---

**Document Version**: 1.0
**Last Updated**: January 2025
**Author**: Claude (AI Assistant)
