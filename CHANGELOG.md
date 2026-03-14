# Changelog - Zypheron CLI

> **Note**: This changelog covers the Zypheron OSS release.
> Exploitation and AI-native tooling workflows remain available in the OSS release.

## [2.1.0] - 2026-02-11 - API Backend, Billing, AI Proxy, Monitoring & Security

### API Backend Merge

- Merged two separate backends (`api-server/` + `zypheron-api/`) into a single unified FastAPI backend (`zypheron-api/`)
- Single entry point, shared config, unified routing

### Stripe Billing

- Annual billing option with 25% discount (ANNUAL25 coupon)
- `BillingInterval` enum (`monthly` / `annual`) throughout checkout and webhooks
- Billing portal endpoint (`POST /license/portal`) for self-service management
- Subscription reactivation (`POST /license/reactivate`) for cancelled-but-active subscriptions
- Prices endpoint (`GET /license/prices`) returns all tiers with monthly/annual pricing
- Webhook idempotency: Redis primary (`48h TTL`) + in-memory `OrderedDict` fallback (10K cap, LRU eviction of oldest 2K)
- Dunning/grace period: `invoice.payment_failed` sets `past_due` status, configurable grace period (`STRIPE_PAYMENT_GRACE_PERIOD_DAYS`), auto-suspend on expiry

### AI Proxy

- Load balancer with per-key health tracking and automatic failover
- Response caching: in-memory LRU + Redis backend + gzip compression
- Token quota tracking per user with monthly reset
- BYOK (Bring Your Own Key) support with AES-256-GCM encryption at rest
- 5 providers: OpenAI, Anthropic, Grok, DeepSeek, Ollama (local)

### Monitoring

- Prometheus metrics: `http_requests_total`, `ai_requests_total`, `cache_hits_total`, `cache_misses_total`, `rate_limit_exceeded_total`
- Metrics middleware on all routes with method/path/status labels
- `GET /metrics` endpoint with IP allowlist + bearer token authentication
- Enhanced `GET /health` with component checks (database, Redis, Stripe)

### Security Fixes (22 Issues)

- Open redirect prevention: `ALLOWED_REDIRECT_DOMAINS` allowlist for Stripe checkout/portal return URLs
- Metrics endpoint authentication (IP allowlist + `METRICS_SECRET_TOKEN`)
- Error response sanitization: no stack traces or internal paths in production error responses
- JWT tokens now expire after 7 days (`JWT_ACCESS_TOKEN_EXPIRE_MINUTES=10080`)
- Webhook idempotency eviction: `OrderedDict` LRU prevents unbounded memory growth
- Stripe metadata null safety checks
- Deprecated Stripe API migration (`.delete()` -> `.cancel()` for subscriptions)
- Cache TTL tightening (prompt: 1h, vuln descriptions: 24h, general: 6h)
- `docker-compose.yml` port binding restricted to `127.0.0.1`

### Infrastructure

- `Dockerfile` (production) + `Dockerfile.test` (test runner)
- `docker-compose.yml`: API + PostgreSQL + Redis + pgAdmin + Prometheus + test-runner service
- Podman support (rootless containers)
- AWS Terraform config: S3 + CloudFront static hosting
- `install.sh` installer script
- CI/CD GitHub Actions workflows

### Testing

- 58 integration tests covering all code review fixes
- Stripe webhook lifecycle tests
- Subscription endpoint tests (checkout, portal, reactivate, cancel, prices)
- AI proxy tests: load balancer, caching, quota tracking, BYOK
- 6 test files, 2656 lines total
- Containerized test runner (`podman-compose --profile test up test-runner`)

---

## [2.0.0] - 2025-10-24 - COMPLETE REWRITE

### 🚀 Major Changes

**Complete rewrite from TypeScript to Go**

- **BREAKING**: Entire codebase rewritten in Go
- **REMOVED**: TypeScript/Node.js CLI
- **REMOVED**: React web application
- **REMOVED**: TypeScript backend
- **REMOVED**: All webapp-related infrastructure

### ✨ New Features

- **Go CLI**: High-performance, single-binary CLI written in Go
- **Zero Dependencies**: Statically linked, no runtime required
- **10-20x Faster**: Native performance with <10ms startup time
- **96% Smaller**: 7-15 MB binary vs 400+ MB with node_modules
- **Better OPSEC**: Single binary, minimal footprint, stripped symbols
- **Kali Integration**: Direct integration with 20+ Kali Linux tools
- **Real-time Streaming**: Live output from security tools
- **Bash Wrappers**: Ultra-fast direct tool execution
- **Cross-platform**: Linux, macOS, Windows support

### 📦 What's Included

```
zypheron/
├── zypheron-go/           # New Go CLI (all code is here)
├── LICENSE               # MIT License
├── .gitignore           # Go-specific ignores
├── README.md            # Quick start guide
└── CHANGELOG.md         # This file
```

### 🛠️ Commands

All commands from v1.x maintained with full feature parity:

- `scan` - Security scanning (nmap, nikto, nuclei, masscan)
- `tools` - Tool management (check, install, list)
- `chat` - AI assistant
- `config` - Configuration management
- `recon` - Reconnaissance
- `bruteforce` - Credential attacks
- `fuzz` - Web fuzzing
- `osint` - OSINT operations
- `threat` - Threat intelligence
- `report` - Report generation
- `dashboard` - Real-time monitoring
- `setup` - Initial setup
- `kali` - Kali-specific operations

**Note**: `exploit` remains available in the OSS release.

### 📊 Performance Improvements

| Metric | v1.x (TypeScript) | v2.0 (Go) | Improvement |
|--------|------------------|-----------|-------------|
| Startup Time | 100-150ms | 5-10ms | **10-20x faster** |
| Binary Size | 400+ MB | 7-15 MB | **96% smaller** |
| Memory Usage | 50-100 MB | 10-20 MB | **3-5x less** |
| Dependencies | Node.js + 2,847 files | 0 files | **∞ better** |

### 🔒 Security Improvements

- Single binary (harder to tamper with)
- No node_modules to scan
- Statically linked (no runtime vulnerabilities)
- Stripped symbols (harder to reverse engineer)
- Minimal OPSEC footprint

### 🗺️ Migration Path

For users of v1.x (TypeScript CLI):

1. Install Go 1.24+
2. Build new CLI: `cd zypheron-go && make build`
3. Install: `sudo make install`
4. All commands work identically

See `zypheron-go/MIGRATION_GUIDE.md` for detailed instructions.

### 📚 Documentation

All documentation is now in `zypheron-go/`:

- `README.md` - Complete documentation
- `QUICK_START.md` - Get started in 5 minutes
- `MIGRATION_GUIDE.md` - Migrate from v1.x
- `IMPLEMENTATION_COMPLETE.md` - Technical details

### 🙏 Acknowledgments

This rewrite was motivated by the need for:
- Better performance in field operations
- Improved OPSEC characteristics
- Reduced dependencies and attack surface
- Native system integration
- Professional-grade tooling

---

## [1.x] - Legacy (Deprecated)

The TypeScript/Node.js implementation has been deprecated and removed.

For historical reference, v1.x features included:
- TypeScript CLI
- React web interface
- Node.js backend
- Docker deployment
- Multiple microservices

**v1.x is no longer maintained. Please migrate to v2.0.**

---

## Future Roadmap

- [x] Cloud backend support (FastAPI + Stripe + AI proxy)
- [x] Automated testing framework (58 integration tests, containerized runner)
- [ ] TUI Dashboard (using bubbletea)
- [ ] More tool integrations
- [ ] Plugin system
- [ ] Team collaboration features
- [ ] Report templates
- [ ] Database migrations (Alembic)
- [ ] Email verification and password reset
- [ ] Admin dashboard

---

**For questions or issues, please open a GitHub issue.**
