# Zypheron CLI - Release Plan

> Consolidated development roadmap, current status, and release blockers.
> Replaces: `nextsteps.txt`, `IMPLEMENTATION_COMPLETE.md`, `docs/archive/*`
>
> Last updated: 2026-02-14

---

## Current Status

| Area | Status |
|------|--------|
| **Go rewrite** | Complete - full feature parity with TypeScript |
| **Licensing system** | Complete - tiers, feature gates, offline grace, device auth, token tracking |
| **TUI** | Complete - Bubble Tea, slash menu, chat, scanner |
| **Scheduling** | Complete - cron, SQLite persistence |
| **Session management** | Complete - save/resume/export |
| **Build** | `go build ./cmd/zypheron` compiles clean |
| **Branch** | `Zypheron-CLI-stage` |
| **Stage** | Closed Beta -> Open Beta pipeline |

---

## Test Suite Status (2026-02-14)

### Current state

- `go test ./...` passes locally.
- Socket/listener-dependent tests now skip gracefully in restricted environments where unix/TCP listen is not permitted.
- Previously listed compile-time test blockers (commands/config/reports/tools/ui/updater) are resolved.

### `go vet` Warnings

| Package | Issue |
|---------|-------|
| `internal/tui/queue` | `ScanJob` passed/copied by value but contains `sync/atomic.Int32` (4 occurrences in `manager.go`) |

---

## Release Blockers (Must Fix Before Open Beta)

### P1 - `go vet` Warnings

1. **`internal/tui/queue`** - `ScanJob` contains `sync/atomic.Int32` but is passed by value
    - `manager.go:174,276,281,290`
    - Fix: use pointer `*ScanJob` in Enqueue and slice operations

---

## Completed Work Log

### 2026-02-10: Licensing Production Fix (3 critical bugs)

**Files changed:** `storage.go`, `test_helpers_test.go` (new), `middleware_test.go`, `api_client.go`, `api_client_test.go`, `license.go`, `license_test.go`, `middleware.go`

| Bug | Fix |
|-----|-----|
| Device auth SIGSEGV | Removed broken `/auth/device/token` fallback, use `/auth/device/login` only |
| `SyncWithServer()` stub | Replaced with real impl delegating to `SyncLicense()` (retry, 401 refresh, offline fallback) |
| SQLite state leaking between tests | Added `overrideDBPath` + `TestMain` temp dir + `resetManager()` clears DB |
| 6 wrong test endpoint paths | `licenses/validate` -> `license/validate`, `licenses/usage` -> `tokens/usage`, `users/devices` -> `devices/register`, `users/devices/heartbeat` -> `devices/<id>/ping` |
| Nil pointer in test | Added nil guard for session in `TestPollDeviceAuth_Authorized` |
| No startup sync | Added `SyncLicenseAsync()` to `InitWithValidation()` |

### Earlier: Go Rewrite Complete

- Full CLI with 14+ Cobra commands
- TUI with Bubble Tea (slash menu, chat, scanner, model selector)
- Tool executor (nmap, nikto, nuclei, masscan, wpscan)
- Session management with SQLite persistence
- Scheduled scans with cron expressions
- AI bridge to Python backend
- Config system with keyring support
- Offline mode with graceful degradation
- Export (JSON, with HTML/MD/PDF stubs)
- Auto-updater framework
- Cross-platform builds via Makefile

---

## Licensing System (Implemented)

### Tiers

| Tier | Price | Tokens/mo | Devices | Features |
|------|-------|-----------|---------|----------|
| **Free** | $0 | 0 (local AI only) | 1 | Scanning, recon, local AI (Ollama) |
| **Starter** | $29/mo | 1M | 2 | + Cloud AI, Autopent, Exploitation, Post-Exploit |
| **Pro** | $149/mo | 3M | 3 | + Priority support |
| **Enterprise** | $499/seat/mo | 15M | Unlimited | + Teams, Compliance, Audit Logs, API Access, SSO |

### Implemented Components

- [x] Tier definitions and feature gates (`types.go`)
- [x] License manager singleton with mutex safety (`license.go`)
- [x] SQLite storage shared with Electron app (`storage.go`)
- [x] API client: login, device auth, token refresh, license fetch (`api_client.go`)
- [x] Retry with exponential backoff + 401 auto-refresh (`api_client.go`)
- [x] Background async sync on startup (`api_client.go`, `middleware.go`)
- [x] Cobra middleware: `RequireFeature`, `RequirePaidTier`, `RequireTokens` (`middleware.go`)
- [x] Convenience middleware: `RequireAutopentMiddleware()`, etc.
- [x] Offline grace period (7 days default, configurable per enterprise)
- [x] Graceful degradation to free tier on expiry
- [x] Device registration and heartbeat
- [x] Token usage tracking and sync
- [x] Test isolation with temp DB

### Not Yet Implemented

- [ ] Stripe payment integration
- [ ] Crypto payments (BTC, XMR)
- [ ] User account management UI (web)
- [ ] Usage dashboard
- [ ] Team management API
- [ ] SSO/SAML integration

---

## Phases to Release

### Phase 1: Fix Build Failures [BLOCKING]

Fix the 6 packages that fail to compile (P0 items above). These are mostly test files referencing removed/renamed functions.

**Estimated scope:** ~1-2 hours, test-only changes

### Phase 2: Fix Test Failures

Fix the 3 packages with runtime test failures + 1 vet warning.

**Estimated scope:** ~2-3 hours

### Phase 3: Security Audit

- [ ] `gosec ./...`
- [ ] `govulncheck ./...`
- [ ] `go vet ./...` clean (0 warnings)
- [ ] Secrets scan (gitleaks/trufflehog) on git history
- [ ] Input validation audit on tool executor
- [ ] Command injection review

### Phase 4: Stability & Polish

- [ ] Run `go test -race ./...` - fix any race conditions
- [ ] Review goroutine lifecycle (no leaks)
- [ ] Ensure all HTTP clients have timeouts
- [ ] Temp file cleanup
- [ ] Error messages are user-friendly (no raw stack traces)

### Phase 5: Documentation

- [x] README.md
- [x] QUICK_START.md
- [x] SCHEDULER.md
- [x] MIGRATION_GUIDE.md
- [x] CLAUDE.md (project rules)
- [x] PLAN.md (this file)
- [ ] CHANGELOG.md
- [ ] SECURITY.md
- [ ] CONTRIBUTING.md
- [ ] INSTALL.md (all platforms)
- [ ] Full command reference (USAGE.md)

### Phase 6: Distribution

- [ ] GitHub Releases with cross-compiled binaries (linux/darwin/windows, amd64/arm64)
- [ ] Install script (`curl | bash`)
- [ ] Homebrew formula
- [ ] Docker image
- [ ] AUR package (Arch)

### Phase 7: Backend & Payments [COMPLETE - 2026-02-11]

- [x] Unified API backend (merged `api-server/` + `zypheron-api/` into single FastAPI app)
- [x] Stripe subscription billing (monthly + annual with 25% discount)
- [x] Billing portal, subscription reactivation, prices endpoint
- [x] Webhook idempotency (Redis + OrderedDict LRU fallback)
- [x] Dunning/grace period with auto-suspend
- [x] AI proxy with load balancing, caching, BYOK, 5 providers
- [x] Prometheus monitoring (`/metrics` with auth)
- [x] Docker/Podman containerization (full stack + test runner)
- [x] 22-issue security code review + fixes
- [x] 58 integration tests (containerized)
- [x] AWS Terraform config (S3 + CloudFront)
- [ ] User signup/login web flow
- [ ] Usage dashboard
- [ ] Crypto payments (BTC via BTCPay, XMR) - post-launch
- [ ] Enterprise: SSO, team management, compliance reports

---

## Architecture

```
zypheron-go/
├── cmd/zypheron/              # Main entry point
├── internal/
│   ├── aibridge/              # Bridge to Python AI backend
│   ├── commands/              # Cobra CLI commands (14+)
│   ├── config/                # Config + keyring
│   ├── export/                # Report export (JSON, HTML, MD, PDF)
│   ├── history/               # Scan history tracking
│   ├── licensing/             # License validation, feature gates, API client
│   ├── offline/               # Offline mode support
│   ├── ratelimit/             # Rate limiting
│   ├── recovery/              # Error recovery
│   ├── reports/               # Report generation
│   ├── scheduler/             # Cron-based scan scheduling
│   ├── session/               # Session save/resume
│   ├── storage/               # Storage abstractions
│   ├── tools/                 # Security tool execution (nmap, nikto, etc.)
│   ├── tui/                   # Bubble Tea TUI
│   │   ├── buffer/
│   │   ├── components/
│   │   ├── queue/
│   │   ├── recovery/
│   │   ├── sanitize/
│   │   └── scanner/
│   ├── ui/                    # Terminal UI utilities, theme
│   └── updater/               # Auto-update system
├── pkg/                       # Public packages
├── scripts/bash/              # Bash wrappers (zscan, ztools)
├── docs/archive/              # Archived earlier docs
├── CLAUDE.md                  # Project rules
├── PLAN.md                    # This file
├── README.md                  # User-facing docs
├── QUICK_START.md             # Getting started
├── SCHEDULER.md               # Scheduler docs
├── MIGRATION_GUIDE.md         # TypeScript -> Go migration
└── Makefile                   # Build system
```

---

## Success Criteria

### Closed Beta Exit (Current)

- [x] All core features functional
- [x] Config persistence working
- [x] Session management working
- [x] Licensing system complete
- [x] Basic error recovery
- [ ] `go vet ./...` clean
- [ ] `go test ./...` all pass
- [ ] Zero P0/P1 bugs
- [ ] Security audit passed

### Open Beta Entry

- [ ] All above criteria met
- [ ] Public documentation complete
- [ ] Multi-platform binaries on GitHub Releases
- [ ] Install script working
- [ ] CHANGELOG.md started
- [ ] SECURITY.md published
- [ ] Community channel active

### Production Ready

- [ ] Account system functional
- [ ] Payment processing live (Stripe)
- [ ] Usage tracking accurate
- [ ] Support process defined
- [ ] SLA defined for paid tiers
- [ ] 90%+ test coverage on licensing & core packages
