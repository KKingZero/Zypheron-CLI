# ZYPHERON PRODUCTION FREEMIUM - IMPLEMENTATION PLAN

> **Status**: Active Development
> **Launch Target**: 2 months
> **Last Updated**: December 2024

---

## Executive Summary

Transform Zypheron into a **privacy-focused, semi-automated** penetration testing platform with:
- **Free tier**: BYOK AI + scanning/recon (no cloud costs for basic users)
- **Paid tiers**: Cloud AI proxy + exploitation features
- **Enterprise**: Local model exploitation + teams + compliance

---

## Confirmed Decisions

| Category | Decision |
|----------|----------|
| **Launch** | 2 months (global) |
| **Model** | Hybrid cloud - Enterprise local exploits, others cloud |
| **Positioning** | Privacy-focused, semi-automated, operator control |
| **Pricing** | Adjustable via Stripe, 25% annual discount |
| **Name** | Zypheron (keeping it) |

---

## Pricing Structure

| Tier | Monthly | Annual (25% off) | Tokens | Key Features |
|------|---------|------------------|--------|--------------|
| **Free** | $0 | - | BYOK only | Recon, scanning, basic MD reports |
| **Starter** | $20 | $180 | 1M | + Cloud AI + Exploitation (cloud) |
| **Pro** | $40 | $360 | 3M | + Higher token allocation |
| **Enterprise** | $500/device | $4,500/device | 15M/5 users | + Local exploits + Teams + Compliance |

### Enterprise Details
- **Minimum**: 4 seats = $2,000/month
- **Token Pool**: 15M tokens per 5 users (shared pool)
- **Device Limit**: 500 devices per license

### Future Discounts (Paused)
- Student/Education: 20% off (implement later)

---

## Feature Matrix

### Free Tier
```
✅ INCLUDED:
├── All scanning tools (nmap, nikto, nuclei, masscan, etc.)
├── Reconnaissance features
├── OSINT operations
├── Bruteforce attacks
├── Directory fuzzing
├── BYOK AI providers (OpenAI, Claude, Grok, DeepSeek)
├── Basic Markdown reports (no templates)
├── Unlimited scans (no limits)
└── 1 device

❌ REQUIRES PAID:
├── Cloud AI proxy
├── Exploitation module
├── Post-exploitation
├── Autopent engine
├── Compliance report templates
├── PDF/HTML formatted reports
└── Multiple devices
```

### Starter ($20/month)
```
Everything in Free, plus:
├── Cloud AI proxy (1M tokens/month)
├── Exploitation module (cloud execution only)
├── Post-exploitation features (cloud only)
├── PDF/HTML report generation
├── Report templates
└── 2 devices
```

### Pro ($40/month)
```
Everything in Starter, plus:
├── 3M tokens/month
└── 3 devices
```

### Enterprise ($500/device/month, min 4 seats)
```
Everything in Pro, plus:
├── Local model exploitation (run on your infrastructure)
├── Team management (owner/admin/member roles)
├── 15M tokens per 5 users (shared pool)
├── Compliance reports (SOC2, HIPAA, PCI-DSS)
├── White-label reports (custom branding)
├── Audit logging
├── SSO integration (post-launch)
└── Up to 500 devices per license
```

---

## Technical Architecture

### Backend Stack
- **Framework**: FastAPI (Python)
- **Database**: Supabase (migrate to self-hosted Postgres later)
- **Hosting**: Railway (US-West region)
- **Payments**: Stripe
- **Cache**: Redis (for AI proxy caching)

### Authentication
- **Providers**: GitHub OAuth, Email/Password
- **Session Duration**: Until logout (no expiry)
- **Device Limits**: Enforced server-side
- **Offline Cache**: 30 days default (configurable)

### AI Proxy Architecture
```
┌─────────────────────────────────────────────────────────┐
│                    AI Proxy Service                      │
├─────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐                   │
│  │    Cache     │    │ Load Balancer│                   │
│  │   (Redis)    │    │              │                   │
│  └──────────────┘    └──────┬───────┘                   │
│                              │                           │
│         ┌────────────────────┼────────────────────┐     │
│         ▼                    ▼                    ▼     │
│  ┌─────────────┐     ┌─────────────┐     ┌───────────┐ │
│  │ Claude Keys │     │ OpenAI Keys │     │ Other     │ │
│  │   (Pool)    │     │   (Pool)    │     │ Providers │ │
│  └─────────────┘     └─────────────┘     └───────────┘ │
└─────────────────────────────────────────────────────────┘

Caching Strategy:
- Cache identical prompts: 15 minutes
- Cache vulnerability descriptions: 1 hour
- Expected cost reduction: 30-40%
```

---

## Team Roles (Enterprise)

| Role | Permissions |
|------|-------------|
| **Owner** | Full control, billing, manage all members, allocate tokens |
| **Admin** | Invite/remove members, view audit logs, allocate tokens |
| **Member** | Use features, view own usage only |

---

## Compliance Reports (Priority Order)

1. **SOC2** - First priority
2. **HIPAA** - Second
3. **PCI-DSS** - Third
4. ISO 27001 - Later
5. Others - As requested

---

## Binary Protection (Medium Level)

```bash
# Build flags
go build -ldflags="-s -w" -trimpath

# UPX compression
upx --best zypheron

# Obfuscation (garble) - optional
garble -literals -tiny build ./cmd/zypheron
```

Configurable in settings - users can disable for debugging.

---

## Implementation Phases

### Phase 1: Critical Fixes (Week 1-2) ✅ COMPLETED

| Task | Time | Status |
|------|------|--------|
| Fix socket permissions (P0 #1) | 2-4 hrs | ✅ DONE |
| Fix BYOK API key validation (P0 #2) | 1-2 hrs | ✅ DONE |
| Show missing tools list (P0 #4) | 2-3 hrs | ✅ DONE |
| Add AI aggressiveness config | 4-6 hrs | ✅ DONE |
| Implement exploit session warning | 2-3 hrs | ✅ DONE |

**Phase 1 Changes:**
- Socket permissions: Changed to 0600 (owner-only) for maximum security
- API key validation: Made patterns more flexible, added aliases (claude/gemini)
- Missing tools: Enhanced display with priority grouping and installation hints
- AI aggressiveness: Added conservative/balanced/aggressive modes with configurable thresholds
- Legal warning: Per-session acknowledgment for exploit/autopent/pwn commands

### Phase 2: Backend Infrastructure (Week 2-4)

| Task | Time | Status |
|------|------|--------|
| FastAPI project scaffold | 4 hrs | 🔴 TODO |
| Supabase schema setup | 2 hrs | 🔴 TODO |
| GitHub OAuth integration | 4 hrs | 🔴 TODO |
| Email/password auth | 3 hrs | 🔴 TODO |
| Stripe integration | 6 hrs | 🔴 TODO |
| License validation API | 4 hrs | 🔴 TODO |

### Phase 3: Feature Gating (Week 4-5)

| Task | Time | Status |
|------|------|--------|
| Go licensing module | 8 hrs | 🔴 TODO |
| Feature gate middleware | 4 hrs | 🔴 TODO |
| BYOK key management | 4 hrs | 🔴 TODO |
| Token tracking system | 6 hrs | 🔴 TODO |
| Upgrade prompts UI | 3 hrs | 🔴 TODO |

### Phase 4: AI Proxy (Week 5-6)

| Task | Time | Status |
|------|------|--------|
| Proxy service scaffold | 4 hrs | 🔴 TODO |
| Load balancer implementation | 6 hrs | 🔴 TODO |
| Redis caching layer | 4 hrs | 🔴 TODO |
| Token counting | 3 hrs | 🔴 TODO |
| Rate limiting per tier | 3 hrs | 🔴 TODO |

### Phase 5: Enterprise Features (Week 6-7)

| Task | Time | Status |
|------|------|--------|
| Team management API | 8 hrs | 🔴 TODO |
| Role-based permissions | 4 hrs | 🔴 TODO |
| Token pool allocation | 4 hrs | 🔴 TODO |
| Audit logging | 4 hrs | 🔴 TODO |
| SOC2 report template | 6 hrs | 🔴 TODO |
| HIPAA report template | 6 hrs | 🔴 TODO |
| White-label reports | 4 hrs | 🔴 TODO |

### Phase 6: TUI Dashboard (Week 7-8)

| Task | Time | Status |
|------|------|--------|
| Bubbletea scaffold | 4 hrs | 🔴 TODO |
| Split-pane layout | 6 hrs | 🔴 TODO |
| Vim keybindings | 3 hrs | 🔴 TODO |
| Real-time scan display | 4 hrs | 🔴 TODO |
| Findings panel | 4 hrs | 🔴 TODO |
| Export functionality | 3 hrs | 🔴 TODO |

### Phase 7: Testing & Launch (Week 8)

| Task | Time | Status |
|------|------|--------|
| OSCP benchmark tests | 8 hrs | 🔴 TODO |
| Integration testing | 8 hrs | 🔴 TODO |
| Security audit | 4 hrs | 🔴 TODO |
| Documentation | 4 hrs | 🔴 TODO |
| Soft launch | - | 🔴 TODO |

---

## TUI Dashboard Design

### Layout (Split-pane, Vim bindings)
```
┌─────────────────────────────────────────────────────────────┐
│ ZYPHERON TUI                              [q]uit [?]help    │
├────────────────────────────┬────────────────────────────────┤
│ SCAN STATUS                │ FINDINGS                       │
│                            │                                │
│ Target: 192.168.1.0/24     │ ● CRITICAL: 3                  │
│ Progress: ████████░░ 80%   │ ● HIGH: 7                      │
│ Ports scanned: 45,000      │ ● MEDIUM: 12                   │
│                            │ ● LOW: 23                      │
│ Open ports found: 127      │                                │
│                            │ [Press 'a' for all findings]   │
├────────────────────────────┴────────────────────────────────┤
│ LIVE OUTPUT                                                  │
│ [*] Scanning 192.168.1.45:443 - HTTPS detected              │
│ [+] Found: Apache/2.4.41 - CVE-2021-41773 possible          │
│ [*] Scanning 192.168.1.45:8080 - HTTP proxy                 │
│ [!] Warning: Rate limit approaching on target               │
└─────────────────────────────────────────────────────────────┘
```

### Key Bindings
```
Navigation:
  j/k     - Navigate up/down
  h/l     - Switch panes
  g/G     - Go to top/bottom
  Ctrl+u  - Page up
  Ctrl+d  - Page down

Actions:
  /       - Search findings
  a       - Show all (toggle important only vs all)
  f       - Filter findings by severity
  s       - Sort findings
  r       - Refresh

Commands:
  :w      - Save report
  :export - Export findings (md, json, pdf)
  :q      - Quit
  :help   - Show help
```

### Metrics Displayed
- Vulnerabilities found (by severity)
- Open ports discovered
- Major findings only (default)
- "Show all" option for complete list

---

## Legal Warning (Exploitation)

Shown once per session on first exploit/post-exploit command:

```
╔═══════════════════════════════════════════════════════════════════╗
║                    ⚠️  ENTERING EXPLOITATION MODE                  ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                    ║
║  You are about to execute exploitation/post-exploitation tools.   ║
║                                                                    ║
║  By proceeding, you confirm:                                       ║
║    ✓ You have explicit written authorization to test this target  ║
║    ✓ You understand the legal implications of these actions       ║
║    ✓ You accept full responsibility for your actions              ║
║                                                                    ║
║  Unauthorized access to computer systems is illegal and may       ║
║  result in criminal prosecution.                                   ║
║                                                                    ║
║  Press [y] to proceed for this session                            ║
║  Press [n] to cancel                                               ║
║                                                                    ║
╚═══════════════════════════════════════════════════════════════════╝
```

- Displays on first exploit command per session
- Logs acknowledgment with timestamp
- Enterprise: Recorded in audit log

---

## OSCP Benchmark Testing

### Metrics
| Metric | Target | Purpose |
|--------|--------|---------|
| **Time to root** | < 2 hours per box | Sales benchmark |
| **Technique coverage** | 80%+ OSCP syllabus | Feature completeness |
| **Success rate** | 90%+ on known vulns | Reliability |

### Test Environment
- Docker containers with known vulnerabilities
- VMs for realistic Windows/Linux testing
- Automated regression testing
- CI/CD integration (later phase)

---

## Future Features (Post-Launch)

### Deferred Items
- [ ] Student/education discount (20% off)
- [ ] SSO/SAML integration
- [ ] Plugin marketplace
- [ ] Plugin monetization (revenue share)
- [ ] Web dashboard integration
- [ ] Distributed scanning (P2P, mDNS)
- [ ] Custom ML models (PyTorch)
- [ ] Threat intel integration (OTX, VirusTotal)
- [ ] Attack graph visualization
- [ ] Continuous monitoring
- [ ] Scan resume/checkpoint

### Plugin System (Future)
- Languages: Go, Python
- Distribution: Local files + Git repos
- Sandboxing: Optional
- Monetization: Revenue share model

---

## Timeline Summary

```
Week 1-2:  Phase 1 - Critical fixes (socket, BYOK, warnings)
Week 2-4:  Phase 2 - Backend API (auth, Stripe, Supabase)
Week 4-5:  Phase 3 - Feature gating + license validation
Week 5-6:  Phase 4 - AI proxy with caching/load balancing
Week 6-7:  Phase 5 - Enterprise features (teams, compliance)
Week 7-8:  Phase 6 - TUI dashboard + polish
Week 8:    Phase 7 - Testing, bug fixes, soft launch
```

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Dec 2024 | Initial plan based on requirements gathering |

---

**Next Action**: Execute Phase 1 critical fixes
