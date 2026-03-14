# Zypheron - Production Readiness Plan

> What's been done, and what remains before production deployment.
>
> Last updated: 2026-02-14

---

## Completed Work Summary

### Milestone 1: API Backend Merge
Merged two separate backends (`api-server/` + `zypheron-api/`) into a single unified FastAPI application.

### Milestone 2: Stripe Billing
Annual billing (25% discount), billing portal, subscription reactivation, prices endpoint, webhook idempotency (OrderedDict LRU + Redis), dunning/grace period with auto-suspend.

### Milestone 3: AI Proxy
Load balancer with per-key health tracking, response caching (in-memory + Redis + gzip), token quota tracking, BYOK key support (AES-256-GCM), 5 providers (OpenAI, Anthropic, Grok, DeepSeek, Ollama).

### Milestone 4: Monitoring
Prometheus metrics (`http_requests_total`, `ai_requests_total`, cache hits/misses, `rate_limit_exceeded`), metrics middleware, `/metrics` endpoint with IP + token auth, enhanced `/health` with component checks.

### Milestone 5: Infrastructure
Dockerfile + Dockerfile.test, docker-compose.yml (API + Postgres + Redis + pgAdmin + Prometheus + test-runner), Podman support, AWS Terraform (S3 + CloudFront), install.sh, CI/CD workflows.

### Milestone 6: Security Code Review (22 Issues Fixed)
Open redirect prevention, metrics auth, error sanitization, JWT 7-day expiry, webhook idempotency eviction, Stripe metadata null safety, deprecated API migration, cache TTL tightening, docker-compose port binding.

### Milestone 7: Integration Tests
58 tests covering all code review fixes, Stripe webhooks, subscription endpoints, AI proxy (6 test files, 2656 lines), containerized test runner.

---

## What Remains Before Production

### CRITICAL (Must fix before production)

**1. API test environment not reproducible in offline/local constrained environments**
- `pip install -e ".[dev]"` fails without package index access
- Impact: cannot validate API tests locally in restricted runners
- Fix: ensure internal package mirror or prebuilt dependency cache

**2. Stripe production price IDs still unset in runtime config**
- `stripe_price_id_*` values default to `None`
- Fix: create prices in Stripe and set production secrets/env

### HIGH (Should fix before production)

**3. Migration workflow must be validated in deployment pipeline**
- Alembic exists with initial migration, but deployment runbook validation remains
- Fix: run `alembic upgrade head` in staging/prod workflow and add rollback procedure

**4. Finalize lockfile process for Python dependencies**
- Direct dependencies are pinned and `requirements.lock` added; transitive lock generation still needs CI automation
- Fix: add/validate lock generation in CI and enforce install from lock for releases

**5. Confirm production domain values with deployment owner**
- Defaults now point to production URLs in code
- Fix: verify `BASE_URL`, frontend URL, and CORS origin list against actual deployed domains

### MEDIUM (Should fix before public release)

**6. Validate narrowed CORS list**
- Wildcard subdomain removed; explicit origins configured
- Fix: verify final set against all frontend environments

**7. AWS infrastructure deployment validation**
- Terraform config exists; deployment/verification checklist still required

**8. End-to-end smoke validation pending**
- Run CLI->API auth, license, AI proxy, webhook, and metrics flows in staging/prod-like environment

### LOW (Polish before GA)

**11. Structured logging inconsistent**
- Some files use `structlog`, others use stdlib `logging`
- Fix: Standardize on one approach (recommend `structlog` throughout)

**12. api-server/ deprecation**
- Old backend directory still exists in repo
- Fix: Remove or archive once confident the merged `zypheron-api/` is stable in production

---

## Recommended Order of Operations

1. Finalize production domain/CORS values with deployment owner
2. Configure Stripe products and set all production price IDs
3. Validate Alembic migration + rollback runbook in staging
4. Enforce locked dependency installation in CI/release path
5. Apply and verify AWS Terraform infrastructure
6. Run full staging smoke tests (CLI + API + billing + AI proxy + metrics)
7. Standardize logging (item 11)
8. Remove/retire `api-server/` (item 12)
