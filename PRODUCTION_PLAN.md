# Zypheron - Production Readiness Plan

> What's been done, and what remains before a local-first open source release.
>
> Last updated: 2026-03-16

---

## Completed Work Summary

### Milestone 1: API Backend Merge
Merged two separate backends (`api-server/` + `zypheron-api/`) into a single unified FastAPI application.

### Milestone 2: Local-First AI Proxy
Load balancer with per-key health tracking, response caching (in-memory + Redis + gzip), token quota tracking, BYOK key support (AES-256-GCM), 5 providers (OpenAI, Anthropic, Grok, DeepSeek, Ollama).

### Milestone 3: Monitoring
Prometheus metrics (`http_requests_total`, `ai_requests_total`, cache hits/misses, `rate_limit_exceeded`), metrics middleware, `/metrics` endpoint with IP + token auth, enhanced `/health` with component checks.

### Milestone 4: Packaging and Local Infrastructure
Dockerfile + Dockerfile.test, docker-compose.yml, Podman support, install.sh, and CI workflows are in place. Redis/Prometheus remain optional runtime components, not release prerequisites.

### Milestone 5: Security Code Review (22 Issues Fixed)
Open redirect prevention, metrics auth, error sanitization, JWT expiry tightening, deprecated API migration, cache TTL tightening, and docker-compose port binding fixes are in place.

### Milestone 6: Integration Tests
Integration coverage exists for the API and AI proxy paths, with a containerized test runner for reproducible validation.

---

## Release Constraints

- Zypheron is being prepared as a free and open source release.
- An external hosted database is not a release requirement.
- Local execution and optional self-hosted services are the default operating model.

---

## What Remains Before Release

### CRITICAL (Must fix before production)

**1. API test environment not reproducible in offline/local constrained environments**
- `pip install -e ".[dev]"` fails without package index access
- Impact: cannot validate API tests locally in restricted runners
- Fix: ensure internal package mirror or prebuilt dependency cache

**2. Release defaults still imply hosted deployment assumptions**
- Some docs/config still reference production domains, hosted services, or SaaS-era workflows
- Impact: users can misconfigure local installs or assume hosted dependencies are required
- Fix: audit defaults and docs so local/offline operation is the primary documented path

### HIGH (Should fix before production)

**3. Finalize lockfile process for Python dependencies**
- Direct dependencies are pinned and `requirements.lock` added; transitive lock generation still needs CI automation
- Fix: add/validate lock generation in CI and enforce install from lock for releases

**4. End-to-end local smoke validation is still pending**
- Run CLI -> local API -> AI proxy -> metrics flows in a local or containerized environment
- Fix: define and execute a repeatable smoke test script for OSS release validation

**5. Optional service boundaries need to be explicit**
- Redis, Prometheus, and any API server mode should be clearly documented as optional or required per feature
- Fix: document fallback behavior and fail-soft expectations when optional services are absent

### MEDIUM (Should fix before public release)

**6. Versioning and release metadata need one final pass**
- User-facing version references may drift across CLI, updater, Makefile, and release docs
- Fix: align version strings and verify `zypheron --version` matches the release target

**7. Structured logging remains inconsistent**
- Some files use `structlog`, others use stdlib `logging`
- Fix: standardize on one logging approach for easier local debugging and support

**8. Packaging and installation need final verification**
- Install scripts, container flow, and dependency bootstrap need one clean validation pass on a fresh machine/user profile
- Fix: run install + basic command smoke tests from a clean environment

### LOW (Polish before GA)

**9. `api-server/` deprecation**
- Old backend directory still exists in repo
- Fix: Remove or archive once confident the merged `zypheron-api/` is stable in production

---

## Recommended Order of Operations

1. Make local/offline execution the documented default and remove hosted-service assumptions from config/docs
2. Fix offline/restricted dependency installation for API tests
3. Enforce locked dependency installation in CI/release paths
4. Run full local smoke tests for CLI, API, AI proxy, and metrics
5. Document optional-service behavior for Redis, Prometheus, and API mode
6. Align versioning and release metadata
7. Standardize logging
8. Validate install/bootstrap on a clean environment
9. Remove or archive `api-server/` when the merged backend is confirmed stable
