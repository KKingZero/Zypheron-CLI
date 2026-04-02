# Zypheron Production Implementation Plan

> Status: historical planning note, superseded by the current OSS release plan
> Last reviewed: 2026-04-02

## Current Source of Truth

Use these files instead:

- `PRODUCTION_PLAN.md`
- `docs/RELEASE_READINESS_PLAN.md`
- `docs/DEV_STATUS.md`

## Current Direction

Zypheron is being prepared as a free, open source, local-first release.

- local CLI usage is the primary path
- self-hosted API mode is optional
- SQLite should remain the zero-config default
- PostgreSQL, Redis, and Prometheus are optional add-ons
- offline and constrained-environment testing should work cleanly

## Active Priorities

1. Remove stale hosted-service assumptions from docs and defaults.
2. Make Python and API setup reproducible in offline or restricted environments.
3. Keep lockfiles and release metadata consistent across the repo.
4. Maintain repeatable smoke tests for CLI, API, AI runtime, and TUI approval flows.
5. Keep optional-service behavior explicit and fail-soft.

## Note

If you encounter older files that assume a different deployment model, prefer the
current release documents listed above.
