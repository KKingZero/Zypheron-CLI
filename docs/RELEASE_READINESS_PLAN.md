# Release Readiness Plan

This plan captures the remaining repository polish items that should be handled
after the contributor metadata and `goreleaser` configuration are in place.

## 1. Align versioning for `v2.0.0`

Current state:

- The active CLI build path is already set to `2.0.0`.
- Some docs and status snapshots still reference `1.x` or an undecided next release.
- API package metadata still reports `0.1.0`, which is confusing during `v2.0.0` release prep.

Recommended execution order:

1. Use `v2.0.0` as the next public release tag.
2. Update the version in:
   - `zypheron-go/cmd/zypheron/main.go`
   - `zypheron-go/internal/updater/updater.go`
   - `zypheron-go/Makefile`
   - `zypheron-api/pyproject.toml`
   - `zypheron-api/app/core/config.py`
   - `zypheron-api/app/__init__.py`
3. Grep for stale version references in install/docs/release files and update the user-facing ones.
4. Build at least one local binary and verify `zypheron --version` returns the intended release number.
5. Create the `v2.0.0` tag only after the above is consistent.

## 2. Triage the remaining Go TODO backlog

Current scan of Go source shows more than five TODOs, so the previous review note
is understated. The actionable ones fall into these buckets:

### A. Shipping blockers or user-visible gaps

- `zypheron-go/internal/updater/updater.go`
  - Verify downloaded checksums
  - Extract release archives
  - Replace the installed binary safely
- `zypheron-go/internal/commands/dork.go`
  - Integrate the command with the AI bridge when that path is ready
- `zypheron-go/internal/commands/workflow.go`
  - Persist and list workflows from storage

### B. Export/reporting gaps

- `zypheron-go/internal/reports/formats.go`
  - HTML export
  - Markdown export
  - PDF export
  - Configurable HTML export
  - Configurable Markdown export

### C. Legacy TUI cleanup

- `zypheron-go/internal/tui/components/_legacy/results.go`
  - Export dialog wiring
- `zypheron-go/internal/tui/components/_legacy/history.go`
  - Actual scan execution
  - Scan re-run
  - Proper viewport scrolling

### D. Nice-to-have command integrations

- `zypheron-go/internal/commands/bounty.go`
  - API-based scope fetching

Recommended execution order:

1. Separate TODOs into `release-blocking`, `post-release`, and `legacy`.
2. Convert each remaining TODO into a GitHub issue with acceptance criteria.
3. Remove or resolve any TODO that is no longer a real roadmap item.
4. For release-blocking work, add tests before implementation where the path is risky.
5. Leave `_legacy` TODOs explicitly out of the milestone if they are not part of the maintained UX.

## 3. Integrate Goreleaser into the release pipeline

Current state:

- `.github/workflows/release.yml` already builds archives and publishes GitHub releases plus S3 artifacts.
- `.goreleaser.yml` now exists, but the workflow does not invoke it yet.

Recommended execution order:

1. Decide whether `goreleaser` replaces the custom build job or only produces GitHub release artifacts.
2. If replacing the build job, update `.github/workflows/release.yml` to use the official `goreleaser/goreleaser-action`.
3. Ensure the generated asset names remain compatible with:
   - `scripts/install.sh`
   - S3 upload paths
   - any downstream docs that reference archive names
4. Run a dry run locally or in CI with `goreleaser release --snapshot --clean`.
5. Only remove custom archive logic after the output matches expectations.

## 4. Harden ownership and contribution flow

Current state:

- `CODEOWNERS` has been added with a single default owner.

Recommended follow-up:

1. Expand ownership rules if collaborators join.
2. Replace the single-user mapping with teams once the GitHub org structure exists.
3. Add required reviews in branch protection so `CODEOWNERS` has an actual effect.

## 5. Keep the release local-first

The active release assumptions for `v2.0.0` are:

- no external hosted database requirement
- local CLI usage is the primary supported path
- optional API/Redis/Prometheus services must be documented as optional

Before tagging `v2.0.0`, confirm the active docs and defaults reflect that model.
