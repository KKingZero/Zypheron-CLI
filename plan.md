# Zypheron CLI C2 + CLI Polish Plan

## Summary

Finish the current C2 integration and CLI polish work as a scoped hardening pass. The goal is to make C2 operations operator-controlled, improve shell/JSON UX, keep installer guidance aligned with the docs, and verify the changed behavior with focused tests plus broad suite runs.

## Implementation Scope

- Add guided C2 workflow support through `zypheron exploit --c2 <framework> --guided`.
- Keep C2 actions explicit: listing sessions/agents is the default, listener creation requires `--listener`, and guided mode must not generate payloads or run autonomous exploitation.
- Support C2 completions for `--c2` and `--listener`.
- Ensure Metasploit C2 execution uses `msfconsole`.
- Validate listener types before invoking external C2 tooling.
- Add `zypheron completion bash|zsh|fish`.
- Make `zypheron scan ... --format json` non-interactive, non-streaming, and JSON-only on stdout.
- Keep optional C2 frameworks out of bulk installs and point Sliver/Empire users to `scripts/install/install-c2.sh`.
- Update live docs: `README.md`, `docs/CLI_REFERENCE.md`, and `docs/INSTALL.md`.

## Review Focus

- C2 safety boundary: guided mode must remain setup-only unless the operator also supplies an explicit action such as `--listener`.
- C2 executable routing: Sliver/Havoc use their framework binary, Empire uses REST API env vars, and Metasploit uses `msfconsole`.
- Machine-readable output: JSON scan mode must not print banners, spinners, warnings, styled text, or storage notices to stdout.
- Backward compatibility: normal scan text output, existing report generation, and existing tool detection should continue to work.
- Documentation consistency: CLI examples and installer guidance should match implemented flags and paths.

## Test Plan

- Run focused Go tests:
  - `go test ./internal/commands ./internal/c2/empire ./internal/tools`
- Run broad Go tests:
  - `go test ./...`
  - Use workspace-local `GOCACHE`, `GOTMPDIR`, and `CCACHE_DIR` when `/home` cache is read-only or `/tmp` is mounted `noexec`.
- Run Python tests where dependencies are available:
  - `zypheron-ai`: `python -m pytest tests -q -o addopts=''`
  - `zypheron-api`: `python -m pytest tests -q`
- Record environment-blocked failures separately from product failures. Known blockers in this sandbox:
  - Go `internal/desktopbridge` tests require local socket listeners.
  - Some Python envs may lack dependencies such as `pytest`, `loguru`, `networkx`, or `stripe`.

## Acceptance Criteria

- Focused Go tests for changed packages pass.
- Broad Go suite has no failures except documented sandbox listener restrictions.
- Python suites either pass in their virtualenvs or fail only on missing local dependencies.
- No generated cache, coverage, or temp artifacts remain in the working tree.
- Review findings are either fixed or documented with file/line references.
