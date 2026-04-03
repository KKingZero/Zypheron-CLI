# Zypheron Go CLI

This directory contains the Go-based CLI and TUI for Zypheron.

For most users, start with the root project README:

- [../README.md](../README.md)

## What Lives Here

- `cmd/zypheron` - CLI entrypoint
- `internal/commands` - Cobra command implementations
- `internal/tui` - terminal UI
- `internal/updater` - update checking and packaged release update flow
- `internal/tools` - external tool integration and execution
- `internal/config` - configuration and provider key management

## Local Build

From this directory:

```bash
go build -o zypheron ./cmd/zypheron
./zypheron --version
```

Or from the repo root, use the supported bootstrap:

```bash
bash ./setup-hybrid.sh
```

## Useful Commands

```bash
./zypheron
./zypheron doctor
./zypheron install-deps --all
./zypheron tools check
./zypheron ai status
```

## Docs

- [../docs/INSTALL.md](../docs/INSTALL.md)
- [../docs/SETUP_AND_USE.md](../docs/SETUP_AND_USE.md)
- [../docs/AI_GUIDE.md](../docs/AI_GUIDE.md)
- [../docs/CLI_REFERENCE.md](../docs/CLI_REFERENCE.md)

## Notes

- This Go CLI is the primary user-facing interface for the project.
- Some broader product and historical documents in this repository may describe older plans or archived states.
- Use command help output as the source of truth for your current build.
