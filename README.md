<div align="center">
  <h1>Zypheron CLI</h1>
  <h3>AI-native offensive security CLI for real operator workflows</h3>

  <p>
    <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
    <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white" alt="Python"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License"></a>
    <a href=".github/ISSUE_TEMPLATE/bug_report.md"><img src="https://img.shields.io/badge/Issues-Bug%20Reports-2ea44f" alt="Issues"></a>
  </p>

  <p>Terminal-first recon, scanning, AI-assisted workflows, and operator tooling in one open source project.</p>

  <p>
    <a href="docs/CHANGELOG.md">Changelog</a> •
    <a href="#install">Install</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#common-commands">Commands</a> •
    <a href="#documentation">Docs</a>
  </p>
</div>

---

## Overview

Zypheron CLI is an AI-native security CLI built around practical terminal workflows rather than disconnected scripts and raw output dumps.

It combines:

- A Go-based CLI and TUI
- AI model integration across local and hosted providers
- Toolchain-aware workflows for recon, scanning, and operator tasks
- Local session, loot, and artifact storage under `~/.zypheron`
- Bootstrap and release installers for both source-based and packaged installs

This repository is the open source CLI. It is intended for authorized security testing, research, and operator workflow automation.

Zypheron is free and open source. This repository should be treated as a local-first security CLI and self-hostable tooling project.

### OSS RC Scope

The production release candidate targets the local/self-hosted OSS path: Go CLI,
Python AI runtime, optional FastAPI service, local tool orchestration, and
packaged CLI artifacts. Hosted SaaS-only surfaces are not launch blockers for
this RC.

Deferred for the OSS RC:

- Enterprise Teams API endpoints may return `501 Not Implemented`
- streaming chat protocol support; chat currently uses the non-streaming path
- full autonomous exploitation; autopent remains approval-gated and safety-first
- hosted billing/dashboard production polish

## Install

Three install paths — pick one.

### 1. Bootstrap from source (recommended)

Full repo, local development workflow, automated dependency setup.

```bash
git clone https://github.com/KKingZero/Zypheron-CLI.git
cd Zypheron-CLI
bash scripts/install/setup-hybrid.sh
```

`setup-hybrid.sh` builds the Go CLI into `~/.local/bin/zypheron`, runs `zypheron install-deps` for Python dependencies, and installs bash/zsh completion.

Common overrides:

```bash
# Custom install dir
ZYPHERON_INSTALL_DIR="$HOME/.local/bin" bash scripts/install/setup-hybrid.sh

# Skip external tool install (manage them yourself)
ZYPHERON_INSTALL_TOOLS=none bash scripts/install/setup-hybrid.sh

# Install every supported external tool
ZYPHERON_INSTALL_TOOLS=all bash scripts/install/setup-hybrid.sh
```

### Manual setup / repair commands

Use these if the bootstrap fails with missing Go checksums, a missing `zypheron`
command, or Python dependency errors.

```bash
# From the repo root
cd Zypheron-CLI

# Generate missing Go checksums
cd zypheron-go
go mod tidy

# Build and install the CLI locally
mkdir -p "$HOME/.local/bin"
go build -o "$HOME/.local/bin/zypheron" ./cmd/zypheron
export PATH="$HOME/.local/bin:$PATH"

# Confirm the CLI is installed
zypheron --version
zypheron --help

# Install Python AI engine dependencies
cd ..
zypheron install-deps

# Optional large dependency packs
zypheron install-deps --security --web --mcp
zypheron install-deps --all

# Check the full install
zypheron doctor
```

If `zypheron` is still not found, add this to your shell profile:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### 2. Release binary

Packaged CLI without cloning the repo.

```bash
curl -sSfL https://download.zypheron.net/install.sh | bash
```

Overrides:

```bash
ZYPHERON_VERSION=v2.0.0 curl -sSfL https://download.zypheron.net/install.sh | bash
ZYPHERON_INSTALL_DIR="$HOME/.local/bin" curl -sSfL https://download.zypheron.net/install.sh | bash
```

The release installer detects OS/arch, downloads the matching archive + `SHA256SUMS`, verifies the checksum, and installs the `zypheron` binary.

### 3. Pentest tools only (per-distro installers)

Standalone installers for external tools (hydra, nuclei, amass, metasploit, ropper, volatility3, one_gadget, ghidra, SecLists, rockyou). Use these when you already have the Zypheron CLI installed and just need the tool ecosystem.

```bash
# Debian / Ubuntu / Kali / Parrot / Mint / Pop!_OS / elementary
sudo bash scripts/install/install-tools.sh

# Arch / Manjaro / EndeavourOS / Garuda / BlackArch
sudo bash scripts/install/install-tools-arch.sh

# Fedora / RHEL 8+ / CentOS Stream / Rocky / Alma / Oracle Linux / Amazon Linux 2023
sudo bash scripts/install/install-tools-rpm.sh
```

All three installers share the same env-flag surface:

| Flag | Effect |
|---|---|
| `ZYPHERON_MIN_FREE_MB=<mb>` | Override disk preflight (default `3072` = 3 GB) |
| `ZYPHERON_ALLOW_REMOTE_INSTALLERS=1` | Enable Metasploit omnibus fallback (pinned commit + SHA256) |
| `ZYPHERON_BUILD_GO=1` | Also build `zypheron-go` from source when present |
| `ZYPHERON_GO_DL_VERSION=1.24.2` | Go tarball version to pull from go.dev when apt/pacman/dnf is too old |
| `ZYPHERON_INSTALL_LOG=<path>` | Log destination (default `/var/log/zypheron-install.log`) |

Arch-only flags:

| Flag | Effect |
|---|---|
| `ZYPHERON_ENABLE_BLACKARCH=1` | Enable BlackArch pacman repo (SHA256-pinned `strap.sh`) |
| `ZYPHERON_AUR_HELPER=paru\|yay` | Preferred AUR helper (default: paru, falls back to yay, bootstraps paru-bin if neither present) |
| `ZYPHERON_ALLOW_AUR_SKIPREVIEW=1` | Skip interactive PKGBUILD review (off by default, not recommended) |

### 4. Optional: C2 frameworks (Sliver, Empire)

Interactive installer, never auto-runs from the main installers.

```bash
sudo bash scripts/install/install-c2.sh
```

- **Sliver** installs from Kali/Parrot apt when available, otherwise from a pinned GitHub release tarball verified against an embedded SHA256. Set `ZYPHERON_ALLOW_UNVERIFIED_SLIVER=1` to fall through to the upstream `curl | bash` installer (not recommended).
- **Empire** installs from `powershell-empire` apt pkg on Kali/Parrot; otherwise clones `BC-SECURITY/Empire` into `/opt/Empire` (override with `ZYPHERON_EMPIRE_DIR`) and runs `./setup/install.sh` after consent.
- **Havoc** is intentionally excluded — install manually from the upstream project.

After install, Empire usage via `zypheron exploit --c2 empire` expects:

```bash
export EMPIRE_HOST=https://127.0.0.1:1337
export EMPIRE_USER=<username>
export EMPIRE_PASS=<password>
# Optional, loopback/RFC1918 only:
export EMPIRE_INSECURE_TLS=1
```

## Quick Start

Shortest end-to-end path for a new box:

```bash
# 1. Clone + bootstrap
git clone https://github.com/KKingZero/Zypheron-CLI.git
cd Zypheron-CLI
bash scripts/install/setup-hybrid.sh

# 2. Install the external pentest tool ecosystem (pick one)
sudo bash scripts/install/install-tools.sh          # Debian / Ubuntu / Kali / Parrot / Mint
sudo bash scripts/install/install-tools-arch.sh     # Arch / Manjaro / BlackArch
sudo bash scripts/install/install-tools-rpm.sh      # Fedora / RHEL / Rocky / Alma

# 3. Verify
zypheron doctor
zypheron tools check

# 4. Launch
zypheron
```

Optional follow-ups:

```bash
# C2 frameworks (Sliver, Empire) — interactive, opt-in per framework
sudo bash scripts/install/install-c2.sh

# Install Python-side AI/ML dependencies
zypheron install-deps --all

# Check CLI version
zypheron --version
```

## Release Validation

For a clean release-candidate gate from source:

```bash
./scripts/setup_api_test_env.sh --allow-online
./scripts/setup_ai_test_env.sh --allow-online
./scripts/run_all_tests.sh --ci
./scripts/local_smoke_test.sh --setup-api-env --allow-online
```

`run_all_tests.sh --ci` runs the API tests, AI runtime tests, Go tests with a
workspace `GOTMPDIR`, and integration checks.

## What It Does

Zypheron CLI is built for operator workflow acceleration, not just command wrapping.

Current project capabilities include:

- AI-assisted terminal workflows
- Interactive TUI with model selection and persisted provider/model settings
- Recon, scanning, and structured terminal output flows
- Workflow execution and session storage
- Dorking and AI-guided query enhancement
- Active Directory, cloud, and broader offensive workflow modules in the CLI
- Integration points for common security tools and local model runtimes
- Updater support for packaged releases

The project is terminal-first. Some workflows depend on external tools being installed locally.

## Common Commands

```bash
# TUI
zypheron
zypheron tui

# Health checks
zypheron doctor
zypheron install-deps --all

# Scan and recon
zypheron scan example.com
zypheron scan example.com --web
zypheron recon example.com

# AI-assisted dorking
zypheron dork "exposed login portals"
zypheron dork "admin panels" --ai-guided

# AI chat
zypheron chat "How would you approach this target?"

# Workflows and sessions
zypheron workflow list
zypheron autopent example.com

# Tooling and environment
zypheron tools check
zypheron tools install-all --critical-only --yes

# Updates
zypheron update check
```

Run `zypheron --help` or `zypheron <command> --help` for the current command surface in your build.

## Setup Notes

### AI providers and models

Zypheron supports local and hosted model providers. In the TUI, selecting a hosted model without a configured API key now prompts for the key and stores it for reuse.

Typical provider setup paths:

- Local models through Ollama
- Hosted models through provider API keys in Zypheron config/key storage

If you want to verify your environment after setup:

```bash
zypheron doctor
zypheron
```

### External tools

Many workflows call external tools. Either let `setup-hybrid.sh` install the critical set:

```bash
ZYPHERON_INSTALL_TOOLS=critical bash scripts/install/setup-hybrid.sh
```

Or skip that step and run the dedicated per-distro installer afterwards (bigger tool set, hardened with pinned versions + SHA256-verified remote installers):

```bash
ZYPHERON_INSTALL_TOOLS=none bash scripts/install/setup-hybrid.sh

# Then one of:
sudo bash scripts/install/install-tools.sh          # Debian / Ubuntu / Kali / Parrot
sudo bash scripts/install/install-tools-arch.sh     # Arch family
sudo bash scripts/install/install-tools-rpm.sh      # RedHat / Fedora family

zypheron tools check
```

### C2 frameworks

Sliver and Empire are not installed by the main installer. Opt in with:

```bash
sudo bash scripts/install/install-c2.sh
```

See the [Install](#install) section for details on verification and env flags.

## Requirements

Minimum local requirements:

- Go `1.24+` for source bootstrap and local builds
- Python `3.9+`
- Linux, macOS, or WSL

Kali or a similarly equipped Linux environment is recommended for heavier offensive workflows.

## Documentation

| Guide | Description |
|---|---|
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Fast install and first run |
| [docs/INSTALL.md](docs/INSTALL.md) | Installation and environment setup |
| [docs/SETUP_AND_USE.md](docs/SETUP_AND_USE.md) | Practical setup and usage |
| [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) | CLI command reference |
| [docs/AI_GUIDE.md](docs/AI_GUIDE.md) | AI providers, keys, and model behavior |
| [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) | MCP and integration details |
| [docs/TOOL_CHAINS.md](docs/TOOL_CHAINS.md) | Toolchain workflows |
| [docs/BUILD_AND_TEST.md](docs/BUILD_AND_TEST.md) | Local build and validation |
| [docs/HELP.md](docs/HELP.md) | Troubleshooting |

## Repository Notes

- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [.github/ISSUE_TEMPLATE/bug_report.md](.github/ISSUE_TEMPLATE/bug_report.md)
- [.github/ISSUE_TEMPLATE/feature_request.md](.github/ISSUE_TEMPLATE/feature_request.md)
- [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md)

## Legal

For authorized security testing only. Always obtain written permission before scanning, exploiting, or interacting with systems you do not own.

## License

MIT License. See [LICENSE](LICENSE).
