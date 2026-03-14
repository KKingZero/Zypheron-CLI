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
    <a href="CHANGELOG.md">Changelog</a> •
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

## Install

There are two primary install paths.

### Option 1: Bootstrap from source

Use this if you want the full repo, local development workflow, and automated dependency setup.

```bash
git clone https://github.com/KKingZero/Zypheron-CLI.git
cd Zypheron-CLI
bash ./setup-hybrid.sh
```

What `setup-hybrid.sh` does:

- Builds the Go CLI into `~/.local/bin/zypheron` by default
- Runs `zypheron install-deps` for Python-side dependencies
- Installs shell completion for `bash` or `zsh` when possible
- Optionally installs missing external tools

Useful bootstrap options:

```bash
ZYPHERON_INSTALL_DIR="$HOME/.local/bin" bash ./setup-hybrid.sh
ZYPHERON_INSTALL_TOOLS=none bash ./setup-hybrid.sh
ZYPHERON_INSTALL_TOOLS=all bash ./setup-hybrid.sh
ZYPHERON_DEP_PACKS=core bash ./setup-hybrid.sh
```

### Option 2: Install a release binary

Use this if you want the packaged CLI without cloning the repo.

```bash
curl -sSfL https://download.zypheron.net/install.sh | bash
```

Useful installer options:

```bash
ZYPHERON_VERSION=v2.0.0 curl -sSfL https://download.zypheron.net/install.sh | bash
ZYPHERON_INSTALL_DIR="$HOME/.local/bin" curl -sSfL https://download.zypheron.net/install.sh | bash
```

The release installer:

- Detects OS and architecture
- Downloads the matching archive and `SHA256SUMS`
- Verifies the checksum when checksum tools are available
- Installs the `zypheron` binary into the target directory

## Quick Start

```bash
# Launch the terminal UI
zypheron

# Verify local setup
zypheron doctor

# Install Python-side dependencies if needed
zypheron install-deps --all

# Check CLI version
zypheron --version
```

For a fresh source install, the shortest path is:

```bash
git clone https://github.com/KKingZero/Zypheron-CLI.git && cd Zypheron-CLI && bash ./setup-hybrid.sh
```

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
zypheron tools status
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

Many workflows call external tools. `setup-hybrid.sh` can install critical tools automatically:

```bash
ZYPHERON_INSTALL_TOOLS=critical bash ./setup-hybrid.sh
```

If you prefer to manage them yourself:

```bash
ZYPHERON_INSTALL_TOOLS=none bash ./setup-hybrid.sh
zypheron tools status
```

## Requirements

Minimum local requirements:

- Go `1.24+` for source bootstrap and local builds
- Python `3.9+`
- Linux, macOS, or WSL

Kali or a similarly equipped Linux environment is recommended for heavier offensive workflows.

## Documentation

| Guide | Description |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | Installation and environment setup |
| [docs/SETUP_AND_USE.md](docs/SETUP_AND_USE.md) | Practical setup and usage |
| [docs/GO_GUIDE.md](docs/GO_GUIDE.md) | Go CLI reference |
| [docs/AI_GUIDE.md](docs/AI_GUIDE.md) | AI providers, keys, and model behavior |
| [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) | MCP and integration details |
| [docs/TOOL_CHAINS.md](docs/TOOL_CHAINS.md) | Toolchain workflows |
| [HELP.md](HELP.md) | Troubleshooting |

## Repository Notes

- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [.github/ISSUE_TEMPLATE/bug_report.md](.github/ISSUE_TEMPLATE/bug_report.md)
- [.github/ISSUE_TEMPLATE/feature_request.md](.github/ISSUE_TEMPLATE/feature_request.md)
- [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md)

## Legal

For authorized security testing only. Always obtain written permission before scanning, exploiting, or interacting with systems you do not own.

## License

MIT License. See [LICENSE](LICENSE).
