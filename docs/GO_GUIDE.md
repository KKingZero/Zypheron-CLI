# Zypheron Go CLI Guide

This is a practical reference for the current Go-based CLI and TUI.

For the current install path, start with [INSTALL.md](INSTALL.md). For setup, see [SETUP_AND_USE.md](SETUP_AND_USE.md).

## Basic Usage

```bash
zypheron [command]
zypheron [command] --help
zypheron --version
```

## Common Global Flags

Common flags you will see across the CLI:

- `--help`, `-h`
- `--version`
- `--debug`, `-d`
- `--no-banner`
- `--no-color`

Use `zypheron --help` as the source of truth for your current build.

## Core Commands

Frequently used commands:

- `zypheron`
- `zypheron tui`
- `zypheron doctor`
- `zypheron install-deps`
- `zypheron scan`
- `zypheron recon`
- `zypheron dork`
- `zypheron chat`
- `zypheron tools`
- `zypheron config`
- `zypheron ai`
- `zypheron workflow`
- `zypheron session`
- `zypheron history`
- `zypheron autopent`
- `zypheron mcp`

The project also includes additional command groups such as `ad`, `cloud`, `mitre`, `compliance`, `exploit`, `pwn`, `api-pentest`, `plugin`, `schedule`, `scheduler`, `team`, and others.

Some commands are more mature than others. Check command help before scripting against them.

## Common Command Patterns

### TUI and Health Checks

```bash
zypheron
zypheron tui
zypheron doctor
```

### Scan and Recon

```bash
zypheron scan example.com
zypheron scan example.com --web
zypheron recon example.com
```

### AI

```bash
zypheron chat "Summarize the likely attack surface"
zypheron dork "admin portals" --ai-guided
zypheron ai status
zypheron ai providers
```

### Tools

```bash
zypheron tools check
zypheron tools list
zypheron tools info nmap
zypheron tools install-all --critical-only --yes
```

### Config

```bash
zypheron config show
zypheron config path
zypheron config get ai.provider
zypheron config set ai.provider ollama
zypheron config set-key anthropic
zypheron config get-providers
```

### Workflows and Sessions

```bash
zypheron workflow list
zypheron autopent example.com
zypheron session list
zypheron history list
```

### MCP

```bash
zypheron mcp config
zypheron mcp start
zypheron mcp status
```

## Notes on External Tools

Many workflows rely on external tools installed on the host system.

Useful checks:

```bash
zypheron tools check
zypheron doctor
```

Useful installation flow:

```bash
zypheron tools install-all --critical-only --yes
```

## Notes on AI Providers

Hosted and local providers are supported.

Common flows:

- store hosted keys with `zypheron config set-key <provider>`
- select models through the TUI model selector
- use Ollama for local models

If you select a hosted model in the TUI without a configured API key, Zypheron prompts for the key and stores it.

## Notes on Accuracy

This guide is intentionally shorter than the older command dump because the command surface is broad and still evolving.

For exact usage:

```bash
zypheron --help
zypheron <command> --help
```
