# Zypheron Setup and Usage Guide

This guide covers first-time setup and the current day-to-day CLI workflow.

## First-Time Setup

After installing Zypheron:

```bash
zypheron --version
zypheron doctor
```

If you installed from source and still need Python-side packages:

```bash
zypheron install-deps --all
```

If you want Zypheron to install critical external tools for you:

```bash
zypheron tools install-all --critical-only --yes
```

## Environment Checks

Useful validation commands:

```bash
zypheron doctor
zypheron tools check
zypheron ai status
```

If you are running on Kali or WSL and want environment-specific checks:

```bash
zypheron kali detect
```

## AI Setup

Zypheron supports local and hosted providers.

Common setup patterns:

```bash
zypheron config set-key anthropic
zypheron config set-key openai
zypheron config set-key deepseek
zypheron config get-providers
```

In the TUI, selecting a hosted model without a configured key will now prompt for the API key and store it for reuse.

For local models, configure Ollama separately and then select an Ollama model in Zypheron.

## Tool Installation

Check the current tool inventory:

```bash
zypheron tools check
zypheron tools list
zypheron tools list --missing
```

Install tools:

```bash
zypheron tools install nmap
zypheron tools install nuclei
zypheron tools install-all --critical-only --yes
zypheron tools install-all --yes
```

If you prefer to manage tools yourself, just keep `tools check` and `doctor` clean.

## Common Workflows

### Launch the TUI

```bash
zypheron
zypheron tui
```

### Recon and Scanning

```bash
zypheron scan example.com
zypheron scan example.com --web
zypheron recon example.com
```

### AI-assisted Dorking

```bash
zypheron dork "admin panels"
zypheron dork " exposed login portals " --ai-guided
```

### AI Chat

```bash
zypheron chat "How would you approach this host?"
```

### Sessions and Workflows

```bash
zypheron workflow list
zypheron autopent example.com
zypheron session list
```

## Configuration

Useful config commands:

```bash
zypheron config show
zypheron config path
zypheron config get ai.provider
zypheron config set ai.provider ollama
zypheron config set ai.model llama3.2:3b
```

Typical config locations:

- Linux/macOS: `~/.zypheron/config.json`
- Windows: `%APPDATA%\\zypheron\\config.json`

## Updating

If you installed a release build:

```bash
zypheron update check
```

If you installed from source, update by pulling the repo and rerunning the bootstrap script:

```bash
git pull
bash ./setup-hybrid.sh
```

## Notes

- some workflows depend on external tools being present locally
- AI features depend on either configured hosted keys or a local model runtime
- not every command is equally mature; use `zypheron --help` and command help output as the source of truth for your build
