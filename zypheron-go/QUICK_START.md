# Zypheron Go CLI Quick Start

This is the shortest path to a working Zypheron CLI install from source.

## Fastest Path

From the repository root:

```bash
git clone https://github.com/KKingZero/Zypheron-CLI.git
cd Zypheron-CLI
bash ./setup-hybrid.sh
```

That bootstrap script:

- builds the Go CLI
- installs Python-side dependencies
- installs shell completion when possible
- can install critical or all external tools

## Verify

```bash
zypheron --version
zypheron doctor
```

## First Commands

```bash
zypheron
zypheron scan example.com
zypheron recon example.com
zypheron dork "admin panels" --ai-guided
zypheron chat "How would you test this target?"
```

## If You Need Dependencies Later

```bash
zypheron install-deps --all
zypheron tools check
zypheron tools install-all --critical-only --yes
```

## AI Setup

Hosted providers:

```bash
zypheron config set-key anthropic
zypheron config set-key openai
zypheron config get-providers
```

Local provider example:

```bash
ollama pull llama3.2:3b
zypheron config set ai.provider ollama
zypheron config set ai.model llama3.2:3b
```

In the TUI, selecting a hosted model without a configured key prompts for the API key and stores it.

## Manual Local Build

If you want to build only the Go binary from `zypheron-go/`:

```bash
cd zypheron-go
go build -o zypheron ./cmd/zypheron
./zypheron --version
```

## Notes

- use the root [README.md](../README.md) for the main install and usage flow
- use [../docs/INSTALL.md](../docs/INSTALL.md) for installation details
- use [../docs/AI_GUIDE.md](../docs/AI_GUIDE.md) for AI/provider setup
