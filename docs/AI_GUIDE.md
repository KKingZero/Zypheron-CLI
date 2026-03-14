# Zypheron AI Guide

This guide covers the current AI engine, provider setup, and model workflow in Zypheron CLI.

## Overview

Zypheron's AI features are powered by the Python-side AI engine used by the Go CLI and TUI.

Current AI-enabled flows include:

- chat in the CLI
- AI-guided dork enhancement
- model/provider selection in the TUI
- AI-assisted analysis and workflow support
- MCP integration for external AI clients

## AI Engine Basics

Useful commands:

```bash
zypheron ai start
zypheron ai stop
zypheron ai status
zypheron ai providers
zypheron ai doctor
zypheron ai test --provider ollama
```

The CLI can auto-start the AI engine when needed for some flows.

## Installing AI Dependencies

If you used the source bootstrap, this is usually handled for you. If not:

```bash
zypheron install-deps --all
```

If you need to work directly inside `zypheron-ai/`, you can still create a virtual environment manually, but the CLI installer is now the preferred path.

## API Keys and Provider Setup

Store hosted-provider keys with the CLI:

```bash
zypheron config set-key anthropic
zypheron config set-key openai
zypheron config set-key deepseek
zypheron config set-key gemini
zypheron config set-key kimi
```

See configured providers:

```bash
zypheron config get-providers
```

Environment variables are also supported for many providers, but the CLI key flow is the preferred user path.

## TUI Model Selection

The TUI supports switching between local and hosted models.

Current behavior:

- selecting a hosted model without a configured API key prompts for the key immediately
- the selected provider/model is persisted
- the selection remains active until changed again in settings
- local models such as Ollama do not require hosted API keys

## Supported Provider Types

The current project supports a mix of hosted and local providers.

Common provider groups:

- Anthropic
- OpenAI
- Google Gemini
- DeepSeek
- Moonshot Kimi
- Ollama

Exact available models depend on the current model registry and your build.

## Ollama Setup

For local models:

```bash
ollama pull llama3.2:3b
ollama pull mistral:latest
zypheron config set ai.provider ollama
zypheron config set ai.model llama3.2:3b
```

Then verify:

```bash
zypheron ai test --provider ollama
```

## Common AI Workflows

```bash
zypheron chat "Summarize this target profile"
zypheron dork "admin login panels" --ai-guided
zypheron ai status
```

In the TUI:

```bash
zypheron
```

Then select your model/provider from the model selector.

## Troubleshooting

If AI is not working:

```bash
zypheron ai doctor
zypheron ai status
zypheron config get-providers
zypheron doctor
```

Common causes:

- missing provider API key
- local model runtime not running
- Python dependencies not installed
- system keyring unavailable, requiring environment variables instead

## MCP

If you want to expose Zypheron tooling to an external AI client, see [MCP_INTEGRATION.md](MCP_INTEGRATION.md).
