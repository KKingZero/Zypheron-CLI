# Zypheron Configuration Package

Local-first configuration support for the OSS CLI.

## Goals

- prefer local execution by default
- support BYOK provider configuration through environment variables
- persist non-secret settings in `~/.zypheron/config.json`
- avoid hosted-service assumptions in the core config package

## Supported Providers

- `ollama`
- `anthropic`
- `openai`
- `deepseek`

## Configuration Sources

Load order, lowest to highest precedence:

1. built-in defaults
2. `~/.zypheron/config.json`
3. environment variables

## Important Notes

- API keys are loaded from environment variables only.
- API keys are not written to disk.
- Ollama is the default local provider path.
- JSON configuration is intended for non-secret settings.

## Common Environment Variables

```bash
export ZYPHERON_AI_PROVIDER=ollama
export OLLAMA_URL=http://localhost:11434
export OLLAMA_MODEL=codellama

export ANTHROPIC_API_KEY=...
export OPENAI_API_KEY=...
export DEEPSEEK_API_KEY=...
```

## Common Tasks

### Use Ollama

```bash
export ZYPHERON_AI_PROVIDER=ollama
export OLLAMA_URL=http://localhost:11434
export OLLAMA_MODEL=codellama
```

### Use a Cloud Provider with BYOK

```bash
export ZYPHERON_AI_PROVIDER=anthropic
export ANTHROPIC_API_KEY=your-key
```

## Security

- keep API keys in the environment or a local secret manager
- never commit secrets to the repo
- keep config files user-readable only

## Scope

This package is for local CLI configuration. It should be treated as part of the
open source runtime, not as a hosted control plane.
