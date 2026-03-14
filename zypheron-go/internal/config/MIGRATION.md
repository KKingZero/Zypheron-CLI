# Migration Guide: BYOK Configuration Package

This guide helps you migrate to or understand the open-source BYOK (Bring Your Own Key) configuration system.

## Overview

The BYOK configuration package is designed for advanced users who want:
- Full control over their AI provider and API keys
- Local AI support (Ollama) without cloud dependencies
- Simple environment variable-based configuration
- No system keyring dependencies
- Manual configuration management

## Key Differences from Production Version

### API Key Management

**Production Version:**
- API keys stored in system keyring
- Automatic key rotation
- Cloud-based key synchronization
- Team key sharing features

**Open Source BYOK:**
- API keys from environment variables only
- Manual key management
- No cloud synchronization
- Keys never written to disk

### Default Behavior

**Production Version:**
- Defaults to cloud-based AI providers
- Requires subscription
- Automatic configuration sync

**Open Source BYOK:**
- Defaults to local Ollama installation
- No subscription required
- Configuration stored in JSON file locally

## Quick Start

### 1. First-Time Setup

```bash
# Install Ollama for local AI (recommended for getting started)
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model
ollama pull codellama

# Run Zypheron - it will use Ollama by default
zypheron init
```

### 2. Using Cloud Providers (BYOK)

#### Anthropic Claude

```bash
# Set your API key
export ANTHROPIC_API_KEY=sk-ant-your-key-here

# Set the provider
export ZYPHERON_AI_PROVIDER=anthropic

# Optional: specify model
export ZYPHERON_AI_MODEL=claude-3-5-sonnet-20241022

# Run Zypheron
zypheron scan
```

#### OpenAI GPT

```bash
export OPENAI_API_KEY=sk-your-key-here
export ZYPHERON_AI_PROVIDER=openai
export ZYPHERON_AI_MODEL=gpt-4

zypheron scan
```

#### DeepSeek

```bash
export DEEPSEEK_API_KEY=sk-your-key-here
export ZYPHERON_AI_PROVIDER=deepseek
export ZYPHERON_AI_MODEL=deepseek-chat

zypheron scan
```

### 3. Persistent Configuration

Create or edit `~/.zypheron/config.json`:

```json
{
  "ai": {
    "provider": "anthropic",
    "model": "claude-3-5-sonnet-20241022",
    "temperature": 0.7,
    "max_tokens": 4096
  },
  "connection_pool_size": 5,
  "max_concurrent_scans": 10,
  "rate_limit_rps": 10,
  "log_sanitization": true,
  "audit_logging": true
}
```

**Important:** API keys are NEVER stored in this file. Always use environment variables.

## Configuration Hierarchy

Settings are loaded in this order (later overrides earlier):

1. **Built-in defaults** (Ollama with sensible settings)
2. **JSON config file** (`~/.zypheron/config.json`)
3. **Environment variables** (highest priority)

This allows you to:
- Set base configuration in JSON
- Override with environment variables per session
- Keep API keys secure in environment only

## Using .env Files

For development, create a `.env` file (don't commit to git!):

```bash
# Copy the example
cp internal/config/.env.example .env

# Edit with your settings
vim .env

# Load before running
source .env
zypheron scan
```

**Security:** Ensure your `.env` file has proper permissions:
```bash
chmod 600 .env
```

## Common Migration Scenarios

### Scenario 1: From Production to Open Source

**Before (Production):**
```bash
# API keys managed by keyring
zypheron auth login
zypheron config set-provider anthropic
```

**After (Open Source BYOK):**
```bash
# Export API key manually
export ANTHROPIC_API_KEY=sk-ant-your-key-here
export ZYPHERON_AI_PROVIDER=anthropic

# Or add to .bashrc/.zshrc for persistence
echo 'export ANTHROPIC_API_KEY=sk-ant-your-key-here' >> ~/.bashrc
echo 'export ZYPHERON_AI_PROVIDER=anthropic' >> ~/.bashrc
```

### Scenario 2: From Cloud to Local AI

**Before (Cloud-dependent):**
```bash
# Required cloud API
zypheron scan  # Uses cloud AI
```

**After (Local Ollama):**
```bash
# Install Ollama
ollama pull codellama

# Unset cloud provider if previously set
unset ZYPHERON_AI_PROVIDER
unset ANTHROPIC_API_KEY

# Run with local AI
zypheron scan  # Uses local Ollama
```

### Scenario 3: Multi-Environment Setup

**Development (.env.development):**
```bash
ZYPHERON_AI_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=codellama
```

**Production (.env.production):**
```bash
ZYPHERON_AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-prod-key-here
ZYPHERON_AI_MODEL=claude-3-5-sonnet-20241022
ZYPHERON_AI_TEMPERATURE=0.5
ZYPHERON_MAX_CONCURRENT_SCANS=20
```

Load the appropriate environment:
```bash
# Development
source .env.development
zypheron scan

# Production
source .env.production
zypheron scan
```

## Programmatic Usage

### Loading Configuration

```go
package main

import (
    "log"
    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"
)

func main() {
    // Load configuration (from JSON + environment)
    cfg, err := config.LoadConfig()
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    // Access configuration
    aiConfig := cfg.GetAIConfig()
    log.Printf("Using AI provider: %s", aiConfig.Provider)

    // Check if API key is required and present
    if cfg.RequiresAPIKey() && !cfg.HasAPIKey() {
        log.Fatal("API key required but not set in environment")
    }
}
```

### Modifying Configuration

```go
// Get global config
cfg := config.Get()

// Change provider
err := cfg.SetAIProvider(config.AIProviderOpenAI)
if err != nil {
    log.Fatal(err)
}

// Configure Ollama
cfg.SetOllamaConfig("http://localhost:11434", "llama2")

// Save to JSON file
err = cfg.Save()
if err != nil {
    log.Fatal(err)
}

// Reload configuration
err = config.Reload()
if err != nil {
    log.Fatal(err)
}
```

### Thread-Safe Operations

```go
// Safe for concurrent use
go func() {
    cfg := config.Get()
    provider := cfg.GetAIProvider()
    log.Printf("Provider: %s", provider)
}()

go func() {
    cfg := config.Get()
    cfg.SetOllamaConfig("http://localhost:11434", "codellama")
}()
```

## Best Practices

### 1. API Key Security

**DO:**
- Use environment variables for API keys
- Use secret management tools in production (Vault, AWS Secrets Manager)
- Rotate keys regularly
- Use different keys for dev/staging/prod
- Add `.env` to `.gitignore`

**DON'T:**
- Commit API keys to version control
- Store keys in JSON config files
- Share keys between environments
- Use production keys in development

### 2. Configuration Management

**DO:**
- Use JSON for non-sensitive configuration
- Use environment variables for secrets
- Document your configuration choices
- Test configuration changes
- Keep backups of working configurations

**DON'T:**
- Mix production and development configurations
- Modify configuration during critical operations
- Forget to reload after changes

### 3. Provider Selection

**Use Ollama when:**
- Developing locally
- Privacy is critical
- No internet connectivity
- Testing/prototyping
- Learning the system

**Use Cloud Providers when:**
- Need latest models
- Require high performance
- Scaling beyond local resources
- Production deployments

## Troubleshooting

### Problem: "API key required for anthropic provider"

**Solution:**
```bash
# Verify environment variable is set
echo $ANTHROPIC_API_KEY

# If not set, export it
export ANTHROPIC_API_KEY=sk-ant-your-key-here

# Or check if correct provider is selected
export ZYPHERON_AI_PROVIDER=anthropic
```

### Problem: "Ollama URL must be specified"

**Solution:**
```bash
# Check if Ollama is running
curl http://localhost:11434

# If not running, start it
ollama serve

# Or specify custom URL
export OLLAMA_URL=http://localhost:11434
```

### Problem: Configuration changes not taking effect

**Solution:**
```bash
# Check configuration priority:
# 1. Environment variables override JSON
# 2. JSON overrides defaults

# To reset to defaults, remove JSON and unset env vars
rm ~/.zypheron/config.json
unset ZYPHERON_AI_PROVIDER
unset ANTHROPIC_API_KEY

# Reload configuration
zypheron config reload
```

### Problem: "failed to parse config JSON"

**Solution:**
```bash
# Validate JSON syntax
cat ~/.zypheron/config.json | jq .

# If invalid, backup and regenerate
mv ~/.zypheron/config.json ~/.zypheron/config.json.backup
zypheron config init
```

## Environment Variable Reference

### AI Provider Configuration

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `ZYPHERON_AI_PROVIDER` | AI provider to use | `ollama` | `anthropic` |
| `ANTHROPIC_API_KEY` | Anthropic API key | - | `sk-ant-...` |
| `OPENAI_API_KEY` | OpenAI API key | - | `sk-...` |
| `DEEPSEEK_API_KEY` | DeepSeek API key | - | `sk-...` |
| `OLLAMA_URL` | Ollama server URL | `http://localhost:11434` | `http://ollama:11434` |
| `OLLAMA_MODEL` | Ollama model name | `codellama` | `llama2` |
| `ZYPHERON_AI_MODEL` | Model override | - | `gpt-4` |
| `ZYPHERON_AI_TEMPERATURE` | Response randomness | `0.7` | `0.5` |
| `ZYPHERON_AI_MAX_TOKENS` | Max response length | `4096` | `8192` |

### Application Configuration

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `ZYPHERON_CONFIG_DIR` | Config directory | `~/.zypheron` | `/etc/zypheron` |
| `ZYPHERON_CONNECTION_POOL_SIZE` | Connection pool size | `5` | `10` |
| `ZYPHERON_MAX_CONCURRENT_SCANS` | Max concurrent scans | `10` | `20` |
| `ZYPHERON_RATE_LIMIT_RPS` | Rate limit (req/sec) | `10` | `20` |
| `ZYPHERON_LOG_SANITIZATION` | Sanitize logs | `true` | `false` |
| `ZYPHERON_AUDIT_LOGGING` | Enable audit logs | `true` | `false` |

## Advanced Configuration

### Custom Configuration Directory

```bash
export ZYPHERON_CONFIG_DIR=/custom/path
zypheron init
```

### Multiple Ollama Instances

```bash
# Instance 1 (default)
export OLLAMA_URL=http://localhost:11434
export OLLAMA_MODEL=codellama

# Instance 2 (custom)
export OLLAMA_URL=http://gpu-server:11434
export OLLAMA_MODEL=llama2-70b
```

### Provider-Specific Models

```bash
# Anthropic with specific model
export ZYPHERON_AI_PROVIDER=anthropic
export ZYPHERON_AI_MODEL=claude-3-opus-20240229

# OpenAI with specific model
export ZYPHERON_AI_PROVIDER=openai
export ZYPHERON_AI_MODEL=gpt-4-turbo-preview
```

### Temperature and Token Control

```bash
# More focused responses
export ZYPHERON_AI_TEMPERATURE=0.3
export ZYPHERON_AI_MAX_TOKENS=2048

# More creative responses
export ZYPHERON_AI_TEMPERATURE=0.9
export ZYPHERON_AI_MAX_TOKENS=8192
```

## Getting Help

- Check the [README.md](README.md) for detailed documentation
- Review example files: `.env.example`, `config.example.json`
- Run tests: `go test -v ./internal/config/...`
- Check logs in `~/.zypheron/logs/`

## Summary

The BYOK configuration package gives you full control over:
- ✅ AI provider selection
- ✅ API key management
- ✅ Local vs cloud AI
- ✅ Configuration persistence
- ✅ Environment-specific settings

It's designed for users who value:
- 🔒 Security and privacy
- 🎛️ Manual control
- 🏠 Local AI options
- 📝 Transparent configuration

Choose local Ollama for development and privacy, or bring your own cloud API keys for production workloads. The choice is yours.
