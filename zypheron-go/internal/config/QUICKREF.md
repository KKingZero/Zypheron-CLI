# Zypheron Configuration - Quick Reference

## TL;DR - Get Started in 30 Seconds

### Option 1: Local AI (No API Key)
```bash
ollama pull codellama && zypheron scan
```

### Option 2: Cloud AI (BYOK)
```bash
export ANTHROPIC_API_KEY=sk-ant-your-key
export ZYPHERON_AI_PROVIDER=anthropic
zypheron scan
```

## Environment Variables Cheat Sheet

### AI Provider Selection
```bash
export ZYPHERON_AI_PROVIDER=ollama      # Local AI (default)
export ZYPHERON_AI_PROVIDER=anthropic   # Anthropic Claude
export ZYPHERON_AI_PROVIDER=openai      # OpenAI GPT
export ZYPHERON_AI_PROVIDER=deepseek    # DeepSeek
```

### API Keys (BYOK)
```bash
export ANTHROPIC_API_KEY=sk-ant-xxx     # Anthropic
export OPENAI_API_KEY=sk-xxx            # OpenAI
export DEEPSEEK_API_KEY=sk-xxx          # DeepSeek
```

### Ollama Configuration
```bash
export OLLAMA_URL=http://localhost:11434
export OLLAMA_MODEL=codellama
```

### AI Parameters
```bash
export ZYPHERON_AI_MODEL=claude-3-5-sonnet  # Override model
export ZYPHERON_AI_TEMPERATURE=0.7           # 0.0-1.0
export ZYPHERON_AI_MAX_TOKENS=4096          # Max response length
```

## Common Commands

### Check Configuration
```bash
# Validate configuration
zypheron config validate

# Show current config
zypheron config show

# Print diagnostics
zypheron config diagnostics
```

### Configuration Files

**Location:** `~/.zypheron/config.json`

**Example:**
```json
{
  "ai": {
    "provider": "ollama",
    "ollama_url": "http://localhost:11434",
    "ollama_model": "codellama",
    "temperature": 0.7,
    "max_tokens": 4096
  }
}
```

**Note:** API keys are NEVER in this file - only in environment variables!

## Quick Troubleshooting

### "API key required"
```bash
export ANTHROPIC_API_KEY=sk-ant-your-key
```

### "Ollama connection failed"
```bash
ollama serve  # Start Ollama server
```

### Configuration not loading
```bash
rm ~/.zypheron/config.json  # Reset to defaults
unset ZYPHERON_AI_PROVIDER  # Clear env override
```

## Provider Quick Setup

### Anthropic Claude
```bash
export ANTHROPIC_API_KEY=sk-ant-xxx
export ZYPHERON_AI_PROVIDER=anthropic
export ZYPHERON_AI_MODEL=claude-3-5-sonnet-20241022
```

### OpenAI GPT-4
```bash
export OPENAI_API_KEY=sk-xxx
export ZYPHERON_AI_PROVIDER=openai
export ZYPHERON_AI_MODEL=gpt-4
```

### DeepSeek
```bash
export DEEPSEEK_API_KEY=sk-xxx
export ZYPHERON_AI_PROVIDER=deepseek
export ZYPHERON_AI_MODEL=deepseek-chat
```

### Ollama (Local)
```bash
ollama pull codellama
export OLLAMA_MODEL=codellama
# ZYPHERON_AI_PROVIDER defaults to ollama
```

## Configuration Priority

1. Environment variables (highest)
2. JSON config file
3. Built-in defaults (lowest)

## Security Reminders

- ✅ API keys in environment variables only
- ✅ Never commit .env files to git
- ✅ Use different keys for dev/prod
- ✅ Rotate keys regularly
- ✅ File permissions: config.json should be 0600

## Quick Validation Script

```bash
#!/bin/bash
# check-config.sh

if [ -z "$ZYPHERON_AI_PROVIDER" ]; then
    echo "Using default provider: ollama"
else
    echo "Provider: $ZYPHERON_AI_PROVIDER"

    case $ZYPHERON_AI_PROVIDER in
        anthropic)
            [ -z "$ANTHROPIC_API_KEY" ] && echo "ERROR: ANTHROPIC_API_KEY not set" && exit 1
            ;;
        openai)
            [ -z "$OPENAI_API_KEY" ] && echo "ERROR: OPENAI_API_KEY not set" && exit 1
            ;;
        deepseek)
            [ -z "$DEEPSEEK_API_KEY" ] && echo "ERROR: DEEPSEEK_API_KEY not set" && exit 1
            ;;
    esac
fi

echo "Configuration valid!"
```

## .env Template

```bash
# Copy to .env and customize
ZYPHERON_AI_PROVIDER=ollama

# For cloud providers, uncomment and set:
# ANTHROPIC_API_KEY=sk-ant-your-key
# OPENAI_API_KEY=sk-your-key
# DEEPSEEK_API_KEY=sk-your-key

# Ollama config
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=codellama

# AI parameters
ZYPHERON_AI_TEMPERATURE=0.7
ZYPHERON_AI_MAX_TOKENS=4096
```

## Programmatic Usage

```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"

// Load configuration
cfg, err := config.LoadConfig()
if err != nil {
    log.Fatal(err)
}

// Check provider
if cfg.RequiresAPIKey() && !cfg.HasAPIKey() {
    log.Fatal("API key required")
}

// Get AI config
aiConfig := cfg.GetAIConfig()
fmt.Printf("Provider: %s\n", aiConfig.Provider)

// Change provider
cfg.SetAIProvider(config.AIProviderAnthropic)

// Save changes
cfg.Save()
```

## Full Documentation

- **README.md** - Complete usage guide
- **MIGRATION.md** - Migration scenarios
- **SUMMARY.md** - Implementation details
- **.env.example** - Full environment template
- **example_usage.go** - Code examples

## Support

Run into issues? Check:
1. `zypheron config validate` - Validate configuration
2. `zypheron config diagnostics` - Detailed diagnostics
3. See README.md for troubleshooting
4. Check ~/.zypheron/logs/ for error logs

---

**Quick Ref Version:** 1.0
**Last Updated:** 2026-01-18
