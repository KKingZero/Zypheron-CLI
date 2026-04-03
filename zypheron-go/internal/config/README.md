# Zypheron Configuration Package

Local-first configuration for the OSS CLI with BYOK (Bring Your Own Key) AI provider support.

## Design Principles

- Local execution by default (Ollama)
- BYOK provider configuration via environment variables
- Non-secret settings persisted in `~/.zypheron/config.json`
- API keys never written to disk
- No hosted-service assumptions

## Quick Start

### Option 1: Local AI (No API Key)

```bash
ollama pull codellama
zypheron scan example.com
```

### Option 2: Cloud AI (BYOK)

```bash
export ANTHROPIC_API_KEY=sk-ant-your-key
export ZYPHERON_AI_PROVIDER=anthropic
zypheron scan example.com
```

## Supported Providers

| Provider | Env Variable | Default Model |
|----------|-------------|---------------|
| `ollama` (default) | `OLLAMA_URL`, `OLLAMA_MODEL` | `codellama` |
| `anthropic` | `ANTHROPIC_API_KEY` | `claude-3-5-sonnet` |
| `openai` | `OPENAI_API_KEY` | `gpt-4` |
| `deepseek` | `DEEPSEEK_API_KEY` | `deepseek-chat` |

## Configuration Sources

Load order (lowest to highest precedence):

1. Built-in defaults
2. `~/.zypheron/config.json`
3. Environment variables

## Environment Variables

### Provider Selection

```bash
export ZYPHERON_AI_PROVIDER=ollama      # Local AI (default)
export ZYPHERON_AI_PROVIDER=anthropic   # Anthropic Claude
export ZYPHERON_AI_PROVIDER=openai      # OpenAI GPT
export ZYPHERON_AI_PROVIDER=deepseek    # DeepSeek
```

### API Keys (BYOK)

```bash
export ANTHROPIC_API_KEY=sk-ant-xxx
export OPENAI_API_KEY=sk-xxx
export DEEPSEEK_API_KEY=sk-xxx
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

## JSON Config File

Location: `~/.zypheron/config.json`

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

API keys are **never** stored in this file -- only in environment variables.

## CLI Commands

```bash
zypheron config validate     # Validate configuration
zypheron config show         # Show current config
zypheron config diagnostics  # Detailed diagnostics
```

## Programmatic API

### Types

```go
type AIProvider string

const (
    AIProviderOllama    AIProvider = "ollama"
    AIProviderAnthropic AIProvider = "anthropic"
    AIProviderOpenAI    AIProvider = "openai"
    AIProviderDeepSeek  AIProvider = "deepseek"
)

type AIConfig struct { ... }
type Config struct { ... }
type ConfigStatus struct { ... }
```

### Configuration Lifecycle

```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"

// Load configuration (merges defaults + file + env)
cfg, err := config.LoadConfig()

// Validate
if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}

// Check provider requirements
if cfg.RequiresAPIKey() && !cfg.HasAPIKey() {
    log.Fatal("API key required for selected provider")
}

// Get AI config
aiConfig := cfg.GetAIConfig()
fmt.Printf("Provider: %s\n", aiConfig.Provider)

// Change provider
cfg.SetAIProvider(config.AIProviderAnthropic)

// Save to disk
cfg.Save()
```

### Global Access

```go
// Get/set global config instance
cfg := config.Get()
config.Set(newCfg)
config.Reload()
```

### File I/O

```go
cfg.LoadFromFile("/path/to/config.json")
cfg.SaveToFile("/path/to/config.json")
```

### Validation

```go
status := config.ValidateEnvironment()
status.PrintStatus()

config.PrintDiagnostics()

if config.QuickCheck() {
    fmt.Println("Configuration valid")
}

help := config.GetProviderHelp(config.AIProviderAnthropic)
```

## Keyring Security

The keyring system provides secure, cross-platform API key storage using OS-native credential managers.

### Platform Backends

- **Linux**: Secret Service API (GNOME Keyring, KWallet)
- **macOS**: Keychain
- **Windows**: Credential Manager

### Keyring API

```go
// Store a key
err := config.SetAPIKey(config.ProviderDeepSeek, "sk-1234567890abcdef")

// Retrieve a key
key, err := config.GetAPIKey(config.ProviderAnthropic)
if errors.Is(err, config.ErrKeyNotFound) {
    // Key not configured
}

// Check existence
if config.HasAPIKey(config.ProviderOpenAI) { ... }

// List configured providers
providers := config.ListProviders()

// Delete a key
config.DeleteAPIKey(config.ProviderSupabaseKey)

// Check keyring availability
if !config.IsKeyringAvailable() {
    fmt.Println("Using environment variable fallback")
}
```

### Environment Variable Fallback

When the system keyring is unavailable (headless servers, containers), keys fall back to environment variables:

```
deepseek     -> DEEPSEEK_API_KEY
anthropic    -> ANTHROPIC_API_KEY
openai       -> OPENAI_API_KEY
supabase_url -> SUPABASE_URL
supabase_key -> SUPABASE_KEY
```

### Security Properties

- Provider names validated against whitelist (prevents injection)
- API keys never logged or printed
- Thread-safe keyring availability check (`sync.Once`)
- Errors never contain key values
- Idempotent delete operations

## Provider Setup

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

## Security Best Practices

- Keep API keys in environment variables or a local secret manager
- Never commit secrets to version control
- Set `config.json` permissions to `0600`
- Use different keys for dev/prod environments
- Rotate keys regularly
- On headless servers, use environment variables (keyring unavailable)
- Limit shell history exposure: `export HISTIGNORE="*API_KEY*"`

## Troubleshooting

**"API key required"**: Set the appropriate environment variable for your provider.

**"Ollama connection failed"**: Start the Ollama server with `ollama serve`.

**Configuration not loading**: Reset with `rm ~/.zypheron/config.json` and `unset ZYPHERON_AI_PROVIDER`.

**Keyring not available**: Install `gnome-keyring` or `kwallet` on Linux, or use environment variables on headless systems.

**Key not found**: Verify with `config.HasAPIKey(provider)`, check environment variables, or re-run `zypheron config set-key <provider>`.

**Permission denied on keyring**: Unlock the keyring (may require desktop login on Linux), grant Keychain access on macOS.

## Testing

```bash
go test -v ./internal/config/...
```

## .env Template

```bash
ZYPHERON_AI_PROVIDER=ollama

# Cloud providers (uncomment and set):
# ANTHROPIC_API_KEY=sk-ant-your-key
# OPENAI_API_KEY=sk-your-key
# DEEPSEEK_API_KEY=sk-your-key

# Ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=codellama

# AI parameters
ZYPHERON_AI_TEMPERATURE=0.7
ZYPHERON_AI_MAX_TOKENS=4096
```
