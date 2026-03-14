# Zypheron Configuration Package (Open Source - BYOK)

This is the open-source configuration package for Zypheron CLI with a **Bring Your Own Key (BYOK)** model. It's designed for advanced users who want full control over their AI provider configuration.

## Features

- **Local AI by Default**: Uses Ollama as the default AI provider (no cloud dependency)
- **BYOK for Cloud Providers**: Support for Anthropic, OpenAI, and DeepSeek via environment variables
- **JSON Persistence**: Configuration stored at `~/.zypheron/config.json`
- **Thread-Safe**: All operations protected with mutexes for concurrent access
- **No Keyring**: No system keyring integration - simple environment variable approach
- **No Subscription Tiers**: No cloud sync or subscription management

## Supported AI Providers

### 1. Ollama (Default - Local AI)
- **Provider**: `ollama`
- **No API Key Required**
- **Default URL**: `http://localhost:11434`
- **Default Model**: `codellama`

### 2. Anthropic Claude
- **Provider**: `anthropic`
- **API Key**: Set via `ANTHROPIC_API_KEY` environment variable
- **Models**: `claude-3-5-sonnet`, `claude-3-opus`, etc.

### 3. OpenAI
- **Provider**: `openai`
- **API Key**: Set via `OPENAI_API_KEY` environment variable
- **Models**: `gpt-4`, `gpt-3.5-turbo`, etc.

### 4. DeepSeek
- **Provider**: `deepseek`
- **API Key**: Set via `DEEPSEEK_API_KEY` environment variable
- **Models**: `deepseek-chat`, `deepseek-coder`, etc.

## Configuration Methods

### 1. Environment Variables (Recommended for BYOK)

```bash
# Set AI provider (default: ollama)
export ZYPHERON_AI_PROVIDER=anthropic

# Provider-specific API keys (BYOK)
export ANTHROPIC_API_KEY=sk-ant-xxx
export OPENAI_API_KEY=sk-xxx
export DEEPSEEK_API_KEY=sk-xxx

# Ollama configuration (if using local AI)
export OLLAMA_URL=http://localhost:11434
export OLLAMA_MODEL=codellama

# Model override (optional)
export ZYPHERON_AI_MODEL=claude-3-5-sonnet

# AI parameters
export ZYPHERON_AI_TEMPERATURE=0.7
export ZYPHERON_AI_MAX_TOKENS=4096

# Other configuration
export ZYPHERON_CONFIG_DIR=$HOME/.zypheron
export ZYPHERON_CONNECTION_POOL_SIZE=5
export ZYPHERON_MAX_CONCURRENT_SCANS=10
export ZYPHERON_RATE_LIMIT_RPS=10
export ZYPHERON_LOG_SANITIZATION=true
export ZYPHERON_AUDIT_LOGGING=true
```

### 2. JSON Configuration File

Configuration is persisted at `~/.zypheron/config.json`:

```json
{
  "ai": {
    "provider": "ollama",
    "ollama_url": "http://localhost:11434",
    "ollama_model": "codellama",
    "temperature": 0.7,
    "max_tokens": 4096
  },
  "ai_engine_timeout": 60000000000,
  "connection_pool_size": 5,
  "ipc_timeout": 30000000000,
  "ipc_retries": 3,
  "scan_timeout": 300000000000,
  "max_concurrent_scans": 10,
  "rate_limit_rps": 10,
  "log_sanitization": true,
  "audit_logging": true
}
```

**Note**: API keys are **NEVER** persisted to the JSON file. They are only loaded from environment variables at runtime.

### 3. Programmatic Configuration

```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"

// Load configuration
cfg, err := config.LoadConfig()
if err != nil {
    log.Fatal(err)
}

// Get global configuration
cfg := config.Get()

// Change AI provider
err := cfg.SetAIProvider(config.AIProviderAnthropic)
if err != nil {
    log.Fatal(err)
}

// Configure Ollama
cfg.SetOllamaConfig("http://localhost:11434", "codellama")

// Save configuration to file
err = cfg.Save()
if err != nil {
    log.Fatal(err)
}

// Check if API key is required
if cfg.RequiresAPIKey() && !cfg.HasAPIKey() {
    fmt.Println("API key required but not configured")
}

// Get AI configuration
aiConfig := cfg.GetAIConfig()
fmt.Printf("Provider: %s\n", aiConfig.Provider)
fmt.Printf("Temperature: %.2f\n", aiConfig.Temperature)

// Reload configuration
err = config.Reload()
if err != nil {
    log.Fatal(err)
}
```

## Quick Start Guide

### Option 1: Use Local AI (Ollama)

1. **Install Ollama**:
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```

2. **Pull a model**:
   ```bash
   ollama pull codellama
   ```

3. **Run Zypheron** (uses Ollama by default):
   ```bash
   zypheron scan
   ```

### Option 2: Use Cloud Provider (BYOK)

1. **Set your API key**:
   ```bash
   export ANTHROPIC_API_KEY=sk-ant-your-key-here
   ```

2. **Set the provider**:
   ```bash
   export ZYPHERON_AI_PROVIDER=anthropic
   ```

3. **Run Zypheron**:
   ```bash
   zypheron scan
   ```

### Option 3: Configure via JSON

1. **Edit** `~/.zypheron/config.json`:
   ```json
   {
     "ai": {
       "provider": "openai",
       "model": "gpt-4",
       "temperature": 0.8,
       "max_tokens": 8192
     }
   }
   ```

2. **Set your API key** (environment only):
   ```bash
   export OPENAI_API_KEY=sk-your-key-here
   ```

3. **Run Zypheron**:
   ```bash
   zypheron scan
   ```

## Configuration Priority

Configuration is loaded in the following order (later overrides earlier):

1. **Default values** (from `DefaultConfig()`)
2. **JSON file** (`~/.zypheron/config.json`)
3. **Environment variables** (highest priority)

## Security Considerations

### API Key Security
- API keys are **NEVER** written to disk
- API keys are only loaded from environment variables
- Use secret management tools in production (e.g., HashiCorp Vault, AWS Secrets Manager)
- Consider using `.env` files with proper permissions (0600)

### File Permissions
- Config directory: `0700` (user only)
- Config file: `0600` (user read/write only)
- Log directory: `0700` (user only)

### Best Practices
1. Never commit API keys to version control
2. Use different API keys for development and production
3. Rotate API keys regularly
4. Use environment-specific configuration files
5. Enable audit logging for production environments

## Thread Safety

All configuration operations are thread-safe:
- Global configuration uses `sync.RWMutex`
- Individual config instances have their own mutexes
- Safe for concurrent access from multiple goroutines

## Validation

Configuration is validated on load with checks for:
- Required fields based on provider type
- API key presence for cloud providers
- Valid provider names
- Reasonable timeout and limit values
- Temperature in valid range (0.0 - 1.0)

## Directory Structure

```
~/.zypheron/
├── config.json          # Main configuration file
├── toolchains.yaml      # Tool chain configurations
├── logs/                # Application logs
├── cache/               # Cached data
└── ai.sock             # IPC socket (if applicable)
```

## Error Handling

All errors use the custom error package:
- `errors.ConfigError()` - Configuration validation errors
- `errors.WrapConfigError()` - Wrapped errors with context

## Migration from Production Version

If migrating from the production version with keyring support:

1. Export your configuration:
   ```bash
   # Save current settings
   zypheron config export > config-backup.json
   ```

2. Set environment variables:
   ```bash
   export ANTHROPIC_API_KEY=<your-key-from-keyring>
   export ZYPHERON_AI_PROVIDER=anthropic
   ```

3. Remove keyring dependencies:
   - API keys now come from environment variables only
   - No more subscription tier management
   - No cloud sync features

## Troubleshooting

### API Key Not Found
**Problem**: "API key required for anthropic provider"

**Solution**:
```bash
export ANTHROPIC_API_KEY=sk-ant-your-key
```

### Ollama Connection Failed
**Problem**: Cannot connect to Ollama

**Solution**:
```bash
# Check if Ollama is running
curl http://localhost:11434

# Start Ollama if not running
ollama serve

# Configure custom URL if needed
export OLLAMA_URL=http://localhost:11434
```

### Invalid Provider
**Problem**: "unknown AI provider: custom"

**Solution**: Use one of the supported providers:
- `ollama` (default)
- `anthropic`
- `openai`
- `deepseek`

### Config File Corrupted
**Problem**: "failed to parse config JSON"

**Solution**:
```bash
# Backup corrupted file
mv ~/.zypheron/config.json ~/.zypheron/config.json.bak

# Regenerate with defaults
zypheron config init
```

## API Reference

### Types

```go
type AIProvider string

const (
    AIProviderOllama    AIProvider = "ollama"
    AIProviderAnthropic AIProvider = "anthropic"
    AIProviderOpenAI    AIProvider = "openai"
    AIProviderDeepSeek  AIProvider = "deepseek"
)

type AIConfig struct {
    Provider    AIProvider
    Model       string
    OllamaURL   string
    OllamaModel string
    APIKey      string  // Runtime only, never persisted
    Temperature float64
    MaxTokens   int
}

type Config struct {
    AI                 AIConfig
    AIEnginePath       string
    AIEngineTimeout    time.Duration
    ConnectionPoolSize int
    // ... other fields
}
```

### Functions

```go
// Configuration lifecycle
func DefaultConfig() *Config
func LoadConfig() (*Config, error)
func (c *Config) Validate() error
func (c *Config) Save() error

// File I/O
func (c *Config) LoadFromFile(path string) error
func (c *Config) SaveToFile(path string) error
func (c *Config) GetConfigPath() string

// AI provider management
func (c *Config) SetAIProvider(provider AIProvider) error
func (c *Config) GetAIProvider() AIProvider
func (c *Config) GetAIConfig() AIConfig
func (c *Config) SetOllamaConfig(url, model string)
func (c *Config) RequiresAPIKey() bool
func (c *Config) HasAPIKey() bool

// Global configuration
func Get() *Config
func Set(cfg *Config)
func Reload() error
```

## Contributing

This is the open-source version of Zypheron's configuration package. Contributions are welcome for:
- Additional AI provider support
- Configuration validation improvements
- Documentation enhancements
- Bug fixes

## License

Open source - see main project license.

## Differences from Production Version

| Feature | Open Source (BYOK) | Production |
|---------|-------------------|------------|
| API Key Storage | Environment variables | System keyring |
| Default Provider | Ollama (local) | Cloud-based |
| Subscription Tiers | None | Multiple tiers |
| Cloud Sync | No | Yes |
| Key Rotation | Manual | Automatic |
| Team Sharing | Manual | Built-in |
| Complexity | Simple | Advanced |

The open-source version is designed for individual users and small teams who prefer manual configuration and local AI models. For enterprise features, consider the production version.
