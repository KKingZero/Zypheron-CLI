package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/errors"
)

// AIProvider represents the AI provider type
type AIProvider string

const (
	// AIProviderOllama represents local Ollama installation
	AIProviderOllama AIProvider = "ollama"
	// AIProviderAnthropic represents Anthropic Claude API
	AIProviderAnthropic AIProvider = "anthropic"
	// AIProviderOpenAI represents OpenAI API
	AIProviderOpenAI AIProvider = "openai"
	// AIProviderGemini represents Google Gemini API
	AIProviderGemini AIProvider = "gemini"
	// AIProviderKimi represents Moonshot/Kimi API
	AIProviderKimi AIProvider = "kimi"
	// AIProviderDeepSeek represents DeepSeek API
	AIProviderDeepSeek AIProvider = "deepseek"
	// AIProviderGrok represents xAI Grok API
	AIProviderGrok AIProvider = "grok"
)

// AIConfig holds AI provider configuration
type AIConfig struct {
	// Provider specifies which AI provider to use
	Provider AIProvider `json:"provider"`

	// Model specifies the model to use (e.g., "claude-3-5-sonnet", "gpt-4", "deepseek-chat")
	Model string `json:"model,omitempty"`

	// OllamaURL is the URL for local Ollama instance (default: http://localhost:11434)
	OllamaURL string `json:"ollama_url,omitempty"`

	// OllamaModel is the model to use with Ollama (default: "llama3.2")
	OllamaModel string `json:"ollama_model,omitempty"`

	// APIKey is loaded from environment variables at runtime (not persisted)
	APIKey string `json:"-"`

	// Temperature controls randomness (0.0 to 1.0)
	Temperature float64 `json:"temperature,omitempty"`

	// MaxTokens is the maximum response length
	MaxTokens int `json:"max_tokens,omitempty"`
}

// Config holds all application configuration
type Config struct {
	// AI Configuration (BYOK model)
	AI AIConfig `json:"ai"`
	// Legacy/TUI-friendly fields
	AIProvider      string  `json:"ai_provider,omitempty"`
	AIModel         string  `json:"ai_model,omitempty"`
	AITemperature   float64 `json:"ai_temperature,omitempty"`
	DefaultPorts    string  `json:"default_ports,omitempty"`
	ScanTimeoutSec  int     `json:"scan_timeout_sec,omitempty"`
	Theme           string  `json:"theme,omitempty"`
	ColorScheme     string  `json:"color_scheme,omitempty"`
	ShowSplash      bool    `json:"show_splash,omitempty"`
	AutoSaveSession bool    `json:"auto_save_session,omitempty"`
	MaxHistoryDays  int     `json:"max_history_days,omitempty"`

	// AI Engine
	AIEnginePath       string        `json:"ai_engine_path,omitempty"`
	AIEngineTimeout    time.Duration `json:"ai_engine_timeout"`
	ConnectionPoolSize int           `json:"connection_pool_size"`

	// IPC
	IPCSocketPath string        `json:"ipc_socket_path,omitempty"`
	IPCTimeout    time.Duration `json:"ipc_timeout"`
	IPCRetries    int           `json:"ipc_retries"`

	// Scanning
	ScanTimeout        time.Duration `json:"scan_timeout"`
	MaxConcurrentScans int           `json:"max_concurrent_scans"`
	RateLimitRPS       int           `json:"rate_limit_rps"`

	// Security
	SecureFilePerms os.FileMode `json:"-"`
	LogSanitization bool        `json:"log_sanitization"`
	AuditLogging    bool        `json:"audit_logging"`

	// Updates
	CheckUpdates bool `json:"check_updates"`

	// Paths
	ConfigDir string `json:"config_dir,omitempty"`
	LogDir    string `json:"log_dir,omitempty"`
	CacheDir  string `json:"cache_dir,omitempty"`

	// Thread safety
	mu sync.RWMutex `json:"-"`
}

// DefaultConfig returns default configuration with Ollama as default AI provider
func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	configDir := filepath.Join(homeDir, ".zypheron")

	cfg := &Config{
		// AI Configuration - defaults to local Ollama
		AI: AIConfig{
			Provider:    AIProviderOllama,
			OllamaURL:   "http://localhost:11434",
			OllamaModel: "llama3.2",
			Temperature: 0.7,
			MaxTokens:   4096,
		},

		// AI Engine
		AIEnginePath:       "", // Auto-detect
		AIEngineTimeout:    60 * time.Second,
		ConnectionPoolSize: 5,

		// IPC
		IPCSocketPath: filepath.Join(configDir, "ai.sock"),
		IPCTimeout:    30 * time.Second,
		IPCRetries:    3,

		// Scanning
		ScanTimeout:        300 * time.Second,
		MaxConcurrentScans: 10,
		RateLimitRPS:       10,

		// Security
		SecureFilePerms: 0o600,
		LogSanitization: true,
		AuditLogging:    true,

		// Updates
		CheckUpdates: true,

		// Paths
		ConfigDir: configDir,
		LogDir:    filepath.Join(configDir, "logs"),
		CacheDir:  filepath.Join(configDir, "cache"),
	}

	cfg.syncLegacyFields()
	return cfg
}

// LoadConfig loads configuration from JSON file and environment variables
func LoadConfig() (*Config, error) {
	cfg := DefaultConfig()

	// Try to load from JSON file first
	configPath := cfg.GetConfigPath()
	if err := cfg.LoadFromFile(configPath); err != nil {
		// If file doesn't exist, that's okay - we'll use defaults
		if !os.IsNotExist(err) {
			return nil, errors.WrapConfigError("failed to load config file", err)
		}
	}

	// Override with environment variables (BYOK model)
	cfg.loadFromEnv()

	// Sync legacy/TUI fields
	cfg.syncLegacyFields()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Ensure directories exist
	if err := cfg.EnsureDirectories(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// loadFromEnv loads configuration from environment variables
func (c *Config) loadFromEnv() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// AI Provider configuration
	if val := os.Getenv("ZYPHERON_AI_PROVIDER"); val != "" {
		switch val {
		case "ollama":
			c.AI.Provider = AIProviderOllama
		case "anthropic":
			c.AI.Provider = AIProviderAnthropic
		case "openai":
			c.AI.Provider = AIProviderOpenAI
		case "gemini":
			c.AI.Provider = AIProviderGemini
		case "kimi":
			c.AI.Provider = AIProviderKimi
		case "deepseek":
			c.AI.Provider = AIProviderDeepSeek
		case "grok":
			c.AI.Provider = AIProviderGrok
		}
	}

	// Ollama configuration
	if val := os.Getenv("OLLAMA_URL"); val != "" {
		c.AI.OllamaURL = val
	}
	if val := os.Getenv("OLLAMA_MODEL"); val != "" {
		c.AI.OllamaModel = val
	}

	// BYOK - Load API keys from environment (never persisted to disk)
	switch c.AI.Provider {
	case AIProviderAnthropic:
		c.AI.APIKey = os.Getenv("ANTHROPIC_API_KEY")
	case AIProviderOpenAI:
		c.AI.APIKey = os.Getenv("OPENAI_API_KEY")
	case AIProviderGemini:
		c.AI.APIKey = os.Getenv("GOOGLE_API_KEY")
	case AIProviderKimi:
		c.AI.APIKey = os.Getenv("KIMI_API_KEY")
	case AIProviderDeepSeek:
		c.AI.APIKey = os.Getenv("DEEPSEEK_API_KEY")
	case AIProviderGrok:
		c.AI.APIKey = os.Getenv("GROK_API_KEY")
	}

	// Model override
	if val := os.Getenv("ZYPHERON_AI_MODEL"); val != "" {
		c.AI.Model = val
	}

	// Temperature
	if val := os.Getenv("ZYPHERON_AI_TEMPERATURE"); val != "" {
		if temp, err := strconv.ParseFloat(val, 64); err == nil && temp >= 0 && temp <= 1 {
			c.AI.Temperature = temp
		}
	}

	// Max tokens
	if val := os.Getenv("ZYPHERON_AI_MAX_TOKENS"); val != "" {
		if tokens, err := strconv.Atoi(val); err == nil && tokens > 0 {
			c.AI.MaxTokens = tokens
		}
	}

	// Other configuration overrides
	if val := os.Getenv("ZYPHERON_AI_PATH"); val != "" {
		c.AIEnginePath = val
	}

	if val := os.Getenv("ZYPHERON_CONFIG_DIR"); val != "" {
		c.ConfigDir = val
		c.IPCSocketPath = filepath.Join(val, "ai.sock")
		c.LogDir = filepath.Join(val, "logs")
		c.CacheDir = filepath.Join(val, "cache")
	}

	if val := os.Getenv("ZYPHERON_CONNECTION_POOL_SIZE"); val != "" {
		if size, err := strconv.Atoi(val); err == nil && size > 0 {
			c.ConnectionPoolSize = size
		}
	}

	if val := os.Getenv("ZYPHERON_MAX_CONCURRENT_SCANS"); val != "" {
		if max, err := strconv.Atoi(val); err == nil && max > 0 {
			c.MaxConcurrentScans = max
		}
	}

	if val := os.Getenv("ZYPHERON_RATE_LIMIT_RPS"); val != "" {
		if rps, err := strconv.Atoi(val); err == nil && rps > 0 {
			c.RateLimitRPS = rps
		}
	}

	if val := os.Getenv("ZYPHERON_LOG_SANITIZATION"); val == "false" {
		c.LogSanitization = false
	}

	if val := os.Getenv("ZYPHERON_AUDIT_LOGGING"); val == "false" {
		c.AuditLogging = false
	}
}

// syncLegacyFields keeps TUI/legacy fields aligned with primary config values.
func (c *Config) syncLegacyFields() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.AIProvider == "" {
		c.AIProvider = string(c.AI.Provider)
	}

	if c.AIModel == "" {
		if c.AI.Model != "" {
			c.AIModel = c.AI.Model
		} else if c.AI.Provider == AIProviderOllama {
			c.AIModel = c.AI.OllamaModel
		}
	}

	if c.AITemperature == 0 {
		c.AITemperature = c.AI.Temperature
	}

	if c.DefaultPorts == "" {
		c.DefaultPorts = "1-1000"
	}

	if c.ScanTimeoutSec == 0 {
		c.ScanTimeoutSec = int(c.ScanTimeout.Seconds())
	}

	if c.Theme == "" {
		c.Theme = "default"
	}

	if c.ColorScheme == "" {
		c.ColorScheme = "default"
	}

	// Default to showing splash unless explicitly disabled
	if !c.ShowSplash {
		c.ShowSplash = true
	}

	if c.MaxHistoryDays == 0 {
		c.MaxHistoryDays = 30
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Validate AI configuration
	switch c.AI.Provider {
	case AIProviderOllama:
		if c.AI.OllamaURL == "" {
			return errors.ConfigError("Ollama URL must be specified when using Ollama provider")
		}
		if c.AI.OllamaModel == "" {
			return errors.ConfigError("Ollama model must be specified when using Ollama provider")
		}
	case AIProviderAnthropic, AIProviderOpenAI, AIProviderGemini, AIProviderKimi, AIProviderDeepSeek, AIProviderGrok:
		// Cloud providers may be authenticated through the Python engine's secure keyring.
	case "":
		return errors.ConfigError("AI provider must be specified")
	default:
		return errors.ConfigError(fmt.Sprintf("unknown AI provider: %s", c.AI.Provider))
	}

	if c.AI.Temperature < 0 || c.AI.Temperature > 1 {
		return errors.ConfigError("AI temperature must be between 0 and 1")
	}

	if c.AI.MaxTokens < 0 {
		return errors.ConfigError("AI max tokens must be non-negative")
	}

	// Validate other settings
	if c.AIEngineTimeout <= 0 {
		return errors.ConfigError("AI engine timeout must be positive")
	}

	if c.ConnectionPoolSize <= 0 {
		return errors.ConfigError("connection pool size must be positive")
	}

	if c.ConnectionPoolSize > 100 {
		return errors.ConfigError("connection pool size too large (max: 100)")
	}

	if c.IPCTimeout <= 0 {
		return errors.ConfigError("IPC timeout must be positive")
	}

	if c.IPCRetries < 0 {
		return errors.ConfigError("IPC retries must be non-negative")
	}

	if c.ScanTimeout <= 0 {
		return errors.ConfigError("scan timeout must be positive")
	}

	if c.MaxConcurrentScans <= 0 {
		return errors.ConfigError("max concurrent scans must be positive")
	}

	if c.MaxConcurrentScans > 100 {
		return errors.ConfigError("max concurrent scans too large (max: 100)")
	}

	if c.RateLimitRPS <= 0 {
		return errors.ConfigError("rate limit RPS must be positive")
	}

	if c.ConfigDir == "" {
		return errors.ConfigError("config directory must be specified")
	}

	return nil
}

// EnsureDirectories creates required directories if they don't exist
func (c *Config) EnsureDirectories() error {
	c.mu.RLock()
	dirs := []string{c.ConfigDir, c.LogDir, c.CacheDir}
	c.mu.RUnlock()

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return errors.WrapConfigError(fmt.Sprintf("failed to create directory %s", dir), err)
		}
	}

	return nil
}

// GetConfigPath returns the path to the JSON configuration file
func (c *Config) GetConfigPath() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return filepath.Join(c.ConfigDir, "config.json")
}

// LoadFromFile loads configuration from a JSON file
func (c *Config) LoadFromFile(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Unmarshal into a temporary config to preserve mutex
	var tempCfg Config
	if err := json.Unmarshal(data, &tempCfg); err != nil {
		return errors.WrapConfigError("failed to parse config JSON", err)
	}

	// Copy fields (excluding mutex)
	c.AI = tempCfg.AI
	c.AIProvider = tempCfg.AIProvider
	c.AIModel = tempCfg.AIModel
	c.AITemperature = tempCfg.AITemperature
	c.DefaultPorts = tempCfg.DefaultPorts
	c.ScanTimeoutSec = tempCfg.ScanTimeoutSec
	c.Theme = tempCfg.Theme
	c.ColorScheme = tempCfg.ColorScheme
	c.ShowSplash = tempCfg.ShowSplash
	c.AutoSaveSession = tempCfg.AutoSaveSession
	c.MaxHistoryDays = tempCfg.MaxHistoryDays
	c.AIEnginePath = tempCfg.AIEnginePath
	c.AIEngineTimeout = tempCfg.AIEngineTimeout
	c.ConnectionPoolSize = tempCfg.ConnectionPoolSize
	c.IPCSocketPath = tempCfg.IPCSocketPath
	c.IPCTimeout = tempCfg.IPCTimeout
	c.IPCRetries = tempCfg.IPCRetries
	c.ScanTimeout = tempCfg.ScanTimeout
	c.MaxConcurrentScans = tempCfg.MaxConcurrentScans
	c.RateLimitRPS = tempCfg.RateLimitRPS
	c.LogSanitization = tempCfg.LogSanitization
	c.AuditLogging = tempCfg.AuditLogging
	c.ConfigDir = tempCfg.ConfigDir
	c.LogDir = tempCfg.LogDir
	c.CacheDir = tempCfg.CacheDir

	return nil
}

// SaveToFile saves configuration to a JSON file
func (c *Config) SaveToFile(path string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Ensure the directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.WrapConfigError("failed to create config directory", err)
	}

	// Marshal config to JSON with indentation
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return errors.WrapConfigError("failed to marshal config to JSON", err)
	}

	// Write with secure permissions
	if err := os.WriteFile(path, data, c.SecureFilePerms); err != nil {
		return errors.WrapConfigError("failed to write config file", err)
	}

	return nil
}

// Save saves the configuration to the default config file
func (c *Config) Save() error {
	path := c.GetConfigPath()
	return c.SaveToFile(path)
}

// SetAIProvider sets the AI provider (thread-safe)
func (c *Config) SetAIProvider(provider AIProvider) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch provider {
	case AIProviderOllama, AIProviderAnthropic, AIProviderOpenAI, AIProviderGemini, AIProviderKimi, AIProviderDeepSeek, AIProviderGrok:
		c.AI.Provider = provider
		return nil
	default:
		return errors.ConfigError(fmt.Sprintf("invalid AI provider: %s", provider))
	}
}

// GetAIProvider returns the current AI provider (thread-safe)
func (c *Config) GetAIProvider() AIProvider {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.AI.Provider
}

// GetAIConfig returns a copy of the AI configuration (thread-safe)
func (c *Config) GetAIConfig() AIConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.AI
}

// SetOllamaConfig sets Ollama configuration (thread-safe)
func (c *Config) SetOllamaConfig(url, model string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.AI.OllamaURL = url
	c.AI.OllamaModel = model
}

// RequiresAPIKey returns true if the current provider requires an API key
func (c *Config) RequiresAPIKey() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	switch c.AI.Provider {
	case AIProviderAnthropic, AIProviderOpenAI, AIProviderGemini, AIProviderKimi, AIProviderDeepSeek, AIProviderGrok:
		return true
	default:
		return false
	}
}

// HasAPIKey returns true if an API key is configured for the current provider
func (c *Config) HasAPIKey() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.AI.APIKey != ""
}

// Global configuration instance with thread-safe access
var (
	globalConfig *Config
	globalMu     sync.RWMutex
	initOnce     sync.Once
)

// Get returns the global configuration (thread-safe)
func Get() *Config {
	globalMu.RLock()
	if globalConfig != nil {
		defer globalMu.RUnlock()
		return globalConfig
	}
	globalMu.RUnlock()

	// Initialize if not already done
	initOnce.Do(func() {
		globalMu.Lock()
		defer globalMu.Unlock()

		cfg, err := LoadConfig()
		if err != nil {
			// Fallback to defaults if loading fails
			cfg = DefaultConfig()
		}
		globalConfig = cfg
	})

	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalConfig
}

// Set sets the global configuration (thread-safe)
func Set(cfg *Config) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalConfig = cfg
}

// Reload reloads the configuration (thread-safe)
func Reload() error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}

	globalMu.Lock()
	globalConfig = cfg
	globalMu.Unlock()

	return nil
}
