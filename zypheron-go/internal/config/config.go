package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/errors"
)

// Config holds all application configuration
type Config struct {
	// AI Engine
	AIEnginePath      string
	AIEngineTimeout   time.Duration
	ConnectionPoolSize int
	
	// IPC
	IPCSocketPath     string
	IPCTimeout        time.Duration
	IPCRetries        int
	
	// Scanning
	ScanTimeout       time.Duration
	MaxConcurrentScans int
	RateLimitRPS      int
	
	// Security
	SecureFilePerms   os.FileMode
	LogSanitization   bool
	AuditLogging      bool
	
	// Paths
	ConfigDir         string
	LogDir            string
	CacheDir          string
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	configDir := filepath.Join(homeDir, ".zypheron")
	
	return &Config{
		// AI Engine
		AIEnginePath:       "",  // Auto-detect
		AIEngineTimeout:    60 * time.Second,
		ConnectionPoolSize: 5,
		
		// IPC
		IPCSocketPath:      filepath.Join(configDir, "ai.sock"),
		IPCTimeout:         30 * time.Second,
		IPCRetries:         3,
		
		// Scanning
		ScanTimeout:        300 * time.Second,
		MaxConcurrentScans: 10,
		RateLimitRPS:       10,
		
		// Security
		SecureFilePerms:    0o600,
		LogSanitization:    true,
		AuditLogging:       true,
		
		// Paths
		ConfigDir:          configDir,
		LogDir:             filepath.Join(configDir, "logs"),
		CacheDir:           filepath.Join(configDir, "cache"),
	}
}

// LoadConfig loads configuration from environment and defaults
func LoadConfig() (*Config, error) {
	cfg := DefaultConfig()
	
	// Override from environment variables
	if val := os.Getenv("ZYPHERON_AI_PATH"); val != "" {
		cfg.AIEnginePath = val
	}
	
	if val := os.Getenv("ZYPHERON_CONFIG_DIR"); val != "" {
		cfg.ConfigDir = val
		cfg.IPCSocketPath = filepath.Join(val, "ai.sock")
		cfg.LogDir = filepath.Join(val, "logs")
		cfg.CacheDir = filepath.Join(val, "cache")
	}
	
	if val := os.Getenv("ZYPHERON_CONNECTION_POOL_SIZE"); val != "" {
		if size, err := strconv.Atoi(val); err == nil && size > 0 {
			cfg.ConnectionPoolSize = size
		}
	}
	
	if val := os.Getenv("ZYPHERON_MAX_CONCURRENT_SCANS"); val != "" {
		if max, err := strconv.Atoi(val); err == nil && max > 0 {
			cfg.MaxConcurrentScans = max
		}
	}
	
	if val := os.Getenv("ZYPHERON_RATE_LIMIT_RPS"); val != "" {
		if rps, err := strconv.Atoi(val); err == nil && rps > 0 {
			cfg.RateLimitRPS = rps
		}
	}
	
	if val := os.Getenv("ZYPHERON_LOG_SANITIZATION"); val == "false" {
		cfg.LogSanitization = false
	}
	
	if val := os.Getenv("ZYPHERON_AUDIT_LOGGING"); val == "false" {
		cfg.AuditLogging = false
	}
	
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

// Validate validates the configuration
func (c *Config) Validate() error {
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
	dirs := []string{c.ConfigDir, c.LogDir, c.CacheDir}
	
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return errors.WrapConfigError(fmt.Sprintf("failed to create directory %s", dir), err)
		}
	}
	
	return nil
}

// Global configuration instance
var globalConfig *Config

// Get returns the global configuration
func Get() *Config {
	if globalConfig == nil {
		cfg, err := LoadConfig()
		if err != nil {
			// Fallback to defaults if loading fails
			cfg = DefaultConfig()
		}
		globalConfig = cfg
	}
	return globalConfig
}

// Set sets the global configuration
func Set(cfg *Config) {
	globalConfig = cfg
}

// Reload reloads the configuration
func Reload() error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	globalConfig = cfg
	return nil
}

