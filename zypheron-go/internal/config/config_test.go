package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Test AI defaults
	if cfg.AI.Provider != AIProviderOllama {
		t.Errorf("Expected default provider to be ollama, got %s", cfg.AI.Provider)
	}

	if cfg.AI.OllamaURL != "http://localhost:11434" {
		t.Errorf("Expected default Ollama URL to be http://localhost:11434, got %s", cfg.AI.OllamaURL)
	}

	if cfg.AI.OllamaModel != "codellama" {
		t.Errorf("Expected default Ollama model to be codellama, got %s", cfg.AI.OllamaModel)
	}

	if cfg.AI.Temperature != 0.7 {
		t.Errorf("Expected default temperature to be 0.7, got %f", cfg.AI.Temperature)
	}

	if cfg.AI.MaxTokens != 4096 {
		t.Errorf("Expected default max tokens to be 4096, got %d", cfg.AI.MaxTokens)
	}

	// Test other defaults
	if cfg.ConnectionPoolSize != 5 {
		t.Errorf("Expected connection pool size to be 5, got %d", cfg.ConnectionPoolSize)
	}

	if cfg.MaxConcurrentScans != 10 {
		t.Errorf("Expected max concurrent scans to be 10, got %d", cfg.MaxConcurrentScans)
	}

	if cfg.RateLimitRPS != 10 {
		t.Errorf("Expected rate limit RPS to be 10, got %d", cfg.RateLimitRPS)
	}
}

func TestAIProviderValidation(t *testing.T) {
	tests := []struct {
		name     string
		provider AIProvider
		apiKey   string
		wantErr  bool
	}{
		{
			name:     "Ollama without API key",
			provider: AIProviderOllama,
			apiKey:   "",
			wantErr:  false,
		},
		{
			name:     "Anthropic without API key",
			provider: AIProviderAnthropic,
			apiKey:   "",
			wantErr:  true,
		},
		{
			name:     "Anthropic with API key",
			provider: AIProviderAnthropic,
			apiKey:   "sk-ant-test-key",
			wantErr:  false,
		},
		{
			name:     "OpenAI with API key",
			provider: AIProviderOpenAI,
			apiKey:   "sk-test-key",
			wantErr:  false,
		},
		{
			name:     "DeepSeek with API key",
			provider: AIProviderDeepSeek,
			apiKey:   "sk-test-key",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.AI.Provider = tt.provider
			cfg.AI.APIKey = tt.apiKey

			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSetAIProvider(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		provider AIProvider
		wantErr  bool
	}{
		{AIProviderOllama, false},
		{AIProviderAnthropic, false},
		{AIProviderOpenAI, false},
		{AIProviderDeepSeek, false},
		{"invalid", true},
	}

	for _, tt := range tests {
		err := cfg.SetAIProvider(tt.provider)
		if (err != nil) != tt.wantErr {
			t.Errorf("SetAIProvider(%s) error = %v, wantErr %v", tt.provider, err, tt.wantErr)
		}

		if err == nil && cfg.GetAIProvider() != tt.provider {
			t.Errorf("Expected provider %s, got %s", tt.provider, cfg.GetAIProvider())
		}
	}
}

func TestRequiresAPIKey(t *testing.T) {
	tests := []struct {
		provider AIProvider
		expected bool
	}{
		{AIProviderOllama, false},
		{AIProviderAnthropic, true},
		{AIProviderOpenAI, true},
		{AIProviderDeepSeek, true},
	}

	for _, tt := range tests {
		cfg := DefaultConfig()
		cfg.AI.Provider = tt.provider

		if cfg.RequiresAPIKey() != tt.expected {
			t.Errorf("RequiresAPIKey() for %s = %v, want %v", tt.provider, cfg.RequiresAPIKey(), tt.expected)
		}
	}
}

func TestHasAPIKey(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.HasAPIKey() {
		t.Error("Expected HasAPIKey() to be false with default config")
	}

	cfg.AI.APIKey = "test-key"
	if !cfg.HasAPIKey() {
		t.Error("Expected HasAPIKey() to be true after setting API key")
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	// Create and configure test config
	cfg := DefaultConfig()
	cfg.ConfigDir = tempDir
	cfg.AI.Provider = AIProviderAnthropic
	cfg.AI.Model = "claude-3-5-sonnet"
	cfg.AIProvider = "anthropic"
	cfg.AIModel = "claude-opus-4-6"
	cfg.DefaultPorts = "1-65535"
	cfg.AI.Temperature = 0.8
	cfg.AI.MaxTokens = 8192
	cfg.ConnectionPoolSize = 10
	cfg.MaxConcurrentScans = 20

	// Save config
	err := cfg.SaveToFile(configPath)
	if err != nil {
		t.Fatalf("SaveToFile() error = %v", err)
	}

	// Check file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatal("Config file was not created")
	}

	// Load config
	loadedCfg := DefaultConfig()
	err = loadedCfg.LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	// Verify loaded values
	if loadedCfg.AI.Provider != cfg.AI.Provider {
		t.Errorf("Provider mismatch: got %s, want %s", loadedCfg.AI.Provider, cfg.AI.Provider)
	}

	if loadedCfg.AI.Model != cfg.AI.Model {
		t.Errorf("Model mismatch: got %s, want %s", loadedCfg.AI.Model, cfg.AI.Model)
	}
	if loadedCfg.AIProvider != cfg.AIProvider {
		t.Errorf("AIProvider mismatch: got %s, want %s", loadedCfg.AIProvider, cfg.AIProvider)
	}
	if loadedCfg.AIModel != cfg.AIModel {
		t.Errorf("AIModel mismatch: got %s, want %s", loadedCfg.AIModel, cfg.AIModel)
	}
	if loadedCfg.DefaultPorts != cfg.DefaultPorts {
		t.Errorf("DefaultPorts mismatch: got %s, want %s", loadedCfg.DefaultPorts, cfg.DefaultPorts)
	}

	if loadedCfg.AI.Temperature != cfg.AI.Temperature {
		t.Errorf("Temperature mismatch: got %f, want %f", loadedCfg.AI.Temperature, cfg.AI.Temperature)
	}

	if loadedCfg.AI.MaxTokens != cfg.AI.MaxTokens {
		t.Errorf("MaxTokens mismatch: got %d, want %d", loadedCfg.AI.MaxTokens, cfg.AI.MaxTokens)
	}

	if loadedCfg.ConnectionPoolSize != cfg.ConnectionPoolSize {
		t.Errorf("ConnectionPoolSize mismatch: got %d, want %d", loadedCfg.ConnectionPoolSize, cfg.ConnectionPoolSize)
	}

	// Verify API key was not persisted
	if loadedCfg.AI.APIKey != "" {
		t.Error("API key should not be persisted to file")
	}
}

func TestLoadFromEnv(t *testing.T) {
	// Save original env vars
	originalVars := map[string]string{
		"ZYPHERON_AI_PROVIDER":          os.Getenv("ZYPHERON_AI_PROVIDER"),
		"ANTHROPIC_API_KEY":             os.Getenv("ANTHROPIC_API_KEY"),
		"ZYPHERON_AI_MODEL":             os.Getenv("ZYPHERON_AI_MODEL"),
		"ZYPHERON_AI_TEMPERATURE":       os.Getenv("ZYPHERON_AI_TEMPERATURE"),
		"ZYPHERON_AI_MAX_TOKENS":        os.Getenv("ZYPHERON_AI_MAX_TOKENS"),
		"ZYPHERON_CONNECTION_POOL_SIZE": os.Getenv("ZYPHERON_CONNECTION_POOL_SIZE"),
	}

	// Restore original env vars after test
	defer func() {
		for k, v := range originalVars {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}()

	// Set test env vars
	os.Setenv("ZYPHERON_AI_PROVIDER", "anthropic")
	os.Setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
	os.Setenv("ZYPHERON_AI_MODEL", "claude-3-5-sonnet")
	os.Setenv("ZYPHERON_AI_TEMPERATURE", "0.9")
	os.Setenv("ZYPHERON_AI_MAX_TOKENS", "8192")
	os.Setenv("ZYPHERON_CONNECTION_POOL_SIZE", "15")

	// Create config and load from env
	cfg := DefaultConfig()
	cfg.loadFromEnv()

	// Verify env vars were loaded
	if cfg.AI.Provider != AIProviderAnthropic {
		t.Errorf("Expected provider anthropic, got %s", cfg.AI.Provider)
	}

	if cfg.AI.APIKey != "sk-ant-test-key" {
		t.Errorf("Expected API key to be loaded from env, got %s", cfg.AI.APIKey)
	}

	if cfg.AI.Model != "claude-3-5-sonnet" {
		t.Errorf("Expected model claude-3-5-sonnet, got %s", cfg.AI.Model)
	}

	if cfg.AI.Temperature != 0.9 {
		t.Errorf("Expected temperature 0.9, got %f", cfg.AI.Temperature)
	}

	if cfg.AI.MaxTokens != 8192 {
		t.Errorf("Expected max tokens 8192, got %d", cfg.AI.MaxTokens)
	}

	if cfg.ConnectionPoolSize != 15 {
		t.Errorf("Expected connection pool size 15, got %d", cfg.ConnectionPoolSize)
	}
}

func TestThreadSafety(t *testing.T) {
	cfg := DefaultConfig()

	// Test concurrent reads and writes
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			cfg.SetOllamaConfig("http://localhost:11434", "codellama")
			time.Sleep(1 * time.Millisecond)
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			_ = cfg.GetAIProvider()
			_ = cfg.GetAIConfig()
			time.Sleep(1 * time.Millisecond)
		}
		done <- true
	}()

	// Wait for both goroutines
	<-done
	<-done
}

func TestValidationEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*Config)
		wantErr bool
	}{
		{
			name: "Temperature too low",
			setup: func(c *Config) {
				c.AI.Temperature = -0.1
			},
			wantErr: true,
		},
		{
			name: "Temperature too high",
			setup: func(c *Config) {
				c.AI.Temperature = 1.1
			},
			wantErr: true,
		},
		{
			name: "Negative max tokens",
			setup: func(c *Config) {
				c.AI.MaxTokens = -1
			},
			wantErr: true,
		},
		{
			name: "Zero connection pool size",
			setup: func(c *Config) {
				c.ConnectionPoolSize = 0
			},
			wantErr: true,
		},
		{
			name: "Connection pool size too large",
			setup: func(c *Config) {
				c.ConnectionPoolSize = 101
			},
			wantErr: true,
		},
		{
			name: "Empty config directory",
			setup: func(c *Config) {
				c.ConfigDir = ""
			},
			wantErr: true,
		},
		{
			name: "Valid configuration",
			setup: func(c *Config) {
				c.AI.APIKey = "test-key"
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.AI.Provider = AIProviderAnthropic
			cfg.AI.APIKey = "test-key"
			tt.setup(cfg)

			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOllamaConfiguration(t *testing.T) {
	// Test Ollama URL from env
	os.Setenv("OLLAMA_URL", "http://custom:11434")
	os.Setenv("OLLAMA_MODEL", "llama2")
	defer os.Unsetenv("OLLAMA_URL")
	defer os.Unsetenv("OLLAMA_MODEL")

	cfg := DefaultConfig()
	cfg.loadFromEnv()

	if cfg.AI.OllamaURL != "http://custom:11434" {
		t.Errorf("Expected custom Ollama URL, got %s", cfg.AI.OllamaURL)
	}

	if cfg.AI.OllamaModel != "llama2" {
		t.Errorf("Expected llama2 model, got %s", cfg.AI.OllamaModel)
	}

	// Test SetOllamaConfig
	cfg.SetOllamaConfig("http://localhost:8080", "mistral")
	if cfg.AI.OllamaURL != "http://localhost:8080" {
		t.Errorf("Expected URL http://localhost:8080, got %s", cfg.AI.OllamaURL)
	}

	if cfg.AI.OllamaModel != "mistral" {
		t.Errorf("Expected model mistral, got %s", cfg.AI.OllamaModel)
	}
}
