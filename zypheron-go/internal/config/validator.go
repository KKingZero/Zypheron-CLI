package config

import (
	"fmt"
	"os"
	"strings"
)

// ConfigStatus represents the status of configuration validation
type ConfigStatus struct {
	Valid    bool
	Warnings []string
	Errors   []string
	Info     []string
}

// ValidateEnvironment validates the current environment configuration
func ValidateEnvironment() *ConfigStatus {
	status := &ConfigStatus{
		Valid:    true,
		Warnings: []string{},
		Errors:   []string{},
		Info:     []string{},
	}

	// Load configuration
	cfg, err := LoadConfig()
	if err != nil {
		status.Valid = false
		status.Errors = append(status.Errors, fmt.Sprintf("Failed to load configuration: %v", err))
		return status
	}

	// Check AI provider configuration
	status.Info = append(status.Info, fmt.Sprintf("AI Provider: %s", cfg.AI.Provider))

	switch cfg.AI.Provider {
	case AIProviderOllama:
		status.Info = append(status.Info, fmt.Sprintf("Ollama URL: %s", cfg.AI.OllamaURL))
		status.Info = append(status.Info, fmt.Sprintf("Ollama Model: %s", cfg.AI.OllamaModel))

		// Check if Ollama is accessible (basic check)
		if cfg.AI.OllamaURL == "" {
			status.Errors = append(status.Errors, "Ollama URL is not configured")
			status.Valid = false
		}

		if cfg.AI.OllamaModel == "" {
			status.Warnings = append(status.Warnings, "Ollama model is not specified, may use default")
		}

	case AIProviderAnthropic:
		status.Info = append(status.Info, "Using Anthropic Claude API")
		if cfg.AI.Model != "" {
			status.Info = append(status.Info, fmt.Sprintf("Model: %s", cfg.AI.Model))
		}

		// Check API key
		if !cfg.HasAPIKey() {
			status.Errors = append(status.Errors, "ANTHROPIC_API_KEY environment variable is not set")
			status.Valid = false
		} else {
			status.Info = append(status.Info, "API Key: ✓ Configured (from environment)")
		}

	case AIProviderOpenAI:
		status.Info = append(status.Info, "Using OpenAI API")
		if cfg.AI.Model != "" {
			status.Info = append(status.Info, fmt.Sprintf("Model: %s", cfg.AI.Model))
		}

		// Check API key
		if !cfg.HasAPIKey() {
			status.Errors = append(status.Errors, "OPENAI_API_KEY environment variable is not set")
			status.Valid = false
		} else {
			status.Info = append(status.Info, "API Key: ✓ Configured (from environment)")
		}

	case AIProviderDeepSeek:
		status.Info = append(status.Info, "Using DeepSeek API")
		if cfg.AI.Model != "" {
			status.Info = append(status.Info, fmt.Sprintf("Model: %s", cfg.AI.Model))
		}

		// Check API key
		if !cfg.HasAPIKey() {
			status.Errors = append(status.Errors, "DEEPSEEK_API_KEY environment variable is not set")
			status.Valid = false
		} else {
			status.Info = append(status.Info, "API Key: ✓ Configured (from environment)")
		}

	default:
		status.Errors = append(status.Errors, fmt.Sprintf("Unknown AI provider: %s", cfg.AI.Provider))
		status.Valid = false
	}

	// Check AI parameters
	if cfg.AI.Temperature < 0 || cfg.AI.Temperature > 1 {
		status.Warnings = append(status.Warnings, fmt.Sprintf("Temperature %.2f is outside recommended range [0.0, 1.0]", cfg.AI.Temperature))
	} else {
		status.Info = append(status.Info, fmt.Sprintf("Temperature: %.2f", cfg.AI.Temperature))
	}

	if cfg.AI.MaxTokens > 0 {
		status.Info = append(status.Info, fmt.Sprintf("Max Tokens: %d", cfg.AI.MaxTokens))
	}

	// Check configuration file
	configPath := cfg.GetConfigPath()
	if _, err := os.Stat(configPath); err == nil {
		status.Info = append(status.Info, fmt.Sprintf("Config file: %s ✓", configPath))
	} else if os.IsNotExist(err) {
		status.Warnings = append(status.Warnings, fmt.Sprintf("Config file not found: %s (using defaults)", configPath))
	}

	// Check directories
	if _, err := os.Stat(cfg.ConfigDir); err != nil {
		status.Warnings = append(status.Warnings, fmt.Sprintf("Config directory does not exist: %s", cfg.ConfigDir))
	}

	// Check resource limits
	if cfg.ConnectionPoolSize > 50 {
		status.Warnings = append(status.Warnings, fmt.Sprintf("Connection pool size %d is quite large", cfg.ConnectionPoolSize))
	}

	if cfg.MaxConcurrentScans > 50 {
		status.Warnings = append(status.Warnings, fmt.Sprintf("Max concurrent scans %d may be too high", cfg.MaxConcurrentScans))
	}

	// Check for security settings
	if !cfg.LogSanitization {
		status.Warnings = append(status.Warnings, "Log sanitization is disabled - sensitive data may be logged")
	}

	if !cfg.AuditLogging {
		status.Warnings = append(status.Warnings, "Audit logging is disabled")
	}

	return status
}

// PrintStatus prints a formatted configuration status
func (s *ConfigStatus) PrintStatus() {
	fmt.Println("\n=== Zypheron Configuration Status ===")
	fmt.Println()

	// Print errors
	if len(s.Errors) > 0 {
		fmt.Println("❌ ERRORS:")
		for _, err := range s.Errors {
			fmt.Printf("  • %s\n", err)
		}
		fmt.Println()
	}

	// Print warnings
	if len(s.Warnings) > 0 {
		fmt.Println("⚠️  WARNINGS:")
		for _, warn := range s.Warnings {
			fmt.Printf("  • %s\n", warn)
		}
		fmt.Println()
	}

	// Print info
	if len(s.Info) > 0 {
		fmt.Println("ℹ️  CONFIGURATION:")
		for _, info := range s.Info {
			fmt.Printf("  • %s\n", info)
		}
		fmt.Println()
	}

	// Overall status
	if s.Valid {
		fmt.Println("✅ Configuration is VALID")
	} else {
		fmt.Println("❌ Configuration is INVALID - please fix errors above")
	}
	fmt.Println()
}

// PrintDiagnostics prints detailed diagnostic information
func PrintDiagnostics() {
	fmt.Println("\n=== Zypheron Configuration Diagnostics ===")
	fmt.Println()

	// Environment variables
	fmt.Println("Environment Variables:")
	envVars := []string{
		"ZYPHERON_AI_PROVIDER",
		"ANTHROPIC_API_KEY",
		"OPENAI_API_KEY",
		"DEEPSEEK_API_KEY",
		"OLLAMA_URL",
		"OLLAMA_MODEL",
		"ZYPHERON_AI_MODEL",
		"ZYPHERON_AI_TEMPERATURE",
		"ZYPHERON_AI_MAX_TOKENS",
		"ZYPHERON_CONFIG_DIR",
		"ZYPHERON_CONNECTION_POOL_SIZE",
		"ZYPHERON_MAX_CONCURRENT_SCANS",
	}

	for _, key := range envVars {
		val := os.Getenv(key)
		if val != "" {
			// Mask API keys
			if strings.Contains(key, "API_KEY") {
				fmt.Printf("  %s: %s... (masked)\n", key, val[:min(10, len(val))])
			} else {
				fmt.Printf("  %s: %s\n", key, val)
			}
		} else {
			fmt.Printf("  %s: (not set)\n", key)
		}
	}
	fmt.Println()

	// Configuration files
	homeDir, _ := os.UserHomeDir()
	configDir := os.Getenv("ZYPHERON_CONFIG_DIR")
	if configDir == "" {
		configDir = fmt.Sprintf("%s/.zypheron", homeDir)
	}

	fmt.Println("Configuration Files:")
	files := []string{
		fmt.Sprintf("%s/config.json", configDir),
		fmt.Sprintf("%s/toolchains.yaml", configDir),
	}

	for _, path := range files {
		if info, err := os.Stat(path); err == nil {
			fmt.Printf("  %s: ✓ (size: %d bytes, modified: %s)\n", path, info.Size(), info.ModTime().Format("2006-01-02 15:04:05"))
		} else {
			fmt.Printf("  %s: ✗ (not found)\n", path)
		}
	}
	fmt.Println()

	// Directories
	fmt.Println("Directories:")
	dirs := []string{
		configDir,
		fmt.Sprintf("%s/logs", configDir),
		fmt.Sprintf("%s/cache", configDir),
	}

	for _, path := range dirs {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			perms := info.Mode().Perm()
			fmt.Printf("  %s: ✓ (permissions: %04o)\n", path, perms)
		} else {
			fmt.Printf("  %s: ✗ (not found or not a directory)\n", path)
		}
	}
	fmt.Println()

	// Provider-specific checks
	provider := os.Getenv("ZYPHERON_AI_PROVIDER")
	if provider == "" {
		provider = "ollama" // default
	}

	fmt.Printf("Provider-Specific Checks (%s):\n", provider)
	switch provider {
	case "ollama":
		ollamaURL := os.Getenv("OLLAMA_URL")
		if ollamaURL == "" {
			ollamaURL = "http://localhost:11434"
		}
		fmt.Printf("  Ollama URL: %s\n", ollamaURL)
		fmt.Printf("  Ollama Model: %s\n", getEnvOrDefault("OLLAMA_MODEL", "codellama"))

	case "anthropic":
		apiKey := os.Getenv("ANTHROPIC_API_KEY")
		if apiKey != "" {
			fmt.Printf("  API Key: ✓ Configured (length: %d)\n", len(apiKey))
		} else {
			fmt.Printf("  API Key: ✗ Not configured\n")
		}

	case "openai":
		apiKey := os.Getenv("OPENAI_API_KEY")
		if apiKey != "" {
			fmt.Printf("  API Key: ✓ Configured (length: %d)\n", len(apiKey))
		} else {
			fmt.Printf("  API Key: ✗ Not configured\n")
		}

	case "deepseek":
		apiKey := os.Getenv("DEEPSEEK_API_KEY")
		if apiKey != "" {
			fmt.Printf("  API Key: ✓ Configured (length: %d)\n", len(apiKey))
		} else {
			fmt.Printf("  API Key: ✗ Not configured\n")
		}
	}
	fmt.Println()
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// QuickCheck performs a quick configuration check and returns success status
func QuickCheck() bool {
	status := ValidateEnvironment()
	return status.Valid
}

// GetProviderHelp returns help text for configuring a specific provider
func GetProviderHelp(provider AIProvider) string {
	switch provider {
	case AIProviderOllama:
		return `Ollama Configuration:

1. Install Ollama:
   curl -fsSL https://ollama.com/install.sh | sh

2. Pull a model:
   ollama pull codellama

3. (Optional) Configure custom URL:
   export OLLAMA_URL=http://localhost:11434
   export OLLAMA_MODEL=codellama

4. Run Zypheron:
   zypheron scan
`

	case AIProviderAnthropic:
		return `Anthropic Configuration:

1. Get API key from: https://console.anthropic.com/

2. Set environment variable:
   export ANTHROPIC_API_KEY=sk-ant-your-key-here

3. Set provider:
   export ZYPHERON_AI_PROVIDER=anthropic

4. (Optional) Set specific model:
   export ZYPHERON_AI_MODEL=claude-3-5-sonnet-20241022

5. Run Zypheron:
   zypheron scan
`

	case AIProviderOpenAI:
		return `OpenAI Configuration:

1. Get API key from: https://platform.openai.com/api-keys

2. Set environment variable:
   export OPENAI_API_KEY=sk-your-key-here

3. Set provider:
   export ZYPHERON_AI_PROVIDER=openai

4. (Optional) Set specific model:
   export ZYPHERON_AI_MODEL=gpt-4

5. Run Zypheron:
   zypheron scan
`

	case AIProviderDeepSeek:
		return `DeepSeek Configuration:

1. Get API key from: https://platform.deepseek.com/

2. Set environment variable:
   export DEEPSEEK_API_KEY=sk-your-key-here

3. Set provider:
   export ZYPHERON_AI_PROVIDER=deepseek

4. (Optional) Set specific model:
   export ZYPHERON_AI_MODEL=deepseek-chat

5. Run Zypheron:
   zypheron scan
`

	default:
		return fmt.Sprintf("Unknown provider: %s\n\nSupported providers: ollama, anthropic, openai, deepseek", provider)
	}
}
