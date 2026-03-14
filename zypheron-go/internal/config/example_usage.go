package config

// This file contains example usage patterns for the configuration package.
// These examples are meant to be used as reference and are not executed directly.

import (
	"fmt"
	"log"
)

// Example1_BasicUsage demonstrates basic configuration loading
func Example1_BasicUsage() {
	// Load configuration from defaults, JSON file, and environment variables
	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Access configuration
	fmt.Printf("AI Provider: %s\n", cfg.AI.Provider)
	fmt.Printf("Config Directory: %s\n", cfg.ConfigDir)

	// Check if API key is required and available
	if cfg.RequiresAPIKey() {
		if !cfg.HasAPIKey() {
			log.Fatal("API key required but not configured")
		}
		fmt.Println("API key is configured")
	}
}

// Example2_GlobalConfiguration demonstrates using the global configuration
func Example2_GlobalConfiguration() {
	// Get the global configuration instance
	cfg := Get()

	// The global config is initialized lazily on first access
	fmt.Printf("Using provider: %s\n", cfg.GetAIProvider())

	// Reload configuration (e.g., after environment changes)
	if err := Reload(); err != nil {
		log.Printf("Failed to reload configuration: %v", err)
	}
}

// Example3_ModifyingConfiguration demonstrates configuration modification
func Example3_ModifyingConfiguration() {
	cfg := Get()

	// Change AI provider
	if err := cfg.SetAIProvider(AIProviderAnthropic); err != nil {
		log.Fatalf("Failed to set AI provider: %v", err)
	}

	// Configure Ollama settings
	cfg.SetOllamaConfig("http://localhost:11434", "codellama")

	// Modify AI parameters
	cfg.mu.Lock()
	cfg.AI.Temperature = 0.8
	cfg.AI.MaxTokens = 8192
	cfg.mu.Unlock()

	// Save configuration to file
	if err := cfg.Save(); err != nil {
		log.Fatalf("Failed to save configuration: %v", err)
	}

	fmt.Println("Configuration saved successfully")
}

// Example4_ValidationCheck demonstrates configuration validation
func Example4_ValidationCheck() {
	cfg := Get()

	// Validate current configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration is invalid: %v", err)
	}

	fmt.Println("Configuration is valid")
}

// Example5_ThreadSafeAccess demonstrates thread-safe configuration access
func Example5_ThreadSafeAccess() {
	cfg := Get()

	// Spawn multiple goroutines accessing configuration
	done := make(chan bool)

	// Reader goroutine
	go func() {
		for i := 0; i < 10; i++ {
			provider := cfg.GetAIProvider()
			aiConfig := cfg.GetAIConfig()
			fmt.Printf("Read: Provider=%s, Temp=%.2f\n", provider, aiConfig.Temperature)
		}
		done <- true
	}()

	// Writer goroutine
	go func() {
		for i := 0; i < 10; i++ {
			cfg.SetOllamaConfig("http://localhost:11434", "codellama")
		}
		done <- true
	}()

	// Wait for goroutines
	<-done
	<-done
}

// Example6_FileOperations demonstrates file I/O operations
func Example6_FileOperations() {
	cfg := DefaultConfig()

	// Customize configuration
	cfg.AI.Provider = AIProviderOpenAI
	cfg.AI.Model = "gpt-4"
	cfg.AI.Temperature = 0.7
	cfg.ConnectionPoolSize = 10

	// Save to custom path
	customPath := "/tmp/zypheron-config.json"
	if err := cfg.SaveToFile(customPath); err != nil {
		log.Fatalf("Failed to save to custom path: %v", err)
	}

	// Load from custom path
	loadedCfg := DefaultConfig()
	if err := loadedCfg.LoadFromFile(customPath); err != nil {
		log.Fatalf("Failed to load from custom path: %v", err)
	}

	fmt.Printf("Loaded provider: %s\n", loadedCfg.AI.Provider)
	fmt.Printf("Loaded model: %s\n", loadedCfg.AI.Model)
}

// Example7_ProviderChecks demonstrates provider-specific checks
func Example7_ProviderChecks() {
	cfg := Get()

	// Check which provider is active
	switch cfg.GetAIProvider() {
	case AIProviderOllama:
		fmt.Println("Using local Ollama installation")
		aiConfig := cfg.GetAIConfig()
		fmt.Printf("URL: %s, Model: %s\n", aiConfig.OllamaURL, aiConfig.OllamaModel)

	case AIProviderAnthropic:
		fmt.Println("Using Anthropic Claude API")
		if !cfg.HasAPIKey() {
			log.Fatal("Anthropic API key not configured")
		}

	case AIProviderOpenAI:
		fmt.Println("Using OpenAI API")
		if !cfg.HasAPIKey() {
			log.Fatal("OpenAI API key not configured")
		}

	case AIProviderDeepSeek:
		fmt.Println("Using DeepSeek API")
		if !cfg.HasAPIKey() {
			log.Fatal("DeepSeek API key not configured")
		}

	default:
		log.Fatalf("Unknown provider: %s", cfg.GetAIProvider())
	}
}

// Example8_ConfigurationStatus demonstrates status checking
func Example8_ConfigurationStatus() {
	// Validate environment and get detailed status
	status := ValidateEnvironment()

	// Print formatted status
	status.PrintStatus()

	// Check if configuration is valid
	if !status.Valid {
		log.Fatal("Please fix configuration errors before proceeding")
	}

	// Access status details programmatically
	if len(status.Warnings) > 0 {
		fmt.Printf("Found %d warnings\n", len(status.Warnings))
	}

	if len(status.Errors) > 0 {
		fmt.Printf("Found %d errors\n", len(status.Errors))
	}
}

// Example9_Diagnostics demonstrates diagnostic output
func Example9_Diagnostics() {
	// Print comprehensive diagnostic information
	PrintDiagnostics()

	// Quick check for scripts
	if !QuickCheck() {
		log.Fatal("Configuration check failed")
	}

	fmt.Println("Configuration check passed")
}

// Example10_ProviderHelp demonstrates getting provider-specific help
func Example10_ProviderHelp() {
	// Get help for Ollama configuration
	help := GetProviderHelp(AIProviderOllama)
	fmt.Println(help)

	// Get help for Anthropic configuration
	help = GetProviderHelp(AIProviderAnthropic)
	fmt.Println(help)

	// Get help for current provider
	cfg := Get()
	help = GetProviderHelp(cfg.GetAIProvider())
	fmt.Println(help)
}

// Example11_ErrorHandling demonstrates proper error handling
func Example11_ErrorHandling() {
	// Load configuration with error handling
	cfg, err := LoadConfig()
	if err != nil {
		log.Printf("Failed to load configuration: %v", err)
		// Fall back to defaults
		cfg = DefaultConfig()
	}

	// Validate with error handling
	if err := cfg.Validate(); err != nil {
		log.Printf("Configuration validation failed: %v", err)
		// Could prompt user for fixes or use safe defaults
		return
	}

	// Save with error handling
	if err := cfg.Save(); err != nil {
		log.Printf("Failed to save configuration: %v", err)
		// Configuration changes won't persist, but can continue
	}

	fmt.Println("Configuration loaded and validated successfully")
}

// Example12_MultipleProviders demonstrates switching between providers
func Example12_MultipleProviders() {
	cfg := Get()

	// Try Ollama first (local, no API key needed)
	if err := cfg.SetAIProvider(AIProviderOllama); err == nil {
		if err := cfg.Validate(); err == nil {
			fmt.Println("Using Ollama (local AI)")
			return
		}
	}

	// Fall back to cloud provider if available
	if apiKey := cfg.AI.APIKey; apiKey != "" {
		// Determine provider from environment
		if cfg.AI.Provider == AIProviderAnthropic {
			fmt.Println("Using Anthropic Claude (cloud AI)")
			return
		}
	}

	log.Fatal("No valid AI provider configuration found")
}

// Example13_CustomDefaults demonstrates creating custom default configurations
func Example13_CustomDefaults() {
	// Start with defaults
	cfg := DefaultConfig()

	// Customize for your use case
	cfg.AI.Temperature = 0.5 // More focused responses
	cfg.AI.MaxTokens = 16384 // Longer responses
	cfg.ConnectionPoolSize = 20
	cfg.MaxConcurrentScans = 30
	cfg.RateLimitRPS = 20

	// Validate custom configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Custom configuration is invalid: %v", err)
	}

	// Set as global configuration
	Set(cfg)

	fmt.Println("Custom configuration applied")
}

// Example14_ProductionVsDevelopment demonstrates environment-specific configuration
func Example14_ProductionVsDevelopment() {
	cfg := Get()

	// Check environment (could be from ENV var)
	environment := "development" // or "production"

	if environment == "production" {
		// Production settings
		cfg.mu.Lock()
		cfg.AI.Temperature = 0.5 // More deterministic
		cfg.LogSanitization = true
		cfg.AuditLogging = true
		cfg.RateLimitRPS = 5 // Conservative
		cfg.mu.Unlock()

		fmt.Println("Production configuration applied")

	} else {
		// Development settings
		cfg.mu.Lock()
		cfg.AI.Temperature = 0.7 // More creative
		cfg.LogSanitization = false // Full logs for debugging
		cfg.AuditLogging = false // Less overhead
		cfg.RateLimitRPS = 20 // Higher for testing
		cfg.mu.Unlock()

		fmt.Println("Development configuration applied")
	}

	// Save environment-specific configuration
	if err := cfg.Save(); err != nil {
		log.Printf("Warning: Failed to persist configuration: %v", err)
	}
}

// Example15_ConfigurationMigration demonstrates migrating configuration
func Example15_ConfigurationMigration() {
	// Load old configuration
	oldCfg := DefaultConfig()
	oldPath := "/path/to/old/config.json"
	if err := oldCfg.LoadFromFile(oldPath); err != nil {
		log.Printf("Could not load old configuration: %v", err)
		return
	}

	// Create new configuration with migrated values
	newCfg := DefaultConfig()
	newCfg.AI = oldCfg.AI
	newCfg.ConnectionPoolSize = oldCfg.ConnectionPoolSize
	newCfg.MaxConcurrentScans = oldCfg.MaxConcurrentScans

	// Validate migrated configuration
	if err := newCfg.Validate(); err != nil {
		log.Fatalf("Migrated configuration is invalid: %v", err)
	}

	// Save to new location
	if err := newCfg.Save(); err != nil {
		log.Fatalf("Failed to save migrated configuration: %v", err)
	}

	fmt.Println("Configuration migrated successfully")
}
