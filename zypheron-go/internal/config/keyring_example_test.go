package config_test

import (
	"fmt"
	"log"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"
)

// ExampleSetAPIKey demonstrates how to securely store an API key
func ExampleSetAPIKey() {
	err := config.SetAPIKey(config.ProviderDeepSeek, "sk-1234567890abcdef")
	if err != nil {
		log.Printf("Failed to store API key: %v", err)
		return
	}

	fmt.Println("API key stored successfully")
	// Output: API key stored successfully
}

// ExampleGetAPIKey demonstrates how to retrieve a stored API key
func ExampleGetAPIKey() {
	// First, store a key (in real usage, this would be done separately)
	testKey := "sk-ant-example123"
	_ = config.SetAPIKey(config.ProviderAnthropic, testKey)

	// Retrieve the key
	key, err := config.GetAPIKey(config.ProviderAnthropic)
	if err != nil {
		log.Printf("Failed to retrieve API key: %v", err)
		return
	}

	// In production, never print the actual key - this is just for demonstration
	fmt.Printf("Retrieved key length: %d\n", len(key))

	// Clean up
	_ = config.DeleteAPIKey(config.ProviderAnthropic)
	// Output: Retrieved key length: 17
}

// ExampleHasAPIKey demonstrates how to check if an API key exists
func ExampleHasAPIKey() {
	// Check if a provider has a stored key
	exists := config.HasAPIKey(config.ProviderOpenAI)

	if exists {
		fmt.Println("OpenAI API key is configured")
	} else {
		fmt.Println("OpenAI API key not found")
	}
	// Output: OpenAI API key not found
}

// ExampleListProviders demonstrates how to list all configured providers
func ExampleListProviders() {
	// Store some keys for demonstration
	_ = config.SetAPIKey(config.ProviderDeepSeek, "test-key-1")
	_ = config.SetAPIKey(config.ProviderAnthropic, "test-key-2")

	// List all providers with stored keys
	providers := config.ListProviders()

	fmt.Printf("Configured providers: %d\n", len(providers))
	for _, provider := range providers {
		fmt.Printf("- %s\n", provider)
	}
}

// ExampleDeleteAPIKey demonstrates how to remove a stored API key
func ExampleDeleteAPIKey() {
	// First store a key
	_ = config.SetAPIKey(config.ProviderSupabaseKey, "test-key")

	// Delete the key
	err := config.DeleteAPIKey(config.ProviderSupabaseKey)
	if err != nil {
		log.Printf("Failed to delete API key: %v", err)
		return
	}

	fmt.Println("API key deleted successfully")
	// Output: API key deleted successfully
}

// ExampleIsKeyringAvailable demonstrates how to check keyring availability
func ExampleIsKeyringAvailable() {
	available := config.IsKeyringAvailable()

	if available {
		fmt.Println("System keyring is available")
	} else {
		fmt.Println("System keyring unavailable - using environment variables")
	}
}

// Example_multiProviderSetup demonstrates a complete setup with multiple providers
func Example_multiProviderSetup() {
	// Define API keys for multiple providers
	keys := map[string]string{
		config.ProviderDeepSeek:    "sk-deepseek-abc123",
		config.ProviderAnthropic:   "sk-ant-xyz789",
		config.ProviderOpenAI:      "sk-openai-def456",
		config.ProviderSupabaseURL: "https://example.supabase.co",
		config.ProviderSupabaseKey: "eyJ...",
	}

	// Store all keys
	for provider, key := range keys {
		err := config.SetAPIKey(provider, key)
		if err != nil {
			log.Printf("Failed to store %s key: %v", provider, err)
			continue
		}
	}

	// Verify all keys are stored
	storedProviders := config.ListProviders()
	fmt.Printf("Successfully configured %d providers\n", len(storedProviders))

	// Retrieve and use a specific key
	deepseekKey, err := config.GetAPIKey(config.ProviderDeepSeek)
	if err != nil {
		log.Printf("Failed to retrieve DeepSeek key: %v", err)
		return
	}

	// Use the key (in production, never print it)
	fmt.Printf("DeepSeek key ready (length: %d)\n", len(deepseekKey))
}

// Example_errorHandling demonstrates proper error handling
func Example_errorHandling() {
	// Attempt to get a non-existent key
	_, err := config.GetAPIKey(config.ProviderOpenAI)
	if err != nil {
		if err == config.ErrKeyNotFound {
			fmt.Println("API key not configured - please run setup")
		} else {
			fmt.Printf("Unexpected error: %v\n", err)
		}
	}

	// Attempt to set an invalid key
	err = config.SetAPIKey(config.ProviderDeepSeek, "")
	if err != nil {
		if err == config.ErrInvalidKey {
			fmt.Println("API key cannot be empty")
		}
	}

	// Attempt to use an invalid provider
	err = config.SetAPIKey("", "test-key")
	if err != nil {
		if err == config.ErrInvalidProvider {
			fmt.Println("Provider name is required")
		}
	}

	// Output:
	// API key not configured - please run setup
	// API key cannot be empty
	// Provider name is required
}
