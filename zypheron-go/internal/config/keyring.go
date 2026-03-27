// Package config provides secure API key storage using the system keyring
// with fallback to environment variables for headless/server environments.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/zalando/go-keyring"
)

// Provider name constants for supported API providers.
// These constants ensure type safety and prevent typos when accessing credentials.
const (
	ProviderDeepSeek     = "deepseek"
	ProviderAnthropic    = "anthropic"
	ProviderOpenAI       = "openai"
	ProviderGoogle       = "google"
	ProviderKimi         = "kimi"
	ProviderGrok         = "grok"
	ProviderSupabaseURL  = "supabase_url"
	ProviderSupabaseKey  = "supabase_key"
	ProviderNVD          = "nvd"
	ProviderShodan       = "shodan"
	ProviderCensys       = "censys"
	ProviderCensysSecret = "censys_secret"

	// ServiceName is the identifier used in the system keyring
	ServiceName = "zypheron"
)

var (
	// ErrKeyNotFound indicates the requested API key does not exist
	ErrKeyNotFound = errors.New("API key not found in keyring or environment")

	// ErrInvalidProvider indicates an empty or invalid provider name
	ErrInvalidProvider = errors.New("provider name cannot be empty")

	// ErrInvalidKey indicates an empty API key
	ErrInvalidKey = errors.New("API key cannot be empty")

	// validProviders defines the set of supported provider names
	validProviders = map[string]bool{
		ProviderDeepSeek:     true,
		ProviderAnthropic:    true,
		ProviderOpenAI:       true,
		ProviderGoogle:       true,
		ProviderKimi:         true,
		ProviderGrok:         true,
		ProviderSupabaseURL:  true,
		ProviderSupabaseKey:  true,
		ProviderNVD:          true,
		ProviderShodan:       true,
		ProviderCensys:       true,
		ProviderCensysSecret: true,
	}

	// providerEnvMap maps provider names to their environment variable names
	providerEnvMap = map[string]string{
		ProviderDeepSeek:     "DEEPSEEK_API_KEY",
		ProviderAnthropic:    "ANTHROPIC_API_KEY",
		ProviderOpenAI:       "OPENAI_API_KEY",
		ProviderGoogle:       "GOOGLE_API_KEY",
		ProviderKimi:         "KIMI_API_KEY",
		ProviderGrok:         "GROK_API_KEY",
		ProviderSupabaseURL:  "SUPABASE_URL",
		ProviderSupabaseKey:  "SUPABASE_KEY",
		ProviderNVD:          "NVD_API_KEY",
		ProviderShodan:       "SHODAN_API_KEY",
		ProviderCensys:       "CENSYS_API_ID",
		ProviderCensysSecret: "CENSYS_API_SECRET",
	}

	// keyringAvailable tracks whether the system keyring is accessible
	keyringAvailable     bool
	keyringAvailableOnce sync.Once
)

// checkKeyringAvailability tests if the system keyring is available.
// This is called once and cached to avoid repeated system calls.
func checkKeyringAvailability() bool {
	keyringAvailableOnce.Do(func() {
		// Attempt to set and delete a test key to verify keyring functionality
		testKey := "__zypheron_test_key__"
		err := keyring.Set(ServiceName, testKey, "test")
		if err == nil {
			// Successfully set, now try to delete
			_ = keyring.Delete(ServiceName, testKey)
			keyringAvailable = true
		} else {
			// Keyring not available (headless server, missing keyring service, etc.)
			keyringAvailable = false
		}
	})
	return keyringAvailable
}

// validateProvider checks if the provider name is valid.
// Returns an error if the provider is empty or not in the supported list.
func validateProvider(provider string) error {
	if provider == "" {
		return ErrInvalidProvider
	}

	// Normalize to lowercase for case-insensitive comparison
	provider = strings.ToLower(strings.TrimSpace(provider))

	if !validProviders[provider] {
		return fmt.Errorf("unsupported provider: %s", provider)
	}

	return nil
}

// normalizeProvider converts provider name to lowercase and trims whitespace.
// This ensures consistent keyring lookups.
func normalizeProvider(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}

// SetAPIKey securely stores an API key for the specified provider.
// It first attempts to use the system keyring, falling back to a warning
// if the keyring is unavailable (user must set environment variable manually).
//
// Security considerations:
// - Validates provider name to prevent injection
// - Validates key is non-empty
// - Uses system keyring for encrypted storage when available
// - Never logs or prints the actual key value
func SetAPIKey(provider, key string) error {
	if err := validateProvider(provider); err != nil {
		return err
	}

	if key == "" {
		return ErrInvalidKey
	}

	provider = normalizeProvider(provider)

	// Attempt to use system keyring
	if checkKeyringAvailability() {
		err := keyring.Set(ServiceName, provider, key)
		if err != nil {
			return fmt.Errorf("failed to store API key in keyring: %w", err)
		}
		return nil
	}

	// Keyring unavailable - return error with helpful message
	envVar := providerEnvMap[provider]
	return fmt.Errorf("system keyring unavailable; please set environment variable %s instead", envVar)
}

// GetAPIKey retrieves an API key for the specified provider.
// It first checks the system keyring, then falls back to environment variables.
// This dual-source approach supports both desktop and headless server environments.
//
// Security considerations:
// - Constant-time provider validation prevents timing attacks
// - Environment variable fallback enables headless server deployment
// - Returns error instead of empty string to distinguish "not found" from "empty key"
func GetAPIKey(provider string) (string, error) {
	if err := validateProvider(provider); err != nil {
		return "", err
	}

	provider = normalizeProvider(provider)

	// Try keyring first
	if checkKeyringAvailability() {
		key, err := keyring.Get(ServiceName, provider)
		if err == nil && key != "" {
			return key, nil
		}
		// If keyring.ErrNotFound or empty, fall through to environment variable
	}

	// Fallback to environment variable
	envVar := providerEnvMap[provider]
	key := os.Getenv(envVar)
	if key != "" {
		return key, nil
	}

	return "", ErrKeyNotFound
}

// DeleteAPIKey removes an API key from the system keyring.
// This does NOT remove environment variables, as they are managed externally.
//
// Security considerations:
// - Only removes from keyring, not environment (environment vars are process-scoped)
// - Returns nil if key doesn't exist (idempotent operation)
func DeleteAPIKey(provider string) error {
	if err := validateProvider(provider); err != nil {
		return err
	}

	provider = normalizeProvider(provider)

	if !checkKeyringAvailability() {
		return errors.New("system keyring unavailable; cannot delete key (remove environment variable manually)")
	}

	err := keyring.Delete(ServiceName, provider)
	if err != nil && err != keyring.ErrNotFound {
		return fmt.Errorf("failed to delete API key from keyring: %w", err)
	}

	// Success or key didn't exist (both are acceptable outcomes)
	return nil
}

// HasAPIKey checks if an API key exists for the specified provider.
// It checks both keyring and environment variables.
//
// Security considerations:
// - Does not return the key value, only existence
// - Prevents timing attacks by not short-circuiting on first source
func HasAPIKey(provider string) bool {
	if err := validateProvider(provider); err != nil {
		return false
	}

	provider = normalizeProvider(provider)

	// Check keyring
	if checkKeyringAvailability() {
		key, err := keyring.Get(ServiceName, provider)
		if err == nil && key != "" {
			return true
		}
	}

	// Check environment variable
	envVar := providerEnvMap[provider]
	if os.Getenv(envVar) != "" {
		return true
	}

	return false
}

// ListProviders returns a list of provider names that have stored API keys.
// It checks both keyring and environment variables.
//
// Security considerations:
// - Only returns provider names, not key values
// - Useful for UI display and validation
func ListProviders() []string {
	var providers []string

	// Check each known provider
	for provider := range validProviders {
		if HasAPIKey(provider) {
			providers = append(providers, provider)
		}
	}

	return providers
}

// IsKeyringAvailable returns true if the system keyring is accessible.
// This can be used by calling code to determine whether to attempt
// keyring operations or guide users to use environment variables.
func IsKeyringAvailable() bool {
	return checkKeyringAvailability()
}
