package config

import (
	"os"
	"testing"
)

// TestValidateProvider verifies provider name validation logic
func TestValidateProvider(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wantErr  bool
	}{
		{"valid deepseek", ProviderDeepSeek, false},
		{"valid anthropic", ProviderAnthropic, false},
		{"valid openai", ProviderOpenAI, false},
		{"valid supabase url", ProviderSupabaseURL, false},
		{"valid supabase key", ProviderSupabaseKey, false},
		{"empty provider", "", true},
		{"invalid provider", "invalid", true},
		{"case insensitive", "DEEPSEEK", false},
		{"whitespace handling", "  anthropic  ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProvider(tt.provider)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateProvider() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestSetAndGetAPIKey tests the basic set/get functionality
func TestSetAndGetAPIKey(t *testing.T) {
	// Test with environment variable fallback
	testProvider := ProviderDeepSeek
	testKey := "test-api-key-12345"
	envVar := providerEnvMap[testProvider]

	// Clean up before test
	os.Unsetenv(envVar)
	_ = DeleteAPIKey(testProvider)

	// If keyring is available, test keyring functionality
	if IsKeyringAvailable() {
		err := SetAPIKey(testProvider, testKey)
		if err != nil {
			t.Fatalf("SetAPIKey() failed: %v", err)
		}

		key, err := GetAPIKey(testProvider)
		if err != nil {
			t.Fatalf("GetAPIKey() failed: %v", err)
		}

		if key != testKey {
			t.Errorf("GetAPIKey() = %v, want %v", key, testKey)
		}

		// Clean up
		_ = DeleteAPIKey(testProvider)
	}

	// Test environment variable fallback
	os.Setenv(envVar, testKey)
	defer os.Unsetenv(envVar)

	key, err := GetAPIKey(testProvider)
	if err != nil {
		t.Fatalf("GetAPIKey() from env failed: %v", err)
	}

	if key != testKey {
		t.Errorf("GetAPIKey() from env = %v, want %v", key, testKey)
	}
}

// TestGetAPIKeyNotFound verifies error handling for missing keys
func TestGetAPIKeyNotFound(t *testing.T) {
	testProvider := ProviderAnthropic
	envVar := providerEnvMap[testProvider]

	// Clean up
	os.Unsetenv(envVar)
	_ = DeleteAPIKey(testProvider)

	_, err := GetAPIKey(testProvider)
	if err != ErrKeyNotFound {
		t.Errorf("GetAPIKey() error = %v, want %v", err, ErrKeyNotFound)
	}
}

// TestHasAPIKey_Keyring verifies key existence checking via keyring
func TestHasAPIKey_Keyring(t *testing.T) {
	testProvider := ProviderOpenAI
	envVar := providerEnvMap[testProvider]

	// Clean up
	os.Unsetenv(envVar)
	_ = DeleteAPIKey(testProvider)

	// Should not exist
	if HasAPIKey(testProvider) {
		t.Error("HasAPIKey() = true, want false for non-existent key")
	}

	// Set via environment
	os.Setenv(envVar, "test-key")
	defer os.Unsetenv(envVar)

	// Should exist now
	if !HasAPIKey(testProvider) {
		t.Error("HasAPIKey() = false, want true for existing key")
	}
}

// TestListProviders verifies listing functionality
func TestListProviders(t *testing.T) {
	// Clean up all providers
	for provider := range validProviders {
		envVar := providerEnvMap[provider]
		os.Unsetenv(envVar)
		_ = DeleteAPIKey(provider)
	}

	// Should be empty
	providers := ListProviders()
	if len(providers) != 0 {
		t.Errorf("ListProviders() = %v, want empty list", providers)
	}

	// Set one provider via environment
	testProvider := ProviderDeepSeek
	envVar := providerEnvMap[testProvider]
	os.Setenv(envVar, "test-key")
	defer os.Unsetenv(envVar)

	// Should contain one provider
	providers = ListProviders()
	if len(providers) != 1 {
		t.Errorf("ListProviders() length = %v, want 1", len(providers))
	}

	found := false
	for _, p := range providers {
		if p == testProvider {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListProviders() = %v, want to contain %v", providers, testProvider)
	}
}

// TestSetAPIKeyValidation tests input validation
func TestSetAPIKeyValidation(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		key      string
		wantErr  bool
	}{
		{"valid input", ProviderDeepSeek, "valid-key", false},
		{"empty provider", "", "valid-key", true},
		{"empty key", ProviderDeepSeek, "", true},
		{"invalid provider", "invalid", "valid-key", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SetAPIKey(tt.provider, tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Clean up if successful
			if err == nil {
				_ = DeleteAPIKey(tt.provider)
			}
		})
	}
}

// TestDeleteAPIKey verifies deletion functionality
func TestDeleteAPIKey(t *testing.T) {
	if !IsKeyringAvailable() {
		t.Skip("Skipping test: keyring not available")
	}

	testProvider := ProviderAnthropic
	testKey := "test-key-to-delete"

	// Set a key
	err := SetAPIKey(testProvider, testKey)
	if err != nil {
		t.Fatalf("SetAPIKey() failed: %v", err)
	}

	// Verify it exists
	if !HasAPIKey(testProvider) {
		t.Fatal("Key should exist after SetAPIKey()")
	}

	// Delete it
	err = DeleteAPIKey(testProvider)
	if err != nil {
		t.Fatalf("DeleteAPIKey() failed: %v", err)
	}

	// Verify it's gone (environment variable not set)
	envVar := providerEnvMap[testProvider]
	os.Unsetenv(envVar)
	if HasAPIKey(testProvider) {
		t.Error("Key should not exist after DeleteAPIKey()")
	}
}

// TestNormalizeProvider verifies provider name normalization
func TestNormalizeProvider(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"DeepSeek", "deepseek"},
		{"ANTHROPIC", "anthropic"},
		{"  openai  ", "openai"},
		{"supabase_url", "supabase_url"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeProvider(tt.input)
			if got != tt.want {
				t.Errorf("normalizeProvider() = %v, want %v", got, tt.want)
			}
		})
	}
}
