package licensing

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"
)

// ============ TierConfig Security Tests ============

// TestTierConfigs_OfflineDays verifies correct offline grace periods per tier
func TestTierConfigs_OfflineDays(t *testing.T) {
	tests := []struct {
		tier     Tier
		expected int
		desc     string
	}{
		{TierFree, -1, "Free tier should have unlimited offline (-1)"},
		{TierStarter, 7, "Starter tier should have 7-day offline grace"},
		{TierPro, 7, "Pro tier should have 7-day offline grace"},
		{TierEnterprise, 7, "Enterprise tier should have 7-day default offline grace"},
	}

	for _, tt := range tests {
		t.Run(string(tt.tier), func(t *testing.T) {
			config, ok := TierConfigs[tt.tier]
			if !ok {
				t.Fatalf("TierConfig not found for tier %v", tt.tier)
			}
			if config.OfflineDays != tt.expected {
				t.Errorf("%s: got OfflineDays=%d, want %d", tt.desc, config.OfflineDays, tt.expected)
			}
		})
	}
}

// TestTierConfigs_FreeTierHasNoFeatures ensures free tier cannot access paid features
func TestTierConfigs_FreeTierHasNoFeatures(t *testing.T) {
	config := TierConfigs[TierFree]
	if len(config.Features) != 0 {
		t.Errorf("Free tier should have 0 features, got %d: %v", len(config.Features), config.Features)
	}
	if config.TokenLimit != 0 {
		t.Errorf("Free tier should have 0 token limit, got %d", config.TokenLimit)
	}
}

// TestTierConfigs_PaidTiersHaveRequiredFeatures ensures paid tiers include gated features
func TestTierConfigs_PaidTiersHaveRequiredFeatures(t *testing.T) {
	requiredStarterFeatures := []Feature{FeatureCloudAI, FeatureAutopent, FeatureExploitation, FeaturePostExploit}

	for _, tier := range []Tier{TierStarter, TierPro} {
		config := TierConfigs[tier]
		for _, feature := range requiredStarterFeatures {
			found := false
			for _, f := range config.Features {
				if f == feature {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Tier %v should have feature %v", tier, feature)
			}
		}
	}

	// Enterprise should have all starter features plus enterprise-only ones
	enterpriseOnly := []Feature{FeatureTeams, FeatureCompliance, FeatureAuditLogs, FeatureAPIAccess, FeatureSSO}
	config := TierConfigs[TierEnterprise]
	for _, feature := range enterpriseOnly {
		found := false
		for _, f := range config.Features {
			if f == feature {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Enterprise tier should have feature %v", feature)
		}
	}
}

// ============ Gate Security Tests ============

// TestIsCloudProvider tests cloud provider detection
func TestIsCloudProvider(t *testing.T) {
	cloudProviders := []string{
		"claude", "anthropic",
		"openai", "gpt",
		"gemini", "google",
		"deepseek",
		"kimi", "moonshot",
	}

	for _, p := range cloudProviders {
		if !IsCloudProvider(p) {
			t.Errorf("IsCloudProvider(%q) should return true", p)
		}
	}

	// Case insensitive
	if !IsCloudProvider("CLAUDE") {
		t.Error("IsCloudProvider should be case-insensitive")
	}
	if !IsCloudProvider("OpenAI") {
		t.Error("IsCloudProvider should be case-insensitive")
	}
}

// TestIsCloudProvider_LocalProviders tests that local providers are not flagged as cloud
func TestIsCloudProvider_LocalProviders(t *testing.T) {
	localProviders := []string{"ollama", "Ollama", "OLLAMA", "local", "custom", ""}

	for _, p := range localProviders {
		if IsCloudProvider(p) {
			t.Errorf("IsCloudProvider(%q) should return false for local/custom providers", p)
		}
	}
}

// TestRequireProviderAccess_OllamaAlwaysFree tests that Ollama bypasses licensing
func TestRequireProviderAccess_OllamaAlwaysFree(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = &License{Tier: TierFree, Features: []Feature{}}
	m.mu.Unlock()

	// Ollama should always pass, even on free tier
	err := RequireProviderAccess("ollama")
	if err != nil {
		t.Errorf("Ollama should always be allowed, got error: %v", err)
	}

	err = RequireProviderAccess("Ollama")
	if err != nil {
		t.Errorf("Ollama (capitalized) should always be allowed, got error: %v", err)
	}
}

// TestRequireProviderAccess_CloudAllowedOnFreeTier tests that BYOK providers are allowed on free tier
func TestRequireProviderAccess_CloudAllowedOnFreeTier(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = &License{Tier: TierFree, Features: []Feature{}}
	m.mu.Unlock()

	cloudProviders := []string{"claude", "openai", "gemini", "deepseek", "kimi"}
	for _, provider := range cloudProviders {
		err := RequireProviderAccess(provider)
		if err != nil {
			t.Errorf("RequireProviderAccess(%q) should allow BYOK providers on free tier, got %v", provider, err)
		}
	}
}

// TestRequireProviderAccess_CloudAllowed tests that cloud providers are allowed on paid tiers
func TestRequireProviderAccess_CloudAllowed(t *testing.T) {
	for _, tier := range []Tier{TierStarter, TierPro, TierEnterprise} {
		t.Run(string(tier), func(t *testing.T) {
			instance = nil
			once = sync.Once{}

			m := GetManager()
			m.mu.Lock()
			m.license = &License{Tier: tier, Features: TierConfigs[tier].Features}
			m.mu.Unlock()

			err := RequireProviderAccess("claude")
			if err != nil {
				t.Errorf("RequireProviderAccess(claude) should be allowed on %v, got: %v", tier, err)
			}
		})
	}
}

// TestRequireExploitation_FreeTierBlocked tests exploitation is blocked on free tier
func TestRequireExploitation_FreeTierBlocked(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = &License{Tier: TierFree, Features: []Feature{}}
	m.mu.Unlock()

	err := RequireExploitation()
	if err == nil {
		t.Error("RequireExploitation should block on free tier")
	}

	lockedErr, ok := err.(*FeatureLockedError)
	if !ok {
		t.Fatalf("Expected FeatureLockedError, got %T", err)
	}
	if lockedErr.Feature != FeatureExploitation {
		t.Errorf("Expected feature %v, got %v", FeatureExploitation, lockedErr.Feature)
	}
	if lockedErr.CurrentTier != TierFree {
		t.Errorf("Expected current tier Free, got %v", lockedErr.CurrentTier)
	}
}

// TestRequireCloudAI_FreeTierBlocked tests legacy Cloud AI feature gating remains unchanged
func TestRequireCloudAI_FreeTierBlocked(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = &License{Tier: TierFree, Features: []Feature{}}
	m.mu.Unlock()

	err := RequireCloudAI()
	if err == nil {
		t.Error("RequireCloudAI should block on free tier")
	}

	if _, ok := err.(*FeatureLockedError); !ok {
		t.Fatalf("Expected FeatureLockedError, got %T", err)
	}
}

// TestRequireCloudAI_PaidTierAllowed tests cloud AI is allowed on paid tiers
func TestRequireCloudAI_PaidTierAllowed(t *testing.T) {
	for _, tier := range []Tier{TierStarter, TierPro, TierEnterprise} {
		t.Run(string(tier), func(t *testing.T) {
			instance = nil
			once = sync.Once{}

			m := GetManager()
			m.mu.Lock()
			m.license = &License{Tier: tier, Features: TierConfigs[tier].Features}
			m.mu.Unlock()

			err := RequireCloudAI()
			if err != nil {
				t.Errorf("RequireCloudAI should pass on %v, got: %v", tier, err)
			}
		})
	}
}

// ============ Dev Mode Bypass Security Tests ============

// TestDevModeBypass_GateCheck verifies the build-tag-gated dev bypass behavior.
func TestDevModeBypass_GateCheck(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = &License{Tier: TierFree, Features: []Feature{}}
	m.mu.Unlock()

	if isDevModeEnabled() {
		err := NewGate(FeatureCloudAI).Check()
		if err != nil {
			t.Errorf("Gate should allow with devmode build tag, got: %v", err)
		}
		return
	}

	// Without a devmode build, should be blocked.
	err := NewGate(FeatureCloudAI).Check()
	if err == nil {
		t.Error("Gate should block without devmode build tag on free tier")
	}

	// A production build must not enable feature bypass from environment alone.
	t.Setenv("ZYPHERON_DEV", "1")

	err = NewGate(FeatureCloudAI).Check()
	if err == nil {
		t.Error("Gate should block when only ZYPHERON_DEV=1 is set in a production build")
	}
}

// TestDevModeBypass_TokenDeduction verifies the build-tag-gated token bypass behavior.
func TestDevModeBypass_TokenDeduction(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:            TierPro,
		TokensRemaining: 0, // No tokens
	}
	m.mu.Unlock()

	if isDevModeEnabled() {
		err := m.DeductTokens(1000, TokenUsage{Action: "test"})
		if err != nil {
			t.Errorf("DeductTokens should be bypassed with devmode build tag, got: %v", err)
		}

		if m.License().TokensRemaining != 0 {
			t.Error("Tokens should not change in dev mode")
		}
		return
	}

	// A production build must not enable token bypass from environment alone.
	t.Setenv("ZYPHERON_DEV", "1")
	err := m.DeductTokens(1000, TokenUsage{Action: "test"})
	if err == nil {
		t.Error("DeductTokens should fail when only ZYPHERON_DEV=1 is set in a production build")
	}

	if m.License().TokensRemaining != 0 {
		t.Error("Tokens should not change after failed deduction")
	}
}

// ============ 401 Auto-Refresh Security Tests ============

// TestAutoTokenRefresh_OnlyRetriesOnce tests that 401 retry only happens once
func TestAutoTokenRefresh_OnlyRetriesOnce(t *testing.T) {
	resetManager()

	requestCount := 0

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		requestCount++

		if r.URL.Path == "/api/v1/auth/refresh" {
			// Refresh always succeeds
			json.NewEncoder(w).Encode(map[string]string{
				"access_token": "new-token",
				"token_type":   "Bearer",
			})
			return
		}

		// Always return 401 for license validate (simulating persistent auth failure)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"detail": "Unauthorized"})
	})
	defer server.Close()

	manager := GetManager()
	manager.SetSession(&AuthSession{
		AccessToken:  "bad-token",
		RefreshToken: "refresh-token",
		UserID:       "user-123",
	})

	client := &APIClient{
		baseURL:    server.URL() + "/api/v1",
		httpClient: &http.Client{},
		manager:    manager,
	}

	// FetchLicense should fail (both original and retry get 401)
	err := client.FetchLicense()
	if err == nil {
		t.Error("FetchLicense should fail when 401 persists after refresh")
	}

	// Should have made exactly 3 requests: original 401, refresh, retry 401
	// NOT infinite recursion
	if requestCount > 4 {
		t.Errorf("Expected at most 4 requests (original + refresh + retry + possible validate), got %d — possible infinite recursion", requestCount)
	}
}

// TestAutoTokenRefresh_SkipsRefreshEndpoint tests that /auth/refresh doesn't trigger retry
func TestAutoTokenRefresh_SkipsRefreshEndpoint(t *testing.T) {
	resetManager()

	requestCount := 0

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		requestCount++

		// Return 401 for refresh endpoint
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"detail": "Invalid refresh token"})
	})
	defer server.Close()

	manager := GetManager()
	manager.SetSession(&AuthSession{
		AccessToken:  "test-token",
		RefreshToken: "bad-refresh-token",
		UserID:       "user-123",
	})

	client := &APIClient{
		baseURL:    server.URL() + "/api/v1",
		httpClient: &http.Client{},
		manager:    manager,
	}

	// RefreshToken hits /auth/refresh which gets 401 — should NOT retry
	err := client.RefreshToken()
	if err == nil {
		t.Error("RefreshToken should fail on 401")
	}

	// Should only make 1 request — no retry loop
	if requestCount != 1 {
		t.Errorf("Expected exactly 1 request for refresh endpoint 401, got %d", requestCount)
	}
}

// ============ FetchLicense OfflineDays Derivation Tests ============

// TestFetchLicense_DerivesOfflineDaysFromTier tests that OfflineDays comes from TierConfigs
func TestFetchLicense_DerivesOfflineDaysFromTier(t *testing.T) {
	tests := []struct {
		tier            string
		expectedOffDays int
	}{
		{"free", -1},
		{"starter", 7},
		{"pro", 7},
		{"enterprise", 7},
	}

	for _, tt := range tests {
		t.Run(tt.tier, func(t *testing.T) {
			resetManager()

			server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(LicenseValidationResponse{
					Valid:     true,
					Tier:      tt.tier,
					Status:    "active",
					Features:  []string{},
					ExpiresAt: time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
				})
			})
			defer server.Close()

			manager := GetManager()
			manager.SetSession(&AuthSession{
				AccessToken: "test-token",
				UserID:      "user-123",
				Email:       "test@example.com",
			})

			client := &APIClient{
				baseURL:    server.URL(),
				httpClient: &http.Client{},
				manager:    manager,
			}

			err := client.FetchLicense()
			if err != nil {
				t.Fatalf("FetchLicense failed: %v", err)
			}

			license := manager.License()
			if license.OfflineDays != tt.expectedOffDays {
				t.Errorf("Expected OfflineDays=%d for tier %q, got %d",
					tt.expectedOffDays, tt.tier, license.OfflineDays)
			}
		})
	}
}

// ============ Token Security Tests ============

// TestDeductTokens_RollbackOnInsufficientBalance tests atomic rollback
func TestDeductTokens_RollbackOnInsufficientBalance(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:            TierPro,
		TokensRemaining: 500,
		TokensUsed:      100,
	}
	m.mu.Unlock()

	// Try to deduct more than available
	err := m.DeductTokens(1000, TokenUsage{Action: "test"})
	if err == nil {
		t.Fatal("DeductTokens should fail with insufficient balance")
	}

	// Verify balance unchanged
	license := m.License()
	if license.TokensRemaining != 500 {
		t.Errorf("TokensRemaining should be unchanged after failed deduction: got %d", license.TokensRemaining)
	}
	if license.TokensUsed != 100 {
		t.Errorf("TokensUsed should be unchanged after failed deduction: got %d", license.TokensUsed)
	}
}

// TestDeductTokens_NilLicense tests deduction with no license
func TestDeductTokens_NilLicense(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = nil
	m.mu.Unlock()

	err := m.DeductTokens(100, TokenUsage{Action: "test"})
	if err == nil {
		t.Error("DeductTokens should fail with nil license")
	}

	if _, ok := err.(*NotAuthenticatedError); !ok {
		t.Errorf("Expected NotAuthenticatedError, got %T", err)
	}
}

// ============ Error Type Security Tests ============

// TestFeatureLockedError_ContainsRequiredInfo tests error messages have required data
func TestFeatureLockedError_ContainsRequiredInfo(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = &License{Tier: TierFree, Features: []Feature{}}
	m.mu.Unlock()

	err := m.RequireFeature(FeatureExploitation)
	if err == nil {
		t.Fatal("Expected error")
	}

	lockedErr, ok := err.(*FeatureLockedError)
	if !ok {
		t.Fatalf("Expected FeatureLockedError, got %T", err)
	}

	if lockedErr.Feature != FeatureExploitation {
		t.Errorf("Expected feature Exploitation, got %v", lockedErr.Feature)
	}
	if lockedErr.CurrentTier != TierFree {
		t.Errorf("Expected current tier Free, got %v", lockedErr.CurrentTier)
	}
	if lockedErr.RequiredTier != TierStarter {
		t.Errorf("Expected required tier Starter, got %v", lockedErr.RequiredTier)
	}
	if lockedErr.Message == "" {
		t.Error("Error message should not be empty")
	}
	if lockedErr.Error() == "" {
		t.Error("Error() should not return empty string")
	}
}

// TestInsufficientTokensError_Fields tests token error contains required data
func TestInsufficientTokensError_Fields(t *testing.T) {
	err := &InsufficientTokensError{
		Required:  5000,
		Available: 100,
		ResetDate: time.Now().Add(7 * 24 * time.Hour),
	}

	if err.Error() == "" {
		t.Error("Error() should not return empty string")
	}
	if err.Required != 5000 {
		t.Errorf("Expected Required=5000, got %d", err.Required)
	}
	if err.Available != 100 {
		t.Errorf("Expected Available=100, got %d", err.Available)
	}
}

// TestNotAuthenticatedError_Fields tests auth error
func TestNotAuthenticatedError_Fields(t *testing.T) {
	// Default message
	err1 := &NotAuthenticatedError{}
	if err1.Error() != "not authenticated" {
		t.Errorf("Expected default message, got %q", err1.Error())
	}

	// Custom message
	err2 := &NotAuthenticatedError{Message: "custom auth error"}
	if err2.Error() != "custom auth error" {
		t.Errorf("Expected custom message, got %q", err2.Error())
	}
}
