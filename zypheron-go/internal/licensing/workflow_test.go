package licensing

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"
)

// ============ Startup Workflow Tests ============

// TestWorkflow_FreeTierStartup tests the full startup flow for a free tier user
func TestWorkflow_FreeTierStartup(t *testing.T) {
	instance = nil
	once = sync.Once{}

	// Free tier user: no session, no license cached
	m := GetManager()

	// Explicitly set free tier (storage may have cached data from other tests)
	m.mu.Lock()
	m.license = &License{Tier: TierFree, Features: []Feature{}}
	m.session = nil
	m.mu.Unlock()

	// License should be free
	if m.GetTier() != TierFree {
		t.Errorf("Default tier should be Free, got %v", m.GetTier())
	}

	// Should NOT be authenticated
	if m.IsAuthenticated() {
		t.Error("Free tier user should not be authenticated")
	}

	// ValidateLicenseOnStartup should succeed (free tier = nothing to validate)
	err := ValidateLicenseOnStartup()
	if err != nil {
		t.Errorf("ValidateLicenseOnStartup should not error for free tier, got: %v", err)
	}

	// Tier should still be free
	if m.GetTier() != TierFree {
		t.Errorf("Tier should remain Free after validation, got %v", m.GetTier())
	}

	// Free tier features should work
	if m.HasFeature(FeatureCloudAI) {
		t.Error("Free tier should NOT have CloudAI")
	}
	if m.HasFeature(FeatureExploitation) {
		t.Error("Free tier should NOT have Exploitation")
	}

	// IsLicenseValid should be true (free tier always valid)
	if !m.IsLicenseValid() {
		t.Error("Free tier license should always be valid")
	}

	// IsLicenseValidForOffline should be true
	if !m.IsLicenseValidForOffline() {
		t.Error("Free tier should always be valid offline")
	}
}

// TestWorkflow_PaidTierStartup_ValidCache tests startup with valid cached paid license
func TestWorkflow_PaidTierStartup_ValidCache(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()

	// Simulate cached paid license (refreshed recently)
	m.mu.Lock()
	m.license = &License{
		Tier:            TierPro,
		Features:        TierConfigs[TierPro].Features,
		TokensRemaining: 2_000_000,
		TokensLimit:     3_000_000,
		RefreshedAt:     time.Now().Add(-2 * 24 * time.Hour), // 2 days ago (within 7-day grace)
		ExpiresAt:       time.Now().Add(25 * 24 * time.Hour), // Expires in 25 days
		OfflineDays:     7,
	}
	m.session = &AuthSession{
		AccessToken:  "cached-token",
		RefreshToken: "cached-refresh",
		UserID:       "user-pro",
		Email:        "pro@example.com",
	}
	m.mu.Unlock()

	// Startup validation should pass
	err := ValidateLicenseOnStartup()
	if err != nil {
		t.Errorf("Startup validation should pass for valid cached license, got: %v", err)
	}

	// Tier should remain Pro
	if m.GetTier() != TierPro {
		t.Errorf("Tier should remain Pro, got %v", m.GetTier())
	}

	// Paid features should be available
	if !m.HasFeature(FeatureCloudAI) {
		t.Error("Pro tier should have CloudAI")
	}
	if !m.HasFeature(FeatureExploitation) {
		t.Error("Pro tier should have Exploitation")
	}

	// Token operations should work
	if !m.HasTokens(1_000_000) {
		t.Error("Should have 1M tokens available")
	}
}

// TestWorkflow_PaidTierStartup_ExpiredGrace tests startup when offline grace period exceeded
func TestWorkflow_PaidTierStartup_ExpiredGrace(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()

	// Simulate cached license that exceeded 7-day offline grace
	m.mu.Lock()
	m.license = &License{
		Tier:            TierStarter,
		Features:        TierConfigs[TierStarter].Features,
		TokensRemaining: 500_000,
		RefreshedAt:     time.Now().Add(-15 * 24 * time.Hour), // 15 days ago (exceeds 7-day grace)
		ExpiresAt:       time.Now().Add(20 * 24 * time.Hour),  // Subscription still valid
		OfflineDays:     7,
	}
	m.session = &AuthSession{
		AccessToken: "old-token",
		UserID:      "user-starter",
	}
	m.mu.Unlock()

	// Startup validation should fail and degrade
	err := ValidateLicenseOnStartup()
	if err == nil {
		t.Error("Startup validation should fail for exceeded offline grace period")
	}

	// Should have degraded to free tier
	if m.GetTier() != TierFree {
		t.Errorf("Should degrade to Free tier, got %v", m.GetTier())
	}

	// Paid features should no longer be available
	if m.HasFeature(FeatureCloudAI) {
		t.Error("Should NOT have CloudAI after degradation")
	}
	if m.HasFeature(FeatureExploitation) {
		t.Error("Should NOT have Exploitation after degradation")
	}
}

// TestWorkflow_PaidTierStartup_SubscriptionExpired tests startup with expired subscription
func TestWorkflow_PaidTierStartup_SubscriptionExpired(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()

	// Simulate cached license with expired subscription
	m.mu.Lock()
	m.license = &License{
		Tier:        TierPro,
		Features:    TierConfigs[TierPro].Features,
		RefreshedAt: time.Now().Add(-3 * 24 * time.Hour), // 3 days ago (within grace)
		ExpiresAt:   time.Now().Add(-1 * 24 * time.Hour), // Expired yesterday
		OfflineDays: 7,
	}
	m.session = &AuthSession{
		AccessToken: "expired-token",
		UserID:      "user-expired",
	}
	m.mu.Unlock()

	// Startup validation should fail (subscription expired)
	err := ValidateLicenseOnStartup()
	if err == nil {
		t.Error("Startup validation should fail for expired subscription")
	}

	// Should degrade to free
	if m.GetTier() != TierFree {
		t.Errorf("Should degrade to Free tier, got %v", m.GetTier())
	}
}

// ============ License Sync Workflow Tests ============

// TestWorkflow_OnlineSync_Success tests successful online license sync
func TestWorkflow_OnlineSync_Success(t *testing.T) {
	resetManager()

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/license/validate" {
			json.NewEncoder(w).Encode(LicenseValidationResponse{
				Valid:           true,
				Tier:            "pro",
				Status:          "active",
				TokensRemaining: 2_500_000,
				TokensUsed:      500_000,
				TokensLimit:     3_000_000,
				Features:        []string{"cloud_ai", "autopent", "exploitation", "post_exploitation"},
				ExpiresAt:       time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
			})
		}
	})
	defer server.Close()

	manager := GetManager()
	manager.SetSession(&AuthSession{
		AccessToken:  "test-token",
		RefreshToken: "refresh-token",
		UserID:       "user-sync",
		Email:        "sync@example.com",
	})

	client := &APIClient{
		baseURL:    server.URL(),
		httpClient: &http.Client{},
		manager:    manager,
	}

	// Sync license
	err := client.FetchLicense()
	if err != nil {
		t.Fatalf("FetchLicense failed: %v", err)
	}

	// Verify license was updated
	license := manager.License()
	if license.Tier != TierPro {
		t.Errorf("Expected Pro tier after sync, got %v", license.Tier)
	}
	if license.TokensRemaining != 2_500_000 {
		t.Errorf("Expected 2.5M tokens, got %d", license.TokensRemaining)
	}
	if license.OfflineDays != 7 {
		t.Errorf("Expected OfflineDays=7 (from TierConfigs[pro]), got %d", license.OfflineDays)
	}
}

// TestWorkflow_OnlineSync_UpgradeTier tests tier upgrade via sync
func TestWorkflow_OnlineSync_UpgradeTier(t *testing.T) {
	resetManager()

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(LicenseValidationResponse{
			Valid:           true,
			Tier:            "enterprise",
			Status:          "active",
			TokensRemaining: 14_000_000,
			TokensLimit:     15_000_000,
			Features:        []string{"cloud_ai", "autopent", "exploitation", "post_exploitation", "teams", "compliance", "audit_logs", "api_access", "sso"},
			ExpiresAt:       time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
		})
	})
	defer server.Close()

	manager := GetManager()
	// Start as Starter
	manager.mu.Lock()
	manager.license = &License{Tier: TierStarter, Features: TierConfigs[TierStarter].Features}
	manager.mu.Unlock()
	manager.SetSession(&AuthSession{AccessToken: "test-token", UserID: "user-upgrade"})

	client := &APIClient{
		baseURL:    server.URL(),
		httpClient: &http.Client{},
		manager:    manager,
	}

	// Before upgrade
	if manager.HasFeature(FeatureTeams) {
		t.Error("Starter should not have Teams before upgrade")
	}

	// Sync (gets enterprise license)
	err := client.FetchLicense()
	if err != nil {
		t.Fatalf("FetchLicense failed: %v", err)
	}

	// After upgrade
	if manager.GetTier() != TierEnterprise {
		t.Errorf("Expected Enterprise after upgrade, got %v", manager.GetTier())
	}
	if !manager.HasFeature(FeatureTeams) {
		t.Error("Enterprise should have Teams after upgrade")
	}
	if !manager.HasFeature(FeatureCompliance) {
		t.Error("Enterprise should have Compliance after upgrade")
	}
	if !manager.HasFeature(FeatureSSO) {
		t.Error("Enterprise should have SSO after upgrade")
	}
}

// ============ Degradation Workflow Tests ============

// TestWorkflow_GracefulDegradation tests the degradation flow
func TestWorkflow_GracefulDegradation(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()

	// Set up as Enterprise
	m.mu.Lock()
	m.license = &License{
		Tier:            TierEnterprise,
		Features:        TierConfigs[TierEnterprise].Features,
		TokensRemaining: 10_000_000,
		ExpiresAt:       time.Now().Add(365 * 24 * time.Hour),
	}
	m.mu.Unlock()

	// Verify enterprise features work
	if !m.HasFeature(FeatureTeams) {
		t.Error("Enterprise should have Teams")
	}
	if !m.HasFeature(FeatureSSO) {
		t.Error("Enterprise should have SSO")
	}
	if m.GetTier() != TierEnterprise {
		t.Error("Should be Enterprise tier")
	}

	// Trigger degradation
	m.DegradeLicenseGracefully("license server unreachable")

	// Verify degraded to free
	if m.GetTier() != TierFree {
		t.Errorf("Should degrade to Free, got %v", m.GetTier())
	}
	if m.HasFeature(FeatureTeams) {
		t.Error("Should NOT have Teams after degradation")
	}
	if m.HasFeature(FeatureCloudAI) {
		t.Error("Should NOT have CloudAI after degradation")
	}
	if m.HasFeature(FeatureSSO) {
		t.Error("Should NOT have SSO after degradation")
	}

	// Free tier license should be valid
	license := m.License()
	if !license.Valid {
		t.Error("Degraded license should be marked as valid (free tier)")
	}
	if license.ExpiresAt.Before(time.Now()) {
		t.Error("Degraded license should have far-future expiration")
	}
}

// TestWorkflow_ClearSession_FullReset tests full session clearing resets everything
func TestWorkflow_ClearSession_FullReset(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()

	// Set up paid license and session
	m.SetSession(&AuthSession{
		AccessToken:  "paid-token",
		RefreshToken: "paid-refresh",
		UserID:       "paid-user",
		Email:        "paid@example.com",
	})
	m.SetLicense(&License{
		Tier:            TierPro,
		TokensRemaining: 2_000_000,
		Features:        TierConfigs[TierPro].Features,
	})

	// Verify paid state
	if !m.IsAuthenticated() {
		t.Error("Should be authenticated")
	}
	if m.GetTier() != TierPro {
		t.Error("Should be Pro tier")
	}

	// Clear everything (logout)
	m.ClearSession()

	// Verify full reset
	if m.IsAuthenticated() {
		t.Error("Should not be authenticated after clear")
	}
	if m.GetTier() != TierFree {
		t.Errorf("Should be Free tier after clear, got %v", m.GetTier())
	}
	if m.GetSession() != nil {
		t.Error("Session should be nil after clear")
	}
	if m.HasFeature(FeatureCloudAI) {
		t.Error("Should not have CloudAI after clear")
	}
}

// ============ Offline Grace Period Workflow Tests ============

// TestWorkflow_OfflineGrace_7DayBoundary tests the exact 7-day boundary
func TestWorkflow_OfflineGrace_7DayBoundary(t *testing.T) {
	tests := []struct {
		name     string
		daysAgo  int
		expected bool
		desc     string
	}{
		{"day_1", 1, true, "1 day offline should be valid"},
		{"day_5", 5, true, "5 days offline should be valid"},
		{"day_6", 6, true, "6 days offline should be valid"},
		{"day_7_minus_1hr", 0, true, "just under 7 days should be valid"}, // handled specially
		{"day_8", 8, false, "8 days offline should be invalid"},
		{"day_14", 14, false, "14 days offline should be invalid"},
		{"day_30", 30, false, "30 days offline should be invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance = nil
			once = sync.Once{}

			m := GetManager()

			refreshedAt := time.Now().Add(-time.Duration(tt.daysAgo) * 24 * time.Hour)
			if tt.name == "day_7_minus_1hr" {
				refreshedAt = time.Now().Add(-7*24*time.Hour + 1*time.Hour)
			}

			m.mu.Lock()
			m.license = &License{
				Tier:        TierPro,
				RefreshedAt: refreshedAt,
				ExpiresAt:   time.Now().Add(60 * 24 * time.Hour), // Subscription valid
				OfflineDays: 7,
			}
			m.mu.Unlock()

			result := m.IsLicenseValidForOffline()
			if result != tt.expected {
				t.Errorf("%s: expected %v, got %v", tt.desc, tt.expected, result)
			}
		})
	}
}

// TestWorkflow_OfflineGrace_FreeTierIgnoresGrace tests free tier ignores grace period
func TestWorkflow_OfflineGrace_FreeTierIgnoresGrace(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:        TierFree,
		RefreshedAt: time.Now().Add(-365 * 24 * time.Hour), // 1 year ago
		ExpiresAt:   time.Now().Add(-365 * 24 * time.Hour), // Expired 1 year ago
		OfflineDays: 7,                                     // Even with 7-day grace
	}
	m.mu.Unlock()

	if !m.IsLicenseValidForOffline() {
		t.Error("Free tier should always be valid offline, regardless of dates")
	}

	if !CheckOfflineGracePeriod() {
		t.Error("CheckOfflineGracePeriod should return true for free tier")
	}
}

// TestWorkflow_OfflineGrace_NeverExpire tests -1 (never expire) offline mode
func TestWorkflow_OfflineGrace_NeverExpire(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:        TierEnterprise,
		RefreshedAt: time.Now().Add(-1000 * 24 * time.Hour), // Very long ago
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour),    // Subscription still valid
		OfflineDays: -1,                                     // Never expire offline
	}
	m.mu.Unlock()

	if !m.IsLicenseValidForOffline() {
		t.Error("License with OfflineDays=-1 should never expire offline")
	}

	if !m.IsLicenseValid() {
		t.Error("License with OfflineDays=-1 should be valid")
	}
}

// ============ Command Gate Workflow Tests ============

// TestWorkflow_ExploitGate_FreeTierBlocked tests exploit command is blocked on free tier
func TestWorkflow_ExploitGate_FreeTierBlocked(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = &License{Tier: TierFree, Features: []Feature{}}
	m.mu.Unlock()

	err := RequireExploitation()
	if err == nil {
		t.Error("Exploitation should be blocked on free tier")
	}
}

// TestWorkflow_ExploitGate_StarterAllowed tests exploit command works on Starter+
func TestWorkflow_ExploitGate_StarterAllowed(t *testing.T) {
	for _, tier := range []Tier{TierStarter, TierPro, TierEnterprise} {
		t.Run(string(tier), func(t *testing.T) {
			instance = nil
			once = sync.Once{}

			m := GetManager()
			m.mu.Lock()
			m.license = &License{Tier: tier, Features: TierConfigs[tier].Features}
			m.mu.Unlock()

			err := RequireExploitation()
			if err != nil {
				t.Errorf("Exploitation should be allowed on %v, got: %v", tier, err)
			}
		})
	}
}

// TestWorkflow_ChatGate_CloudVsLocal tests chat command provider gating
func TestWorkflow_ChatGate_CloudVsLocal(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = &License{Tier: TierFree, Features: []Feature{}}
	m.mu.Unlock()

	// Cloud providers should be allowed on free tier when users bring their own key
	cloudErr := RequireProviderAccess("claude")
	if cloudErr != nil {
		t.Errorf("Claude should be allowed on free tier with BYOK, got: %v", cloudErr)
	}

	// Ollama should always pass
	ollamaErr := RequireProviderAccess("ollama")
	if ollamaErr != nil {
		t.Errorf("Ollama should always pass, got: %v", ollamaErr)
	}

	// Unknown providers should pass (BYOK)
	unknownErr := RequireProviderAccess("custom-provider")
	if unknownErr != nil {
		t.Errorf("Unknown providers should pass, got: %v", unknownErr)
	}
}

// TestWorkflow_ScanAIProviderAccess tests scan AI provider access does not enforce paid cloud tiers
func TestWorkflow_ScanAIProviderAccess(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = &License{Tier: TierFree, Features: []Feature{}}
	m.mu.Unlock()

	err := RequireProviderAccess("claude")
	if err != nil {
		t.Errorf("Cloud AI provider access should allow BYOK on free tier, got: %v", err)
	}
}

// ============ Token Workflow Tests ============

// TestWorkflow_TokenDeductionLifecycle tests full token deduction cycle
func TestWorkflow_TokenDeductionLifecycle(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:            TierPro,
		TokensRemaining: 10000,
		TokensUsed:      0,
		TokensLimit:     3_000_000,
	}
	m.mu.Unlock()

	// Deduct tokens in sequence
	steps := []struct {
		deduct          int64
		expectRemaining int64
		expectUsed      int64
		shouldFail      bool
	}{
		{3000, 7000, 3000, false},
		{2000, 5000, 5000, false},
		{5000, 0, 10000, false},
		{1, 0, 10000, true}, // Should fail — no tokens left
	}

	for i, step := range steps {
		err := m.DeductTokens(step.deduct, TokenUsage{Action: "test"})

		if step.shouldFail {
			if err == nil {
				t.Errorf("Step %d: expected failure, got success", i)
			}
			continue
		}

		if err != nil {
			t.Errorf("Step %d: unexpected error: %v", i, err)
			continue
		}

		license := m.License()
		if license.TokensRemaining != step.expectRemaining {
			t.Errorf("Step %d: expected remaining=%d, got %d", i, step.expectRemaining, license.TokensRemaining)
		}
		if license.TokensUsed != step.expectUsed {
			t.Errorf("Step %d: expected used=%d, got %d", i, step.expectUsed, license.TokensUsed)
		}
	}
}

// ============ Auth Refresh Workflow Tests ============

// TestWorkflow_TokenRefresh_Success tests successful token refresh flow
func TestWorkflow_TokenRefresh_Success(t *testing.T) {
	resetManager()

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/auth/refresh" {
			json.NewEncoder(w).Encode(map[string]string{
				"access_token": "new-access-token",
				"token_type":   "Bearer",
			})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	manager := GetManager()
	manager.SetSession(&AuthSession{
		AccessToken:  "old-token",
		RefreshToken: "valid-refresh",
		UserID:       "user-refresh",
	})

	client := &APIClient{
		baseURL:    server.URL(),
		httpClient: &http.Client{},
		manager:    manager,
	}

	// Refresh token
	err := client.RefreshToken()
	if err != nil {
		t.Fatalf("RefreshToken failed: %v", err)
	}

	// Verify new access token
	session := manager.GetSession()
	if session.AccessToken != "new-access-token" {
		t.Errorf("Expected new-access-token, got %s", session.AccessToken)
	}

	// Refresh token should be unchanged
	if session.RefreshToken != "valid-refresh" {
		t.Errorf("Refresh token should be unchanged, got %s", session.RefreshToken)
	}
}

// TestWorkflow_TokenRefresh_NoSession tests refresh without session
func TestWorkflow_TokenRefresh_NoSession(t *testing.T) {
	resetManager()

	manager := GetManager()
	// Explicitly clear session (storage may have cached data from other tests)
	manager.mu.Lock()
	manager.session = nil
	manager.mu.Unlock()

	client := &APIClient{
		baseURL:    "http://localhost:9999",
		httpClient: &http.Client{},
		manager:    manager,
	}

	err := client.RefreshToken()
	if err == nil {
		t.Error("RefreshToken should fail without session")
	}

	if _, ok := err.(*NotAuthenticatedError); !ok {
		t.Errorf("Expected NotAuthenticatedError, got %T", err)
	}
}

// ============ Concurrent Access Workflow Tests ============

// TestWorkflow_ConcurrentFeatureChecks tests thread safety of feature checks
func TestWorkflow_ConcurrentFeatureChecks(t *testing.T) {
	instance = nil
	once = sync.Once{}

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:     TierPro,
		Features: TierConfigs[TierPro].Features,
	}
	m.mu.Unlock()

	done := make(chan bool)
	goroutines := 20

	for i := 0; i < goroutines; i++ {
		go func() {
			// Read operations should be safe concurrent
			m.HasFeature(FeatureCloudAI)
			m.HasFeature(FeatureExploitation)
			m.GetTier()
			m.IsPaidTier()
			m.IsAuthenticated()
			m.IsOffline()
			m.License()
			m.IsLicenseValid()
			m.IsLicenseValidForOffline()
			CheckOfflineGracePeriod()

			done <- true
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}
