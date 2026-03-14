package licensing

import (
	"testing"
	"time"
)

// TestGetManager tests singleton pattern
func TestGetManager(t *testing.T) {
	m1 := GetManager()
	m2 := GetManager()

	if m1 != m2 {
		t.Error("GetManager should return same instance")
	}

	if m1 == nil {
		t.Error("GetManager should not return nil")
	}
}

// TestLicenseDefaultsToFree tests that new manager has free tier
func TestLicenseDefaultsToFree(t *testing.T) {
	// Reset for testing
	resetManager()

	m := GetManager()
	license := m.License()

	if license.Tier != TierFree {
		t.Errorf("Expected TierFree, got %v", license.Tier)
	}
}

// TestHasFeature tests feature checking
func TestHasFeature(t *testing.T) {
	tests := []struct {
		name     string
		tier     Tier
		feature  Feature
		expected bool
	}{
		{"free_has_no_cloud_ai", TierFree, FeatureCloudAI, false},
		{"free_has_no_autopent", TierFree, FeatureAutopent, false},
		{"starter_has_cloud_ai", TierStarter, FeatureCloudAI, true},
		{"starter_has_autopent", TierStarter, FeatureAutopent, true},
		{"starter_has_exploitation", TierStarter, FeatureExploitation, true},
		{"starter_no_teams", TierStarter, FeatureTeams, false},
		{"pro_has_cloud_ai", TierPro, FeatureCloudAI, true},
		{"pro_no_teams", TierPro, FeatureTeams, false},
		{"enterprise_has_teams", TierEnterprise, FeatureTeams, true},
		{"enterprise_has_compliance", TierEnterprise, FeatureCompliance, true},
		{"enterprise_has_sso", TierEnterprise, FeatureSSO, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset manager
			resetManager()

			m := GetManager()

			// Set up license with test tier
			m.mu.Lock()
			m.license = &License{
				Tier:     tt.tier,
				Features: TierConfigs[tt.tier].Features,
			}
			m.mu.Unlock()

			result := m.HasFeature(tt.feature)
			if result != tt.expected {
				t.Errorf("HasFeature(%v) for tier %v: expected %v, got %v",
					tt.feature, tt.tier, tt.expected, result)
			}
		})
	}
}

// TestIsLicenseValid tests license validity checks
func TestIsLicenseValid(t *testing.T) {
	tests := []struct {
		name      string
		tier      Tier
		expiresAt time.Time
		issuedAt  time.Time
		offDays   int
		expected  bool
	}{
		{
			name:      "free_always_valid",
			tier:      TierFree,
			expiresAt: time.Now().Add(-24 * time.Hour), // Expired
			issuedAt:  time.Now().Add(-60 * 24 * time.Hour),
			offDays:   30,
			expected:  true,
		},
		{
			name:      "paid_valid_not_expired",
			tier:      TierPro,
			expiresAt: time.Now().Add(24 * time.Hour),
			issuedAt:  time.Now().Add(-5 * 24 * time.Hour),
			offDays:   30,
			expected:  true,
		},
		{
			name:      "paid_expired",
			tier:      TierPro,
			expiresAt: time.Now().Add(-24 * time.Hour),
			issuedAt:  time.Now().Add(-60 * 24 * time.Hour),
			offDays:   30,
			expected:  false,
		},
		{
			name:      "paid_offline_too_long",
			tier:      TierPro,
			expiresAt: time.Now().Add(365 * 24 * time.Hour), // Not expired
			issuedAt:  time.Now().Add(-60 * 24 * time.Hour), // 60 days ago
			offDays:   30,                                   // Only 30 days offline allowed
			expected:  false,
		},
		{
			name:      "enterprise_never_expire_offline",
			tier:      TierEnterprise,
			expiresAt: time.Now().Add(365 * 24 * time.Hour),
			issuedAt:  time.Now().Add(-365 * 24 * time.Hour), // 1 year ago
			offDays:   -1,                                    // Never expire
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset manager
			resetManager()

			m := GetManager()
			m.mu.Lock()
			m.license = &License{
				Tier:        tt.tier,
				ExpiresAt:   tt.expiresAt,
				IssuedAt:    tt.issuedAt,
				OfflineDays: tt.offDays,
			}
			m.mu.Unlock()

			result := m.IsLicenseValid()
			if result != tt.expected {
				t.Errorf("IsLicenseValid(): expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestIsPaidTier tests paid tier detection
func TestIsPaidTier(t *testing.T) {
	tests := []struct {
		tier     Tier
		expected bool
	}{
		{TierFree, false},
		{TierStarter, true},
		{TierPro, true},
		{TierEnterprise, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.tier), func(t *testing.T) {
			resetManager()

			m := GetManager()
			m.mu.Lock()
			m.license = &License{Tier: tt.tier}
			m.mu.Unlock()

			result := m.IsPaidTier()
			if result != tt.expected {
				t.Errorf("IsPaidTier() for %v: expected %v, got %v",
					tt.tier, tt.expected, result)
			}
		})
	}
}

// TestGetMinTierForFeature tests feature tier requirements
func TestGetMinTierForFeature(t *testing.T) {
	tests := []struct {
		feature  Feature
		expected Tier
	}{
		{FeatureCloudAI, TierStarter},
		{FeatureAutopent, TierStarter},
		{FeatureExploitation, TierStarter},
		{FeatureTeams, TierEnterprise},
		{FeatureCompliance, TierEnterprise},
		{FeatureSSO, TierEnterprise},
		{FeatureLocalAI, TierFree},
	}

	for _, tt := range tests {
		t.Run(string(tt.feature), func(t *testing.T) {
			result := getMinTierForFeature(tt.feature)
			if result != tt.expected {
				t.Errorf("getMinTierForFeature(%v): expected %v, got %v",
					tt.feature, tt.expected, result)
			}
		})
	}
}

// TestFormatFeatureLockedMessage tests upgrade message formatting
func TestFormatFeatureLockedMessage(t *testing.T) {
	msg := formatFeatureLockedMessage(FeatureAutopent, TierFree)

	if msg == "" {
		t.Error("Message should not be empty")
	}

	// Should contain upgrade URL
	if !contains(msg, UpgradeURL) {
		t.Errorf("Message should contain upgrade URL: %s", UpgradeURL)
	}

	// Should contain tier name
	if !contains(msg, "Starter") {
		t.Error("Message should mention required tier")
	}

	// Should contain feature name
	if !contains(msg, "Penetration Testing") {
		t.Error("Message should mention feature name")
	}
}

// TestCheckOfflineGracePeriod tests offline grace period
func TestCheckOfflineGracePeriod(t *testing.T) {
	tests := []struct {
		name        string
		tier        Tier
		refreshedAt time.Time
		offDays     int
		expected    bool
	}{
		{
			name:        "free_always_valid",
			tier:        TierFree,
			refreshedAt: time.Now().Add(-100 * 24 * time.Hour),
			offDays:     30,
			expected:    true,
		},
		{
			name:        "paid_within_grace",
			tier:        TierPro,
			refreshedAt: time.Now().Add(-10 * 24 * time.Hour),
			offDays:     30,
			expected:    true,
		},
		{
			name:        "paid_exceeded_grace",
			tier:        TierPro,
			refreshedAt: time.Now().Add(-60 * 24 * time.Hour),
			offDays:     30,
			expected:    false,
		},
		{
			name:        "never_expire",
			tier:        TierEnterprise,
			refreshedAt: time.Now().Add(-365 * 24 * time.Hour),
			offDays:     -1,
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetManager()

			m := GetManager()
			m.mu.Lock()
			m.license = &License{
				Tier:        tt.tier,
				RefreshedAt: tt.refreshedAt,
				OfflineDays: tt.offDays,
			}
			m.mu.Unlock()

			result := CheckOfflineGracePeriod()
			if result != tt.expected {
				t.Errorf("CheckOfflineGracePeriod(): expected %v, got %v",
					tt.expected, result)
			}
		})
	}
}

// TestGetDeviceID tests device ID generation
func TestGetDeviceID(t *testing.T) {
	resetManager()

	m := GetManager()
	deviceID := m.GetDeviceID()

	if deviceID == "" {
		t.Error("Device ID should not be empty")
	}

	if len(deviceID) != 32 {
		t.Errorf("Device ID should be 32 chars (16 bytes hex), got %d", len(deviceID))
	}

	// Should be consistent
	deviceID2 := m.GetDeviceID()
	if deviceID != deviceID2 {
		t.Error("Device ID should be consistent across calls")
	}
}

// TestTierConfigs tests tier configuration values
func TestTierConfigs(t *testing.T) {
	// Free tier
	if TierConfigs[TierFree].TokenLimit != 0 {
		t.Error("Free tier should have 0 token limit")
	}
	if len(TierConfigs[TierFree].Features) != 0 {
		t.Error("Free tier should have no features")
	}

	// Starter tier
	if TierConfigs[TierStarter].TokenLimit != 1_000_000 {
		t.Error("Starter tier should have 1M tokens")
	}
	if TierConfigs[TierStarter].DeviceLimit != 2 {
		t.Error("Starter tier should have 2 device limit")
	}

	// Pro tier
	if TierConfigs[TierPro].TokenLimit != 3_000_000 {
		t.Error("Pro tier should have 3M tokens")
	}

	// Enterprise tier
	if TierConfigs[TierEnterprise].TokenLimit != 15_000_000 {
		t.Error("Enterprise tier should have 15M tokens")
	}
	if TierConfigs[TierEnterprise].DeviceLimit != -1 {
		t.Error("Enterprise tier should have unlimited devices")
	}
}

// TestOfflineGracePeriod_Valid tests that licenses within 7-day grace period are valid
func TestOfflineGracePeriod_Valid(t *testing.T) {
	// Reset manager
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:        TierPro,
		RefreshedAt: time.Now().Add(-5 * 24 * time.Hour), // 5 days ago
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour), // Not expired
		OfflineDays: 0,                                   // Should use default 7 days
	}
	m.mu.Unlock()

	if !m.IsLicenseValidForOffline() {
		t.Error("License should be valid within 7-day grace period")
	}

	// Also test with explicit 7 days
	m.mu.Lock()
	m.license.OfflineDays = 7
	m.mu.Unlock()

	if !m.IsLicenseValidForOffline() {
		t.Error("License should be valid with explicit 7-day offline period")
	}
}

// TestOfflineGracePeriod_Expired tests that licenses exceeding 7-day grace period are invalid
func TestOfflineGracePeriod_Expired(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:        TierStarter,
		RefreshedAt: time.Now().Add(-10 * 24 * time.Hour), // 10 days ago
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour),  // Not expired
		OfflineDays: 7,                                    // 7-day grace period
	}
	m.mu.Unlock()

	if m.IsLicenseValidForOffline() {
		t.Error("License should be invalid after exceeding 7-day grace period")
	}
}

// TestIsLicenseValidForOffline_FreeTier tests that free tier is always valid offline
func TestIsLicenseValidForOffline_FreeTier(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:        TierFree,
		RefreshedAt: time.Now().Add(-365 * 24 * time.Hour), // 1 year ago
		ExpiresAt:   time.Now().Add(-100 * 24 * time.Hour), // Expired long ago
		OfflineDays: 7,
	}
	m.mu.Unlock()

	if !m.IsLicenseValidForOffline() {
		t.Error("Free tier should always be valid offline regardless of dates")
	}
}

// TestIsLicenseValidForOffline_PaidTier tests paid tier offline validation
func TestIsLicenseValidForOffline_PaidTier(t *testing.T) {
	tests := []struct {
		name        string
		tier        Tier
		refreshedAt time.Time
		expiresAt   time.Time
		offlineDays int
		expected    bool
		description string
	}{
		{
			name:        "within_grace_and_valid",
			tier:        TierPro,
			refreshedAt: time.Now().Add(-3 * 24 * time.Hour),
			expiresAt:   time.Now().Add(30 * 24 * time.Hour),
			offlineDays: 7,
			expected:    true,
			description: "License refreshed 3 days ago, expires in 30 days, 7-day grace",
		},
		{
			name:        "exceeded_grace_period",
			tier:        TierStarter,
			refreshedAt: time.Now().Add(-15 * 24 * time.Hour),
			expiresAt:   time.Now().Add(30 * 24 * time.Hour),
			offlineDays: 7,
			expected:    false,
			description: "License refreshed 15 days ago, exceeds 7-day grace",
		},
		{
			name:        "subscription_expired",
			tier:        TierPro,
			refreshedAt: time.Now().Add(-2 * 24 * time.Hour),
			expiresAt:   time.Now().Add(-1 * 24 * time.Hour),
			offlineDays: 7,
			expected:    false,
			description: "Subscription expired 1 day ago",
		},
		{
			name:        "never_expire_offline",
			tier:        TierEnterprise,
			refreshedAt: time.Now().Add(-100 * 24 * time.Hour),
			expiresAt:   time.Now().Add(30 * 24 * time.Hour),
			offlineDays: -1,
			expected:    true,
			description: "Enterprise with never-expire offline mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetManager()

			m := GetManager()
			m.mu.Lock()
			m.license = &License{
				Tier:        tt.tier,
				RefreshedAt: tt.refreshedAt,
				ExpiresAt:   tt.expiresAt,
				OfflineDays: tt.offlineDays,
			}
			m.mu.Unlock()

			result := m.IsLicenseValidForOffline()
			if result != tt.expected {
				t.Errorf("%s: expected %v, got %v", tt.description, tt.expected, result)
			}
		})
	}
}

// TestDegradeLicenseGracefully tests graceful license degradation
func TestDegradeLicenseGracefully(t *testing.T) {
	resetManager()

	m := GetManager()

	// Set up a paid license
	m.mu.Lock()
	m.license = &License{
		Tier:            TierPro,
		TokensRemaining: 1_000_000,
		Features:        []Feature{FeatureCloudAI, FeatureAutopent},
		ExpiresAt:       time.Now().Add(30 * 24 * time.Hour),
	}
	m.mu.Unlock()

	// Verify initial state
	if m.GetTier() != TierPro {
		t.Error("Initial tier should be Pro")
	}

	// Degrade license
	m.DegradeLicenseGracefully("test degradation")

	// Verify degraded to free tier
	if m.GetTier() != TierFree {
		t.Errorf("After degradation, tier should be Free, got %v", m.GetTier())
	}

	license := m.License()
	if len(license.Features) != 0 {
		t.Errorf("Free tier should have no features, got %d", len(license.Features))
	}

	if !license.Valid {
		t.Error("Free tier license should be marked as valid")
	}
}

// TestSetFreeTier tests the setFreeTier internal function
func TestSetFreeTier(t *testing.T) {
	resetManager()

	m := GetManager()

	// Set up a paid license
	m.mu.Lock()
	m.license = &License{
		Tier:            TierEnterprise,
		TokensRemaining: 5_000_000,
		Features:        []Feature{FeatureCloudAI, FeatureTeams, FeatureCompliance},
	}
	m.mu.Unlock()

	// Call setFreeTier
	m.setFreeTier()

	license := m.License()
	if license.Tier != TierFree {
		t.Errorf("Expected TierFree, got %v", license.Tier)
	}

	if len(license.Features) != 0 {
		t.Error("Free tier should have no features")
	}

	if license.ExpiresAt.Before(time.Now()) {
		t.Error("Free tier should have far-future expiration")
	}

	if !license.Valid {
		t.Error("Free tier license should be valid")
	}
}

// TestValidateLicenseOnStartup_ValidCache tests startup validation with valid cached license
func TestValidateLicenseOnStartup_ValidCache(t *testing.T) {
	resetManager()

	m := GetManager()

	// Set up valid cached license
	m.mu.Lock()
	m.license = &License{
		Tier:        TierPro,
		RefreshedAt: time.Now().Add(-2 * 24 * time.Hour), // 2 days ago
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour), // Valid for 30 more days
		OfflineDays: 7,
	}
	m.session = &AuthSession{
		AccessToken: "test_token",
		UserID:      "user123",
		Email:       "test@example.com",
	}
	m.mu.Unlock()

	// Validate - should not error for valid license
	err := ValidateLicenseOnStartup()
	if err != nil {
		t.Errorf("ValidateLicenseOnStartup should not error for valid license, got: %v", err)
	}

	// Tier should still be Pro
	if m.GetTier() != TierPro {
		t.Error("License tier should remain Pro after validation")
	}
}

// TestValidateLicenseOnStartup_ExpiredCache tests startup validation with expired cache
func TestValidateLicenseOnStartup_ExpiredCache(t *testing.T) {
	resetManager()

	m := GetManager()

	// Set up expired cached license (exceeded offline grace period)
	m.mu.Lock()
	m.license = &License{
		Tier:        TierStarter,
		RefreshedAt: time.Now().Add(-15 * 24 * time.Hour), // 15 days ago
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour),  // Still valid subscription
		OfflineDays: 7,                                    // Only 7-day grace allowed
	}
	m.session = &AuthSession{
		AccessToken: "test_token",
		UserID:      "user123",
	}
	m.mu.Unlock()

	// Validate - should error and degrade to free tier
	err := ValidateLicenseOnStartup()
	if err == nil {
		t.Error("ValidateLicenseOnStartup should return error for expired offline grace period")
	}

	// Should have degraded to free tier
	if m.GetTier() != TierFree {
		t.Errorf("License should degrade to Free tier, got %v", m.GetTier())
	}
}

// TestHasFeature_Authorized tests feature authorization for authorized features
func TestHasFeature_Authorized(t *testing.T) {
	tests := []struct {
		name    string
		tier    Tier
		feature Feature
	}{
		{"starter_cloud_ai", TierStarter, FeatureCloudAI},
		{"starter_autopent", TierStarter, FeatureAutopent},
		{"starter_exploitation", TierStarter, FeatureExploitation},
		{"pro_cloud_ai", TierPro, FeatureCloudAI},
		{"pro_autopent", TierPro, FeatureAutopent},
		{"enterprise_teams", TierEnterprise, FeatureTeams},
		{"enterprise_compliance", TierEnterprise, FeatureCompliance},
		{"enterprise_sso", TierEnterprise, FeatureSSO},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetManager()

			m := GetManager()
			m.mu.Lock()
			m.license = &License{
				Tier:     tt.tier,
				Features: TierConfigs[tt.tier].Features,
			}
			m.mu.Unlock()

			if !m.HasFeature(tt.feature) {
				t.Errorf("Tier %v should have feature %v", tt.tier, tt.feature)
			}

			// RequireFeature should not return error
			if err := m.RequireFeature(tt.feature); err != nil {
				t.Errorf("RequireFeature(%v) should not error for tier %v, got: %v",
					tt.feature, tt.tier, err)
			}
		})
	}
}

// TestHasFeature_Unauthorized tests feature authorization for unauthorized features
func TestHasFeature_Unauthorized(t *testing.T) {
	tests := []struct {
		name    string
		tier    Tier
		feature Feature
	}{
		{"free_cloud_ai", TierFree, FeatureCloudAI},
		{"free_autopent", TierFree, FeatureAutopent},
		{"free_teams", TierFree, FeatureTeams},
		{"starter_teams", TierStarter, FeatureTeams},
		{"starter_compliance", TierStarter, FeatureCompliance},
		{"pro_teams", TierPro, FeatureTeams},
		{"pro_sso", TierPro, FeatureSSO},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetManager()

			m := GetManager()
			m.mu.Lock()
			m.license = &License{
				Tier:     tt.tier,
				Features: TierConfigs[tt.tier].Features,
			}
			m.mu.Unlock()

			if m.HasFeature(tt.feature) {
				t.Errorf("Tier %v should NOT have feature %v", tt.tier, tt.feature)
			}

			// RequireFeature should return FeatureLockedError
			err := m.RequireFeature(tt.feature)
			if err == nil {
				t.Errorf("RequireFeature(%v) should error for tier %v", tt.feature, tt.tier)
			}

			if _, ok := err.(*FeatureLockedError); !ok {
				t.Errorf("RequireFeature should return FeatureLockedError, got: %T", err)
			}
		})
	}
}

// TestIsPaidTier_Complete tests comprehensive paid tier detection
func TestIsPaidTier_Complete(t *testing.T) {
	tiers := []struct {
		tier     Tier
		expected bool
	}{
		{TierFree, false},
		{TierStarter, true},
		{TierPro, true},
		{TierEnterprise, true},
	}

	for _, tt := range tiers {
		t.Run(string(tt.tier), func(t *testing.T) {
			resetManager()

			m := GetManager()
			m.mu.Lock()
			m.license = &License{Tier: tt.tier}
			m.mu.Unlock()

			result := m.IsPaidTier()
			if result != tt.expected {
				t.Errorf("IsPaidTier() for %v: expected %v, got %v",
					tt.tier, tt.expected, result)
			}
		})
	}
}

// TestDeductTokens tests token deduction
func TestDeductTokens(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:            TierPro,
		TokensRemaining: 1000,
		TokensUsed:      0,
		TokensLimit:     3_000_000,
	}
	m.mu.Unlock()

	usage := TokenUsage{
		Action:   "test_action",
		Provider: "claude",
		Feature:  "autopent",
	}

	// Deduct 500 tokens
	err := m.DeductTokens(500, usage)
	if err != nil {
		t.Errorf("DeductTokens should not error, got: %v", err)
	}

	license := m.License()
	if license.TokensRemaining != 500 {
		t.Errorf("Expected 500 tokens remaining, got %d", license.TokensRemaining)
	}
	if license.TokensUsed != 500 {
		t.Errorf("Expected 500 tokens used, got %d", license.TokensUsed)
	}

	// Try to deduct more than available
	err = m.DeductTokens(1000, usage)
	if err == nil {
		t.Error("DeductTokens should error when insufficient tokens")
	}

	if _, ok := err.(*InsufficientTokensError); !ok {
		t.Errorf("Should return InsufficientTokensError, got: %T", err)
	}

	// Remaining should be unchanged after failed deduction
	license = m.License()
	if license.TokensRemaining != 500 {
		t.Errorf("Tokens should remain 500 after failed deduction, got %d", license.TokensRemaining)
	}
}

// TestHasTokens tests token availability checks
func TestHasTokens(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		TokensRemaining: 1000,
	}
	m.mu.Unlock()

	if !m.HasTokens(500) {
		t.Error("Should have 500 tokens available")
	}

	if !m.HasTokens(1000) {
		t.Error("Should have exactly 1000 tokens available")
	}

	if m.HasTokens(1001) {
		t.Error("Should NOT have 1001 tokens available")
	}
}

// TestIsAuthenticated tests authentication state
func TestIsAuthenticated(t *testing.T) {
	resetManager()

	m := GetManager()

	// Not authenticated initially
	if m.IsAuthenticated() {
		t.Error("Should not be authenticated without session")
	}

	// Set session
	m.SetSession(&AuthSession{
		AccessToken: "test_token",
		UserID:      "user123",
		Email:       "test@example.com",
	})

	if !m.IsAuthenticated() {
		t.Error("Should be authenticated with valid session")
	}

	// Empty access token
	m.SetSession(&AuthSession{
		AccessToken: "",
		UserID:      "user123",
	})

	if m.IsAuthenticated() {
		t.Error("Should not be authenticated with empty access token")
	}
}

// TestClearSession tests session clearing
func TestClearSession(t *testing.T) {
	resetManager()

	m := GetManager()

	// Set up session and license
	m.SetSession(&AuthSession{
		AccessToken: "test_token",
		UserID:      "user123",
		Email:       "test@example.com",
	})
	m.SetLicense(&License{
		Tier:            TierPro,
		TokensRemaining: 1_000_000,
	})

	// Verify state
	if !m.IsAuthenticated() {
		t.Error("Should be authenticated")
	}
	if m.GetTier() != TierPro {
		t.Error("Should be Pro tier")
	}

	// Clear session
	m.ClearSession()

	// Verify cleared
	if m.IsAuthenticated() {
		t.Error("Should not be authenticated after clear")
	}
	if m.GetTier() != TierFree {
		t.Error("Should be Free tier after clear")
	}
	if m.GetSession() != nil {
		t.Error("Session should be nil after clear")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
