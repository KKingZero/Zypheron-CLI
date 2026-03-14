package licensing

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// resetManager resets the singleton manager for testing
// This is a helper function to ensure each test starts with a clean slate
func resetManager() {
	if instance != nil && instance.storage != nil {
		instance.storage.ClearAll()
	}
	instance = nil
	once = sync.Once{}
}

// TestLicenseMiddleware_RequireFeature_Allowed tests middleware allows authorized features
func TestLicenseMiddleware_RequireFeature_Allowed(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:     TierStarter,
		Features: TierConfigs[TierStarter].Features,
	}
	m.mu.Unlock()

	// Create middleware requiring cloud AI (Starter has this)
	middleware := NewLicenseMiddleware().RequireFeature(FeatureCloudAI)
	preRunE := middleware.PreRunE()

	// Create a dummy command
	cmd := &cobra.Command{Use: "test"}

	// Should not error
	err := preRunE(cmd, []string{})
	if err != nil {
		t.Errorf("Middleware should allow feature CloudAI for Starter tier, got error: %v", err)
	}
}

// TestLicenseMiddleware_RequireFeature_Denied tests middleware blocks unauthorized features
func TestLicenseMiddleware_RequireFeature_Denied(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:     TierFree,
		Features: TierConfigs[TierFree].Features,
	}
	m.mu.Unlock()

	// Create middleware requiring cloud AI (Free tier doesn't have this)
	middleware := NewLicenseMiddleware().RequireFeature(FeatureCloudAI)
	preRunE := middleware.PreRunE()

	cmd := &cobra.Command{Use: "test"}

	// Should error
	err := preRunE(cmd, []string{})
	if err == nil {
		t.Error("Middleware should deny feature CloudAI for Free tier")
	}

	// Should be FeatureLockedError
	if _, ok := err.(*FeatureLockedError); !ok {
		t.Errorf("Expected FeatureLockedError, got: %T", err)
	}
}

// TestLicenseMiddleware_RequirePaidTier_Free tests paid tier requirement blocks free tier
func TestLicenseMiddleware_RequirePaidTier_Free(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier: TierFree,
	}
	m.mu.Unlock()

	// Create middleware requiring paid tier
	middleware := NewLicenseMiddleware().RequirePaidTier()
	preRunE := middleware.PreRunE()

	cmd := &cobra.Command{Use: "test"}

	// Should error for free tier
	err := preRunE(cmd, []string{})
	if err == nil {
		t.Error("Middleware should deny free tier when paid tier required")
	}

	if _, ok := err.(*FeatureLockedError); !ok {
		t.Errorf("Expected FeatureLockedError, got: %T", err)
	}
}

// TestLicenseMiddleware_RequirePaidTier_Paid tests paid tier requirement allows paid tiers
func TestLicenseMiddleware_RequirePaidTier_Paid(t *testing.T) {
	paidTiers := []Tier{TierStarter, TierPro, TierEnterprise}

	for _, tier := range paidTiers {
		t.Run(string(tier), func(t *testing.T) {
			resetManager()

			m := GetManager()
			m.mu.Lock()
			m.license = &License{
				Tier: tier,
			}
			m.mu.Unlock()

			middleware := NewLicenseMiddleware().RequirePaidTier()
			preRunE := middleware.PreRunE()

			cmd := &cobra.Command{Use: "test"}

			// Should not error for paid tiers
			err := preRunE(cmd, []string{})
			if err != nil {
				t.Errorf("Middleware should allow paid tier %v, got error: %v", tier, err)
			}
		})
	}
}

// TestLicenseMiddleware_RequireTokens_Sufficient tests middleware with sufficient tokens
func TestLicenseMiddleware_RequireTokens_Sufficient(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:            TierPro,
		TokensRemaining: 10000,
		TokensLimit:     3_000_000,
	}
	m.mu.Unlock()

	// Require 5000 tokens (we have 10000)
	middleware := NewLicenseMiddleware().RequireTokens(5000)
	preRunE := middleware.PreRunE()

	cmd := &cobra.Command{Use: "test"}

	// Should not error
	err := preRunE(cmd, []string{})
	if err != nil {
		t.Errorf("Middleware should allow operation with sufficient tokens, got error: %v", err)
	}
}

// TestLicenseMiddleware_RequireTokens_Insufficient tests middleware with insufficient tokens
func TestLicenseMiddleware_RequireTokens_Insufficient(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:            TierStarter,
		TokensRemaining: 100,
		TokensLimit:     1_000_000,
		ResetDate:       time.Now().Add(7 * 24 * time.Hour),
	}
	m.mu.Unlock()

	// Require 5000 tokens (we only have 100)
	middleware := NewLicenseMiddleware().RequireTokens(5000)
	preRunE := middleware.PreRunE()

	cmd := &cobra.Command{Use: "test"}

	// Should error
	err := preRunE(cmd, []string{})
	if err == nil {
		t.Error("Middleware should deny operation with insufficient tokens")
	}

	// Should be InsufficientTokensError
	if _, ok := err.(*InsufficientTokensError); !ok {
		t.Errorf("Expected InsufficientTokensError, got: %T", err)
	}
}

// TestLicenseMiddleware_Chaining tests method chaining with multiple requirements
func TestLicenseMiddleware_Chaining(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:            TierPro,
		Features:        TierConfigs[TierPro].Features,
		TokensRemaining: 10000,
	}
	m.mu.Unlock()

	// Chain multiple requirements: feature + tokens
	middleware := NewLicenseMiddleware().
		RequireFeature(FeatureCloudAI).
		RequireTokens(5000)

	preRunE := middleware.PreRunE()
	cmd := &cobra.Command{Use: "test"}

	// Should pass all checks
	err := preRunE(cmd, []string{})
	if err != nil {
		t.Errorf("Middleware should allow operation with all requirements met, got error: %v", err)
	}

	// Now test with insufficient tokens
	m.mu.Lock()
	m.license.TokensRemaining = 100
	m.mu.Unlock()

	err = preRunE(cmd, []string{})
	if err == nil {
		t.Error("Middleware should deny operation when token requirement not met")
	}

	// Test with wrong tier (no feature)
	m.mu.Lock()
	m.license.Tier = TierFree
	m.license.Features = TierConfigs[TierFree].Features
	m.license.TokensRemaining = 10000
	m.mu.Unlock()

	err = preRunE(cmd, []string{})
	if err == nil {
		t.Error("Middleware should deny operation when feature requirement not met")
	}
}

// TestFormatUpgradePrompt tests upgrade prompt formatting
func TestFormatUpgradePrompt(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier: TierFree,
	}
	m.mu.Unlock()

	// Test with feature requirement
	middleware := NewLicenseMiddleware().RequireFeature(FeatureAutopent)
	prompt := middleware.FormatUpgradePrompt()

	if prompt == "" {
		t.Error("Upgrade prompt should not be empty")
	}

	// Should mention the feature
	if !strings.Contains(prompt, "autopent") && !strings.Contains(prompt, "Autopent") {
		t.Error("Prompt should mention the required feature")
	}

	// Should mention current tier
	if !strings.Contains(prompt, "free") && !strings.Contains(prompt, "Free") {
		t.Error("Prompt should mention current tier")
	}

	// Should show upgrade options
	if !strings.Contains(prompt, "Starter") {
		t.Error("Prompt should show Starter tier option")
	}
	if !strings.Contains(prompt, "Pro") {
		t.Error("Prompt should show Pro tier option")
	}
	if !strings.Contains(prompt, "Enterprise") {
		t.Error("Prompt should show Enterprise tier option")
	}

	// Test with paid tier requirement
	middleware2 := NewLicenseMiddleware().RequirePaidTier()
	prompt2 := middleware2.FormatUpgradePrompt()

	if !strings.Contains(prompt2, "paid features") {
		t.Error("Prompt should mention paid features when requiring paid tier")
	}
}

// TestRequireAutopentMiddleware tests the convenience constructor
func TestRequireAutopentMiddleware(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:     TierStarter,
		Features: TierConfigs[TierStarter].Features,
	}
	m.mu.Unlock()

	preRunE := RequireAutopentMiddleware()
	cmd := &cobra.Command{Use: "test"}

	// Should allow Starter tier (has autopent)
	err := preRunE(cmd, []string{})
	if err != nil {
		t.Errorf("RequireAutopentMiddleware should allow Starter tier, got error: %v", err)
	}

	// Test with Free tier (no autopent)
	m.mu.Lock()
	m.license.Tier = TierFree
	m.license.Features = TierConfigs[TierFree].Features
	m.mu.Unlock()

	err = preRunE(cmd, []string{})
	if err == nil {
		t.Error("RequireAutopentMiddleware should deny Free tier")
	}
}

// TestRequireExploitationMiddleware tests exploitation middleware
func TestRequireExploitationMiddleware(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:     TierPro,
		Features: TierConfigs[TierPro].Features,
	}
	m.mu.Unlock()

	preRunE := RequireExploitationMiddleware()
	cmd := &cobra.Command{Use: "test"}

	// Should allow Pro tier
	err := preRunE(cmd, []string{})
	if err != nil {
		t.Errorf("RequireExploitationMiddleware should allow Pro tier, got error: %v", err)
	}
}

// TestRequireCloudAIMiddleware tests cloud AI middleware
func TestRequireCloudAIMiddleware(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:     TierStarter,
		Features: TierConfigs[TierStarter].Features,
	}
	m.mu.Unlock()

	preRunE := RequireCloudAIMiddleware()
	cmd := &cobra.Command{Use: "test"}

	// Should allow Starter tier
	err := preRunE(cmd, []string{})
	if err != nil {
		t.Errorf("RequireCloudAIMiddleware should allow Starter tier, got error: %v", err)
	}
}

// TestRequireTeamsMiddleware tests teams middleware (Enterprise only)
func TestRequireTeamsMiddleware(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:     TierEnterprise,
		Features: TierConfigs[TierEnterprise].Features,
	}
	m.mu.Unlock()

	preRunE := RequireTeamsMiddleware()
	cmd := &cobra.Command{Use: "test"}

	// Should allow Enterprise tier
	err := preRunE(cmd, []string{})
	if err != nil {
		t.Errorf("RequireTeamsMiddleware should allow Enterprise tier, got error: %v", err)
	}

	// Test with Pro tier (no teams feature)
	m.mu.Lock()
	m.license.Tier = TierPro
	m.license.Features = TierConfigs[TierPro].Features
	m.mu.Unlock()

	err = preRunE(cmd, []string{})
	if err == nil {
		t.Error("RequireTeamsMiddleware should deny Pro tier")
	}
}

// TestRequireComplianceMiddleware tests compliance middleware (Enterprise only)
func TestRequireComplianceMiddleware(t *testing.T) {
	resetManager()

	m := GetManager()
	m.mu.Lock()
	m.license = &License{
		Tier:     TierEnterprise,
		Features: TierConfigs[TierEnterprise].Features,
	}
	m.mu.Unlock()

	preRunE := RequireComplianceMiddleware()
	cmd := &cobra.Command{Use: "test"}

	// Should allow Enterprise tier
	err := preRunE(cmd, []string{})
	if err != nil {
		t.Errorf("RequireComplianceMiddleware should allow Enterprise tier, got error: %v", err)
	}

	// Test with Starter tier (no compliance)
	m.mu.Lock()
	m.license.Tier = TierStarter
	m.license.Features = TierConfigs[TierStarter].Features
	m.mu.Unlock()

	err = preRunE(cmd, []string{})
	if err == nil {
		t.Error("RequireComplianceMiddleware should deny Starter tier")
	}
}

// TestMiddleware_MultipleRequirements tests complex scenarios
func TestMiddleware_MultipleRequirements(t *testing.T) {
	tests := []struct {
		name          string
		tier          Tier
		tokens        int64
		requireFeature Feature
		requireTokens int64
		shouldPass    bool
		description   string
	}{
		{
			name:          "all_requirements_met",
			tier:          TierPro,
			tokens:        100000,
			requireFeature: FeatureCloudAI,
			requireTokens: 50000,
			shouldPass:    true,
			description:   "Pro tier with sufficient tokens and feature",
		},
		{
			name:          "insufficient_tokens",
			tier:          TierPro,
			tokens:        1000,
			requireFeature: FeatureCloudAI,
			requireTokens: 50000,
			shouldPass:    false,
			description:   "Pro tier with insufficient tokens",
		},
		{
			name:          "missing_feature",
			tier:          TierFree,
			tokens:        100000,
			requireFeature: FeatureCloudAI,
			requireTokens: 0,
			shouldPass:    false,
			description:   "Free tier missing required feature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetManager()

			m := GetManager()
			m.mu.Lock()
			m.license = &License{
				Tier:            tt.tier,
				Features:        TierConfigs[tt.tier].Features,
				TokensRemaining: tt.tokens,
			}
			m.mu.Unlock()

			middleware := NewLicenseMiddleware()
			if tt.requireFeature != "" {
				middleware.RequireFeature(tt.requireFeature)
			}
			if tt.requireTokens > 0 {
				middleware.RequireTokens(tt.requireTokens)
			}

			preRunE := middleware.PreRunE()
			cmd := &cobra.Command{Use: "test"}

			err := preRunE(cmd, []string{})

			if tt.shouldPass && err != nil {
				t.Errorf("%s: expected to pass but got error: %v", tt.description, err)
			}
			if !tt.shouldPass && err == nil {
				t.Errorf("%s: expected to fail but passed", tt.description)
			}
		})
	}
}

// TestMiddleware_NilLicense tests middleware behavior with nil license
func TestMiddleware_NilLicense(t *testing.T) {
	resetManager()

	// GetManager will return a manager with TierFree license if nil
	_ = GetManager()

	// Middleware requiring paid feature
	middleware := NewLicenseMiddleware().RequireFeature(FeatureCloudAI)
	preRunE := middleware.PreRunE()

	cmd := &cobra.Command{Use: "test"}

	// Should error because free tier doesn't have cloud AI
	err := preRunE(cmd, []string{})
	if err == nil {
		t.Error("Middleware should deny when license defaults to free tier")
	}
}
