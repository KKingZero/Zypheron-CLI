// Package licensing provides license middleware for Cobra commands
package licensing

import (
	"fmt"

	"github.com/spf13/cobra"
)

// LicenseMiddleware provides feature gating for Cobra commands
// This middleware integrates with Cobra's PreRunE to check license requirements
// before command execution
type LicenseMiddleware struct {
	feature     Feature // The feature required for this command
	requirePaid bool    // Whether any paid tier is required (Starter+)
	minTokens   int64   // Minimum tokens required for this operation
}

// NewLicenseMiddleware creates a new middleware instance
// Example: licensing.NewLicenseMiddleware().RequireFeature(licensing.FeatureAutopent).PreRunE()
func NewLicenseMiddleware() *LicenseMiddleware {
	return &LicenseMiddleware{
		requirePaid: false,
		minTokens:   0,
	}
}

// RequireFeature sets the feature requirement for this command
// Returns self for method chaining
func (m *LicenseMiddleware) RequireFeature(feature Feature) *LicenseMiddleware {
	m.feature = feature
	return m
}

// RequirePaidTier requires any paid tier (Starter, Pro, or Enterprise)
// Returns self for method chaining
func (m *LicenseMiddleware) RequirePaidTier() *LicenseMiddleware {
	m.requirePaid = true
	return m
}

// RequireTokens sets minimum token balance requirement
// Returns self for method chaining
func (m *LicenseMiddleware) RequireTokens(tokens int64) *LicenseMiddleware {
	m.minTokens = tokens
	return m
}

// PreRunE returns a Cobra PreRunE function that validates license requirements
// This is the main integration point - use it like:
//   cmd.PreRunE = licensing.NewLicenseMiddleware().RequireFeature(licensing.FeatureAutopent).PreRunE()
func (m *LicenseMiddleware) PreRunE() func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		// Dev mode bypass — only available in devmode builds
		if isDevModeEnabled() {
			return nil
		}

		manager := GetManager()

		// Check paid tier requirement
		if m.requirePaid && !manager.IsPaidTier() {
			return &FeatureLockedError{
				Feature:      m.feature,
				RequiredTier: TierStarter,
				CurrentTier:  manager.GetTier(),
				Message:      m.FormatUpgradePrompt(),
			}
		}

		// Check specific feature requirement
		if m.feature != "" {
			if err := manager.RequireFeature(m.feature); err != nil {
				return err
			}
		}

		// Check token requirement
		if m.minTokens > 0 {
			license := manager.License()
			if license.TokensRemaining < m.minTokens {
				return &InsufficientTokensError{
					Required:  m.minTokens,
					Available: license.TokensRemaining,
					ResetDate: license.ResetDate,
				}
			}
		}

		return nil
	}
}

// FormatUpgradePrompt generates a user-friendly upgrade prompt
// This is shown when a user tries to access a gated feature
func (m *LicenseMiddleware) FormatUpgradePrompt() string {
	manager := GetManager()
	currentTier := manager.GetTier()

	var featureName string
	if m.feature != "" {
		featureName = string(m.feature)
	} else if m.requirePaid {
		featureName = "paid features"
	} else {
		featureName = "this feature"
	}

	// Get required tier
	requiredTier := getMinTierForFeature(m.feature)
	if requiredTier == TierFree {
		requiredTier = TierStarter // Default to Starter for paid features
	}

	return fmt.Sprintf(`
╔═══════════════════════════════════════════════════════════════╗
║                    FEATURE LOCKED                              ║
╚═══════════════════════════════════════════════════════════════╝

  %s requires %s or higher

  Your current plan: %s

┌─────────────────────────────────────────────────────────────┐
│  UPGRADE OPTIONS                                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Starter ($29/mo)                                            │
│    • 1M tokens/month                                         │
│    • Cloud AI (Claude, OpenAI, DeepSeek)                    │
│    • Exploitation & Autopent                                 │
│    • 2 devices                                               │
│                                                              │
│  Pro ($149/mo)                                               │
│    • 5M tokens/month                                         │
│    • All Starter features                                    │
│    • 5 devices                                               │
│    • Priority support                                        │
│                                                              │
│  Enterprise ($499/user/mo)                                   │
│    • 25M tokens/user/month                                   │
│    • Unlimited devices                                       │
│    • Team management                                         │
│    • Compliance reporting                                    │
│    • Audit logs & SSO                                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘

  Upgrade: zypheron upgrade
  Login:   zypheron login

`, featureName, requiredTier, currentTier)
}

// ---- Convenience constructors for common middleware patterns ----

// RequireAutopentMiddleware returns middleware for autopent commands
func RequireAutopentMiddleware() func(*cobra.Command, []string) error {
	return NewLicenseMiddleware().RequireFeature(FeatureAutopent).PreRunE()
}

// RequireExploitationMiddleware returns middleware for exploitation commands
func RequireExploitationMiddleware() func(*cobra.Command, []string) error {
	return NewLicenseMiddleware().RequireFeature(FeatureExploitation).PreRunE()
}

// RequireCloudAIMiddleware returns middleware for cloud AI commands
func RequireCloudAIMiddleware() func(*cobra.Command, []string) error {
	return NewLicenseMiddleware().RequireFeature(FeatureCloudAI).PreRunE()
}

// RequirePostExploitMiddleware returns middleware for post-exploitation commands
func RequirePostExploitMiddleware() func(*cobra.Command, []string) error {
	return NewLicenseMiddleware().RequireFeature(FeaturePostExploit).PreRunE()
}

// RequireComplianceMiddleware returns middleware for compliance commands
func RequireComplianceMiddleware() func(*cobra.Command, []string) error {
	return NewLicenseMiddleware().RequireFeature(FeatureCompliance).PreRunE()
}

// RequireTeamsMiddleware returns middleware for team management commands
func RequireTeamsMiddleware() func(*cobra.Command, []string) error {
	return NewLicenseMiddleware().RequireFeature(FeatureTeams).PreRunE()
}

// RequireAuditLogsMiddleware returns middleware for audit log commands
func RequireAuditLogsMiddleware() func(*cobra.Command, []string) error {
	return NewLicenseMiddleware().RequireFeature(FeatureAuditLogs).PreRunE()
}

// ---- Helper to create InitWithValidation alias ----

// InitWithValidation initializes licensing system with startup validation
// This is called from main.go during CLI startup
// It performs validation and starts background sync if needed
func InitWithValidation() error {
	// First call the regular Init() to load cached data
	Init()

	// Then perform startup validation
	if err := ValidateLicenseOnStartup(); err != nil {
		return err
	}

	// Start background license sync (non-blocking)
	SyncLicenseAsync()
	return nil
}
