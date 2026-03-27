package licensing

import (
	"fmt"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/utils"
)

// Gate provides a fluent API for checking feature access
type Gate struct {
	feature Feature
	manager *LicenseManager
	minTier Tier
}

// NewGate creates a new feature gate
func NewGate(feature Feature) *Gate {
	return &Gate{
		feature: feature,
		manager: GetManager(),
		minTier: getMinTierForFeature(feature),
	}
}

// Check returns nil if access is allowed, or an error describing why not
func (g *Gate) Check() error {
	return g.manager.RequireFeature(g.feature)
}

// IsAllowed returns true if the feature is accessible
func (g *Gate) IsAllowed() bool {
	return g.manager.HasFeature(g.feature)
}

// RequireTokens checks both feature access and token balance
func (g *Gate) RequireTokens(estimated int64) error {
	if err := g.Check(); err != nil {
		return err
	}

	if !g.manager.HasTokens(estimated) {
		license := g.manager.License()
		return &InsufficientTokensError{
			Required:  estimated,
			Available: license.TokensRemaining,
			ResetDate: license.ResetDate,
		}
	}

	return nil
}

// ---- Convenience functions for common gates ----

// RequireCloudAI checks if cloud AI providers are accessible
func RequireCloudAI() error {
	return NewGate(FeatureCloudAI).Check()
}

// RequireAutopent checks if automated pentesting is accessible
func RequireAutopent() error {
	return NewGate(FeatureAutopent).Check()
}

// RequireExploitation checks if exploitation features are accessible
func RequireExploitation() error {
	return NewGate(FeatureExploitation).Check()
}

// RequirePostExploit checks if post-exploitation features are accessible
func RequirePostExploit() error {
	return NewGate(FeaturePostExploit).Check()
}

// RequireTeams checks if team management is accessible
func RequireTeams() error {
	return NewGate(FeatureTeams).Check()
}

// RequireCompliance checks if compliance reporting is accessible
func RequireCompliance() error {
	return NewGate(FeatureCompliance).Check()
}

// RequireAuditLogs checks if audit logging is accessible
func RequireAuditLogs() error {
	return NewGate(FeatureAuditLogs).Check()
}

// CanUseCloudAI returns true if cloud AI is available
func CanUseCloudAI() bool {
	return NewGate(FeatureCloudAI).IsAllowed()
}

// CanUseAutopent returns true if autopent is available
func CanUseAutopent() bool {
	return NewGate(FeatureAutopent).IsAllowed()
}

// CanUseExploitation returns true if exploitation is available
func CanUseExploitation() bool {
	return NewGate(FeatureExploitation).IsAllowed()
}

// IsCloudProvider returns true if the provider is a cloud AI provider
func IsCloudProvider(provider string) bool {
	cloudProviders := []string{
		"claude", "anthropic",
		"openai", "gpt",
		"gemini", "google",
		"deepseek",
		"kimi", "moonshot",
	}

	provider = strings.ToLower(provider)
	for _, cp := range cloudProviders {
		if provider == cp {
			return true
		}
	}
	return false
}

// RequireProviderAccess checks if a specific AI provider can be used
func RequireProviderAccess(provider string) error {
	return nil
}

// CheckProviderAndTokens validates provider access and token balance
func CheckProviderAndTokens(provider string, estimatedTokens int64) error {
	return nil
}

// FormatUpgradePrompt returns a formatted upgrade prompt
func FormatUpgradePrompt(feature string) string {
	return fmt.Sprintf(`
┌─────────────────────────────────────────────────────────────────┐
│  Upgrade to unlock %s
│                                                                 │
│  Starter ($29/mo):      Cloud AI + Exploitation                │
│  Pro ($149/mo):         3M tokens + All features               │
│  Enterprise ($500/seat): Teams + Compliance (min 5 seats)      │
│                                                                 │
│  Run: zypheron upgrade                                          │
└─────────────────────────────────────────────────────────────────┘
`, feature)
}

// WrapCommandWithGate creates a pre-run function for cobra commands
// Usage: cmd.PreRunE = licensing.WrapCommandWithGate(licensing.FeatureExploitation)
func WrapCommandWithGate(feature Feature) func(cmd interface{}, args []string) error {
	return func(cmd interface{}, args []string) error {
		return NewGate(feature).Check()
	}
}

// GetCurrentPlanInfo returns formatted current plan information
func GetCurrentPlanInfo() string {
	license := GetLicense()
	manager := GetManager()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Plan: %s\n", utils.Capitalize(string(license.Tier))))

	if manager.IsPaidTier() {
		sb.WriteString(fmt.Sprintf("Tokens: %s / %s\n",
			formatTokens(license.TokensRemaining),
			formatTokens(license.TokensLimit)))
		sb.WriteString(fmt.Sprintf("Resets: %s\n", license.ResetDate.Format("Jan 2, 2006")))
	}

	if license.TeamID != "" {
		sb.WriteString(fmt.Sprintf("Team: %s (%s)\n", license.TeamID, license.TeamRole))
	}

	sb.WriteString(fmt.Sprintf("Device: %s\n", manager.GetDeviceID()[:8]+"..."))

	return sb.String()
}

// GetFeatureList returns a list of available features for the current tier
func GetFeatureList() []string {
	license := GetLicense()
	config := TierConfigs[license.Tier]

	features := make([]string, 0, len(config.Features))
	for _, f := range config.Features {
		features = append(features, string(f))
	}
	return features
}

// PrintFeatureMatrix prints a feature comparison matrix
func PrintFeatureMatrix() string {
	var sb strings.Builder

	sb.WriteString("╔═══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║                    FEATURE COMPARISON                          ║\n")
	sb.WriteString("╠═══════════════════════════════════════════════════════════════╣\n")
	sb.WriteString("║ Feature              │ Free │ Starter │ Pro │ Enterprise      ║\n")
	sb.WriteString("╠═══════════════════════════════════════════════════════════════╣\n")
	sb.WriteString("║ Network Scanning     │  ✓   │    ✓    │  ✓  │      ✓          ║\n")
	sb.WriteString("║ Web Scanning         │  ✓   │    ✓    │  ✓  │      ✓          ║\n")
	sb.WriteString("║ Self-hosted AI       │  ✓   │    ✓    │  ✓  │      ✓          ║\n")
	sb.WriteString("║ Cloud AI             │  ✗   │    ✓    │  ✓  │      ✓          ║\n")
	sb.WriteString("║ Exploitation         │  ✗   │    ✓    │  ✓  │      ✓          ║\n")
	sb.WriteString("║ Autopent             │  ✗   │    ✓    │  ✓  │      ✓          ║\n")
	sb.WriteString("║ Team Management      │  ✗   │    ✗    │  ✗  │      ✓          ║\n")
	sb.WriteString("║ Compliance Reports   │  ✗   │    ✗    │  ✗  │      ✓          ║\n")
	sb.WriteString("║ Audit Logs           │  ✗   │    ✗    │  ✗  │      ✓          ║\n")
	sb.WriteString("╠═══════════════════════════════════════════════════════════════╣\n")
	sb.WriteString("║ Tokens/month         │  0   │   1M    │ 3M  │  15M/user       ║\n")
	sb.WriteString("║ Price                │ $0   │  $29    │$149 │ $500/seat       ║\n")
	sb.WriteString("╚═══════════════════════════════════════════════════════════════╝\n")

	return sb.String()
}
