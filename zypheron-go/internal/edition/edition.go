package edition

import (
	"fmt"
	"strings"
)

// Edition represents the Zypheron edition
type Edition string

const (
	// EditionFree is the free edition with pre-exploitation features only
	EditionFree Edition = "free"
	
	// EditionPro is the professional edition with full features
	EditionPro Edition = "pro"
)

// Current edition - set at compile time via ldflags
// Default to pro if not set
var current = EditionPro

// SetEdition sets the current edition (used by main package from ldflags)
func SetEdition(ed string) {
	normalized := strings.ToLower(strings.TrimSpace(ed))
	switch normalized {
	case "free":
		current = EditionFree
	case "pro":
		current = EditionPro
	default:
		// Default to pro for backward compatibility
		current = EditionPro
	}
}

// Current returns the current edition
func Current() Edition {
	return current
}

// IsFree returns true if running free edition
func IsFree() bool {
	return current == EditionFree
}

// IsPro returns true if running pro edition
func IsPro() bool {
	return current == EditionPro
}

// String returns the edition as a string
func (e Edition) String() string {
	return string(e)
}

// DisplayName returns the formatted display name
func (e Edition) DisplayName() string {
	switch e {
	case EditionFree:
		return "Free Edition"
	case EditionPro:
		return "Professional Edition"
	default:
		return "Unknown Edition"
	}
}

// UpgradeMessage returns the message to display when a pro feature is blocked
func UpgradeMessage() string {
	return fmt.Sprintf(`
╔═══════════════════════════════════════════════════════════╗
║  ⚠️  FEATURE BLOCKED - FREE EDITION                       ║
╚═══════════════════════════════════════════════════════════╝

This feature requires Zypheron Professional Edition.

FREE EDITION includes:
  ✓ OSINT & Reconnaissance
  ✓ Vulnerability Scanning  
  ✓ AI-Powered Analysis
  ✓ Secret Detection
  ✓ Manual Security Tools

PRO EDITION adds:
  ⚡ Automated Exploitation
  ⚡ Autopent Engine
  ⚡ Post-Exploitation
  ⚡ Full MCP Integration
  ⚡ Advanced Attack Chains

Upgrade at: https://zypheron.com/upgrade
Support:    https://zypheron.com/support
`)
}

// ShortUpgradeMessage returns a brief upgrade message
func ShortUpgradeMessage() string {
	return "⚠️  This feature requires Zypheron Pro. Upgrade: https://zypheron.com/upgrade"
}

// Features returns the list of features available in the current edition
func Features() map[string]bool {
	base := map[string]bool{
		"osint":           true,
		"recon":           true,
		"scan":            true,
		"vuln_scan":       true,
		"secrets_scan":    true,
		"deps_scan":       true,
		"ai_analysis":     true,
		"ai_chat":         true,
		"forensics":       true,
		"reverse_eng":     true,
		"api_pentest":     true,
		"fuzz":            true,
		"mcp_recon":       true,
	}
	
	if IsPro() {
		base["exploitation"] = true
		base["autopent"] = true
		base["bruteforce"] = true
		base["pwn"] = true
		base["post_exploit"] = true
		base["mcp_full"] = true
		base["integrate_exploit"] = true
	} else {
		base["exploitation"] = false
		base["autopent"] = false
		base["bruteforce"] = false
		base["pwn"] = false
		base["post_exploit"] = false
		base["mcp_full"] = false
		base["integrate_exploit"] = false
	}
	
	return base
}

// HasFeature checks if a feature is available in the current edition
func HasFeature(feature string) bool {
	features := Features()
	has, exists := features[feature]
	return exists && has
}

