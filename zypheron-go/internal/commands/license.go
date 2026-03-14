package commands

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/licensing"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/utils"
	"github.com/spf13/cobra"
)

// LicenseCmd returns the license management command
func LicenseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "license",
		Short: "Manage license and subscription",
		Long: `View and manage your Zypheron license and subscription.

Commands:
  zypheron license           # Show license status
  zypheron license info      # Detailed license information
  zypheron license activate  # Activate with license key
  zypheron license refresh   # Refresh license from server
  zypheron license features  # List available features`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLicenseStatus()
		},
	}

	cmd.AddCommand(licenseInfoCmd())
	cmd.AddCommand(licenseActivateCmd())
	cmd.AddCommand(licenseRefreshCmd())
	cmd.AddCommand(licenseFeaturesCmd())
	cmd.AddCommand(licenseUsageCmd())

	return cmd
}

func runLicenseStatus() error {
	fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
	fmt.Println(ui.Primary.Sprint("║              LICENSE STATUS                             ║"))
	fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

	manager := licensing.GetManager()
	license := manager.License()

	// Plan tier
	tierColor := ui.Muted
	switch license.Tier {
	case licensing.TierStarter:
		tierColor = ui.Accent
	case licensing.TierPro:
		tierColor = ui.Success
	case licensing.TierEnterprise:
		tierColor = ui.Primary
	}

	fmt.Println(ui.InfoMsg("Subscription"))
	fmt.Printf("  Plan:         %s\n", tierColor.Sprint(strings.ToUpper(string(license.Tier))))

	if license.Email != "" {
		fmt.Printf("  Account:      %s\n", ui.Accent.Sprint(license.Email))
	}

	if license.ExpiresAt.After(time.Now()) {
		fmt.Printf("  Valid Until:  %s\n", ui.Success.Sprint(license.ExpiresAt.Format("Jan 2, 2006")))
	} else if !license.ExpiresAt.IsZero() {
		fmt.Printf("  Expired:      %s\n", ui.Error(license.ExpiresAt.Format("Jan 2, 2006")))
	}
	fmt.Println()

	// Token usage
	if license.TokensLimit > 0 {
		fmt.Println(ui.InfoMsg("Token Usage"))
		percentUsed := float64(license.TokensUsed) / float64(license.TokensLimit) * 100
		fmt.Printf("  Used:         %s / %s (%.1f%%)\n",
			formatTokens(license.TokensUsed),
			formatTokens(license.TokensLimit),
			percentUsed)
		fmt.Printf("  Remaining:    %s\n", ui.Success.Sprint(formatTokens(license.TokensRemaining)))
		if !license.ResetDate.IsZero() {
			fmt.Printf("  Resets:       %s\n", ui.Muted.Sprint(license.ResetDate.Format("Jan 2, 2006")))
		}
		fmt.Println()
	}

	// Device info
	fmt.Println(ui.InfoMsg("Device"))
	deviceID := license.DeviceID
	if len(deviceID) > 12 {
		deviceID = deviceID[:12] + "..."
	}
	fmt.Printf("  Device ID:    %s\n", ui.Muted.Sprint(deviceID))
	fmt.Printf("  Devices:      %d / %d\n", license.DevicesUsed, license.DevicesLimit)
	fmt.Println()

	// Team info (if applicable)
	if license.TeamID != "" {
		fmt.Println(ui.InfoMsg("Team"))
		fmt.Printf("  Team ID:      %s\n", ui.Accent.Sprint(license.TeamID))
		fmt.Printf("  Your Role:    %s\n", ui.Success.Sprint(utils.Capitalize(license.TeamRole)))
		fmt.Println()
	}

	// Quick actions
	if license.Tier == licensing.TierFree {
		fmt.Println(ui.InfoMsg("Upgrade Options"))
		fmt.Println(ui.Muted.Sprint("  zypheron upgrade          Compare plans and upgrade"))
		fmt.Println()
	}

	return nil
}

// licenseInfoCmd shows detailed license information
func licenseInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show detailed license information",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║              LICENSE DETAILS                            ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

			manager := licensing.GetManager()
			license := manager.License()

			fmt.Println(ui.InfoMsg("License Information"))
			fmt.Printf("  License ID:     %s\n", ui.Muted.Sprint(license.LicenseID))
			fmt.Printf("  User ID:        %s\n", ui.Muted.Sprint(license.UserID))
			fmt.Printf("  Device ID:      %s\n", ui.Muted.Sprint(license.DeviceID))
			fmt.Printf("  Tier:           %s\n", ui.Accent.Sprint(string(license.Tier)))
			fmt.Println()

			fmt.Println(ui.InfoMsg("Validity"))
			fmt.Printf("  Valid:          %s\n", formatBool(license.Valid))
			fmt.Printf("  Created:        %s\n", ui.Muted.Sprint(license.CreatedAt.Format(time.RFC3339)))
			fmt.Printf("  Expires:        %s\n", ui.Muted.Sprint(license.ExpiresAt.Format(time.RFC3339)))
			fmt.Printf("  Last Refresh:   %s\n", ui.Muted.Sprint(license.RefreshedAt.Format(time.RFC3339)))
			fmt.Println()

			fmt.Println(ui.InfoMsg("Tokens"))
			fmt.Printf("  Limit:          %s\n", formatTokens(license.TokensLimit))
			fmt.Printf("  Used:           %s\n", formatTokens(license.TokensUsed))
			fmt.Printf("  Remaining:      %s\n", formatTokens(license.TokensRemaining))
			fmt.Printf("  Reset Date:     %s\n", ui.Muted.Sprint(license.ResetDate.Format("2006-01-02")))
			fmt.Println()

			fmt.Println(ui.InfoMsg("Offline Mode"))
			fmt.Printf("  Enabled:        %s\n", formatBool(license.OfflineMode))
			fmt.Printf("  Token Exists:   %s\n", formatBool(license.OfflineToken != ""))
			fmt.Printf("  Grace Period:   %s\n", ui.Muted.Sprint(fmt.Sprintf("%d days", license.OfflineGraceDays)))
			fmt.Println()

			return nil
		},
	}
}

// licenseActivateCmd activates a license key
func licenseActivateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "activate [key]",
		Short: "Activate with a license key",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(ui.InfoMsg("License Activation"))
			fmt.Println()

			if len(args) > 0 {
				key := args[0]
				fmt.Printf("Activating license key: %s...\n", key[:8]+"...")
			}

			fmt.Println(ui.WarningMsg("API connection required for license activation"))
			fmt.Println()
			fmt.Println(ui.InfoMsg("To activate your license:"))
			fmt.Println(ui.Muted.Sprint("  1. Run: zypheron auth login"))
			fmt.Println(ui.Muted.Sprint("  2. Your subscription will be automatically applied"))
			fmt.Println()
			fmt.Println(ui.Muted.Sprint("Or visit: https://zypheron.io/account/license"))
			fmt.Println()

			return nil
		},
	}
}

// licenseRefreshCmd refreshes the license from server
func licenseRefreshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "refresh",
		Short: "Refresh license from server",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(ui.InfoMsg("Refreshing license..."))

			manager := licensing.GetManager()
			if err := manager.Refresh(); err != nil {
				fmt.Println(ui.Error(fmt.Sprintf("Failed to refresh: %s", err)))
				fmt.Println()
				fmt.Println(ui.Muted.Sprint("If offline, try: zypheron auth login"))
				return nil
			}

			fmt.Println(ui.SuccessMsg("License refreshed successfully"))
			fmt.Println()

			return runLicenseStatus()
		},
	}
}

// licenseFeaturesCmd lists available features
func licenseFeaturesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "features",
		Short: "List available features",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║              AVAILABLE FEATURES                         ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

			manager := licensing.GetManager()
			license := manager.License()

			fmt.Printf("Your Plan: %s\n\n", ui.Accent.Sprint(strings.ToUpper(string(license.Tier))))

			features := []struct {
				name    string
				feature licensing.Feature
			}{
				{"Network Scanning", licensing.FeatureNetworkScan},
				{"Web Scanning", licensing.FeatureWebScan},
				{"Self-hosted AI (Ollama)", licensing.FeatureLocalAI},
				{"Cloud AI Providers", licensing.FeatureCloudAI},
				{"Exploitation Tools", licensing.FeatureExploitation},
				{"Automated Pentesting", licensing.FeatureAutopent},
				{"Post-Exploitation", licensing.FeaturePostExploit},
				{"Team Management", licensing.FeatureTeams},
				{"Compliance Reports", licensing.FeatureCompliance},
				{"Audit Logging", licensing.FeatureAuditLogs},
				{"Priority Support", licensing.FeaturePrioritySupport},
			}

			for _, f := range features {
				status := ui.Error("✗")
				if manager.HasFeature(f.feature) {
					status = ui.Success.Sprint("✓")
				}
				fmt.Printf("  %s  %s\n", status, f.name)
			}
			fmt.Println()

			if license.Tier == licensing.TierFree {
				fmt.Println(ui.InfoMsg("Unlock more features:"))
				fmt.Println(ui.Muted.Sprint("  zypheron upgrade"))
				fmt.Println()
			}

			return nil
		},
	}
}

// licenseUsageCmd shows detailed usage information
func licenseUsageCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "usage",
		Short: "Show detailed usage statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║              USAGE STATISTICS                           ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

			manager := licensing.GetManager()
			license := manager.License()

			if license.TokensLimit == 0 {
				fmt.Println(ui.InfoMsg("Free Plan - No token tracking"))
				fmt.Println()
				fmt.Println(ui.Muted.Sprint("Upgrade to track cloud AI usage:"))
				fmt.Println(ui.Muted.Sprint("  zypheron upgrade"))
				fmt.Println()
				return nil
			}

			// Token usage bar
			percentUsed := float64(license.TokensUsed) / float64(license.TokensLimit) * 100
			barWidth := 40
			filled := int(percentUsed / 100 * float64(barWidth))
			if filled > barWidth {
				filled = barWidth
			}

			bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

			fmt.Println(ui.InfoMsg("Token Usage This Period"))
			fmt.Printf("  [%s] %.1f%%\n", bar, percentUsed)
			fmt.Printf("  Used:      %s\n", formatTokens(license.TokensUsed))
			fmt.Printf("  Limit:     %s\n", formatTokens(license.TokensLimit))
			fmt.Printf("  Remaining: %s\n", ui.Success.Sprint(formatTokens(license.TokensRemaining)))
			fmt.Println()

			fmt.Println(ui.InfoMsg("Billing Period"))
			fmt.Printf("  Resets: %s\n", license.ResetDate.Format("January 2, 2006"))
			daysLeft := int(time.Until(license.ResetDate).Hours() / 24)
			if daysLeft > 0 {
				fmt.Printf("  Days Left: %d\n", daysLeft)
			}
			fmt.Println()

			fmt.Println(ui.InfoMsg("Device Usage"))
			fmt.Printf("  Active Devices: %d / %d\n", license.DevicesUsed, license.DevicesLimit)
			fmt.Println()

			return nil
		},
	}
}

func formatBool(b bool) string {
	if b {
		return ui.Success.Sprint("Yes")
	}
	return ui.Muted.Sprint("No")
}
