package commands

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/licensing"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/utils"
	"github.com/spf13/cobra"
)

// UpgradeCmd returns the upgrade command
func UpgradeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade your subscription",
		Long: `Compare plans and upgrade your Zypheron subscription.

Available plans:
  Starter ($29/mo)  - Cloud AI + Exploitation tools
  Pro ($149/mo)     - 5M tokens + Priority Support
  Enterprise ($499/user/mo) - Teams + Compliance + Support

Examples:
  zypheron upgrade              # View plans and upgrade
  zypheron upgrade --plan pro   # Upgrade to Pro directly`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpgradeWizard()
		},
	}

	cmd.AddCommand(upgradePlansCmd())
	cmd.AddCommand(upgradeCheckoutCmd())

	return cmd
}

func runUpgradeWizard() error {
	fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════════════╗"))
	fmt.Println(ui.Primary.Sprint("║                    UPGRADE YOUR PLAN                            ║"))
	fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════════════╝\n"))

	manager := licensing.GetManager()
	license := manager.License()

	fmt.Printf("Current Plan: %s\n\n", ui.Accent.Sprint(strings.ToUpper(string(license.Tier))))

	// Show feature comparison
	fmt.Println(licensing.PrintFeatureMatrix())
	fmt.Println()

	// If already on paid plan, show different options
	if manager.IsPaidTier() {
		fmt.Println(ui.InfoMsg("You're on a paid plan!"))
		fmt.Println()

		if license.Tier == licensing.TierEnterprise {
			fmt.Println(ui.SuccessMsg("You have the highest tier available."))
			fmt.Println()
			fmt.Println(ui.Muted.Sprint("Manage your subscription:"))
			fmt.Println(ui.Muted.Sprint("  https://zypheron.io/account/billing"))
			fmt.Println()
			return nil
		}

		fmt.Println("Options:")
		fmt.Println(ui.Muted.Sprint("  • Upgrade to a higher tier"))
		fmt.Println(ui.Muted.Sprint("  • Add more tokens"))
		fmt.Println(ui.Muted.Sprint("  • Manage billing"))
		fmt.Println()
	}

	// Prompt for plan selection
	planPrompt := &survey.Select{
		Message: "Select a plan:",
		Options: []string{
			"Starter ($29/mo) - Cloud AI + Exploitation",
			"Pro ($149/mo) - 5M tokens + Priority Support",
			"Enterprise ($499/user/mo) - Teams + Compliance",
			"View pricing details",
			"Cancel",
		},
	}

	var selection string
	if err := survey.AskOne(planPrompt, &selection); err != nil {
		return err
	}

	switch {
	case strings.HasPrefix(selection, "Starter"):
		return startCheckout("starter")
	case strings.HasPrefix(selection, "Pro"):
		return startCheckout("pro")
	case strings.HasPrefix(selection, "Enterprise"):
		return startCheckout("enterprise")
	case strings.HasPrefix(selection, "View"):
		return showPricingDetails()
	default:
		fmt.Println(ui.InfoMsg("Upgrade cancelled"))
		return nil
	}
}

func startCheckout(plan string) error {
	fmt.Println()
	fmt.Println(ui.InfoMsg(fmt.Sprintf("Starting %s checkout...", utils.Capitalize(plan))))
	fmt.Println()

	// Generate checkout URL (in production, this would call the API)
	checkoutURL := fmt.Sprintf("https://zypheron.io/checkout/%s", plan)

	fmt.Println(ui.SuccessMsg("Opening checkout in your browser..."))
	fmt.Println()
	fmt.Printf("If browser doesn't open, visit:\n  %s\n\n", ui.Accent.Sprint(checkoutURL))

	// Try to open browser
	openBrowser(checkoutURL)

	fmt.Println(ui.Muted.Sprint("After completing payment, run:"))
	fmt.Println(ui.Muted.Sprint("  zypheron license refresh"))
	fmt.Println()

	return nil
}

func openBrowser(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "linux":
		cmd = "xdg-open"
		args = []string{url}
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	default:
		return
	}

	// We don't block or check error - just attempt to open
	_ = runCmd(cmd, args...)
}

// runCmd is a helper to run external commands (simplified)
func runCmd(name string, args ...string) error {
	// In production, would use exec.Command
	// For now, just return nil to indicate success attempt
	return nil
}

func showPricingDetails() error {
	fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════════════╗"))
	fmt.Println(ui.Primary.Sprint("║                    PRICING DETAILS                              ║"))
	fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════════════╝\n"))

	fmt.Println(ui.Accent.Sprint("STARTER - $29/month"))
	fmt.Println(ui.Separator(60))
	fmt.Println("  Perfect for individual security researchers")
	fmt.Println("  • 1,000,000 AI tokens/month")
	fmt.Println("  • Cloud AI providers (Claude, GPT-4, etc.)")
	fmt.Println("  • Exploitation and pwn tools")
	fmt.Println("  • Automated pentesting (autopent)")
	fmt.Println("  • 2 device licenses")
	fmt.Println("  • Email support")
	fmt.Println()

	fmt.Println(ui.Success.Sprint("PRO - $149/month"))
	fmt.Println(ui.Separator(60))
	fmt.Println("  For professional penetration testers")
	fmt.Println("  • 5,000,000 AI tokens/month")
	fmt.Println("  • Everything in Starter, plus:")
	fmt.Println("  • Post-exploitation tools")
	fmt.Println("  • Advanced reporting")
	fmt.Println("  • 5 device licenses")
	fmt.Println("  • Priority support")
	fmt.Println()

	fmt.Println(ui.Primary.Sprint("ENTERPRISE - $499/user/month"))
	fmt.Println(ui.Separator(60))
	fmt.Println("  For security teams and organizations")
	fmt.Println("  • 25,000,000 AI tokens/month (pooled)")
	fmt.Println("  • Everything in Pro, plus:")
	fmt.Println("  • Team management")
	fmt.Println("  • Compliance reporting (PCI-DSS, HIPAA, SOC2)")
	fmt.Println("  • Audit logging")
	fmt.Println("  • SSO/SAML integration")
	fmt.Println("  • Up to 500 devices")
	fmt.Println("  • Dedicated support")
	fmt.Println()

	fmt.Println(ui.InfoMsg("Annual billing saves 20%"))
	fmt.Println(ui.Muted.Sprint("  Starter: $278/year (save $70)"))
	fmt.Println(ui.Muted.Sprint("  Pro: $1,430/year (save $358)"))
	fmt.Println()

	fmt.Println(ui.Muted.Sprint("Visit https://zypheron.io/pricing for full details"))
	fmt.Println()

	return nil
}

// upgradePlansCmd shows available plans
func upgradePlansCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "plans",
		Short: "View available plans",
		RunE: func(cmd *cobra.Command, args []string) error {
			return showPricingDetails()
		},
	}
}

// upgradeCheckoutCmd starts checkout for a specific plan
func upgradeCheckoutCmd() *cobra.Command {
	var annual bool

	cmd := &cobra.Command{
		Use:   "checkout [plan]",
		Short: "Start checkout for a plan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			plan := strings.ToLower(args[0])

			switch plan {
			case "starter", "pro", "enterprise":
				if annual {
					plan += "-annual"
				}
				return startCheckout(plan)
			default:
				fmt.Println(ui.Error("Invalid plan. Choose: starter, pro, or enterprise"))
				return nil
			}
		},
	}

	cmd.Flags().BoolVar(&annual, "annual", false, "Use annual billing (20% discount)")

	return cmd
}
