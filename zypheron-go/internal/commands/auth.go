package commands

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/licensing"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/utils"
	"github.com/spf13/cobra"
)

// API endpoints (will be configured in production)
const (
	APIBaseURL    = "https://api.zypheron.net"
	AuthURL       = APIBaseURL + "/auth"
	WebLoginURL   = "https://zypheron.net/auth/cli"
	BillingPortal = "https://zypheron.net/billing"
	UpgradeURL    = "https://zypheron.net/cli"
)

// AuthCmd returns the authentication parent command
func AuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authentication and account management",
		Long: `Manage authentication and account settings.

Commands:
  login      Log in to your Zypheron account
  logout     Log out of your account
  whoami     Show current user information
  account    View account details and usage
  billing    Manage billing and subscriptions`,
	}

	cmd.AddCommand(LoginCmd())
	cmd.AddCommand(LogoutCmd())
	cmd.AddCommand(WhoamiCmd())
	cmd.AddCommand(AccountCmd())
	cmd.AddCommand(BillingCmd())

	return cmd
}

// LoginCmd returns the login command
func LoginCmd() *cobra.Command {
	var useEmail bool

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to your Zypheron account",
		Long: `Log in to your Zypheron account to access paid features.

Authentication methods:
  • Browser OAuth (default) - Opens browser for secure login
  • Email magic link - Sends login link to your email

After logging in, your session is cached locally and shared
with the Zypheron desktop app if installed.

Examples:
  zypheron login              # Browser-based login
  zypheron login --email      # Email magic link`,
		RunE: func(cmd *cobra.Command, args []string) error {
			manager := licensing.GetManager()

			// Check if already logged in
			if manager.IsAuthenticated() {
				license := manager.License()
				fmt.Println(ui.SuccessMsg("You are already logged in"))
				fmt.Printf("  Email: %s\n", license.Email)
				fmt.Printf("  Plan:  %s\n", utils.Capitalize(string(license.Tier)))
				fmt.Println()

				relogin := false
				prompt := &survey.Confirm{
					Message: "Would you like to log in with a different account?",
					Default: false,
				}
				if err := survey.AskOne(prompt, &relogin); err != nil || !relogin {
					return nil
				}
				manager.ClearSession()
			}

			if useEmail {
				return runEmailLogin()
			}
			return runBrowserLogin()
		},
	}

	cmd.Flags().BoolVar(&useEmail, "email", false, "Use email magic link instead of browser")
	return cmd
}

// runBrowserLogin opens browser for OAuth login with device code flow
func runBrowserLogin() error {
	fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
	fmt.Println(ui.Primary.Sprint("║              ZYPHERON LOGIN                            ║"))
	fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

	client := licensing.NewAPIClient()

	// Request device code from API
	fmt.Println(ui.InfoMsg("Initiating device authentication..."))
	fmt.Println()

	deviceResp, err := client.RequestDeviceCode()
	if err != nil {
		// UX FIX: Return error instead of silently succeeding
		fmt.Println(ui.WarningMsg("Could not connect to authentication server"))
		fmt.Println()
		deviceID := licensing.GetManager().GetDeviceID()
		loginURL := fmt.Sprintf("https://zypheron.net/auth/cli?device=%s&cli=true", deviceID[:16])

		fmt.Println(ui.InfoMsg("Please visit this URL to authenticate:"))
		fmt.Println(ui.Accent.Sprint("  " + loginURL))
		fmt.Println()

		if openErr := openBrowserAuth(loginURL); openErr == nil {
			fmt.Println(ui.Muted.Sprint("Browser opened automatically."))
		} else {
			fmt.Println(ui.Muted.Sprint("Could not open browser - please copy the URL above"))
		}
		fmt.Println()
		return fmt.Errorf("authentication server unavailable: %w", err)
	}

	// Display user code prominently
	fmt.Println(ui.Primary.Sprint("══════════════════════════════════════════════════════"))
	fmt.Println(ui.Primary.Sprint("  YOUR AUTHENTICATION CODE:"))
	fmt.Println()
	fmt.Println(ui.Primary.Sprint("          " + deviceResp.UserCode))
	fmt.Println()
	fmt.Println(ui.Primary.Sprint("══════════════════════════════════════════════════════"))
	fmt.Println()

	// Build verification URL
	verificationURL := deviceResp.VerificationURL
	if verificationURL == "" {
		verificationURL = fmt.Sprintf("https://zypheron.net/auth/device?code=%s", deviceResp.UserCode)
	}

	fmt.Println(ui.InfoMsg("Opening browser for authentication..."))

	// Auto-open browser with verification URL
	if err := openBrowserAuth(verificationURL); err != nil {
		fmt.Println(ui.WarningMsg("Could not open browser automatically"))
		fmt.Println()
		fmt.Println(ui.InfoMsg("Please visit:"))
		fmt.Println(ui.Accent.Sprint("  " + verificationURL))
		fmt.Println()
		fmt.Println(ui.InfoMsg("And enter the code shown above"))
	} else {
		fmt.Println(ui.Success.Sprint("✓ Browser opened"))
		fmt.Println(ui.Muted.Sprint("  Enter the code shown above to continue"))
	}
	fmt.Println()

	// Poll for authentication completion with spinner
	fmt.Print(ui.Muted.Sprint("Waiting for authorization"))

	pollInterval := time.Duration(deviceResp.Interval) * time.Second
	timeout := time.Duration(deviceResp.ExpiresIn) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Minute // Default 5 minute timeout
	}

	startTime := time.Now()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	spinnerChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinnerIdx := 0

	for {
		select {
		case <-ticker.C:
			// Check timeout
			if time.Since(startTime) > timeout {
				fmt.Println()
				fmt.Println()
				fmt.Println(ui.WarningMsg("Authentication timed out. Please try again."))
				return fmt.Errorf("authentication timed out")
			}

			// Poll device auth status
			resp, err := client.PollDeviceAuth(deviceResp.DeviceCode)
			if err != nil {
				// Show spinner and continue polling
				fmt.Printf("\r%s Waiting for authorization... %s",
					ui.Accent.Sprint(spinnerChars[spinnerIdx%len(spinnerChars)]),
					ui.Muted.Sprint(fmt.Sprintf("(%ds)", int(time.Since(startTime).Seconds()))))
				spinnerIdx++
				continue
			}

			switch resp.Status {
			case "authorized":
				fmt.Print("\r" + strings.Repeat(" ", 80) + "\r") // Clear spinner line
				fmt.Println()
				fmt.Println(ui.SuccessMsg("✓ Successfully authenticated!"))
				fmt.Println()
				fmt.Printf("  Email: %s\n", ui.Accent.Sprint(resp.Email))

				// Register device
				if _, err := client.RegisterDevice(); err != nil {
					fmt.Fprintf(os.Stderr, "  %s\n", ui.Muted.Sprint("Warning: device registration failed: "+err.Error()))
				} else {
					fmt.Printf("  Device: %s\n", ui.Muted.Sprint("Registered"))
				}

				// Fetch license
				if err := client.FetchLicense(); err == nil {
					license := licensing.GetManager().License()
					fmt.Printf("  Plan: %s\n", ui.Success.Sprint(utils.Capitalize(string(license.Tier))))
					if licensing.GetManager().IsPaidTier() {
						fmt.Printf("  Tokens: %s remaining\n", ui.Accent.Sprint(formatTokens(license.TokensRemaining)))
					}
				}
				fmt.Println()
				return nil

			case "expired":
				fmt.Print("\r" + strings.Repeat(" ", 80) + "\r") // Clear spinner line
				fmt.Println()
				fmt.Println(ui.Error("Authentication code expired. Please try again."))
				return fmt.Errorf("authentication code expired")

			case "pending":
				// Still waiting - show spinner
				fmt.Printf("\r%s Waiting for authorization... %s",
					ui.Accent.Sprint(spinnerChars[spinnerIdx%len(spinnerChars)]),
					ui.Muted.Sprint(fmt.Sprintf("(%ds)", int(time.Since(startTime).Seconds()))))
				spinnerIdx++
			}
		}
	}
}

// runEmailLogin authenticates with email and password
func runEmailLogin() error {
	fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
	fmt.Println(ui.Primary.Sprint("║              ZYPHERON LOGIN                            ║"))
	fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

	var email string
	emailPrompt := &survey.Input{
		Message: "Enter your email address:",
	}
	if err := survey.AskOne(emailPrompt, &email, survey.WithValidator(survey.Required)); err != nil {
		return err
	}

	var password string
	passwordPrompt := &survey.Password{
		Message: "Enter your password:",
	}
	if err := survey.AskOne(passwordPrompt, &password, survey.WithValidator(survey.Required)); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println(ui.InfoMsg("Authenticating..."))

	client := licensing.NewAPIClient()
	resp, err := client.Login(email, password)
	if err != nil {
		fmt.Println()
		fmt.Println(ui.Error("Authentication failed: " + err.Error()))
		fmt.Println()
		fmt.Println(ui.Muted.Sprint("Forgot password? Visit: https://zypheron.net/auth/reset"))
		fmt.Println(ui.Muted.Sprint("New user? Visit: https://zypheron.net/signup"))
		return fmt.Errorf("authentication failed: %w", err)
	}

	fmt.Println()
	fmt.Println(ui.SuccessMsg("Successfully authenticated!"))
	fmt.Printf("  Email: %s\n", resp.User.Email)
	fmt.Printf("  Plan:  %s\n", utils.Capitalize(resp.User.Tier))

	// Register device
	if _, err := client.RegisterDevice(); err != nil {
		fmt.Fprintf(os.Stderr, "  %s\n", ui.Muted.Sprint("Warning: device registration failed: "+err.Error()))
	} else {
		fmt.Println(ui.Muted.Sprint("  Device registered"))
	}

	// Show token balance for paid users
	license := licensing.GetManager().License()
	if licensing.GetManager().IsPaidTier() {
		fmt.Printf("  Tokens: %s remaining\n", formatTokens(license.TokensRemaining))
	}

	fmt.Println()
	return nil
}

// LogoutCmd returns the logout command
func LogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out of your Zypheron account",
		Long: `Log out of your Zypheron account.

This clears your local session and cached license.
You will need to log in again to access paid features.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			manager := licensing.GetManager()

			if !manager.IsAuthenticated() {
				fmt.Println(ui.InfoMsg("You are not currently logged in"))
				return nil
			}

			manager.ClearSession()
			fmt.Println(ui.SuccessMsg("Successfully logged out"))
			fmt.Println(ui.Muted.Sprint("Your local session has been cleared."))
			return nil
		},
	}
}

// WhoamiCmd returns the whoami command
func WhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "whoami",
		Aliases: []string{"me"},
		Short:   "Show current user information",
		RunE: func(cmd *cobra.Command, args []string) error {
			manager := licensing.GetManager()
			license := manager.License()

			fmt.Println()
			if !manager.IsAuthenticated() {
				fmt.Println(ui.WarningMsg("Not logged in"))
				fmt.Println()
				fmt.Println(ui.InfoMsg("Current mode: Free tier (anonymous)"))
				fmt.Println(ui.Muted.Sprint("  • Network scanning: Available"))
				fmt.Println(ui.Muted.Sprint("  • Self-hosted AI (Ollama): Available"))
				fmt.Println(ui.Muted.Sprint("  • Cloud AI: Requires login"))
				fmt.Println(ui.Muted.Sprint("  • Exploitation: Available locally"))
				fmt.Println()
				fmt.Println(ui.InfoMsg("Login: zypheron login"))
				fmt.Println()
				return nil
			}

			fmt.Println(ui.SuccessMsg("Logged in"))
			fmt.Println()
			fmt.Printf("  Email:    %s\n", ui.Accent.Sprint(license.Email))
			fmt.Printf("  User ID:  %s\n", ui.Muted.Sprint(license.UserID))
			fmt.Printf("  Plan:     %s\n", ui.Success.Sprint(utils.Capitalize(string(license.Tier))))

			if manager.IsPaidTier() {
				fmt.Printf("  Tokens:   %s / %s\n",
					ui.Accent.Sprint(formatTokens(license.TokensRemaining)),
					ui.Muted.Sprint(formatTokens(license.TokensLimit)))
				fmt.Printf("  Resets:   %s\n", ui.Muted.Sprint(license.ResetDate.Format("Jan 2, 2006")))
			}

			if license.TeamID != "" {
				fmt.Printf("  Team:     %s (%s)\n", license.TeamID, license.TeamRole)
			}

			fmt.Printf("  Device:   %s\n", ui.Muted.Sprint(manager.GetDeviceID()[:12]+"..."))
			fmt.Println()

			return nil
		},
	}
}

// AccountCmd returns the account command
func AccountCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "account",
		Short: "Manage your Zypheron account",
		Long: `Manage your Zypheron account and subscription.

Subcommands:
  usage     - View token usage statistics
  devices   - Manage registered devices
  upgrade   - Upgrade your subscription`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Default: show account overview
			return runAccountOverview()
		},
	}

	cmd.AddCommand(accountUsageCmd())
	cmd.AddCommand(accountDevicesCmd())
	return cmd
}

func runAccountOverview() error {
	manager := licensing.GetManager()
	license := manager.License()

	fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
	fmt.Println(ui.Primary.Sprint("║              ZYPHERON ACCOUNT                          ║"))
	fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

	if !manager.IsAuthenticated() {
		fmt.Println(ui.WarningMsg("Not logged in"))
		fmt.Println()
		fmt.Println(ui.InfoMsg("Login to view your account: zypheron login"))
		return nil
	}

	// Account info
	fmt.Println(ui.InfoMsg("Account Information"))
	fmt.Printf("  Email:        %s\n", ui.Accent.Sprint(license.Email))
	fmt.Printf("  Plan:         %s\n", ui.Success.Sprint(utils.Capitalize(string(license.Tier))))
	fmt.Println()

	// Token usage
	if manager.IsPaidTier() {
		fmt.Println(ui.InfoMsg("Token Usage"))
		usedPercent := float64(license.TokensUsed) / float64(license.TokensLimit) * 100
		fmt.Printf("  Used:         %s / %s (%.1f%%)\n",
			formatTokens(license.TokensUsed),
			formatTokens(license.TokensLimit),
			usedPercent)
		fmt.Printf("  Remaining:    %s\n", ui.Success.Sprint(formatTokens(license.TokensRemaining)))
		fmt.Printf("  Resets:       %s\n", license.ResetDate.Format("January 2, 2006"))
		fmt.Println()

		// Usage bar
		barWidth := 40
		filledWidth := int(usedPercent / 100 * float64(barWidth))
		bar := strings.Repeat("█", filledWidth) + strings.Repeat("░", barWidth-filledWidth)
		fmt.Printf("  [%s] %.1f%%\n", bar, usedPercent)
		fmt.Println()
	}

	// Available features
	fmt.Println(ui.InfoMsg("Available Features"))
	features := licensing.GetFeatureList()
	if len(features) == 0 {
		fmt.Println(ui.Muted.Sprint("  • Basic scanning (free)"))
		fmt.Println(ui.Muted.Sprint("  • Self-hosted AI - Ollama (free)"))
	} else {
		for _, f := range features {
			fmt.Printf("  • %s\n", f)
		}
	}
	fmt.Println()

	// Actions
	fmt.Println(ui.InfoMsg("Actions"))
	fmt.Println(ui.Muted.Sprint("  zypheron account usage      View detailed usage"))
	fmt.Println(ui.Muted.Sprint("  zypheron account devices    Manage devices"))
	fmt.Println(ui.Muted.Sprint("  zypheron upgrade            Upgrade plan"))
	fmt.Println(ui.Muted.Sprint("  zypheron billing            Open billing portal"))
	fmt.Println()

	return nil
}

func accountUsageCmd() *cobra.Command {
	var days int

	cmd := &cobra.Command{
		Use:   "usage",
		Short: "View token usage statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			manager := licensing.GetManager()

			if !manager.IsAuthenticated() {
				return fmt.Errorf("not logged in - run: zypheron login")
			}

			if !manager.IsPaidTier() {
				fmt.Println(ui.InfoMsg("Token usage tracking is available on paid plans"))
				fmt.Println()
				fmt.Println(licensing.FormatUpgradePrompt("usage tracking"))
				return nil
			}

			license := manager.License()

			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║              TOKEN USAGE                               ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

			fmt.Println(ui.InfoMsg(fmt.Sprintf("Usage for last %d days", days)))
			fmt.Println()

			fmt.Printf("  Total tokens used:     %s\n", formatTokens(license.TokensUsed))
			fmt.Printf("  Tokens remaining:      %s\n", ui.Success.Sprint(formatTokens(license.TokensRemaining)))
			fmt.Printf("  Monthly limit:         %s\n", formatTokens(license.TokensLimit))
			fmt.Printf("  Reset date:            %s\n", license.ResetDate.Format("January 2, 2006"))
			fmt.Println()

			// In production, this would fetch detailed breakdown from API
			fmt.Println(ui.Muted.Sprint("Detailed breakdown available in web dashboard"))
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().IntVarP(&days, "days", "d", 30, "Number of days to show")
	return cmd
}

func accountDevicesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "devices",
		Short: "Manage registered devices",
		RunE: func(cmd *cobra.Command, args []string) error {
			manager := licensing.GetManager()

			if !manager.IsAuthenticated() {
				return fmt.Errorf("not logged in - run: zypheron login")
			}

			license := manager.License()
			config := licensing.TierConfigs[license.Tier]

			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║              REGISTERED DEVICES                        ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

			fmt.Println(ui.InfoMsg("Current Device"))
			fmt.Printf("  Device ID: %s\n", manager.GetDeviceID()[:16]+"...")
			fmt.Printf("  Platform:  %s\n", runtime.GOOS+"/"+runtime.GOARCH)
			fmt.Println()

			if config.DeviceLimit == -1 {
				fmt.Println(ui.InfoMsg("Device limit: Unlimited (Enterprise)"))
			} else {
				fmt.Printf("%s Device limit: %d\n", ui.InfoMsg(""), config.DeviceLimit)
			}
			fmt.Println()

			// In production, this would list all devices from API
			fmt.Println(ui.Muted.Sprint("Full device list available in web dashboard"))
			fmt.Println()

			return nil
		},
	}
}

// UpgradeCmdAuth returns the upgrade command (auth version)
func UpgradeCmdAuth() *cobra.Command {
	return &cobra.Command{
		Use:   "upgrade-auth",
		Short: "Upgrade your subscription",
		Long: `Open the upgrade page to change your subscription plan.

Available plans:
  • Starter ($29/mo)  - 1M tokens, Cloud AI, Exploitation
  • Pro ($149/mo)     - 5M tokens, Priority Support
  • Enterprise ($499) - 25M tokens/user, Teams, Compliance`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println()
			fmt.Println(licensing.PrintFeatureMatrix())

			fmt.Println(ui.InfoMsg("Opening upgrade page..."))
			fmt.Println()

			if err := openBrowserAuth(UpgradeURL); err != nil {
				fmt.Println(ui.WarningMsg("Could not open browser automatically"))
				fmt.Println()
				fmt.Println(ui.InfoMsg("Visit:"))
				fmt.Println(ui.Accent.Sprint("  " + UpgradeURL))
			}
			fmt.Println()

			return nil
		},
	}
}

// BillingCmd returns the billing command
func BillingCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "billing",
		Short: "Open billing portal",
		Long: `Open the Stripe billing portal to manage your subscription.

In the billing portal you can:
  • Update payment method
  • View invoices
  • Cancel subscription
  • Change plan`,
		RunE: func(cmd *cobra.Command, args []string) error {
			manager := licensing.GetManager()

			if !manager.IsAuthenticated() {
				fmt.Println(ui.WarningMsg("Not logged in"))
				fmt.Println(ui.Muted.Sprint("Login first: zypheron login"))
				return fmt.Errorf("not logged in - run: zypheron login")
			}

			if !manager.IsPaidTier() {
				fmt.Println(ui.InfoMsg("You are on the free plan"))
				fmt.Println()
				fmt.Println(ui.InfoMsg("Upgrade to access billing portal:"))
				fmt.Println(ui.Accent.Sprint("  zypheron upgrade"))
				return nil
			}

			fmt.Println(ui.InfoMsg("Opening billing portal..."))
			fmt.Println()

			if err := openBrowserAuth(BillingPortal); err != nil {
				fmt.Println(ui.WarningMsg("Could not open browser automatically"))
				fmt.Println()
				fmt.Println(ui.InfoMsg("Visit:"))
				fmt.Println(ui.Accent.Sprint("  " + BillingPortal))
			}
			fmt.Println()

			return nil
		},
	}
}

// openBrowserAuth opens the default browser
func openBrowserAuth(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported platform")
	}

	return cmd.Start()
}

// formatTokens formats token counts for display
func formatTokens(n int64) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

// Helper for displaying time until reset
func timeUntilReset(resetDate time.Time) string {
	duration := time.Until(resetDate)
	days := int(duration.Hours() / 24)
	if days == 0 {
		return "today"
	} else if days == 1 {
		return "tomorrow"
	}
	return fmt.Sprintf("in %d days", days)
}
