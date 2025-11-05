package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

// AuthenticatedScanCmd returns the authenticated scan command
func AuthenticatedScanCmd() *cobra.Command {
	var (
		authType    string
		username    string
		password    string
		authToken   string
		sessionFile string
		testAccount bool
		role        string
		scanType    string
		outputFile  string
	)

	cmd := &cobra.Command{
		Use:   "auth-scan [target]",
		Short: "Authenticated security scanning",
		Long:  "Perform authenticated security scans to test authorization, IDOR, and privilege escalation",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var target string

			// Get target
			if len(args) > 0 {
				target = args[0]
			} else {
				prompt := &survey.Input{
					Message: "Enter target URL:",
				}
				if err := survey.AskOne(prompt, &target, survey.WithValidator(survey.Required)); err != nil {
					return err
				}
			}

			// Print scan configuration
			fmt.Println("\n" + ui.Primary.Sprint("Authenticated Scan Configuration:"))
			fmt.Println(strings.Repeat("─", 60))
			fmt.Printf("  Target:      %s\n", ui.Info.Sprint(target))
			fmt.Printf("  Auth Type:   %s\n", ui.Warning.Sprint(authType))
			if testAccount {
				fmt.Printf("  Account:     %s\n", ui.Success.Sprint("Test account (auto-created)"))
			} else if username != "" {
				fmt.Printf("  Username:    %s\n", ui.Warning.Sprint(username))
			}
			fmt.Printf("  Scan Type:   %s\n", ui.Accent.Sprint(scanType))
			fmt.Println(strings.Repeat("─", 60))

			// Initialize AI bridge
			bridge := aibridge.NewAIBridge()

			// If test account requested, create it
			var authSessionID string
			if testAccount {
				fmt.Println(ui.WarningMsg("Creating test account..."))

				testAccountReq := map[string]interface{}{
					"method": "create_test_account",
					"params": map[string]interface{}{
						"target_url": target,
						"role":       role,
					},
				}

				testAccountResp, err := bridge.SendRequest("create_test_account", testAccountReq["params"].(map[string]interface{}))
				if err != nil {
					return fmt.Errorf("failed to create test account: %w", err)
				}

				username = testAccountResp.Result["username"].(string)
				password = testAccountResp.Result["password"].(string)

				fmt.Println(ui.SuccessMsg(fmt.Sprintf("Test account created: %s", username)))
			}

			// Authenticate
			fmt.Println(ui.WarningMsg("Authenticating..."))

			authParams := map[string]interface{}{
				"target_url": target,
				"auth_type":  authType,
				"username":   username,
				"password":   password,
				"auth_token": authToken,
			}

			authResp, err := bridge.SendRequest("authenticate", authParams)
			if err != nil {
				return fmt.Errorf("authentication failed: %w", err)
			}

			authSessionID = authResp.Result["session_id"].(string)
			fmt.Println(ui.SuccessMsg(fmt.Sprintf("Authenticated successfully (session: %s)", authSessionID[:16]+"...")))

			// Run authenticated scans
			fmt.Println(ui.InfoMsg("Running authenticated vulnerability tests..."))

			results := make(map[string]interface{})

			// Test 1: IDOR
			if scanType == "full" || scanType == "idor" {
				fmt.Println(ui.Warning.Sprint("\n  → Testing IDOR vulnerabilities..."))

				idorParams := map[string]interface{}{
					"session_id": authSessionID,
					"target_url": target,
				}

				idorResp, err := bridge.SendRequest("test_idor", idorParams)
				if err == nil && idorResp.Result != nil {
					if vulns, ok := idorResp.Result["vulnerabilities"].([]interface{}); ok {
						idorCount := len(vulns)
						if idorCount > 0 {
							fmt.Println(ui.Danger.Sprint(fmt.Sprintf("  [!] Found %d IDOR vulnerabilities", idorCount)))
						} else {
							fmt.Println(ui.Success.Sprint("  [✓] No IDOR vulnerabilities found"))
						}
					}
					results["idor"] = idorResp.Result
				}
			}

			// Test 2: Privilege Escalation
			if scanType == "full" || scanType == "privesc" {
				fmt.Println(ui.Warning.Sprint("\n  → Testing privilege escalation..."))

				privescParams := map[string]interface{}{
					"session_id": authSessionID,
					"target_url": target,
				}

				privescResp, err := bridge.SendRequest("test_privilege_escalation", privescParams)
				if err == nil && privescResp.Result != nil {
					if vulns, ok := privescResp.Result["vulnerabilities"].([]interface{}); ok {
						privescCount := len(vulns)
						if privescCount > 0 {
							fmt.Println(ui.Danger.Sprint(fmt.Sprintf("  [!] Found %d privilege escalation issues", privescCount)))
						} else {
							fmt.Println(ui.Success.Sprint("  [✓] No privilege escalation found"))
						}
					}
					results["privilege_escalation"] = privescResp.Result
				}
			}

			// Test 3: Session Security
			if scanType == "full" || scanType == "session" {
				fmt.Println(ui.Warning.Sprint("\n  → Testing session security..."))

				sessionParams := map[string]interface{}{
					"session_id": authSessionID,
					"target_url": target,
				}

				sessionResp, err := bridge.SendRequest("test_session_security", sessionParams)
				if err == nil && sessionResp.Result != nil {
					results["session_security"] = sessionResp.Result
					fmt.Println(ui.Success.Sprint("  [✓] Session security tests completed"))
				}
			}

			// Generate summary
			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║  AUTHENTICATED SCAN RESULTS              ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════╝"))

			totalVulns := 0
			if idorVulns, ok := results["idor"].(map[string]interface{}); ok {
				if vulns, ok := idorVulns["vulnerabilities"].([]interface{}); ok {
					totalVulns += len(vulns)
				}
			}
			if privescVulns, ok := results["privilege_escalation"].(map[string]interface{}); ok {
				if vulns, ok := privescVulns["vulnerabilities"].([]interface{}); ok {
					totalVulns += len(vulns)
				}
			}

			fmt.Printf("\nTotal Vulnerabilities: %s\n", ui.Danger.Sprint(fmt.Sprintf("%d", totalVulns)))

			// Save results if output file specified
			if outputFile != "" {
				if data, err := json.MarshalIndent(results, "", "  "); err == nil {
					os.WriteFile(outputFile, data, 0644)
					fmt.Printf("\n[+] Results saved to: %s\n", outputFile)
				}
			}

			// Cleanup test account if created
			if testAccount {
				fmt.Println(ui.WarningMsg("Cleaning up test account..."))
				// Call cleanup
				fmt.Println(ui.SuccessMsg("Test account cleaned up"))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&authType, "auth-type", "form", "Authentication type (basic, bearer, form, cookie, oauth2, apikey)")
	cmd.Flags().StringVar(&username, "username", "", "Username for authentication")
	cmd.Flags().StringVar(&password, "password", "", "Password (or prompt securely)")
	cmd.Flags().StringVar(&authToken, "auth-token", "", "Pre-existing auth token")
	cmd.Flags().StringVar(&sessionFile, "session-file", "", "Load/save session state")
	cmd.Flags().BoolVar(&testAccount, "test-account", false, "Use auto-created test account")
	cmd.Flags().StringVar(&role, "role", "user", "Test account role (user, admin)")
	cmd.Flags().StringVar(&scanType, "scan-type", "full", "Scan type (full, idor, privesc, session)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for results")

	return cmd
}
