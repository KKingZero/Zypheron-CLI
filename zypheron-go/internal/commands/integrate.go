package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/edition"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

// IntegrateCmd returns the tool integration command
func IntegrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "integrate [tool]",
		Short: "Integrate with third-party security tools",
		Long:  "Integrate with Burp Suite, OWASP ZAP, and other security testing tools",
		Args:  cobra.MaximumNArgs(1),
	}

	// Add subcommands
	cmd.AddCommand(integrateBurpCmd())
	cmd.AddCommand(integrateZAPCmd())

	return cmd
}

func integrateBurpCmd() *cobra.Command {
	var (
		target         string
		apiKey         string
		host           string
		port           int
		sessionID      string
		spider         bool
		activeScan     bool
		importFindings bool
		outputFile     string
	)

	cmd := &cobra.Command{
		Use:   "burp",
		Short: "Integrate with Burp Suite Professional [PRO for Active Scan]",
		Long:  "Send targets to Burp Suite for advanced scanning and import results",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check edition for active scanning
			if activeScan && edition.IsFree() {
				fmt.Println(edition.UpgradeMessage())
				return fmt.Errorf("burp suite active scanning requires Zypheron Pro (passive scanning is available)")
			}
			
			if target == "" {
				prompt := &survey.Input{
					Message: "Enter target URL:",
				}
				survey.AskOne(prompt, &target, survey.WithValidator(survey.Required))
			}

			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║  BURP SUITE INTEGRATION                  ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════╝"))

			fmt.Println("\n" + ui.Primary.Sprint("Configuration:"))
			fmt.Println(strings.Repeat("─", 60))
			fmt.Printf("  Target:       %s\n", ui.Info.Sprint(target))
			fmt.Printf("  Burp Suite:   %s:%d\n", host, port)
			fmt.Printf("  Spider:       %v\n", spider)
			fmt.Printf("  Active Scan:  %v\n", activeScan)
			fmt.Println(strings.Repeat("─", 60))

			bridge := aibridge.NewAIBridge()

			// Check Burp availability
			fmt.Println(ui.WarningMsg("Checking Burp Suite availability..."))

			checkParams := map[string]interface{}{
				"host":    host,
				"port":    port,
				"api_key": apiKey,
			}

			checkResp, err := bridge.SendRequest("check_burp_available", checkParams)
			if err != nil {
				return fmt.Errorf("failed to connect to burp suite: ensure burp is running with rest api enabled")
			}

			if available, ok := checkResp.Result["available"].(bool); !ok || !available {
				return fmt.Errorf("burp suite is not available")
			}

			if version, ok := checkResp.Result["version"].(map[string]interface{}); ok {
				if burpVer, ok := version["burp_version"].(string); ok {
					fmt.Println(ui.SuccessMsg(fmt.Sprintf("Burp Suite %s available", burpVer)))
				}
			}

			// Run scan
			fmt.Println(ui.WarningMsg("Starting Burp scan..."))

			scanParams := map[string]interface{}{
				"target":      target,
				"session_id":  sessionID,
				"spider":      spider,
				"active_scan": activeScan,
			}

			scanResp, err := bridge.SendRequest("burp_scan", scanParams)
			if err != nil {
				return fmt.Errorf("burp scan failed: %w", err)
			}

			taskID := scanResp.Result["task_id"].(string)
			fmt.Println(ui.SuccessMsg(fmt.Sprintf("Burp scan started: %s", taskID)))

			// Wait for completion
			fmt.Println(ui.WarningMsg("Waiting for scan completion..."))
			// Progress monitoring would go here

			// Import findings
			if importFindings {
				fmt.Println(ui.WarningMsg("Importing Burp findings..."))

				importParams := map[string]interface{}{
					"task_id": taskID,
				}

				importResp, err := bridge.SendRequest("import_burp_findings", importParams)
				if err == nil && importResp.Result != nil {
					if count, ok := importResp.Result["imported_count"].(float64); ok {
						fmt.Println(ui.SuccessMsg(fmt.Sprintf("Imported %d findings from Burp", int(count))))

						if outputFile != "" {
							data, _ := json.MarshalIndent(importResp.Result, "", "  ")
							os.WriteFile(outputFile, data, 0644)
							fmt.Printf("[+] Results saved to: %s\n", outputFile)
						}
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&target, "target", "", "Target URL")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "Burp Suite API key")
	cmd.Flags().StringVar(&host, "host", "127.0.0.1", "Burp Suite host")
	cmd.Flags().IntVar(&port, "port", 1337, "Burp Suite REST API port")
	cmd.Flags().StringVar(&sessionID, "session-id", "", "Authenticated session ID")
	cmd.Flags().BoolVar(&spider, "spider", true, "Run spider")
	cmd.Flags().BoolVar(&activeScan, "active-scan", true, "Run active scan")
	cmd.Flags().BoolVar(&importFindings, "import", true, "Import findings into Zypheron")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for results")

	return cmd
}

func integrateZAPCmd() *cobra.Command {
	var (
		target         string
		host           string
		port           int
		sessionID      string
		spider         bool
		ajaxSpider     bool
		activeScan     bool
		importFindings bool
		outputFile     string
	)

	cmd := &cobra.Command{
		Use:   "zap",
		Short: "Integrate with OWASP ZAP [PRO for Active Scan]",
		Long:  "Send targets to OWASP ZAP for automated scanning and import results",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check edition for active scanning
			if activeScan && edition.IsFree() {
				fmt.Println(edition.UpgradeMessage())
				return fmt.Errorf("zap active scanning requires Zypheron Pro (passive scanning is available)")
			}
			
			if target == "" {
				prompt := &survey.Input{
					Message: "Enter target URL:",
				}
				survey.AskOne(prompt, &target, survey.WithValidator(survey.Required))
			}

			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║  OWASP ZAP INTEGRATION                   ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════╝"))

			fmt.Println("\n" + ui.Primary.Sprint("Configuration:"))
			fmt.Println(strings.Repeat("─", 60))
			fmt.Printf("  Target:        %s\n", ui.Info.Sprint(target))
			fmt.Printf("  ZAP:           %s:%d\n", host, port)
			fmt.Printf("  Spider:        %v\n", spider)
			fmt.Printf("  AJAX Spider:   %v\n", ajaxSpider)
			fmt.Printf("  Active Scan:   %v\n", activeScan)
			fmt.Println(strings.Repeat("─", 60))

			bridge := aibridge.NewAIBridge()

			// Check ZAP availability
			fmt.Println(ui.WarningMsg("Checking OWASP ZAP availability..."))

			checkParams := map[string]interface{}{
				"host": host,
				"port": port,
			}

			checkResp, err := bridge.SendRequest("check_zap_available", checkParams)
			if err != nil {
				return fmt.Errorf("failed to connect to owasp zap: ensure zap is running with api enabled")
			}

			if available, ok := checkResp.Result["available"].(bool); !ok || !available {
				return fmt.Errorf("owasp zap is not available")
			}

			if zapVersion, ok := checkResp.Result["version"].(string); ok {
				fmt.Println(ui.SuccessMsg(fmt.Sprintf("OWASP ZAP %s available", zapVersion)))
			}

			// Run scan
			fmt.Println(ui.WarningMsg("Starting ZAP scan..."))

			scanParams := map[string]interface{}{
				"target":      target,
				"session_id":  sessionID,
				"spider":      spider,
				"ajax_spider": ajaxSpider,
				"active_scan": activeScan,
			}

			scanResp, err := bridge.SendRequest("zap_scan", scanParams)
			if err != nil {
				return fmt.Errorf("zap scan failed: %w", err)
			}

			fmt.Println(ui.SuccessMsg("ZAP scan completed"))

			// Display summary
			if scanResp.Result != nil {
				if alerts, ok := scanResp.Result["alerts"].([]interface{}); ok {
					fmt.Printf("\n%s: %d\n", ui.Info.Sprint("Total Alerts"), len(alerts))

					// Count by risk
					byRisk := make(map[string]int)
					for _, a := range alerts {
						alert := a.(map[string]interface{})
						if risk, ok := alert["risk"].(string); ok {
							byRisk[risk]++
						}
					}

					fmt.Println("\nBy Risk:")
					if byRisk["High"] > 0 {
						fmt.Printf("  %s: %d\n", ui.Danger.Sprint("High"), byRisk["High"])
					}
					if byRisk["Medium"] > 0 {
						fmt.Printf("  %s: %d\n", ui.Warning.Sprint("Medium"), byRisk["Medium"])
					}
					if byRisk["Low"] > 0 {
						fmt.Printf("  %s: %d\n", ui.Success.Sprint("Low"), byRisk["Low"])
					}
				}
			}

			// Save results
			if outputFile != "" {
				data, _ := json.MarshalIndent(scanResp.Result, "", "  ")
				os.WriteFile(outputFile, data, 0644)
				fmt.Printf("\n[+] Results saved to: %s\n", outputFile)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&target, "target", "", "Target URL")
	cmd.Flags().StringVar(&host, "host", "127.0.0.1", "ZAP host")
	cmd.Flags().IntVar(&port, "port", 8080, "ZAP API port")
	cmd.Flags().StringVar(&sessionID, "session-id", "", "Authenticated session ID")
	cmd.Flags().BoolVar(&spider, "spider", true, "Run spider")
	cmd.Flags().BoolVar(&ajaxSpider, "ajax-spider", true, "Run AJAX spider")
	cmd.Flags().BoolVar(&activeScan, "active-scan", true, "Run active scan")
	cmd.Flags().BoolVar(&importFindings, "import", true, "Import findings into Zypheron")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for results")

	return cmd
}
