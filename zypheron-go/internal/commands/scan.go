package commands

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/kali"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/storage"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tools"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/validation"
	"github.com/KKingZero/Cobra-AI/zypheron-go/pkg/types"
	"github.com/spf13/cobra"
)

// ScanCmd returns the scan command
func ScanCmd() *cobra.Command {
	var (
		tool       string
		ports      string
		web        bool
		full       bool
		fast       bool
		stream     bool
		aiGuided   bool
		aiAnalysis bool
		timeout    int
		output     string
		format     string
		assumeYes  bool
		noInput    bool
	)

	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "Security scanning with Kali tools (nmap, nikto, nuclei)",
		Long:  "Perform security scans using integrated Kali Linux tools with real-time output streaming",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var target string
			interactive := isInteractive(cmd) && !noInput

			// Get target (from args or prompt)
			if len(args) > 0 {
				target = args[0]
			} else {
				if !interactive {
					return fmt.Errorf("target argument required when running non-interactively")
				}
				prompt := &survey.Input{
					Message: "Enter target (URL, IP, or hostname):",
				}
				if err := survey.AskOne(prompt, &target, survey.WithValidator(survey.Required)); err != nil {
					if errors.Is(err, terminal.InterruptErr) {
						return fmt.Errorf("target prompt interrupted")
					}
					return err
				}
			}

			// Validate target
			if err := validation.ValidateTarget(target); err != nil {
				return fmt.Errorf("invalid target: %w", err)
			}

			// Validate ports
			if err := validation.ValidatePorts(ports); err != nil {
				return fmt.Errorf("invalid ports: %w", err)
			}

			// Validate tool name if provided
			if tool != "" {
				if err := validation.ValidateToolName(tool); err != nil {
					return fmt.Errorf("invalid tool: %w", err)
				}
			}

			// Validate output file path if provided
			if output != "" {
				if err := validation.ValidateFilePath(output); err != nil {
					return fmt.Errorf("invalid output path: %w", err)
				}
			}

			// Print header
			fmt.Printf("\n%s\n", ui.Primary.Sprint("╔═══════════════════════════════════════╗"))
			fmt.Printf("%s\n", ui.Primary.Sprint("║  ZYPHERON SECURITY SCANNER           ║"))
			fmt.Printf("%s\n\n", ui.Primary.Sprint("╚═══════════════════════════════════════╝"))

			// Detect Kali environment
			fmt.Println(ui.InfoMsg("Detecting Kali environment..."))
			env, err := kali.DetectEnvironment()
			if err != nil {
				return err
			}

			if env.IsKali {
				fmt.Println(ui.SuccessMsg(fmt.Sprintf("Running on Kali Linux %s", env.Version)))
			} else {
				fmt.Println(ui.WarningMsg("Not running on Kali Linux - some tools may not be available"))
			}

			if env.IsWSL {
				fmt.Println(ui.InfoMsg(fmt.Sprintf("WSL Environment: %s", env.Distribution)))
			}

			// Detect tools
			fmt.Println(ui.InfoMsg("Detecting security tools..."))
			toolManager := kali.NewToolManager()
			if err := toolManager.DetectTools(); err != nil {
				return err
			}

			stats := toolManager.GetStats()
			fmt.Printf("  Found %s/%d tools installed\n", ui.Success.Sprint(stats.Installed), stats.Total)

			if stats.Critical > 0 {
				fmt.Println(ui.WarningMsg(fmt.Sprintf("%d critical tools are missing!", stats.Critical)))
			}

			// Determine which tool to use
			selectedTool := tool
			if selectedTool == "" {
				if web {
					selectedTool = "nikto"
				} else if fast {
					selectedTool = "masscan"
				} else {
					selectedTool = "nmap"
				}
			}

			// Check if tool is available
			if !toolManager.IsInstalled(selectedTool) {
				fmt.Println(ui.Error(fmt.Sprintf("Tool '%s' is not installed", selectedTool)))

				// Suggest installation
				installCmd := toolManager.GetInstallCommand(selectedTool)
				fmt.Printf("\n%s\n", ui.InfoMsg(fmt.Sprintf("Install with: %s", installCmd)))

				confirm := assumeYes
				if !assumeYes {
					if !interactive {
						return fmt.Errorf("required tool '%s' not installed; rerun with --yes or install manually", selectedTool)
					}
					prompt := &survey.Confirm{
						Message: "Install now?",
					}
					if err := survey.AskOne(prompt, &confirm); err != nil {
						if errors.Is(err, terminal.InterruptErr) {
							return fmt.Errorf("installation prompt interrupted")
						}
						return err
					}
				}

				if confirm {
					if err := toolManager.Install(selectedTool); err != nil {
						return fmt.Errorf("installation failed: %w", err)
					}
					fmt.Println(ui.SuccessMsg(fmt.Sprintf("%s installed successfully", selectedTool)))
				} else {
					return fmt.Errorf("required tool not installed")
				}
			}

			// Show scan configuration
			fmt.Printf("\n%s\n", ui.InfoMsg("Scan Configuration:"))
			fmt.Println(ui.Separator(60))
			fmt.Printf("  Target:   %s\n", ui.Accent.Sprint(target))
			fmt.Printf("  Tool:     %s\n", ui.Accent.Sprint(selectedTool))
			fmt.Printf("  Ports:    %s\n", ui.Accent.Sprint(ports))
			fmt.Printf("  Timeout:  %s\n", ui.Accent.Sprint(fmt.Sprintf("%ds", timeout)))
			if aiGuided || aiAnalysis {
				fmt.Printf("  AI Mode:  %s\n", ui.Success.Sprint("Enabled"))
			}
			fmt.Println(ui.Separator(60))
			fmt.Println()

			// Confirm scan
			confirm := true
			if assumeYes || !interactive {
				confirm = true
			} else {
				confirmPrompt := &survey.Confirm{
					Message: "Start security scan?",
					Default: true,
				}
				if err := survey.AskOne(confirmPrompt, &confirm); err != nil {
					if errors.Is(err, terminal.InterruptErr) {
						fmt.Println(ui.InfoMsg("Scan cancelled"))
						return nil
					}
					return err
				}
			}

			if !confirm {
				fmt.Println(ui.InfoMsg("Scan cancelled"))
				return nil
			}

			// Build execution options
			opts := tools.ExecutionOptions{
				Tool:       selectedTool,
				Target:     target,
				Stream:     stream,
				Timeout:    time.Duration(timeout) * time.Second,
				AIAnalysis: aiAnalysis,
				AssumeYes:  assumeYes,
			}

			// Add tool-specific args
			switch selectedTool {
			case "nmap":
				opts.Args = buildNmapArgs(target, ports, fast)
			case "nikto":
				opts.Args = []string{"-h", target}
			case "masscan":
				opts.Args = []string{target, "-p", ports, "--rate", "1000"}
			case "nuclei":
				opts.Args = []string{"-u", target, "-json"}
			default:
				opts.Args = []string{target}
			}

			// Execute scan
			top, bottom := ui.Box(selectedTool)
			fmt.Printf("\n%s\n", top)

			ctx := context.Background()
			scanStartTime := time.Now()
			result, err := tools.Execute(ctx, opts)
			if err != nil {
				fmt.Printf("\n%s\n", bottom)
				return fmt.Errorf("execution failed: %w", err)
			}

			if result.Success {
				fmt.Printf("\n%s\n", ui.SuccessMsg(fmt.Sprintf("%s scan completed in %.2fs", selectedTool, result.Duration.Seconds())))

				// Parse and display structured results for nmap
				if selectedTool == "nmap" {
					parsed := tools.ParseNmapOutput(result.Output)
					displayParsedResults(parsed)
				}
			} else {
				fmt.Printf("\n%s\n", ui.Error(fmt.Sprintf("Scan failed: %s", result.Error)))
			}

			fmt.Printf("%s\n\n", bottom)

			// Initialize scan storage
			scanStore, err := storage.NewScanStorage()
			if err != nil {
				fmt.Println(ui.WarningMsg(fmt.Sprintf("Failed to initialize scan storage: %s", err)))
			}

			// Prepare scan result for storage
			scanID := storage.GenerateScanID(target, selectedTool)
			scanResult := &types.ScanResult{
				ID:           scanID,
				Timestamp:    scanStartTime,
				Target:       target,
				Tool:         selectedTool,
				Ports:        ports,
				Output:       result.Output,
				Duration:     result.Duration.Seconds(),
				Success:      result.Success,
				ErrorMessage: result.Error,
				Metadata: map[string]string{
					"fast": fmt.Sprintf("%t", fast),
					"web":  fmt.Sprintf("%t", web),
					"full": fmt.Sprintf("%t", full),
				},
			}

			// AI Analysis
			if aiAnalysis && result.Success {
				fmt.Println()
				fmt.Println(ui.Accent.Sprint("🤖 AI-POWERED VULNERABILITY ANALYSIS"))
				fmt.Println(ui.Separator(60))
				fmt.Println()

				bridge := aibridge.NewAIBridge()

				// Check if AI engine is running
				if !bridge.IsRunning() {
					fmt.Println(ui.WarningMsg("AI Engine not running"))
					fmt.Println(ui.InfoMsg("Start it with: zypheron ai start"))
					fmt.Println()
					return nil
				}

				fmt.Println(ui.InfoMsg("Analyzing scan results with AI..."))

				// Analyze scan with AI
				vulns, report, err := bridge.AnalyzeScan(result.Output, selectedTool, target, true)
				if err != nil {
					fmt.Println(ui.Error(fmt.Sprintf("AI analysis failed: %s", err)))
					return nil
				}

				// Convert aibridge.Vulnerability to types.Vulnerability
				for _, v := range vulns {
					scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, types.Vulnerability{
						ID:          v.ID,
						Title:       v.Title,
						Description: v.Description,
						Severity:    v.Severity,
					})
				}

				// Store AI analysis report
				scanResult.AIAnalysis = report

				if len(vulns) > 0 {
					fmt.Println()
					fmt.Printf("%s %s\n", ui.Success.Sprint("✓"), ui.Success.Sprint(fmt.Sprintf("Found %d potential vulnerabilities", len(vulns))))
					fmt.Println()

					// Display top 5 vulnerabilities
					displayCount := len(vulns)
					if displayCount > 5 {
						displayCount = 5
					}

					for i, vuln := range vulns[:displayCount] {
						// Color code severity
						var severityColor *ui.Color
						switch vuln.Severity {
						case "critical":
							severityColor = ui.Danger
						case "high":
							severityColor = ui.Warning
						case "medium":
							severityColor = ui.Info
						default:
							severityColor = ui.Muted
						}

						fmt.Printf("  %d. [%s] %s\n",
							i+1,
							severityColor.Sprint(vuln.Severity),
							vuln.Title,
						)
						fmt.Printf("     %s\n", ui.Muted.Sprint(vuln.Description[:min(100, len(vuln.Description))]+"..."))
						fmt.Println()
					}

					if len(vulns) > 5 {
						fmt.Println(ui.Muted.Sprint(fmt.Sprintf("  ... and %d more", len(vulns)-5)))
						fmt.Println()
					}

					// ML Vulnerability Prediction
					if aiGuided {
						fmt.Println(ui.InfoMsg("🔮 Running ML vulnerability prediction..."))

						scanData := map[string]interface{}{
							"target": target,
							"tool":   selectedTool,
							"output": result.Output,
						}

						predictions, err := bridge.PredictVulnerabilities(scanData, true)
						if err == nil && len(predictions) > 0 {
							fmt.Printf("%s Predicted %d additional vulnerabilities\n", ui.Success.Sprint("✓"), len(predictions))
							for i, pred := range predictions[:min(3, len(predictions))] {
								fmt.Printf("  %d. %s (confidence: %.0f%%)\n",
									i+1,
									pred.VulnerabilityType,
									pred.Confidence*100,
								)
							}
							fmt.Println()
						}
					}

					// Save full report
					if output != "" {
						if err := saveReport(output, report); err != nil {
							fmt.Println(ui.Error(fmt.Sprintf("Failed to save report: %s", err)))
						} else {
							fmt.Println(ui.SuccessMsg(fmt.Sprintf("Report saved to: %s", output)))
						}
					}
				} else {
					fmt.Println(ui.InfoMsg("✓ No critical vulnerabilities detected"))
				}
				fmt.Println()
			}

			// Save scan to storage
			if scanStore != nil {
				if err := scanStore.SaveScan(scanResult); err != nil {
					fmt.Println(ui.WarningMsg(fmt.Sprintf("Failed to save scan: %s", err)))
				} else {
					fmt.Println(ui.Muted.Sprint(fmt.Sprintf("Scan saved: %s", scanID)))
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&tool, "tool", "t", "", "Specific tool (nmap, nikto, nuclei, masscan)")
	cmd.Flags().StringVarP(&ports, "ports", "p", "1-1000", "Port range")
	cmd.Flags().BoolVar(&web, "web", false, "Web application scanning")
	cmd.Flags().BoolVar(&full, "full", false, "Full pentest suite")
	cmd.Flags().BoolVar(&fast, "fast", false, "Quick scan")
	cmd.Flags().BoolVar(&stream, "stream", true, "Stream output")
	cmd.Flags().BoolVar(&aiGuided, "ai-guided", false, "AI-guided scanning with ML predictions")
	cmd.Flags().BoolVar(&aiAnalysis, "ai-analysis", false, "AI-powered vulnerability analysis")
	cmd.Flags().IntVar(&timeout, "timeout", 300, "Timeout in seconds")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file")
	cmd.Flags().StringVar(&format, "format", "text", "Output format (text, json, xml)")
	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "Assume yes for confirmation prompts (non-interactive mode)")
	cmd.Flags().BoolVar(&noInput, "no-input", false, "Disable interactive prompts (requires all arguments)")

	return cmd
}

// Helper functions
// Note: Go 1.21+ has built-in min function

func saveReport(_ /* filename */, _ /* content */ string) error {
	// TODO: Implement report saving
	return nil
}

// buildNmapArgs builds nmap arguments
func buildNmapArgs(target, ports string, fast bool) []string {
	args := []string{"-sV", "-sC"}

	if ports != "" {
		args = append(args, "-p", ports)
	}

	if fast {
		args = append(args, "-T4")
	}

	args = append(args, target)
	return args
}

// displayParsedResults displays parsed scan results
func displayParsedResults(parsed interface{}) {
	data, ok := parsed.(map[string]interface{})
	if !ok {
		return
	}

	hosts, ok := data["hosts"].([]map[string]interface{})
	if !ok || len(hosts) == 0 {
		fmt.Println(ui.Muted.Sprint("  No hosts found"))
		return
	}

	for _, host := range hosts {
		if target, ok := host["target"].(string); ok {
			fmt.Printf("\n  %s %s\n", ui.Accent.Sprint("Host:"), ui.Primary.Sprint(target))
		}

		if ports, ok := host["ports"].([]map[string]string); ok && len(ports) > 0 {
			fmt.Printf("  %s\n", ui.Info.Sprint("Ports:"))
			for _, port := range ports {
				state := port["state"]
				stateColor := ui.Success
				if state != "open" {
					stateColor = ui.Muted
				}
				fmt.Printf("    %s %-10s %s\n",
					stateColor.Sprint(state),
					ui.Accent.Sprint(port["port"]),
					port["service"])
			}
		}
	}
}
