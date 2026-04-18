package commands

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/kali"
	reportpkg "github.com/KKingZero/Cobra-AI/zypheron-go/internal/report"
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
		noStream   bool
		aiGuided   bool
		aiAnalysis bool
		timeout    int
		output     string
		format     string
		assumeYes  bool
		noInput    bool
	)

	cmd := &cobra.Command{
		Use:     "scan [target]",
		Aliases: []string{"s"},
		Short:   "Security scanning with security tools (nmap, nikto, nuclei)",
		Long: `Perform security scans using integrated security tools with real-time output streaming.

Supports multiple scan types:
  • Port scanning (nmap, masscan)
  • Web application scanning (nikto, nuclei)
  • AI-guided scanning with vulnerability prediction
  • AI-powered analysis of scan results

Examples:
  zypheron scan example.com                    # Basic port scan
  zypheron scan 192.168.1.1 --ports 1-65535   # Full port scan
  zypheron scan https://example.com --web      # Web application scan
  zypheron scan example.com --fast             # Quick scan with masscan
  zypheron scan example.com --ai-analysis      # Scan with AI analysis
  zypheron scan example.com --tool nuclei      # Use specific tool
  zypheron scan example.com --ai-guided        # AI-guided scanning`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var target string
			interactive := isInteractive(cmd) && !noInput

			// Full profile defaults to full port coverage unless user provided --ports.
			if full && ports == "1-1000" {
				ports = "1-65535"
			}

			// Resolve conflicting profiles deterministically.
			if full && fast {
				fmt.Println(ui.WarningMsg("Both --full and --fast were set; using --full profile"))
				fast = false
			}

			// UX: Validate flags early (before interactive prompts)
			// This way users get immediate feedback on bad flags
			if err := validation.ValidatePorts(ports); err != nil {
				fmt.Println(ui.ValidationError("ports", err.Error(),
					"1-1000",
					"80,443,8080",
					"1-65535",
					"22,80,443",
				))
				return fmt.Errorf("invalid ports '%s': %w. Examples: 1-1000, 80,443,8080, 1-65535", ports, err)
			}

			if tool != "" {
				if err := validation.ValidateToolName(tool); err != nil {
					fmt.Println(ui.ErrorWithSuggestion(
						fmt.Sprintf("Invalid tool '%s'", tool),
						"Available tools: nmap, nikto, nuclei, masscan. Check with: zypheron tools list",
					))
					return fmt.Errorf("invalid tool '%s': %w. Available tools: nmap, nikto, nuclei, masscan", tool, err)
				}
			}

			if output != "" {
				if err := validation.ValidateFilePath(output); err != nil {
					return fmt.Errorf("invalid output path: %w", err)
				}
			}

			// Get target (from args or prompt)
			if len(args) > 0 {
				target = args[0]
			} else {
				if !interactive {
					fmt.Println(ui.ErrorWithSuggestion(
						"Target argument required",
						"Provide a target: zypheron scan <target>",
					))
					return fmt.Errorf("target argument required when running non-interactively. Examples: zypheron scan example.com or zypheron scan 192.168.1.1")
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
				fmt.Println(ui.ValidationError("target", err.Error(),
					"example.com",
					"192.168.1.1",
					"https://example.com",
					"10.0.0.0/24",
				))
				return fmt.Errorf("invalid target '%s': %w. Examples: example.com, 192.168.1.1, https://example.com", target, err)
			}

			// Print header
			fmt.Printf("\n%s\n", ui.Primary.Sprint("╔═══════════════════════════════════════╗"))
			fmt.Printf("%s\n", ui.Primary.Sprint("║  ZYPHERON SECURITY SCANNER           ║"))
			fmt.Printf("%s\n\n", ui.Primary.Sprint("╚═══════════════════════════════════════╝"))

			if _, err := printSecurityEnvironment(); err != nil {
				return err
			}

			// Detect tools
			fmt.Println(ui.InfoMsg("Detecting security tools..."))
			toolManager := kali.NewToolManager()
			if err := toolManager.DetectTools(); err != nil {
				return err
			}

			stats := toolManager.GetStats()
			fmt.Printf("  Found %s/%d tools installed\n", ui.Success.Sprint(stats.Installed), stats.Total)

			if stats.Missing > 0 {
				missingTools := toolManager.GetMissingTools()
				fmt.Printf("  Missing %d tools: ", stats.Missing)
				displayCount := 0
				for i, tool := range missingTools {
					if displayCount >= 5 {
						fmt.Printf(", %s", ui.Muted.Sprint(fmt.Sprintf("+%d more", len(missingTools)-5)))
						break
					}
					if i > 0 {
						fmt.Printf(", ")
					}
					if tool.Priority == "critical" {
						fmt.Printf("%s", ui.Danger.Sprint(tool.Name))
					} else if tool.Priority == "high" {
						fmt.Printf("%s", ui.Warning.Sprint(tool.Name))
					} else {
						fmt.Printf("%s", ui.Muted.Sprint(tool.Name))
					}
					displayCount++
				}
				fmt.Println()
				fmt.Printf("  %s\n", ui.Muted.Sprint("Run 'zypheron tools check' for full list and install commands"))
			}

			if stats.Critical > 0 {
				fmt.Println(ui.WarningMsg(fmt.Sprintf("%d critical tools are missing! Some features may not work.", stats.Critical)))
				// Show quick fix for critical missing tools
				var criticalTools []string
				for _, tool := range toolManager.GetMissingTools() {
					if tool.Priority == "critical" {
						criticalTools = append(criticalTools, tool.Name)
					}
				}
				if len(criticalTools) <= 3 {
					fmt.Printf("  %s %s\n", ui.InfoMsg("Quick fix:"),
						ui.Accent.Sprint(fmt.Sprintf("sudo apt-get install -y %s", strings.Join(criticalTools, " "))))
				}
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
				fmt.Println(ui.ErrorWithCommand(
					fmt.Sprintf("Tool '%s' is not installed", selectedTool),
					fmt.Sprintf("zypheron tools install %s", selectedTool),
				))

				// Suggest installation
				installCmd := toolManager.GetInstallCommand(selectedTool)
				fmt.Printf("\n%s\n", ui.InfoMsg(fmt.Sprintf("Install with: %s", installCmd)))
				fmt.Println(ui.InfoMsg(fmt.Sprintf("Or use: zypheron tools install %s", selectedTool)))

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
				Stream:     !noStream, // Streaming is default (on), --no-stream disables it
				Timeout:    time.Duration(timeout) * time.Second,
				AIAnalysis: aiAnalysis,
				AssumeYes:  assumeYes,
			}

			// Add tool-specific args
			switch selectedTool {
			case "nmap":
				opts.Args = buildNmapArgsWithProfile(target, ports, fast, full)
			case "nikto":
				// Nikto requires http:// or https:// prefix for domain names
				niktoTarget := buildNiktoTarget(target)
				opts.Args = []string{"-h", niktoTarget}
			case "masscan":
				opts.Args = []string{target, "-p", ports, "--rate", "1000"}
			case "nuclei":
				opts.Args = []string{"-u", target, "-json"}
			default:
				opts.Args = []string{target}
			}

			// Initialize checkpoint storage for scan resume support
			checkpointStore, checkpointErr := storage.NewCheckpointStorage()
			var checkpoint *storage.ScanCheckpoint
			if checkpointErr == nil {
				// Create checkpoint for this scan
				checkpoint = storage.CreateCheckpoint(target, selectedTool, ports, opts.Args, map[string]string{
					"fast":        fmt.Sprintf("%t", fast),
					"web":         fmt.Sprintf("%t", web),
					"full":        fmt.Sprintf("%t", full),
					"ai_guided":   fmt.Sprintf("%t", aiGuided),
					"ai_analysis": fmt.Sprintf("%t", aiAnalysis),
				})
				if err := checkpointStore.SaveCheckpoint(checkpoint); err != nil {
					fmt.Println(ui.Muted.Sprint(fmt.Sprintf("  Note: checkpoint saving disabled (%s)", err)))
					checkpoint = nil
				}
			}

			// Set up signal handler for graceful interruption
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			var interrupted atomic.Bool // Use atomic to avoid race condition

			// Execute scan
			top, bottom := ui.Box(selectedTool)
			fmt.Printf("\n%s\n", top)

			ctx, cancel := context.WithCancel(context.Background())
			if timeout > 0 {
				ctx, cancel = context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
			}

			// Handle interrupt in goroutine
			go func() {
				select {
				case <-sigChan:
					interrupted.Store(true)
					fmt.Println()
					fmt.Println(ui.WarningMsg("Scan interrupted - saving checkpoint..."))
					cancel()
				case <-ctx.Done():
					// Context cancelled normally
				}
			}()

			scanStartTime := time.Now()
			result, err := tools.Execute(ctx, opts)
			cancel() // Ensure context is cancelled
			signal.Stop(sigChan)

			// Handle interruption
			if interrupted.Load() && checkpoint != nil && checkpointStore != nil {
				checkpoint.MarkPaused()
				if result != nil {
					checkpoint.PartialOutput = result.Output
					checkpoint.Progress = estimateScanProgress(result.Output, selectedTool)
				}
				if saveErr := checkpointStore.SaveCheckpoint(checkpoint); saveErr != nil {
					fmt.Println(ui.WarningMsg(fmt.Sprintf("Failed to save checkpoint: %s", saveErr)))
				} else {
					fmt.Printf("\n%s\n", bottom)
					fmt.Println(ui.SuccessMsg("Checkpoint saved successfully"))
					fmt.Printf("  %s %s\n", ui.Muted.Sprint("Resume with:"), ui.Accent.Sprint("zypheron scan resume"))
					fmt.Printf("  %s %s\n", ui.Muted.Sprint("Checkpoint ID:"), ui.Muted.Sprint(checkpoint.ID))
				}
				return nil
			}

			if err != nil {
				// Mark checkpoint as failed
				if checkpoint != nil && checkpointStore != nil {
					checkpoint.MarkFailed(err.Error())
					if saveErr := checkpointStore.SaveCheckpoint(checkpoint); saveErr != nil {
						fmt.Println(ui.WarningMsg(fmt.Sprintf("Failed to save checkpoint: %s", saveErr)))
					}
				}
				fmt.Printf("\n%s\n", bottom)
				return fmt.Errorf("execution failed: %w", err)
			}

			// Mark checkpoint as completed
			if checkpoint != nil && checkpointStore != nil {
				checkpoint.MarkCompleted()
				checkpoint.PartialOutput = result.Output
				if saveErr := checkpointStore.SaveCheckpoint(checkpoint); saveErr != nil {
					fmt.Println(ui.WarningMsg(fmt.Sprintf("Failed to save checkpoint: %s", saveErr)))
				}
			}

			if result.Success {
				fmt.Printf("\n%s\n", ui.SuccessMsg(fmt.Sprintf("%s scan completed in %.2fs", selectedTool, result.Duration.Seconds())))

				// Parse and display structured results for nmap
				if selectedTool == "nmap" {
					parsed := tools.ParseNmapOutput(result.Output)
					if parsed != nil {
						displayParsedResults(parsed)
					}
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
						// Detect format from extension if not specified
						detectedFormat := format
						if format == "text" || format == "" {
							detectedFormat = reportpkg.DetectFormatFromExtension(output)
						}
						// Map format names
						if detectedFormat == "md" {
							detectedFormat = "markdown"
						}

						if err := saveReport(scanResult, output, detectedFormat); err != nil {
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

			// Save report if output specified and not already saved in AI analysis branch
			if output != "" && !aiAnalysis {
				// Detect format from extension if not specified
				detectedFormat := format
				if format == "text" || format == "" {
					detectedFormat = reportpkg.DetectFormatFromExtension(output)
				}
				// Map format names
				if detectedFormat == "md" {
					detectedFormat = "markdown"
				}

				if err := saveReport(scanResult, output, detectedFormat); err != nil {
					fmt.Println(ui.Error(fmt.Sprintf("Failed to save report: %s", err)))
				} else {
					fmt.Println(ui.SuccessMsg(fmt.Sprintf("Report saved to: %s", output)))
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&tool, "tool", "t", "", "Specific tool (nmap, nikto, nuclei, masscan)")
	// Register tool name completion
	cmd.RegisterFlagCompletionFunc("tool", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getToolCompletions(toComplete), cobra.ShellCompDirectiveNoFileComp
	})
	cmd.Flags().StringVarP(&ports, "ports", "p", "1-1000", "Port range")
	cmd.Flags().BoolVar(&web, "web", false, "Web application scanning")
	cmd.Flags().BoolVar(&full, "full", false, "Full pentest suite")
	cmd.Flags().BoolVar(&fast, "fast", false, "Quick scan")
	cmd.Flags().BoolVar(&noStream, "no-stream", false, "Disable output streaming (streaming is enabled by default)")
	cmd.Flags().BoolVar(&aiGuided, "ai-guided", false, "AI-guided scanning with ML predictions")
	cmd.Flags().BoolVar(&aiAnalysis, "ai-analysis", false, "AI-powered vulnerability analysis")
	cmd.Flags().IntVar(&timeout, "timeout", 300, "Timeout in seconds")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file")
	cmd.Flags().StringVar(&format, "format", "text", "Output format (text, json, html, markdown, pdf)")
	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "Assume yes for confirmation prompts (non-interactive mode)")
	cmd.Flags().BoolVar(&noInput, "no-input", false, "Disable interactive prompts (requires all arguments)")

	// Add subcommands for checkpoint management
	cmd.AddCommand(ScanResumeCmd())
	cmd.AddCommand(ScanCheckpointsCmd())

	return cmd
}

// Helper functions
// Note: Go 1.21+ has built-in min function

func saveReport(scanResult *types.ScanResult, filename string, format string) error {
	return reportpkg.GenerateReport(scanResult, format, filename)
}

// buildNmapArgs builds nmap arguments
func buildNmapArgs(target, ports string, fast bool) []string {
	return buildNmapArgsWithProfile(target, ports, fast, false)
}

func buildNmapArgsWithProfile(target, ports string, fast, full bool) []string {
	args := []string{"-sV", "-sC"}

	if full {
		args = append(args, "-A")
	}

	if ports != "" {
		if full && ports == "1-65535" {
			args = append(args, "-p-")
		} else {
			args = append(args, "-p", ports)
		}
	}

	if fast {
		args = append(args, "-T4")
	}

	// Add stats every 2s for progress bar parsing
	args = append(args, "--stats-every", "2s")

	args = append(args, target)
	return args
}

// buildNiktoTarget prepares the target for nikto
// Nikto expects http:// or https:// prefix for domain names
func buildNiktoTarget(target string) string {
	// If already has a protocol, use as-is
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}

	// If it's an IP address, use as-is (nikto handles IPs fine without protocol)
	if ip := net.ParseIP(target); ip != nil {
		return target
	}

	// For domain names, try HTTPS first (more secure default)
	// Nikto will automatically try HTTP if HTTPS fails
	// But we need to provide a valid starting point
	return "http://" + target
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

// getToolCompletions returns tool name completions for shell completion
func getToolCompletions(prefix string) []string {
	// Available security tools with descriptions for completion
	tools := []string{
		"nmap\tNetwork scanner and port discovery",
		"nikto\tWeb server vulnerability scanner",
		"nuclei\tFast vulnerability scanner with templates",
		"masscan\tFast TCP port scanner",
		"sqlmap\tAutomatic SQL injection tool",
		"gobuster\tDirectory and DNS busting tool",
		"ffuf\tFast web fuzzer",
		"hydra\tNetwork login cracker",
		"subfinder\tSubdomain discovery tool",
		"amass\tIn-depth DNS enumeration",
	}

	// Filter by prefix if provided
	if prefix == "" {
		return tools
	}

	filtered := []string{}
	for _, tool := range tools {
		// Tool name is before the tab character
		parts := strings.Split(tool, "\t")
		if len(parts) > 0 && strings.HasPrefix(parts[0], prefix) {
			filtered = append(filtered, tool)
		}
	}
	return filtered
}

// estimateScanProgress estimates scan progress based on output (tool-specific heuristics)
func estimateScanProgress(output string, tool string) float64 {
	lines := strings.Count(output, "\n")

	switch tool {
	case "nmap":
		// Look for nmap progress indicators
		if strings.Contains(output, "Nmap done") {
			return 100
		}
		// Estimate based on typical scan phases
		if strings.Contains(output, "PORT") && strings.Contains(output, "STATE") {
			return 60
		}
		if strings.Contains(output, "Host is up") {
			return 30
		}
		if strings.Contains(output, "Starting Nmap") {
			return 10
		}
	case "nikto":
		// Nikto progress estimation
		if strings.Contains(output, "End Time:") {
			return 100
		}
		// Count test items completed
		testCount := strings.Count(output, "+ ")
		if testCount > 0 {
			// Rough estimate based on typical nikto tests (~6000 tests)
			progress := float64(testCount) / 60
			if progress > 90 {
				progress = 90
			}
			return progress
		}
	case "nuclei":
		if strings.Contains(output, "Templates") && strings.Contains(output, "matched") {
			return 100
		}
		// Count findings
		findingCount := strings.Count(output, `"matched-at"`)
		if findingCount > 0 {
			progress := float64(findingCount)*5 + 20
			if progress > 90 {
				progress = 90
			}
			return progress
		}
	case "masscan":
		if strings.Contains(output, "Quitting") {
			return 100
		}
		// Count discovered ports
		portCount := strings.Count(output, "Discovered open port")
		if portCount > 0 {
			progress := float64(portCount)*10 + 20
			if progress > 90 {
				progress = 90
			}
			return progress
		}
	}

	// Default: rough estimate based on output size
	if lines > 200 {
		return 80
	} else if lines > 100 {
		return 60
	} else if lines > 50 {
		return 40
	} else if lines > 10 {
		return 20
	}
	return 5
}
