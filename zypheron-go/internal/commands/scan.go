package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
	"github.com/yourusername/zypheron/internal/kali"
	"github.com/yourusername/zypheron/internal/tools"
	"github.com/yourusername/zypheron/internal/ui"
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
	)

	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "Security scanning with Kali tools (nmap, nikto, nuclei)",
		Long:  "Perform security scans using integrated Kali Linux tools with real-time output streaming",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var target string

			// Get target (from args or prompt)
			if len(args) > 0 {
				target = args[0]
			} else {
				prompt := &survey.Input{
					Message: "Enter target (URL, IP, or hostname):",
				}
				if err := survey.AskOne(prompt, &target, survey.WithValidator(survey.Required)); err != nil {
					return err
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

				confirm := false
				prompt := &survey.Confirm{
					Message: "Install now?",
				}
				if err := survey.AskOne(prompt, &confirm); err != nil {
					return err
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
			confirmPrompt := &survey.Confirm{
				Message: "Start security scan?",
				Default: true,
			}
			if err := survey.AskOne(confirmPrompt, &confirm); err != nil {
				return err
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

			// AI Analysis
			if aiAnalysis && result.Success {
				fmt.Println(ui.Accent.Sprint("🤖 AI Analysis:"))
				fmt.Println(ui.InfoMsg("AI analysis would integrate with your backend API here"))
				fmt.Println(ui.Muted.Sprint("  (Connect to your existing TypeScript backend for AI insights)"))
				fmt.Println()
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
	cmd.Flags().BoolVar(&aiGuided, "ai-guided", false, "AI-guided scanning")
	cmd.Flags().BoolVar(&aiAnalysis, "ai-analysis", false, "AI analysis")
	cmd.Flags().IntVar(&timeout, "timeout", 300, "Timeout in seconds")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file")
	cmd.Flags().StringVar(&format, "format", "text", "Output format (text, json, xml)")

	return cmd
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

