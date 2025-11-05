package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/kali"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/storage"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tools"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/validation"
	"github.com/KKingZero/Cobra-AI/zypheron-go/pkg/types"
	"github.com/spf13/cobra"
)

// ReverseEngCmd returns the reverse engineering command
func ReverseEngCmd() *cobra.Command {
	var (
		tool       string
		chain      string
		stream     bool
		timeout    int
		output     string
		assumeYes  bool
		noInput    bool
	)

	cmd := &cobra.Command{
		Use:   "reverse-eng [binary]",
		Short: "Reverse engineering analysis of binaries",
		Long:  "Perform reverse engineering analysis using tools like radare2, ghidra, gdb, and objdump",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var targetBinary string
			interactive := isInteractive(cmd) && !noInput

			// Get target binary (from args or prompt)
			if len(args) > 0 {
				targetBinary = args[0]
			} else {
				if !interactive {
					return fmt.Errorf("binary argument required when running non-interactively")
				}
				prompt := &survey.Input{
					Message: "Enter binary path:",
				}
				if err := survey.AskOne(prompt, &targetBinary, survey.WithValidator(survey.Required)); err != nil {
					if errors.Is(err, terminal.InterruptErr) {
						return fmt.Errorf("binary prompt interrupted")
					}
					return err
				}
			}

			// Validate binary exists
			if _, err := os.Stat(targetBinary); os.IsNotExist(err) {
				return fmt.Errorf("binary file does not exist: %s", targetBinary)
			}

			// Validate tool name if provided
			if tool != "" {
				if err := validation.ValidateToolName(tool); err != nil {
					return fmt.Errorf("invalid tool: %w", err)
				}
			}

			// Print header
			fmt.Printf("\n%s\n", ui.Primary.Sprint("╔═══════════════════════════════════════╗"))
			fmt.Printf("%s\n", ui.Primary.Sprint("║  ZYPHERON REVERSE ENGINEERING        ║"))
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

			// Detect tools
			fmt.Println(ui.InfoMsg("Detecting reverse engineering tools..."))
			toolManager := kali.NewToolManager()
			if err := toolManager.DetectTools(); err != nil {
				return err
			}

			stats := toolManager.GetStats()
			fmt.Printf("  Found %s/%d tools installed\n", ui.Success.Sprint(stats.Installed), stats.Total)

			// Load tool chain configuration
			chainConfig, err := loadToolChainConfig()
			if err != nil {
				fmt.Println(ui.WarningMsg(fmt.Sprintf("Failed to load tool chain config: %s", err)))
				chainConfig = config.GetDefaultToolChains()
			}

			// Determine which tool to use
			selectedTool := tool
			if selectedTool == "" {
				if chain != "" {
					// Use tool chain
					chainTools := chainConfig.GetToolChain(chain)
					if len(chainTools) == 0 {
						return fmt.Errorf("unknown chain: %s", chain)
					}
					// Use first tool in chain
					selectedTool = chainTools[0].Tool
				} else {
					selectedTool = "file" // Default
				}
			}

			// Check if tool is available
			if !toolManager.IsInstalled(selectedTool) {
				fmt.Println(ui.Error(fmt.Sprintf("Tool '%s' is not installed", selectedTool)))
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

			// Show analysis configuration
			fmt.Printf("\n%s\n", ui.InfoMsg("Analysis Configuration:"))
			fmt.Println(ui.Separator(60))
			fmt.Printf("  Binary:   %s\n", ui.Accent.Sprint(targetBinary))
			fmt.Printf("  Tool:     %s\n", ui.Accent.Sprint(selectedTool))
			fmt.Printf("  Timeout:  %s\n", ui.Accent.Sprint(fmt.Sprintf("%ds", timeout)))
			if chain != "" {
				fmt.Printf("  Chain:    %s\n", ui.Accent.Sprint(chain))
			}
			fmt.Println(ui.Separator(60))
			fmt.Println()

			// Confirm analysis
			confirm := true
			if assumeYes || !interactive {
				confirm = true
			} else {
				confirmPrompt := &survey.Confirm{
					Message: "Start reverse engineering analysis?",
					Default: true,
				}
				if err := survey.AskOne(confirmPrompt, &confirm); err != nil {
					if errors.Is(err, terminal.InterruptErr) {
						fmt.Println(ui.InfoMsg("Analysis cancelled"))
						return nil
					}
					return err
				}
			}

			if !confirm {
				fmt.Println(ui.InfoMsg("Analysis cancelled"))
				return nil
			}

			// Build execution options
			opts := tools.ExecutionOptions{
				Tool:    selectedTool,
				Target:  targetBinary,
				Stream:  stream,
				Timeout: time.Duration(timeout) * time.Second,
				AssumeYes: assumeYes,
			}

			// Add tool-specific args
			opts.Args = buildReverseEngArgs(selectedTool, targetBinary)

			// Execute analysis
			top, bottom := ui.Box(selectedTool)
			fmt.Printf("\n%s\n", top)

			ctx := context.Background()
			analysisStartTime := time.Now()
			result, err := tools.Execute(ctx, opts)
			if err != nil {
				fmt.Printf("\n%s\n", bottom)
				return fmt.Errorf("execution failed: %w", err)
			}

			if result.Success {
				fmt.Printf("\n%s\n", ui.SuccessMsg(fmt.Sprintf("%s analysis completed in %.2fs", selectedTool, result.Duration.Seconds())))
			} else {
				fmt.Printf("\n%s\n", ui.Error(fmt.Sprintf("Analysis failed: %s", result.Error)))
			}

			fmt.Printf("%s\n\n", bottom)

			// Save analysis to storage
			scanStore, err := storage.NewScanStorage()
			if err != nil {
				fmt.Println(ui.WarningMsg(fmt.Sprintf("Failed to initialize scan storage: %s", err)))
			} else {
				scanID := storage.GenerateScanID(targetBinary, selectedTool)
				scanResult := &types.ScanResult{
					ID:         scanID,
					Timestamp:  analysisStartTime,
					Target:     targetBinary,
					Tool:       selectedTool,
					Output:     result.Output,
					Duration:   result.Duration.Seconds(),
					Success:    result.Success,
					ErrorMessage: result.Error,
					Metadata: map[string]string{
						"type": "reverse-engineering",
						"chain": chain,
					},
				}

				if err := scanStore.SaveScan(scanResult); err != nil {
					fmt.Println(ui.WarningMsg(fmt.Sprintf("Failed to save analysis: %s", err)))
				} else {
					fmt.Println(ui.Muted.Sprint(fmt.Sprintf("Analysis saved: %s", scanID)))
				}
			}

			// Save output if requested
			if output != "" {
				if err := os.WriteFile(output, []byte(result.Output), 0644); err != nil {
					fmt.Println(ui.Error(fmt.Sprintf("Failed to save output: %s", err)))
				} else {
					fmt.Println(ui.SuccessMsg(fmt.Sprintf("Output saved to: %s", output)))
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&tool, "tool", "t", "", "Specific tool (file, strings, objdump, readelf, radare2, gdb, ghidra)")
	cmd.Flags().StringVarP(&chain, "chain", "c", "", "Use tool chain (reverse_engineering)")
	cmd.Flags().BoolVar(&stream, "stream", true, "Stream output")
	cmd.Flags().IntVar(&timeout, "timeout", 600, "Timeout in seconds")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file")
	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "Assume yes for confirmation prompts")
	cmd.Flags().BoolVar(&noInput, "no-input", false, "Disable interactive prompts")

	return cmd
}

// loadToolChainConfig loads tool chain configuration
func loadToolChainConfig() (*config.ToolChainConfig, error) {
	configPath := config.GetConfigPath()
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Return default config if file doesn't exist
		return config.GetDefaultToolChains(), nil
	}
	return config.LoadToolChains(configPath)
}

// buildReverseEngArgs builds arguments for reverse engineering tools
func buildReverseEngArgs(tool, binary string) []string {
	var args []string

	switch tool {
	case "file":
		args = []string{binary}
	case "strings":
		args = []string{binary}
	case "objdump":
		args = []string{"-d", "-h", binary}
	case "readelf":
		args = []string{"-h", "-S", binary}
	case "radare2":
		args = []string{"-A", "-a", binary}
	case "gdb":
		args = []string{"--batch", "--ex", "disassemble main", binary}
	case "ghidra":
		args = []string{binary}
	default:
		args = []string{binary}
	}

	return args
}

