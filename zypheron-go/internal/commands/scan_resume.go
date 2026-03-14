package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/storage"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tools"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

// ScanResumeCmd returns the scan resume subcommand
func ScanResumeCmd() *cobra.Command {
	var (
		checkpointID string
		force        bool
	)

	cmd := &cobra.Command{
		Use:   "resume [checkpoint-id]",
		Short: "Resume an interrupted scan from checkpoint",
		Long: `Resume a previously interrupted scan from its saved checkpoint.

When a scan is interrupted (Ctrl+C) or fails, Zypheron automatically saves
a checkpoint with the scan's progress. Use this command to resume from
where the scan left off.

Examples:
  zypheron scan resume                     # Interactive: select from available checkpoints
  zypheron scan resume cp-nmap-example-... # Resume specific checkpoint
  zypheron scan resume --force             # Resume without confirmation`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			checkpointStore, err := storage.NewCheckpointStorage()
			if err != nil {
				return fmt.Errorf("failed to initialize checkpoint storage: %w", err)
			}

			// Get checkpoint ID from args or prompt
			if len(args) > 0 {
				checkpointID = args[0]
			}

			if checkpointID == "" {
				// Show list of resumable checkpoints
				resumable, err := checkpointStore.GetResumableCheckpoints()
				if err != nil {
					return fmt.Errorf("failed to get checkpoints: %w", err)
				}

				if len(resumable) == 0 {
					fmt.Println(ui.InfoMsg("No resumable checkpoints found"))
					fmt.Println(ui.Muted.Sprint("Checkpoints are created when scans are interrupted (Ctrl+C)"))
					return nil
				}

				// Build selection options
				options := make([]string, len(resumable))
				for i, cp := range resumable {
					elapsed := cp.ElapsedTime().Round(time.Second)
					options[i] = fmt.Sprintf("%s | %s | %s | %.0f%% | %s ago",
						cp.ID[:min(30, len(cp.ID))],
						cp.Tool,
						cp.Target,
						cp.Progress,
						elapsed)
				}

				prompt := &survey.Select{
					Message: "Select checkpoint to resume:",
					Options: options,
				}

				var selected int
				if err := survey.AskOne(prompt, &selected); err != nil {
					if errors.Is(err, terminal.InterruptErr) {
						return nil
					}
					return err
				}

				checkpointID = resumable[selected].ID
			}

			// Load checkpoint
			checkpoint, err := checkpointStore.LoadCheckpoint(checkpointID)
			if err != nil {
				return fmt.Errorf("failed to load checkpoint: %w", err)
			}

			if !checkpoint.IsResumable() {
				return fmt.Errorf("checkpoint %s is not resumable (status: %s)", checkpointID, checkpoint.Status)
			}

			// Show checkpoint details
			fmt.Printf("\n%s\n", ui.Primary.Sprint("╔═══════════════════════════════════════╗"))
			fmt.Printf("%s\n", ui.Primary.Sprint("║       RESUMING SCAN FROM CHECKPOINT   ║"))
			fmt.Printf("%s\n\n", ui.Primary.Sprint("╚═══════════════════════════════════════╝"))

			fmt.Printf("  %s %s\n", ui.Muted.Sprint("Checkpoint:"), ui.Accent.Sprint(checkpoint.ID))
			fmt.Printf("  %s %s\n", ui.Muted.Sprint("Target:"), ui.Accent.Sprint(checkpoint.Target))
			fmt.Printf("  %s %s\n", ui.Muted.Sprint("Tool:"), ui.Accent.Sprint(checkpoint.Tool))
			fmt.Printf("  %s %.1f%%\n", ui.Muted.Sprint("Progress:"), checkpoint.Progress)
			fmt.Printf("  %s %s\n", ui.Muted.Sprint("Started:"), checkpoint.StartTime.Format("2006-01-02 15:04:05"))
			fmt.Printf("  %s %s\n", ui.Muted.Sprint("Elapsed:"), checkpoint.ElapsedTime().Round(time.Second))

			if len(checkpoint.PartialOutput) > 0 {
				lines := strings.Count(checkpoint.PartialOutput, "\n")
				fmt.Printf("  %s %d lines captured\n", ui.Muted.Sprint("Output:"), lines)
			}
			fmt.Println()

			// Confirm resume
			if !force {
				confirm := false
				confirmPrompt := &survey.Confirm{
					Message: "Resume this scan?",
					Default: true,
				}
				if err := survey.AskOne(confirmPrompt, &confirm); err != nil {
					if errors.Is(err, terminal.InterruptErr) {
						return nil
					}
					return err
				}
				if !confirm {
					fmt.Println(ui.InfoMsg("Resume cancelled"))
					return nil
				}
			}

			// Execute the resumed scan
			return executeResume(checkpoint, checkpointStore)
		},
	}

	cmd.Flags().StringVar(&checkpointID, "id", "", "Checkpoint ID to resume")
	cmd.Flags().BoolVar(&force, "force", false, "Resume without confirmation")

	return cmd
}

// ScanCheckpointsCmd returns the scan checkpoints subcommand for listing/managing checkpoints
func ScanCheckpointsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "checkpoints",
		Short: "List and manage scan checkpoints",
		Long: `View and manage saved scan checkpoints.

Checkpoints are automatically created when scans are interrupted or paused.
Use this command to list available checkpoints or clean up old ones.

Examples:
  zypheron scan checkpoints              # List all checkpoints
  zypheron scan checkpoints list         # Same as above
  zypheron scan checkpoints clean        # Remove old completed checkpoints
  zypheron scan checkpoints delete <id>  # Delete specific checkpoint`,
	}

	cmd.AddCommand(scanCheckpointsListCmd())
	cmd.AddCommand(scanCheckpointsCleanCmd())
	cmd.AddCommand(scanCheckpointsDeleteCmd())

	// Default to list if no subcommand
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return listCheckpoints()
	}

	return cmd
}

func scanCheckpointsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all checkpoints",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listCheckpoints()
		},
	}
}

func scanCheckpointsCleanCmd() *cobra.Command {
	var maxAgeDays int

	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Remove old completed checkpoints",
		RunE: func(cmd *cobra.Command, args []string) error {
			checkpointStore, err := storage.NewCheckpointStorage()
			if err != nil {
				return err
			}

			maxAge := time.Duration(maxAgeDays) * 24 * time.Hour
			cleaned, err := checkpointStore.CleanupOldCheckpoints(maxAge)
			if err != nil {
				return err
			}

			if cleaned > 0 {
				fmt.Println(ui.SuccessMsg(fmt.Sprintf("Cleaned up %d old checkpoint(s)", cleaned)))
			} else {
				fmt.Println(ui.InfoMsg("No old checkpoints to clean up"))
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&maxAgeDays, "older-than", 7, "Remove checkpoints older than N days")
	return cmd
}

func scanCheckpointsDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <checkpoint-id>",
		Short: "Delete a specific checkpoint",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			checkpointStore, err := storage.NewCheckpointStorage()
			if err != nil {
				return err
			}

			if err := checkpointStore.DeleteCheckpoint(args[0]); err != nil {
				return err
			}

			fmt.Println(ui.SuccessMsg(fmt.Sprintf("Deleted checkpoint: %s", args[0])))
			return nil
		},
	}
}

func listCheckpoints() error {
	checkpointStore, err := storage.NewCheckpointStorage()
	if err != nil {
		return err
	}

	checkpoints, err := checkpointStore.ListCheckpoints()
	if err != nil {
		return err
	}

	if len(checkpoints) == 0 {
		fmt.Println(ui.InfoMsg("No checkpoints found"))
		fmt.Println(ui.Muted.Sprint("Checkpoints are created when scans are interrupted (Ctrl+C)"))
		return nil
	}

	fmt.Printf("\n%s\n\n", ui.Primary.Sprint("Scan Checkpoints"))

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Tool", "Target", "Status", "Progress", "Last Update"})
	table.SetBorder(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetColumnSeparator("  ")

	for _, cp := range checkpoints {
		// Color status
		var statusStr string
		switch cp.Status {
		case storage.CheckpointStatusRunning:
			statusStr = ui.Warning.Sprint("running")
		case storage.CheckpointStatusPaused:
			statusStr = ui.Info.Sprint("paused")
		case storage.CheckpointStatusCompleted:
			statusStr = ui.Success.Sprint("completed")
		case storage.CheckpointStatusFailed:
			statusStr = ui.Danger.Sprint("failed")
		default:
			statusStr = string(cp.Status)
		}

		// Truncate ID and target for display
		displayID := cp.ID
		if len(displayID) > 25 {
			displayID = displayID[:22] + "..."
		}
		displayTarget := cp.Target
		if len(displayTarget) > 20 {
			displayTarget = displayTarget[:17] + "..."
		}

		table.Append([]string{
			displayID,
			cp.Tool,
			displayTarget,
			statusStr,
			fmt.Sprintf("%.0f%%", cp.Progress),
			cp.LastUpdate.Format("01/02 15:04"),
		})
	}

	table.Render()
	fmt.Println()

	// Show hint for resumable checkpoints
	resumable, _ := checkpointStore.GetResumableCheckpoints()
	if len(resumable) > 0 {
		fmt.Printf("%s %s\n\n",
			ui.InfoMsg("Tip:"),
			ui.Muted.Sprint("Run 'zypheron scan resume' to continue an interrupted scan"))
	}

	return nil
}

// executeResume executes a scan from a checkpoint
func executeResume(checkpoint *storage.ScanCheckpoint, checkpointStore *storage.CheckpointStorage) error {
	// Set up signal handler for graceful interruption
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	// Update checkpoint status to running
	checkpoint.Status = storage.CheckpointStatusRunning
	if err := checkpointStore.SaveCheckpoint(checkpoint); err != nil {
		fmt.Println(ui.WarningMsg(fmt.Sprintf("Failed to update checkpoint: %s", err)))
	}

	// Build execution options
	opts := tools.ExecutionOptions{
		Tool:    checkpoint.Tool,
		Target:  checkpoint.Target,
		Args:    checkpoint.Args,
		Stream:  true,
		Timeout: 0, // No timeout for resumed scans by default
	}

	// For nmap, check if we can use native resume
	if checkpoint.Tool == "nmap" && checkpoint.NmapResumeFile != "" {
		// Check if the resume file exists
		if _, err := os.Stat(checkpoint.NmapResumeFile); err == nil {
			fmt.Println(ui.InfoMsg("Using nmap's native --resume feature"))
			opts.Args = []string{"--resume", checkpoint.NmapResumeFile}
		}
	}

	// Execute with interrupt handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt
	go func() {
		<-sigChan
		fmt.Println()
		fmt.Println(ui.WarningMsg("Scan interrupted - saving checkpoint..."))
		cancel()
	}()

	// Execute scan
	top, bottom := ui.Box(checkpoint.Tool + " (resumed)")
	fmt.Printf("\n%s\n", top)

	result, err := tools.Execute(ctx, opts)

	fmt.Printf("\n%s\n\n", bottom)

	// Handle result
	if ctx.Err() == context.Canceled {
		// Save checkpoint on interrupt
		checkpoint.MarkPaused()
		if result != nil {
			// Append new output to existing
			checkpoint.PartialOutput += result.Output
			checkpoint.Progress = estimateProgress(result.Output, checkpoint.Tool)
		}
		if err := checkpointStore.SaveCheckpoint(checkpoint); err != nil {
			return fmt.Errorf("failed to save checkpoint: %w", err)
		}
		fmt.Println(ui.SuccessMsg("Checkpoint saved. Resume with: zypheron scan resume"))
		return nil
	}

	if err != nil {
		checkpoint.MarkFailed(err.Error())
		if saveErr := checkpointStore.SaveCheckpoint(checkpoint); saveErr != nil {
			fmt.Println(ui.WarningMsg(fmt.Sprintf("Failed to save checkpoint: %s", saveErr)))
		}
		return fmt.Errorf("scan failed: %w", err)
	}

	// Mark completed
	checkpoint.MarkCompleted()
	checkpoint.PartialOutput += result.Output
	if err := checkpointStore.SaveCheckpoint(checkpoint); err != nil {
		fmt.Println(ui.WarningMsg(fmt.Sprintf("Failed to update checkpoint: %s", err)))
	}

	if result.Success {
		fmt.Println(ui.SuccessMsg(fmt.Sprintf("Resumed scan completed in %.2fs", result.Duration.Seconds())))
	} else {
		fmt.Println(ui.Error(fmt.Sprintf("Scan failed: %s", result.Error)))
	}

	return nil
}

// estimateProgress estimates scan progress based on output (tool-specific heuristics)
func estimateProgress(output string, tool string) float64 {
	lines := strings.Count(output, "\n")

	switch tool {
	case "nmap":
		// Look for nmap progress indicators
		if strings.Contains(output, "Nmap done") {
			return 100
		}
		// Estimate based on typical scan phases
		if strings.Contains(output, "PORT") {
			return 50
		}
		if strings.Contains(output, "Starting Nmap") {
			return 10
		}
	case "nikto":
		// Nikto progress estimation
		if strings.Contains(output, "End Time:") {
			return 100
		}
		// Rough estimate based on lines
		progress := float64(lines) / 100 * 10
		if progress > 90 {
			progress = 90
		}
		return progress
	case "nuclei":
		if strings.Contains(output, "Templates") && strings.Contains(output, "matched") {
			return 100
		}
	}

	// Default: rough estimate based on output size
	if lines > 100 {
		return 80
	} else if lines > 50 {
		return 50
	} else if lines > 10 {
		return 25
	}
	return 10
}
