package commands

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/scheduler"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tools"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/validation"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

// ScheduleCmd returns the schedule command
func ScheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "schedule",
		Aliases: []string{"sched"},
		Short:   "Manage scheduled scans",
		Long: `Manage scheduled security scans with cron-like scheduling.

Schedule scans to run automatically at specified intervals using cron expressions.

Examples:
  zypheron schedule create --name "Daily Scan" --target 192.168.1.0/24 --cron "0 2 * * *" --tools nmap
  zypheron schedule list
  zypheron schedule show <id>
  zypheron schedule delete <id>
  zypheron schedule enable <id>
  zypheron schedule disable <id>
  zypheron schedule run

Cron Expression Format:
  * * * * *
  │ │ │ │ │
  │ │ │ │ └─── Day of week (0-6, Sunday=0)
  │ │ │ └───── Month (1-12)
  │ │ └─────── Day of month (1-31)
  │ └───────── Hour (0-23)
  └─────────── Minute (0-59)

Common Patterns:
  "0 2 * * *"      - Every day at 2:00 AM
  "*/15 * * * *"   - Every 15 minutes
  "0 0 * * 0"      - Every Sunday at midnight
  "30 3 1 * *"     - First day of month at 3:30 AM
  "0 */6 * * *"    - Every 6 hours`,
	}

	cmd.AddCommand(scheduleCreateCmd())
	cmd.AddCommand(scheduleListCmd())
	cmd.AddCommand(scheduleShowCmd())
	cmd.AddCommand(scheduleDeleteCmd())
	cmd.AddCommand(scheduleEnableCmd())
	cmd.AddCommand(scheduleDisableCmd())
	cmd.AddCommand(scheduleRunCmd())

	return cmd
}

// scheduleCreateCmd creates a new scheduled scan
func scheduleCreateCmd() *cobra.Command {
	var (
		name     string
		target   string
		tools    string
		cronExpr string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new scheduled scan",
		Long: `Create a new scheduled scan that runs automatically.

Examples:
  zypheron schedule create --name "Daily Network Scan" --target 192.168.1.0/24 --cron "0 2 * * *" --tools nmap
  zypheron schedule create --name "Hourly Web Scan" --target https://example.com --cron "0 * * * *" --tools nikto
  zypheron schedule create --name "Weekly Full Scan" --target example.com --cron "0 0 * * 0" --tools nmap,nikto,nuclei`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate required flags
			if name == "" {
				return fmt.Errorf("scan name is required (--name)")
			}
			if target == "" {
				return fmt.Errorf("target is required (--target)")
			}
			if tools == "" {
				return fmt.Errorf("tools are required (--tools)")
			}
			if cronExpr == "" {
				return fmt.Errorf("cron expression is required (--cron)")
			}

			// Validate target
			if err := validation.ValidateTarget(target); err != nil {
				return fmt.Errorf("invalid target: %w", err)
			}

			// Validate cron expression
			if err := scheduler.ValidateCronExpression(cronExpr); err != nil {
				return fmt.Errorf("invalid cron expression: %w", err)
			}

			// Validate tools
			toolList := strings.Split(tools, ",")
			for _, tool := range toolList {
				tool = strings.TrimSpace(tool)
				if err := validation.ValidateToolName(tool); err != nil {
					return fmt.Errorf("invalid tool '%s': %w", tool, err)
				}
			}

			// Create scheduler
			s, err := scheduler.NewScheduler(scheduler.DefaultDBPath)
			if err != nil {
				return fmt.Errorf("failed to initialize scheduler: %w", err)
			}
			defer s.Close()

			// Generate ID
			scanID := generateScanID(name)

			// Create scan
			scan := scheduler.ScheduledScan{
				ID:       scanID,
				Name:     name,
				Target:   target,
				Tools:    tools,
				CronExpr: cronExpr,
				Enabled:  true,
			}

			if err := s.CreateScan(scan); err != nil {
				return fmt.Errorf("failed to create scheduled scan: %w", err)
			}

			// Get the created scan to show next run time
			created, err := s.GetScan(scanID)
			if err != nil {
				return fmt.Errorf("failed to retrieve created scan: %w", err)
			}

			// Display success message
			fmt.Printf("\n%s\n", ui.SuccessMsg("Scheduled scan created successfully"))
			fmt.Println()
			fmt.Printf("  ID:          %s\n", ui.Accent.Sprint(created.ID))
			fmt.Printf("  Name:        %s\n", ui.Primary.Sprint(created.Name))
			fmt.Printf("  Target:      %s\n", created.Target)
			fmt.Printf("  Tools:       %s\n", created.Tools)
			fmt.Printf("  Schedule:    %s\n", created.CronExpr)
			fmt.Printf("  Description: %s\n", ui.Muted.Sprint(scheduler.GetCronDescription(created.CronExpr)))
			fmt.Printf("  Next Run:    %s\n", ui.Info.Sprint(created.NextRun.Format("2006-01-02 15:04:05")))
			fmt.Printf("  Status:      %s\n", ui.Success.Sprint("Enabled"))
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", "Scan name (required)")
	cmd.Flags().StringVarP(&target, "target", "t", "", "Target to scan (required)")
	cmd.Flags().StringVar(&tools, "tools", "", "Comma-separated list of tools (required)")
	cmd.Flags().StringVar(&cronExpr, "cron", "", "Cron expression (required)")

	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("target")
	cmd.MarkFlagRequired("tools")
	cmd.MarkFlagRequired("cron")

	return cmd
}

// scheduleListCmd lists all scheduled scans
func scheduleListCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all scheduled scans",
		Long: `List all scheduled scans with their status and next run times.

Examples:
  zypheron schedule list
  zypheron schedule list --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Create scheduler
			s, err := scheduler.NewScheduler(scheduler.DefaultDBPath)
			if err != nil {
				return fmt.Errorf("failed to initialize scheduler: %w", err)
			}
			defer s.Close()

			// List scans
			scans, err := s.ListScans()
			if err != nil {
				return fmt.Errorf("failed to list scans: %w", err)
			}

			if len(scans) == 0 {
				fmt.Println(ui.InfoMsg("No scheduled scans found"))
				fmt.Println()
				fmt.Println(ui.Muted.Sprint("Create a scan with: zypheron schedule create --name \"My Scan\" --target <target> --cron \"0 2 * * *\" --tools nmap"))
				return nil
			}

			if jsonOutput {
				return displayScansJSON(scans)
			}

			// Display as table
			fmt.Printf("\n%s\n", ui.Primary.Sprint("Scheduled Scans"))
			fmt.Println(ui.Separator(100))
			fmt.Println()

			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"ID", "Name", "Target", "Tools", "Schedule", "Next Run", "Status"})
			table.SetBorder(false)
			table.SetHeaderColor(
				tablewriter.Colors{tablewriter.FgHiCyanColor},
				tablewriter.Colors{tablewriter.FgHiCyanColor},
				tablewriter.Colors{tablewriter.FgHiCyanColor},
				tablewriter.Colors{tablewriter.FgHiCyanColor},
				tablewriter.Colors{tablewriter.FgHiCyanColor},
				tablewriter.Colors{tablewriter.FgHiCyanColor},
				tablewriter.Colors{tablewriter.FgHiCyanColor},
			)

			for _, scan := range scans {
				status := "Disabled"
				if scan.Enabled {
					status = "Enabled"
				}

				// Format next run time
				nextRun := scan.NextRun.Format("2006-01-02 15:04")
				if scan.NextRun.Before(time.Now()) {
					nextRun += " (due)"
				}

				table.Append([]string{
					scan.ID,
					scan.Name,
					truncate(scan.Target, 30),
					truncate(scan.Tools, 20),
					scan.CronExpr,
					nextRun,
					status,
				})
			}

			table.Render()
			fmt.Println()
			fmt.Printf("Total: %s scans\n", ui.Accent.Sprint(len(scans)))
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")

	return cmd
}

// scheduleShowCmd shows details of a specific scheduled scan
func scheduleShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show details of a scheduled scan",
		Long: `Show detailed information about a specific scheduled scan.

Examples:
  zypheron schedule show daily-scan-123`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanID := args[0]

			// Create scheduler
			s, err := scheduler.NewScheduler(scheduler.DefaultDBPath)
			if err != nil {
				return fmt.Errorf("failed to initialize scheduler: %w", err)
			}
			defer s.Close()

			// Get scan
			scan, err := s.GetScan(scanID)
			if err != nil {
				return fmt.Errorf("failed to get scan: %w", err)
			}

			// Display scan details
			fmt.Printf("\n%s\n", ui.Primary.Sprint("Scheduled Scan Details"))
			fmt.Println(ui.Separator(60))
			fmt.Println()
			fmt.Printf("  ID:          %s\n", ui.Accent.Sprint(scan.ID))
			fmt.Printf("  Name:        %s\n", ui.Primary.Sprint(scan.Name))
			fmt.Printf("  Target:      %s\n", scan.Target)
			fmt.Printf("  Tools:       %s\n", scan.Tools)
			fmt.Printf("  Schedule:    %s\n", scan.CronExpr)
			fmt.Printf("  Description: %s\n", ui.Muted.Sprint(scheduler.GetCronDescription(scan.CronExpr)))
			fmt.Println()

			status := ui.Danger.Sprint("Disabled")
			if scan.Enabled {
				status = ui.Success.Sprint("Enabled")
			}
			fmt.Printf("  Status:      %s\n", status)
			fmt.Printf("  Created:     %s\n", scan.CreatedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Next Run:    %s\n", ui.Info.Sprint(scan.NextRun.Format("2006-01-02 15:04:05")))

			if !scan.LastRun.IsZero() {
				fmt.Printf("  Last Run:    %s\n", scan.LastRun.Format("2006-01-02 15:04:05"))
			} else {
				fmt.Printf("  Last Run:    %s\n", ui.Muted.Sprint("Never"))
			}

			// Check if due
			if scan.Enabled && scan.NextRun.Before(time.Now()) {
				fmt.Println()
				fmt.Printf("  %s\n", ui.Warning.Sprint("⚠ This scan is due to run"))
			}

			fmt.Println()

			return nil
		},
	}

	return cmd
}

// scheduleDeleteCmd deletes a scheduled scan
func scheduleDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "delete <id>",
		Aliases: []string{"del", "rm"},
		Short:   "Delete a scheduled scan",
		Long: `Delete a scheduled scan permanently.

Examples:
  zypheron schedule delete daily-scan-123`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanID := args[0]

			// Create scheduler
			s, err := scheduler.NewScheduler(scheduler.DefaultDBPath)
			if err != nil {
				return fmt.Errorf("failed to initialize scheduler: %w", err)
			}
			defer s.Close()

			// Get scan details before deletion
			scan, err := s.GetScan(scanID)
			if err != nil {
				return fmt.Errorf("failed to get scan: %w", err)
			}

			// Delete scan
			if err := s.DeleteScan(scanID); err != nil {
				return fmt.Errorf("failed to delete scan: %w", err)
			}

			fmt.Printf("\n%s\n", ui.SuccessMsg(fmt.Sprintf("Deleted scheduled scan: %s", scan.Name)))
			fmt.Println()

			return nil
		},
	}

	return cmd
}

// scheduleEnableCmd enables a scheduled scan
func scheduleEnableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enable <id>",
		Short: "Enable a scheduled scan",
		Long: `Enable a disabled scheduled scan to resume automatic execution.

Examples:
  zypheron schedule enable daily-scan-123`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanID := args[0]

			// Create scheduler
			s, err := scheduler.NewScheduler(scheduler.DefaultDBPath)
			if err != nil {
				return fmt.Errorf("failed to initialize scheduler: %w", err)
			}
			defer s.Close()

			// Enable scan
			if err := s.EnableScan(scanID); err != nil {
				return fmt.Errorf("failed to enable scan: %w", err)
			}

			// Get updated scan
			scan, err := s.GetScan(scanID)
			if err != nil {
				return fmt.Errorf("failed to get scan: %w", err)
			}

			fmt.Printf("\n%s\n", ui.SuccessMsg(fmt.Sprintf("Enabled scheduled scan: %s", scan.Name)))
			fmt.Printf("  Next run: %s\n", ui.Info.Sprint(scan.NextRun.Format("2006-01-02 15:04:05")))
			fmt.Println()

			return nil
		},
	}

	return cmd
}

// scheduleDisableCmd disables a scheduled scan
func scheduleDisableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disable <id>",
		Short: "Disable a scheduled scan",
		Long: `Disable a scheduled scan to prevent automatic execution.

Examples:
  zypheron schedule disable daily-scan-123`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanID := args[0]

			// Create scheduler
			s, err := scheduler.NewScheduler(scheduler.DefaultDBPath)
			if err != nil {
				return fmt.Errorf("failed to initialize scheduler: %w", err)
			}
			defer s.Close()

			// Disable scan
			if err := s.DisableScan(scanID); err != nil {
				return fmt.Errorf("failed to disable scan: %w", err)
			}

			// Get updated scan
			scan, err := s.GetScan(scanID)
			if err != nil {
				return fmt.Errorf("failed to get scan: %w", err)
			}

			fmt.Printf("\n%s\n", ui.InfoMsg(fmt.Sprintf("Disabled scheduled scan: %s", scan.Name)))
			fmt.Println()

			return nil
		},
	}

	return cmd
}

// scheduleRunCmd runs all due scans immediately
func scheduleRunCmd() *cobra.Command {
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run all due scans now",
		Long: `Execute all enabled scans that are due to run.

This command checks for scans whose scheduled time has passed and executes them.
After successful execution, the next run time is automatically calculated.

Examples:
  zypheron schedule run
  zypheron schedule run --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Create scheduler
			s, err := scheduler.NewScheduler(scheduler.DefaultDBPath)
			if err != nil {
				return fmt.Errorf("failed to initialize scheduler: %w", err)
			}
			defer s.Close()

			// Get due scans
			scans, err := s.GetDueScans()
			if err != nil {
				return fmt.Errorf("failed to get due scans: %w", err)
			}

			if len(scans) == 0 {
				fmt.Println(ui.InfoMsg("No scans are currently due to run"))
				return nil
			}

			fmt.Printf("\n%s\n", ui.Primary.Sprint(fmt.Sprintf("Found %d due scan(s)", len(scans))))
			fmt.Println()

			if dryRun {
				fmt.Println(ui.InfoMsg("Dry run mode - scans will not be executed"))
				fmt.Println()
				for i, scan := range scans {
					fmt.Printf("%d. %s\n", i+1, ui.Accent.Sprint(scan.Name))
					fmt.Printf("   Target: %s\n", scan.Target)
					fmt.Printf("   Tools:  %s\n", scan.Tools)
					fmt.Println()
				}
				return nil
			}

			// Execute each due scan
			successCount := 0
			failCount := 0

			for i, scan := range scans {
				fmt.Printf("[%d/%d] Running: %s\n", i+1, len(scans), ui.Accent.Sprint(scan.Name))
				fmt.Printf("        Target: %s\n", scan.Target)
				fmt.Printf("        Tools:  %s\n", scan.Tools)
				fmt.Println()

				// Execute scan for each tool
				toolList := strings.Split(scan.Tools, ",")
				scanSuccess := true

				for _, tool := range toolList {
					tool = strings.TrimSpace(tool)

					fmt.Printf("        Executing %s...\n", tool)

					// Build execution options
					opts := tools.ExecutionOptions{
						Tool:    tool,
						Target:  scan.Target,
						Stream:  true,
						Timeout: 300 * time.Second,
					}

					// Execute
					ctx := context.Background()
					result, err := tools.Execute(ctx, opts)

					if err != nil || !result.Success {
						fmt.Printf("        %s\n", ui.Error(fmt.Sprintf("%s failed: %v", tool, err)))
						scanSuccess = false
						continue
					}

					fmt.Printf("        %s\n", ui.SuccessMsg(fmt.Sprintf("%s completed in %.2fs", tool, result.Duration.Seconds())))
				}

				if scanSuccess {
					// Mark scan as completed
					if err := s.MarkCompleted(scan.ID); err != nil {
						fmt.Printf("        %s\n", ui.WarningMsg(fmt.Sprintf("Failed to update scan status: %v", err)))
					} else {
						updated, _ := s.GetScan(scan.ID)
						if updated != nil {
							fmt.Printf("        Next run: %s\n", ui.Info.Sprint(updated.NextRun.Format("2006-01-02 15:04:05")))
						}
					}
					successCount++
				} else {
					failCount++
				}

				fmt.Println()
			}

			// Summary
			fmt.Println(ui.Separator(60))
			fmt.Printf("Completed: %s  Failed: %s\n",
				ui.Success.Sprint(fmt.Sprintf("%d", successCount)),
				ui.Danger.Sprint(fmt.Sprintf("%d", failCount)))
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would run without executing")

	return cmd
}

// Helper functions

func generateScanID(name string) string {
	// Simple ID generation: lowercase, replace spaces with hyphens, add timestamp
	id := strings.ToLower(name)
	id = strings.ReplaceAll(id, " ", "-")
	id = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return -1
	}, id)
	return fmt.Sprintf("%s-%d", id, time.Now().Unix())
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func displayScansJSON(scans []scheduler.ScheduledScan) error {
	// This would use encoding/json to marshal scans
	// For now, return a simple implementation
	fmt.Println("[")
	for i, scan := range scans {
		fmt.Printf("  {\n")
		fmt.Printf("    \"id\": \"%s\",\n", scan.ID)
		fmt.Printf("    \"name\": \"%s\",\n", scan.Name)
		fmt.Printf("    \"target\": \"%s\",\n", scan.Target)
		fmt.Printf("    \"tools\": \"%s\",\n", scan.Tools)
		fmt.Printf("    \"cron_expr\": \"%s\",\n", scan.CronExpr)
		fmt.Printf("    \"next_run\": \"%s\",\n", scan.NextRun.Format(time.RFC3339))
		fmt.Printf("    \"enabled\": %t\n", scan.Enabled)
		if i < len(scans)-1 {
			fmt.Printf("  },\n")
		} else {
			fmt.Printf("  }\n")
		}
	}
	fmt.Println("]")
	return nil
}
