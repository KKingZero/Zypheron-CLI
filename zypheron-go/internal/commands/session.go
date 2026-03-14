package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/session"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

// SessionCmd returns the session management command
func SessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage scan sessions",
		Long: `Manage, resume, and export scan sessions.

Sessions store complete scan state including progress, results, chat history,
and AI analysis. Use these commands to manage your scanning workflow.

Examples:
  zypheron session list                    # List all saved sessions
  zypheron session resume <id>             # Resume a session
  zypheron session export <id>             # Export session to JSON
  zypheron session export <id> output.json # Export to specific file
  zypheron session delete <id>             # Delete a session`,
	}

	cmd.AddCommand(sessionListCmd())
	cmd.AddCommand(sessionResumeCmd())
	cmd.AddCommand(sessionExportCmd())
	cmd.AddCommand(sessionDeleteCmd())
	cmd.AddCommand(sessionShowCmd())

	return cmd
}

// sessionListCmd lists all saved sessions
func sessionListCmd() *cobra.Command {
	var (
		limit  int
		target string
		status string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all saved sessions",
		Long:  "Display all saved scan sessions with status and summary information",
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionMgr, err := session.NewSessionManager()
			if err != nil {
				return fmt.Errorf("failed to initialize session manager: %w", err)
			}

			summaries, err := sessionMgr.ListSessions()
			if err != nil {
				return fmt.Errorf("failed to list sessions: %w", err)
			}

			// Apply filters
			var filtered []session.SessionSummary
			for _, summary := range summaries {
				// Filter by target if specified
				if target != "" && summary.Target != target {
					continue
				}

				// Filter by status if specified
				if status != "" && string(summary.Status) != status {
					continue
				}

				filtered = append(filtered, summary)
			}

			// Apply limit
			if limit > 0 && len(filtered) > limit {
				filtered = filtered[:limit]
			}

			if len(filtered) == 0 {
				fmt.Println()
				fmt.Println(ui.InfoMsg("No sessions found"))
				fmt.Println(ui.Muted.Sprint("  Start a scan to create a session: zypheron scan <target>"))
				fmt.Println()
				return nil
			}

			fmt.Printf("\n%s\n", ui.Primary.Sprint("Saved Sessions"))
			fmt.Printf("%s\n\n", ui.Muted.Sprint(fmt.Sprintf("Showing %d session(s)", len(filtered))))

			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"ID", "Started", "Target", "Type", "Status", "Progress", "Vulns"})
			table.SetBorder(false)
			table.SetHeaderColor(
				tablewriter.Colors{tablewriter.Bold},
				tablewriter.Colors{tablewriter.Bold},
				tablewriter.Colors{tablewriter.Bold},
				tablewriter.Colors{tablewriter.Bold},
				tablewriter.Colors{tablewriter.Bold},
				tablewriter.Colors{tablewriter.Bold},
				tablewriter.Colors{tablewriter.Bold},
			)

			for _, summary := range filtered {
				// Format session ID (show first 12 chars)
				idDisplay := summary.SessionID
				if len(idDisplay) > 12 {
					idDisplay = idDisplay[:12] + "..."
				}

				// Status with color
				var statusColor *ui.Color
				switch summary.Status {
				case session.StatusCompleted:
					statusColor = ui.Success
				case session.StatusRunning:
					statusColor = ui.Info
				case session.StatusPaused:
					statusColor = ui.Warning
				case session.StatusFailed:
					statusColor = ui.Danger
				default:
					statusColor = ui.Muted
				}

				// Vulnerability counts
				vulnDisplay := fmt.Sprintf("%d", summary.VulnCount)
				if summary.CriticalCount > 0 {
					vulnDisplay += fmt.Sprintf(" (C:%d", summary.CriticalCount)
					if summary.HighCount > 0 {
						vulnDisplay += fmt.Sprintf(" H:%d", summary.HighCount)
					}
					vulnDisplay += ")"
				} else if summary.HighCount > 0 {
					vulnDisplay += fmt.Sprintf(" (H:%d)", summary.HighCount)
				}

				table.Append([]string{
					idDisplay,
					summary.StartTime.Format("01-02 15:04"),
					summary.Target,
					string(summary.ScanType),
					statusColor.Sprint(summary.Status),
					fmt.Sprintf("%.0f%%", summary.ProgressPercent),
					vulnDisplay,
				})
			}

			table.Render()
			fmt.Println()
			fmt.Println(ui.Muted.Sprint("Use 'zypheron session show <id>' to view details"))
			fmt.Println(ui.Muted.Sprint("Use 'zypheron session resume <id>' to continue a session"))
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().IntVarP(&limit, "limit", "n", 20, "Maximum number of sessions to show")
	cmd.Flags().StringVarP(&target, "target", "t", "", "Filter by target")
	cmd.Flags().StringVarP(&status, "status", "s", "", "Filter by status (running, paused, completed, failed)")

	return cmd
}

// sessionShowCmd shows detailed information about a session
func sessionShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <session-id>",
		Short: "Show session details",
		Long:  "Display detailed information about a specific session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]

			sessionMgr, err := session.NewSessionManager()
			if err != nil {
				return fmt.Errorf("failed to initialize session manager: %w", err)
			}

			sess, err := sessionMgr.Load(sessionID)
			if err != nil {
				return fmt.Errorf("failed to load session: %w", err)
			}

			// Display session details
			fmt.Printf("\n%s\n", ui.Primary.Sprint("═══════════════════════════════════════"))
			fmt.Printf("%s\n", ui.Primary.Sprint("  SESSION DETAILS"))
			fmt.Printf("%s\n\n", ui.Primary.Sprint("═══════════════════════════════════════"))

			fmt.Printf("  %s: %s\n", ui.Accent.Sprint("Session ID"), sess.SessionID)
			fmt.Printf("  %s: %s\n", ui.Accent.Sprint("Target"), sess.Target)
			fmt.Printf("  %s: %s\n", ui.Accent.Sprint("Scan Type"), sess.ScanType)
			fmt.Printf("  %s: %s\n", ui.Accent.Sprint("Started"), sess.StartTime.Format("2006-01-02 15:04:05"))

			if !sess.EndTime.IsZero() {
				fmt.Printf("  %s: %s\n", ui.Accent.Sprint("Ended"), sess.EndTime.Format("2006-01-02 15:04:05"))
				duration := sess.GetDuration()
				fmt.Printf("  %s: %s\n", ui.Accent.Sprint("Duration"), duration.String())
			}

			// Status
			var statusColor *ui.Color
			switch sess.Status {
			case session.StatusCompleted:
				statusColor = ui.Success
			case session.StatusRunning:
				statusColor = ui.Info
			case session.StatusPaused:
				statusColor = ui.Warning
			case session.StatusFailed:
				statusColor = ui.Danger
			default:
				statusColor = ui.Muted
			}
			fmt.Printf("  %s: %s\n", ui.Accent.Sprint("Status"), statusColor.Sprint(sess.Status))

			// Progress
			fmt.Printf("  %s: %.1f%%\n", ui.Accent.Sprint("Progress"), sess.Progress.Percentage)
			if sess.Progress.CurrentPhase != "" {
				fmt.Printf("  %s: %s\n", ui.Accent.Sprint("Current Phase"), sess.Progress.CurrentPhase)
			}
			if sess.Progress.StepsTotal > 0 {
				fmt.Printf("  %s: %d/%d\n", ui.Accent.Sprint("Steps"), sess.Progress.StepsCompleted, sess.Progress.StepsTotal)
			}

			// Results
			fmt.Println()
			fmt.Printf("%s\n", ui.Primary.Sprint("Results:"))
			fmt.Printf("  %s: %d\n", ui.Accent.Sprint("Findings"), len(sess.Results.ParsedFindings))
			fmt.Printf("  %s: %d\n", ui.Accent.Sprint("Vulnerabilities"), len(sess.Results.Vulnerabilities))

			// Vulnerability breakdown
			if len(sess.Results.Vulnerabilities) > 0 {
				criticalCount := 0
				highCount := 0
				mediumCount := 0
				lowCount := 0

				for _, vuln := range sess.Results.Vulnerabilities {
					switch vuln.Severity {
					case "critical":
						criticalCount++
					case "high":
						highCount++
					case "medium":
						mediumCount++
					case "low":
						lowCount++
					}
				}

				if criticalCount > 0 {
					fmt.Printf("    %s: %s\n", ui.Accent.Sprint("Critical"), ui.Danger.Sprint(criticalCount))
				}
				if highCount > 0 {
					fmt.Printf("    %s: %s\n", ui.Accent.Sprint("High"), ui.Warning.Sprint(highCount))
				}
				if mediumCount > 0 {
					fmt.Printf("    %s: %s\n", ui.Accent.Sprint("Medium"), ui.Info.Sprint(mediumCount))
				}
				if lowCount > 0 {
					fmt.Printf("    %s: %s\n", ui.Accent.Sprint("Low"), ui.Muted.Sprint(lowCount))
				}
			}

			// Tags
			if len(sess.Tags) > 0 {
				fmt.Println()
				fmt.Printf("%s\n", ui.Accent.Sprint("Tags:"))
				for _, tag := range sess.Tags {
					fmt.Printf("  - %s\n", tag)
				}
			}

			// Notes
			if sess.Notes != "" {
				fmt.Println()
				fmt.Printf("%s\n", ui.Accent.Sprint("Notes:"))
				fmt.Printf("  %s\n", sess.Notes)
			}

			// Summary
			if sess.Results.Summary != "" {
				fmt.Println()
				fmt.Printf("%s\n", ui.Accent.Sprint("Summary:"))
				fmt.Printf("  %s\n", sess.Results.Summary)
			}

			// AI Analysis
			if sess.Results.AIAnalysis != "" {
				fmt.Println()
				fmt.Printf("%s\n", ui.Primary.Sprint("AI Analysis:"))
				fmt.Println(sess.Results.AIAnalysis)
			}

			fmt.Println()

			return nil
		},
	}
}

// sessionResumeCmd resumes a paused or saved session
func sessionResumeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "resume <session-id>",
		Short: "Resume a saved session",
		Long:  "Resume a paused or saved scan session to continue where you left off",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]

			sessionMgr, err := session.NewSessionManager()
			if err != nil {
				return fmt.Errorf("failed to initialize session manager: %w", err)
			}

			sess, err := sessionMgr.Load(sessionID)
			if err != nil {
				return fmt.Errorf("failed to load session: %w", err)
			}

			fmt.Printf("\n%s\n", ui.InfoMsg(fmt.Sprintf("Resuming session: %s", sessionID)))
			fmt.Printf("  Target: %s\n", sess.Target)
			fmt.Printf("  Type:   %s\n", sess.ScanType)
			fmt.Printf("  Status: %s\n", sess.Status)
			fmt.Println()

			// In a real implementation, this would trigger the scan engine
			// For now, we'll just show a message
			fmt.Println(ui.WarningMsg("Session resume functionality requires integration with the scan engine"))
			fmt.Println(ui.InfoMsg("This feature will be available in the next release"))
			fmt.Println()

			return nil
		},
	}
}

// sessionExportCmd exports a session to JSON file
func sessionExportCmd() *cobra.Command {
	var pretty bool

	cmd := &cobra.Command{
		Use:   "export <session-id> [output-file]",
		Short: "Export session to JSON",
		Long:  "Export a session to a JSON file for backup or analysis",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]
			outputFile := fmt.Sprintf("session-%s.json", sessionID)
			if len(args) > 1 {
				outputFile = args[1]
			}

			sessionMgr, err := session.NewSessionManager()
			if err != nil {
				return fmt.Errorf("failed to initialize session manager: %w", err)
			}

			sess, err := sessionMgr.Load(sessionID)
			if err != nil {
				return fmt.Errorf("failed to load session: %w", err)
			}

			// Marshal to JSON
			var data []byte
			if pretty {
				data, err = json.MarshalIndent(sess, "", "  ")
			} else {
				data, err = json.Marshal(sess)
			}
			if err != nil {
				return fmt.Errorf("failed to marshal session: %w", err)
			}

			// Write to file
			if err := os.WriteFile(outputFile, data, 0644); err != nil {
				return fmt.Errorf("failed to write file: %w", err)
			}

			fmt.Println(ui.SuccessMsg(fmt.Sprintf("Session exported to: %s", outputFile)))
			return nil
		},
	}

	cmd.Flags().BoolVarP(&pretty, "pretty", "p", true, "Pretty-print JSON output")

	return cmd
}

// sessionDeleteCmd deletes a session
func sessionDeleteCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "delete <session-id>",
		Short: "Delete a session",
		Long:  "Permanently delete a saved session. This action cannot be undone.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]

			if !force {
				fmt.Println()
				fmt.Println(ui.WarningMsg(fmt.Sprintf("Delete session: %s?", sessionID)))
				fmt.Print(ui.Muted.Sprint("Are you sure? (yes/no): "))

				var response string
				fmt.Scanln(&response)

				if response != "yes" && response != "y" {
					fmt.Println(ui.InfoMsg("Cancelled"))
					return nil
				}
			}

			sessionMgr, err := session.NewSessionManager()
			if err != nil {
				return fmt.Errorf("failed to initialize session manager: %w", err)
			}

			if err := sessionMgr.DeleteSession(sessionID); err != nil {
				return fmt.Errorf("failed to delete session: %w", err)
			}

			fmt.Println(ui.SuccessMsg(fmt.Sprintf("Session %s deleted", sessionID)))
			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")

	return cmd
}
