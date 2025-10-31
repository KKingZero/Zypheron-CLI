package commands

import (
	"fmt"
	"os"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/storage"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

// HistoryCmd returns the history command
func HistoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "history",
		Short: "View scan history",
		Long:  "List, view, and manage previous security scans",
	}

	cmd.AddCommand(historyListCmd())
	cmd.AddCommand(historyShowCmd())
	cmd.AddCommand(historyDeleteCmd())

	return cmd
}

// historyListCmd lists all saved scans
func historyListCmd() *cobra.Command {
	var limit int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all saved scans",
		RunE: func(cmd *cobra.Command, args []string) error {
			scanStore, err := storage.NewScanStorage()
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}

			scans, err := scanStore.ListScans()
			if err != nil {
				return fmt.Errorf("failed to list scans: %w", err)
			}

			if len(scans) == 0 {
				fmt.Println()
				fmt.Println(ui.InfoMsg("No scans found"))
				fmt.Println(ui.Muted.Sprint("  Run a scan with: zypheron scan <target>"))
				fmt.Println()
				return nil
			}

			// Apply limit if specified
			if limit > 0 && len(scans) > limit {
				scans = scans[:limit]
			}

			fmt.Printf("\n%s\n\n", ui.Primary.Sprint("Scan History"))

			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"ID", "Timestamp", "Target", "Tool", "Status", "Vulns", "Critical", "High"})
			table.SetBorder(false)
			table.SetHeaderColor(
				tablewriter.Colors{tablewriter.Bold},
				tablewriter.Colors{tablewriter.Bold},
				tablewriter.Colors{tablewriter.Bold},
				tablewriter.Colors{tablewriter.Bold},
				tablewriter.Colors{tablewriter.Bold},
				tablewriter.Colors{tablewriter.Bold},
				tablewriter.Colors{tablewriter.Bold},
				tablewriter.Colors{tablewriter.Bold},
			)

			for _, scan := range scans {
				status := "✓"
				if !scan.Success {
					status = "✗"
				}

				table.Append([]string{
					scan.ID[:min(20, len(scan.ID))] + "...",
					scan.Timestamp.Format("2006-01-02 15:04"),
					scan.Target,
					scan.Tool,
					status,
					fmt.Sprintf("%d", scan.VulnCount),
					fmt.Sprintf("%d", scan.CriticalCount),
					fmt.Sprintf("%d", scan.HighCount),
				})
			}

			table.Render()
			fmt.Println()
			fmt.Println(ui.Muted.Sprint(fmt.Sprintf("Showing %d scan(s)", len(scans))))
			fmt.Println(ui.Muted.Sprint("Use 'zypheron history show <id>' to view details"))
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().IntVarP(&limit, "limit", "n", 20, "Maximum number of scans to show")

	return cmd
}

// historyShowCmd shows details of a specific scan
func historyShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <scan-id>",
		Short: "Show scan details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanID := args[0]

			scanStore, err := storage.NewScanStorage()
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}

			scan, err := scanStore.LoadScan(scanID)
			if err != nil {
				return fmt.Errorf("failed to load scan: %w", err)
			}

			// Display scan details
			fmt.Printf("\n%s\n", ui.Primary.Sprint("═══════════════════════════════════════"))
			fmt.Printf("%s\n", ui.Primary.Sprint("  SCAN DETAILS"))
			fmt.Printf("%s\n\n", ui.Primary.Sprint("═══════════════════════════════════════"))

			fmt.Printf("  %s: %s\n", ui.Accent.Sprint("ID"), scan.ID)
			fmt.Printf("  %s: %s\n", ui.Accent.Sprint("Timestamp"), scan.Timestamp.Format("2006-01-02 15:04:05"))
			fmt.Printf("  %s: %s\n", ui.Accent.Sprint("Target"), scan.Target)
			fmt.Printf("  %s: %s\n", ui.Accent.Sprint("Tool"), scan.Tool)
			fmt.Printf("  %s: %s\n", ui.Accent.Sprint("Ports"), scan.Ports)
			fmt.Printf("  %s: %.2fs\n", ui.Accent.Sprint("Duration"), scan.Duration)

			if scan.Success {
				fmt.Printf("  %s: %s\n", ui.Accent.Sprint("Status"), ui.Success.Sprint("✓ Success"))
			} else {
				fmt.Printf("  %s: %s\n", ui.Accent.Sprint("Status"), ui.Danger.Sprint("✗ Failed"))
				if scan.ErrorMessage != "" {
					fmt.Printf("  %s: %s\n", ui.Accent.Sprint("Error"), scan.ErrorMessage)
				}
			}

			// Display vulnerabilities
			if len(scan.Vulnerabilities) > 0 {
				fmt.Println()
				fmt.Printf("%s\n\n", ui.Primary.Sprint("Vulnerabilities"))

				for i, vuln := range scan.Vulnerabilities {
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
					fmt.Printf("     %s\n", ui.Muted.Sprint(vuln.Description))
					fmt.Println()
				}
			} else {
				fmt.Println()
				fmt.Println(ui.Muted.Sprint("  No vulnerabilities found"))
			}

			// Display AI analysis if available
			if scan.AIAnalysis != "" {
				fmt.Println()
				fmt.Printf("%s\n\n", ui.Primary.Sprint("AI Analysis"))
				fmt.Println(scan.AIAnalysis)
			}

			fmt.Println()

			return nil
		},
	}
}

// historyDeleteCmd deletes a scan from history
func historyDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <scan-id>",
		Short: "Delete a scan from history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanID := args[0]

			scanStore, err := storage.NewScanStorage()
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}

			if err := scanStore.DeleteScan(scanID); err != nil {
				return fmt.Errorf("failed to delete scan: %w", err)
			}

			fmt.Println(ui.SuccessMsg(fmt.Sprintf("Scan %s deleted", scanID)))

			return nil
		},
	}
}

// Note: Go 1.21+ has built-in min function
