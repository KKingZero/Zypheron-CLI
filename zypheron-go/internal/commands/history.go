package commands

import (
    "fmt"
    "os"

    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/history"
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
    cmd.AddCommand(historyStatsCmd())
    cmd.AddCommand(historySearchCmd())
    cmd.AddCommand(historyClearCmd())

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

// historyStatsCmd shows aggregated statistics
func historyStatsCmd() *cobra.Command {
    return &cobra.Command{
        Use:   "stats",
        Short: "Show scan history statistics",
        Long:  "Display aggregated statistics about your scan history",
        RunE: func(cmd *cobra.Command, args []string) error {
            histManager, err := history.NewManager()
            if err != nil {
                return fmt.Errorf("failed to initialize history manager: %w", err)
            }

            stats, err := histManager.GetStats()
            if err != nil {
                return fmt.Errorf("failed to get statistics: %w", err)
            }

            fmt.Printf("\n%s\n", ui.Primary.Sprint("═══════════════════════════════════════"))
            fmt.Printf("%s\n", ui.Primary.Sprint("  SCAN HISTORY STATISTICS"))
            fmt.Printf("%s\n\n", ui.Primary.Sprint("═══════════════════════════════════════"))

            // Overall stats
            fmt.Printf("%s\n", ui.Accent.Sprint("Overall:"))
            fmt.Printf("  Total Scans:       %d\n", stats.TotalScans)
            fmt.Printf("  Total Findings:    %d\n", stats.TotalFindings)
            fmt.Printf("  Total Vulnerabilities: %d\n", stats.TotalVulns)
            fmt.Printf("  Success Rate:      %.1f%%\n", stats.SuccessRate)

            if stats.LastScanTime != nil {
                fmt.Printf("  Last Scan:         %s\n", stats.LastScanTime.Format("2006-01-02 15:04:05"))
            }

            if stats.TotalScans > 0 {
                avgDurationSec := float64(stats.AvgDuration) / 1000.0
                totalDurationSec := float64(stats.TotalDuration) / 1000.0
                fmt.Printf("  Average Duration:  %.2fs\n", avgDurationSec)
                fmt.Printf("  Total Duration:    %.2fs\n", totalDurationSec)
            }

            // Scans by tool
            if len(stats.ScansByTool) > 0 {
                fmt.Printf("\n%s\n", ui.Accent.Sprint("Scans by Tool:"))
                for tool, count := range stats.ScansByTool {
                    fmt.Printf("  %-15s %d\n", tool, count)
                }
            }

            // Scans by target
            if len(stats.ScansByTarget) > 0 {
                fmt.Printf("\n%s\n", ui.Accent.Sprint("Scans by Target:"))
                type targetCount struct {
                    target string
                    count  int
                }
                var targets []targetCount
                for target, count := range stats.ScansByTarget {
                    targets = append(targets, targetCount{target, count})
                }
                // Sort by count descending
                for i := 0; i < len(targets); i++ {
                    for j := i + 1; j < len(targets); j++ {
                        if targets[j].count > targets[i].count {
                            targets[i], targets[j] = targets[j], targets[i]
                        }
                    }
                }
                maxTargets := 10
                if len(targets) < maxTargets {
                    maxTargets = len(targets)
                }
                for i := 0; i < maxTargets; i++ {
                    fmt.Printf("  %-30s %d\n", targets[i].target, targets[i].count)
                }
                if len(targets) > 10 {
                    fmt.Printf("  %s\n", ui.Muted.Sprint(fmt.Sprintf("... and %d more", len(targets)-10)))
                }
            }

            // Scans by status
            if len(stats.ScansByStatus) > 0 {
                fmt.Printf("\n%s\n", ui.Accent.Sprint("Scans by Status:"))
                for status, count := range stats.ScansByStatus {
                    var statusColor *ui.Color
                    switch status {
                    case history.StatusSuccess:
                        statusColor = ui.Success
                    case history.StatusFailed:
                        statusColor = ui.Danger
                    case history.StatusCancelled:
                        statusColor = ui.Warning
                    default:
                        statusColor = ui.Muted
                    }
                    fmt.Printf("  %-15s %s\n", status, statusColor.Sprint(count))
                }
            }

            fmt.Println()
            return nil
        },
    }
}

// historySearchCmd searches scan history
func historySearchCmd() *cobra.Command {
    return &cobra.Command{
        Use:   "search <query>",
        Short: "Search scan history",
        Long:  "Search scan history by target, tool, scan type, tags, or session ID",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            query := args[0]

            histManager, err := history.NewManager()
            if err != nil {
                return fmt.Errorf("failed to initialize history manager: %w", err)
            }

            entries, err := histManager.SearchHistory(query)
            if err != nil {
                return fmt.Errorf("failed to search history: %w", err)
            }

            if len(entries) == 0 {
                fmt.Println()
                fmt.Println(ui.InfoMsg(fmt.Sprintf("No results found for: %s", query)))
                fmt.Println()
                return nil
            }

            fmt.Printf("\n%s\n", ui.Primary.Sprint(fmt.Sprintf("Search Results for: %s", query)))
            fmt.Printf("%s\n\n", ui.Muted.Sprint(fmt.Sprintf("Found %d matches", len(entries))))

            table := tablewriter.NewWriter(os.Stdout)
            table.SetHeader([]string{"ID", "Timestamp", "Target", "Tool", "Status", "Findings"})
            table.SetBorder(false)
            table.SetHeaderColor(
                tablewriter.Colors{tablewriter.Bold},
                tablewriter.Colors{tablewriter.Bold},
                tablewriter.Colors{tablewriter.Bold},
                tablewriter.Colors{tablewriter.Bold},
                tablewriter.Colors{tablewriter.Bold},
                tablewriter.Colors{tablewriter.Bold},
            )

            for _, entry := range entries {
                var statusIcon string
                switch entry.Status {
                case history.StatusFailed:
                    statusIcon = "✗"
                case history.StatusCancelled:
                    statusIcon = "⊘"
                default:
                    statusIcon = "✓"
                }

                idDisplay := entry.ID
                if len(idDisplay) > 12 {
                    idDisplay = idDisplay[:12] + "..."
                }

                table.Append([]string{
                    idDisplay,
                    entry.Timestamp.Format("2006-01-02 15:04"),
                    entry.Target,
                    entry.Tool,
                    statusIcon,
                    fmt.Sprintf("%d", entry.FindingsCount),
                })
            }

            table.Render()
            fmt.Println()
            fmt.Println(ui.Muted.Sprint("Use 'zypheron history show <id>' to view details"))
            fmt.Println()

            return nil
        },
    }
}

// historyClearCmd clears all scan history
func historyClearCmd() *cobra.Command {
    var force bool

    cmd := &cobra.Command{
        Use:   "clear",
        Short: "Clear all scan history",
        Long:  "Remove all scan history entries. This action cannot be undone.",
        RunE: func(cmd *cobra.Command, args []string) error {
            if !force {
                fmt.Println()
                fmt.Println(ui.WarningMsg("This will delete ALL scan history!"))
                fmt.Print(ui.Muted.Sprint("Are you sure? (yes/no): "))

                var response string
                fmt.Scanln(&response)

                if response != "yes" && response != "y" {
                    fmt.Println(ui.InfoMsg("Cancelled"))
                    return nil
                }
            }

            histManager, err := history.NewManager()
            if err != nil {
                return fmt.Errorf("failed to initialize history manager: %w", err)
            }

            if err := histManager.ClearHistory(); err != nil {
                return fmt.Errorf("failed to clear history: %w", err)
            }

            fmt.Println(ui.SuccessMsg("Scan history cleared successfully"))
            return nil
        },
    }

    cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")

    return cmd
}

// Note: Go 1.21+ has built-in min function
