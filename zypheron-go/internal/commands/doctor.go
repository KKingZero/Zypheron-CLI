package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tools"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

// DoctorCmd returns the doctor command for system health checks
func DoctorCmd() *cobra.Command {
	var (
		verbose    bool
		category   string
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "System health check for security tools",
		Long: `Check system configuration and verify all required security tools are installed.

This command performs a comprehensive health check of your Zypheron installation,
verifying that all necessary security tools are available and properly configured.

Examples:
  zypheron doctor                        # Full system check
  zypheron doctor --verbose              # Detailed output with versions
  zypheron doctor --category scan        # Check only scan tools
  zypheron doctor --category web         # Check only web tools`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check tools first (shared by text + JSON output modes).
			var toolStatuses []tools.ToolStatus
			if category != "" {
				toolStatuses = tools.CheckToolsByCategory(category)
			} else {
				toolStatuses = tools.CheckAllTools()
			}

			if jsonOutput {
				type doctorJSONResult struct {
					OS        string             `json:"os"`
					Arch      string             `json:"arch"`
					GoVersion string             `json:"go_version"`
					Category  string             `json:"category,omitempty"`
					Tools     []tools.ToolStatus `json:"tools"`
					Summary   struct {
						Total           int `json:"total"`
						Installed       int `json:"installed"`
						Missing         int `json:"missing"`
						MissingRequired int `json:"missing_required"`
						MissingOptional int `json:"missing_optional"`
					} `json:"summary"`
				}

				result := doctorJSONResult{
					OS:        runtime.GOOS,
					Arch:      runtime.GOARCH,
					GoVersion: runtime.Version(),
					Category:  category,
					Tools:     toolStatuses,
				}
				result.Summary.Total = len(toolStatuses)
				for _, status := range toolStatuses {
					if status.Installed {
						result.Summary.Installed++
						continue
					}
					if status.Tool.Required {
						result.Summary.MissingRequired++
					} else {
						result.Summary.MissingOptional++
					}
				}
				result.Summary.Missing = result.Summary.Total - result.Summary.Installed

				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}

			fmt.Printf("\n%s\n", ui.Primary.Sprint("═══════════════════════════════════════════════════════"))
			fmt.Printf("%s\n", ui.Primary.Sprint("  ZYPHERON SYSTEM HEALTH CHECK"))
			fmt.Printf("%s\n\n", ui.Primary.Sprint("═══════════════════════════════════════════════════════"))

			// System information
			fmt.Printf("%s\n", ui.Accent.Sprint("System Information:"))
			fmt.Printf("  OS:           %s\n", runtime.GOOS)
			fmt.Printf("  Architecture: %s\n", runtime.GOARCH)
			fmt.Printf("  Go Version:   %s\n\n", runtime.Version())

			if category != "" {
				fmt.Printf("%s\n", ui.InfoMsg(fmt.Sprintf("Checking tools in category: %s", category)))
			} else {
				fmt.Printf("%s\n", ui.InfoMsg("Checking all security tools..."))
			}

			if len(toolStatuses) == 0 {
				fmt.Println(ui.WarningMsg(fmt.Sprintf("No tools found in category: %s", category)))
				return nil
			}

			// Separate required and optional tools
			var requiredTools, optionalTools []tools.ToolStatus
			for _, status := range toolStatuses {
				if status.Tool.Required {
					requiredTools = append(requiredTools, status)
				} else {
					optionalTools = append(optionalTools, status)
				}
			}

			// Display required tools
			if len(requiredTools) > 0 {
				fmt.Printf("\n%s\n\n", ui.Primary.Sprint("Required Tools:"))
				displayToolTable(requiredTools, verbose)
			}

			// Display optional tools
			if len(optionalTools) > 0 {
				fmt.Printf("\n%s\n\n", ui.Primary.Sprint("Optional Tools:"))
				displayToolTable(optionalTools, verbose)
			}

			// Calculate statistics
			totalTools := len(toolStatuses)
			installedCount := 0
			missingRequired := 0
			missingOptional := 0

			for _, status := range toolStatuses {
				if status.Installed {
					installedCount++
				} else {
					if status.Tool.Required {
						missingRequired++
					} else {
						missingOptional++
					}
				}
			}

			// Display summary
			fmt.Printf("\n%s\n", ui.Primary.Sprint("═══════════════════════════════════════════════════════"))
			fmt.Printf("%s\n\n", ui.Primary.Sprint("  SUMMARY"))
			fmt.Printf("%s\n", ui.Primary.Sprint("═══════════════════════════════════════════════════════"))

			fmt.Printf("  Total Tools:       %d\n", totalTools)
			fmt.Printf("  Installed:         %s\n", ui.Success.Sprint(installedCount))
			fmt.Printf("  Missing:           %s\n", ui.Danger.Sprint(totalTools-installedCount))

			if missingRequired > 0 {
				fmt.Printf("  Missing Required:  %s\n", ui.Danger.Sprint(missingRequired))
			}
			if missingOptional > 0 {
				fmt.Printf("  Missing Optional:  %s\n", ui.Warning.Sprint(missingOptional))
			}

			fmt.Println()

			// Health status
			if missingRequired > 0 {
				fmt.Printf("%s\n", ui.Error("CRITICAL: Required tools are missing!"))
				fmt.Printf("%s\n\n", ui.InfoMsg("Install missing tools with: zypheron tools install-all --critical-only"))
				return nil
			} else if missingOptional > 0 {
				fmt.Printf("%s\n", ui.WarningMsg("WARNING: Some optional tools are missing"))
				fmt.Printf("%s\n\n", ui.InfoMsg("Install all tools with: zypheron tools install-all"))
			} else {
				fmt.Printf("%s\n\n", ui.SuccessMsg("All tools are installed and ready!"))
			}

			// Display installation suggestions for missing tools
			missingTools := tools.GetMissingTools()
			if len(missingTools) > 0 && verbose {
				fmt.Printf("%s\n\n", ui.Accent.Sprint("Installation Commands:"))

				bulkCmd := tools.GetBulkInstallCommand(extractToolInfos(missingTools))
				if bulkCmd != "" {
					fmt.Printf("  Install all missing:\n")
					fmt.Printf("    %s\n\n", ui.Muted.Sprint(bulkCmd))
				}

				fmt.Printf("  Individual installations:\n")
				for _, status := range missingTools {
					installCmd := tools.GetInstallCommand(status.Tool)
					fmt.Printf("    %s:\n      %s\n",
						ui.Accent.Sprint(status.Tool.Name),
						ui.Muted.Sprint(installCmd))
				}
				fmt.Println()
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed information including versions and install commands")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	cmd.Flags().StringVarP(&category, "category", "c", "", "Check only tools in specific category (scan, web, exploit, recon)")

	return cmd
}

// displayToolTable displays tools in a formatted table
func displayToolTable(statuses []tools.ToolStatus, verbose bool) {
	table := tablewriter.NewWriter(os.Stdout)

	if verbose {
		table.SetHeader([]string{"Tool", "Status", "Version", "Categories"})
	} else {
		table.SetHeader([]string{"Tool", "Status", "Categories"})
	}

	table.SetBorder(false)
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	for _, status := range statuses {
		var statusStr string
		var statusColor *ui.Color

		if status.Installed {
			statusStr = "✓ Installed"
			statusColor = ui.Success
		} else {
			statusStr = "✗ Missing"
			statusColor = ui.Danger
		}

		// Join categories
		categories := ""
		for i, cat := range status.Tool.Categories {
			if i > 0 {
				categories += ", "
			}
			categories += cat
		}

		if verbose {
			version := status.Version
			if version == "" {
				version = "N/A"
			}
			table.Append([]string{
				ui.Accent.Sprint(status.Tool.Name),
				statusColor.Sprint(statusStr),
				ui.Muted.Sprint(version),
				ui.Muted.Sprint(categories),
			})
		} else {
			table.Append([]string{
				ui.Accent.Sprint(status.Tool.Name),
				statusColor.Sprint(statusStr),
				ui.Muted.Sprint(categories),
			})
		}
	}

	table.Render()
}

// extractToolInfos extracts ToolInfo from ToolStatus slice
func extractToolInfos(statuses []tools.ToolStatus) []tools.ToolInfo {
	var infos []tools.ToolInfo
	for _, status := range statuses {
		infos = append(infos, status.Tool)
	}
	return infos
}
