package commands

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/kali"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"os"
)

// ToolsCmd returns the tools management command
func ToolsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tools",
		Short: "Manage and check Kali security tools",
		Long:  "Check, list, install, and manage Kali Linux security tools",
	}

	cmd.AddCommand(toolsCheckCmd())
	cmd.AddCommand(toolsListCmd())
	cmd.AddCommand(toolsInfoCmd())
	cmd.AddCommand(toolsSuggestCmd())
	cmd.AddCommand(toolsInstallCmd())
	cmd.AddCommand(toolsInstallAllCmd())

	return cmd
}

// toolsCheckCmd checks installed tools
func toolsCheckCmd() *cobra.Command {
	var category string

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check installed tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(ui.InfoMsg("Checking installed security tools...\n"))

			toolManager := kali.NewToolManager()
			if err := toolManager.DetectTools(); err != nil {
				return err
			}

			allTools := toolManager.GetAllTools()
			tools := allTools

			if category != "" {
				filtered := []kali.Tool{}
				for _, t := range allTools {
					if t.Category == category {
						filtered = append(filtered, t)
					}
				}
				tools = filtered
			}

			// Display tool status
			for _, tool := range tools {
				if tool.Installed {
					fmt.Printf("  %s %s", ui.Success.Sprint("✓"), ui.Accent.Sprint(tool.Name))
					if tool.Version != "" {
						fmt.Printf(" (%s)", ui.Muted.Sprint(tool.Version))
					}
					fmt.Println()
				} else {
					fmt.Printf("  %s %s\n", ui.Danger.Sprint("✗"), ui.Muted.Sprint(tool.Name))
				}
			}

			// Show statistics
			stats := toolManager.GetStats()
			fmt.Printf("\n%s\n", ui.InfoMsg("Statistics:"))
			fmt.Printf("  Total:     %d\n", stats.Total)
			fmt.Printf("  Installed: %s\n", ui.Success.Sprint(stats.Installed))
			fmt.Printf("  Missing:   %s\n", ui.Danger.Sprint(stats.Missing))

			if stats.Critical > 0 {
				fmt.Printf("  Critical Missing: %s\n", ui.Danger.Sprint(stats.Critical))
			}
			if stats.High > 0 {
				fmt.Printf("  High Priority Missing: %s\n", ui.Warning.Sprint(stats.High))
			}

			fmt.Println()
			return nil
		},
	}

	cmd.Flags().StringVarP(&category, "category", "c", "", "Filter by category")
	return cmd
}

// toolsListCmd lists all available tools
func toolsListCmd() *cobra.Command {
	var (
		category  string
		installed bool
		missing   bool
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all available tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			toolManager := kali.NewToolManager()
			if err := toolManager.DetectTools(); err != nil {
				return err
			}

			tools := toolManager.GetAllTools()

			// Apply filters
			if category != "" {
				filtered := []kali.Tool{}
				for _, t := range tools {
					if t.Category == category {
						filtered = append(filtered, t)
					}
				}
				tools = filtered
			}

			if installed {
				filtered := []kali.Tool{}
				for _, t := range tools {
					if t.Installed {
						filtered = append(filtered, t)
					}
				}
				tools = filtered
			} else if missing {
				filtered := []kali.Tool{}
				for _, t := range tools {
					if !t.Installed {
						filtered = append(filtered, t)
					}
				}
				tools = filtered
			}

			// Create table
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Tool", "Category", "Status", "Priority", "Version"})
			table.SetBorder(false)
			table.SetColumnSeparator("")
			table.SetRowSeparator("")
			table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
			table.SetAlignment(tablewriter.ALIGN_LEFT)

			for _, tool := range tools {
				status := "Missing"
				statusColor := ui.Danger
				if tool.Installed {
					status = "Installed"
					statusColor = ui.Success
				}

				version := tool.Version
				if version == "" {
					version = "N/A"
				}

				table.Append([]string{
					ui.Accent.Sprint(tool.Name),
					tool.Category,
					statusColor.Sprint(status),
					getPriorityColor(tool.Priority).Sprint(tool.Priority),
					ui.Muted.Sprint(version),
				})
			}

			table.Render()
			fmt.Println()
			return nil
		},
	}

	cmd.Flags().StringVarP(&category, "category", "c", "", "Filter by category")
	cmd.Flags().BoolVar(&installed, "installed", false, "Show only installed tools")
	cmd.Flags().BoolVar(&missing, "missing", false, "Show only missing tools")

	return cmd
}

// toolsInfoCmd shows information about a specific tool
func toolsInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <tool>",
		Short: "Get information about a specific tool",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			toolName := args[0]

			toolManager := kali.NewToolManager()
			if err := toolManager.DetectTools(); err != nil {
				return err
			}

			tool := toolManager.GetTool(toolName)
			if tool == nil {
				return fmt.Errorf("tool '%s' not found", toolName)
			}

			// Display tool info
			top, bottom := ui.Box(tool.Name)
			fmt.Printf("\n%s\n", top)
			fmt.Println()

			fmt.Printf("%s\n", ui.Accent.Sprint("Description:"))
			fmt.Printf("  %s\n\n", tool.Description)

			fmt.Printf("%s\n", ui.Accent.Sprint("Status:"))
			if tool.Installed {
				fmt.Printf("  %s\n", ui.SuccessMsg("Installed"))
				if tool.Version != "" {
					fmt.Printf("  Version: %s\n", tool.Version)
				}
			} else {
				fmt.Printf("  %s\n", ui.Error("Not Installed"))
			}
			fmt.Println()

			fmt.Printf("%s %s\n", ui.Accent.Sprint("Category:"), tool.Category)
			fmt.Printf("%s %s\n", ui.Accent.Sprint("Priority:"), getPriorityColor(tool.Priority).Sprint(tool.Priority))
			fmt.Printf("%s %v\n\n", ui.Accent.Sprint("Required For:"), tool.RequiredFor)

			if !tool.Installed {
				fmt.Printf("%s\n", ui.Accent.Sprint("Installation:"))
				fmt.Printf("  %s\n\n", tool.InstallCmd)
			}

			if len(tool.Aliases) > 0 {
				fmt.Printf("%s %v\n", ui.Accent.Sprint("Aliases:"), tool.Aliases)
			}

			fmt.Printf("%s\n\n", bottom)
			return nil
		},
	}
}

// toolsSuggestCmd suggests the best tool for a task
func toolsSuggestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "suggest <task>",
		Short: "Suggest best tool for a task",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			task := args[0]

			toolManager := kali.NewToolManager()
			if err := toolManager.DetectTools(); err != nil {
				return err
			}

			tool := toolManager.SuggestTool(task)
			if tool == nil {
				fmt.Println(ui.WarningMsg(fmt.Sprintf("No tool found for task: %s", task)))
				fmt.Println(ui.InfoMsg("Available tasks: scan, exploit, bruteforce, recon, web, osint, wireless"))
				return nil
			}

			fmt.Printf("\n%s\n\n", ui.Primary.Sprint(fmt.Sprintf("🤖 Best tool for '%s':", task)))
			fmt.Printf("%s\n", ui.Accent.Sprint(tool.Name))
			fmt.Printf("%s\n\n", tool.Description)

			if tool.Installed {
				fmt.Println(ui.SuccessMsg(fmt.Sprintf("%s is installed and ready to use", tool.Name)))
				fmt.Printf("\n%s\n\n", ui.InfoMsg(fmt.Sprintf("Run: zypheron scan <target> --tool %s", tool.Name)))
			} else {
				fmt.Println(ui.WarningMsg(fmt.Sprintf("%s is not installed", tool.Name)))
				fmt.Printf("\n%s\n", ui.InfoMsg("Install with:"))
				fmt.Printf("  %s\n\n", ui.Accent.Sprint(tool.InstallCmd))
			}

			return nil
		},
	}
}

// toolsInstallCmd installs a specific tool
func toolsInstallCmd() *cobra.Command {
	var yes bool

	cmd := &cobra.Command{
		Use:   "install <tool>",
		Short: "Install a specific tool",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			toolName := args[0]

			toolManager := kali.NewToolManager()
			if err := toolManager.DetectTools(); err != nil {
				return err
			}

			tool := toolManager.GetTool(toolName)
			if tool == nil {
				return fmt.Errorf("tool '%s' not found", toolName)
			}

			if tool.Installed {
				fmt.Println(ui.InfoMsg(fmt.Sprintf("%s is already installed (%s)", tool.Name, tool.Version)))
				return nil
			}

			fmt.Printf("\n%s\n", ui.InfoMsg(fmt.Sprintf("Installing %s...", ui.Accent.Sprint(tool.Name))))
			fmt.Printf("%s\n\n", tool.Description)

			if !yes {
				confirm := false
				prompt := &survey.Confirm{
					Message: fmt.Sprintf("Install %s?", tool.Name),
					Default: true,
				}
				if err := survey.AskOne(prompt, &confirm); err != nil {
					return err
				}

				if !confirm {
					fmt.Println(ui.WarningMsg("Installation cancelled"))
					return nil
				}
			}

			if err := toolManager.Install(toolName); err != nil {
				return err
			}

			fmt.Println(ui.SuccessMsg(fmt.Sprintf("%s installed successfully", tool.Name)))
			return nil
		},
	}

	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	return cmd
}

// toolsInstallAllCmd installs all missing tools
func toolsInstallAllCmd() *cobra.Command {
	var (
		yes          bool
		criticalOnly bool
		highPriority bool
	)

	cmd := &cobra.Command{
		Use:   "install-all",
		Short: "Install all missing tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			toolManager := kali.NewToolManager()
			if err := toolManager.DetectTools(); err != nil {
				return err
			}

			allTools := toolManager.GetAllTools()
			var toolsToInstall []kali.Tool

			// Filter tools
			for _, tool := range allTools {
				if tool.Installed {
					continue
				}

				if criticalOnly && tool.Priority != "critical" {
					continue
				}

				if highPriority && tool.Priority != "critical" && tool.Priority != "high" {
					continue
				}

				toolsToInstall = append(toolsToInstall, tool)
			}

			if len(toolsToInstall) == 0 {
				fmt.Println(ui.SuccessMsg("All tools are already installed!"))
				return nil
			}

			// Show list
			top, bottom := ui.Box("TOOL INSTALLATION")
			fmt.Printf("\n%s\n", top)
			fmt.Printf("\n%s\n\n", ui.InfoMsg(fmt.Sprintf("Found %d tools to install:", len(toolsToInstall))))

			for _, tool := range toolsToInstall {
				priority := getPriorityColor(tool.Priority).Sprintf("[%s]", tool.Priority)
				fmt.Printf("  %s %s - %s\n", priority, ui.Accent.Sprint(tool.Name), tool.Description)
			}

			fmt.Println()

			if !yes {
				confirm := false
				prompt := &survey.Confirm{
					Message: fmt.Sprintf("Install %d tools?", len(toolsToInstall)),
					Default: true,
				}
				if err := survey.AskOne(prompt, &confirm); err != nil {
					return err
				}

				if !confirm {
					fmt.Println(ui.WarningMsg("Installation cancelled"))
					return nil
				}
			}

			// Install tools
			successCount := 0
			failCount := 0

			for _, tool := range toolsToInstall {
				fmt.Printf("\n%s\n", ui.InfoMsg(fmt.Sprintf("Installing %s...", tool.Name)))
				if err := toolManager.Install(tool.Name); err != nil {
					fmt.Println(ui.Error(fmt.Sprintf("Failed to install %s: %v", tool.Name, err)))
					failCount++
				} else {
					successCount++
				}
			}

			// Summary
			fmt.Printf("\n%s\n", bottom)
			fmt.Printf("%s Installed: %d\n", ui.Success.Sprint("✓"), successCount)
			if failCount > 0 {
				fmt.Printf("%s Failed: %d\n", ui.Danger.Sprint("✗"), failCount)
			}
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	cmd.Flags().BoolVar(&criticalOnly, "critical-only", false, "Install only critical priority tools")
	cmd.Flags().BoolVar(&highPriority, "high-priority", false, "Install critical and high priority tools")

	return cmd
}

// getPriorityColor returns the appropriate color for a priority level
func getPriorityColor(priority string) *ui.Color {
	switch priority {
	case "critical":
		return ui.Danger
	case "high":
		return ui.Warning
	default:
		return ui.Muted
	}
}

