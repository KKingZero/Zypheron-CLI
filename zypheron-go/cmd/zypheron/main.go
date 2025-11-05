package main

import (
	"fmt"
	"os"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/commands"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/edition"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

var (
	version    = "1.0.0"
	editionStr = "pro" // Set via ldflags: -X main.editionStr=free
	debug      bool
	noColor    bool
	noBanner   bool
)

func main() {
	// Initialize edition system
	edition.SetEdition(editionStr)
	
	rootCmd := &cobra.Command{
		Use:   "zypheron",
		Short: "🐍 Zypheron - AI-Powered Penetration Testing Platform",
		Long:  "Zypheron CLI - AI-Powered Penetration Testing Platform with Kali Linux Integration",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Define commands that should NOT show the full banner (main pentest workflow)
			noBannerCommands := map[string]bool{
				"scan":               true,
				"authenticated-scan": true,
				"recon":              true,
				"bruteforce":         true,
				"exploit":            true,
				"fuzz":               true,
				"osint":              true,
				"threat":             true,
				"secrets":            true,
				"deps":               true,
				"integrate":          true,
				"chat":               true,
				"ai":                 true,
				"version":            true,
				"completion":         true,
				"reverse-eng":        true,
				"pwn":                true,
				"forensics":          true,
				"api-pentest":        true,
				"dork":               true,
			// Tools subcommands
			"install":     true,
			"install-all": true,
			"check":       true,
			"list":        true,
			"info":        true,
			"suggest":     true,
			// MCP subcommands
			"mcp":    true,
			"start":  true,
			"stop":   true,
			"status": true,
			"config": true,
		}

			// Show banner only for info/setup commands (not in pentest workflow)
			if !noBanner && !noBannerCommands[cmd.Name()] {
				fmt.Println(ui.Banner())
			}
			if debug {
				os.Setenv("ZYPHERON_DEBUG", "1")
			}
			if noColor {
				ui.DisableColors()
			}
		},
	}

	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug mode")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().BoolVar(&noBanner, "no-banner", false, "Disable ASCII banner")

	// Register all commands
	rootCmd.AddCommand(commands.ScanCmd())
	rootCmd.AddCommand(commands.ToolsCmd())
	rootCmd.AddCommand(commands.ConfigCmd())
	rootCmd.AddCommand(commands.ChatCmd())
	rootCmd.AddCommand(commands.AICmd())
	rootCmd.AddCommand(commands.SetupCmd())
	rootCmd.AddCommand(commands.HistoryCmd())
	rootCmd.AddCommand(commands.ReconCmd())
	rootCmd.AddCommand(commands.BruteforceCmd())
	rootCmd.AddCommand(commands.ExploitCmd())
	rootCmd.AddCommand(commands.FuzzCmd())
	rootCmd.AddCommand(commands.OsintCmd())
	rootCmd.AddCommand(commands.ThreatCmd())
	rootCmd.AddCommand(commands.ReportCmd())
	rootCmd.AddCommand(commands.DashboardCmd())
	rootCmd.AddCommand(commands.KaliCmd())

	// Enterprise features
	rootCmd.AddCommand(commands.AuthenticatedScanCmd())
	rootCmd.AddCommand(commands.SecretsCmd())
	rootCmd.AddCommand(commands.DepsCmd())
	rootCmd.AddCommand(commands.IntegrateCmd())

	// Security analysis commands
	rootCmd.AddCommand(commands.ReverseEngCmd())
	rootCmd.AddCommand(commands.PwnCmd())
	rootCmd.AddCommand(commands.ForensicsCmd())
	rootCmd.AddCommand(commands.APIPentestCmd())
	rootCmd.AddCommand(commands.DorkCmd())

	// MCP integration
	rootCmd.AddCommand(commands.NewMCPCmd())

	// Version (include edition)
	versionStr := fmt.Sprintf("%s (%s)", version, edition.Current().DisplayName())
	rootCmd.Version = versionStr
	rootCmd.SetVersionTemplate(fmt.Sprintf("Zypheron CLI v{{.Version}}\n"))

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
		os.Exit(1)
	}
}
