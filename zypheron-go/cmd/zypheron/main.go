package main

import (
	"fmt"
	"os"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/commands"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

var (
	version  = "1.0.0"
	debug    bool
	noColor  bool
	noBanner bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "zypheron",
		Short: "🐍 Zypheron - AI-Powered Penetration Testing Platform",
		Long:  "Zypheron CLI - AI-Powered Penetration Testing Platform with Kali Linux Integration",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Show banner unless disabled or running certain commands
			if !noBanner && cmd.Name() != "version" && cmd.Name() != "completion" {
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
	// Exploit command removed in FREE version
	rootCmd.AddCommand(commands.FuzzCmd())
	rootCmd.AddCommand(commands.OsintCmd())
	rootCmd.AddCommand(commands.ThreatCmd())
	rootCmd.AddCommand(commands.ReportCmd())
	rootCmd.AddCommand(commands.DashboardCmd())
	rootCmd.AddCommand(commands.KaliCmd())

	// Version
	rootCmd.Version = version

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
		os.Exit(1)
	}
}
