package main

import (
	"fmt"
	"os"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/commands"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/commands/bridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	version  = "2.0.0"
	debug    bool
	noColor  bool
	noBanner bool
	noTUI    bool
)

func ensureAIEngineRunning() {
	bridge := aibridge.GetSharedBridge()
	if bridge.IsRunning() {
		return
	}

	// Non-blocking: start AI engine in background goroutine
	go func() {
		fmt.Println(ui.Muted.Sprint("AI engine not running, starting in background..."))
		if err := bridge.Start(); err != nil {
			fmt.Fprintln(os.Stderr, ui.WarningMsg(fmt.Sprintf("AI engine auto-start failed: %v", err)))
		}
	}()
}

func shouldAutoStartAI(cmd *cobra.Command) bool {
	if cmd == nil {
		return true
	}

	// Skip auto-start for explicit AI engine lifecycle commands
	if cmd.Name() == "start" || cmd.Name() == "stop" || cmd.Name() == "status" {
		if parent := cmd.Parent(); parent != nil && parent.Name() == "ai" {
			return false
		}
	}

	// For safety, avoid auto-start on the AI doctor command
	if cmd.Name() == "doctor" {
		if parent := cmd.Parent(); parent != nil && parent.Name() == "ai" {
			return false
		}
	}

	// Commands that don't need AI at all - skip startup entirely
	noAICommands := map[string]bool{
		"tools": true, "config": true, "setup": true,
		"completion": true, "version": true, "help": true,
		"history": true, "session": true,
		"install-deps": true,
	}
	if noAICommands[cmd.Name()] {
		return false
	}

	return true
}

func shouldShowStartupBanner(rootCmd, cmd *cobra.Command) bool {
	if noBanner || cmd == nil {
		return false
	}

	if cmd.Name() == "version" || cmd.Name() == "completion" {
		return false
	}

	// The TUI owns the splash when launching the dashboard.
	if cmd == rootCmd && !noTUI {
		return false
	}
	if cmd.Name() == "tui" {
		return false
	}

	return true
}

func stdoutIsTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "zypheron",
		Short: "Zypheron - AI-Powered Penetration Testing Platform",
		Long:  "Zypheron CLI - AI-Powered Penetration Testing Platform with Kali Linux Integration",
		RunE: func(cmd *cobra.Command, args []string) error {
			if noTUI {
				return cmd.Help()
			}
			if err := commands.TUICmd().RunE(cmd, args); err != nil {
				return err
			}
			return nil
		},
	}
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if debug {
			os.Setenv("ZYPHERON_DEBUG", "1")
		}
		if noColor {
			ui.DisableColors()
		}
		if shouldShowStartupBanner(rootCmd, cmd) {
			_ = ui.PlayStartupBanner(os.Stdout, ui.StartupBannerOptions{
				Version:  "v" + version,
				Byline:   ui.StartupBannerByline,
				Animated: stdoutIsTTY() && !noColor,
				Color:    !noColor,
			})
		}
		if shouldAutoStartAI(cmd) {
			ensureAIEngineRunning()
		}
	}

	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug mode")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().BoolVar(&noBanner, "no-banner", false, "Disable ASCII banner")
	rootCmd.PersistentFlags().BoolVar(&noTUI, "no-tui", false, "Disable TUI (useful for developer/debug mode)")

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
	rootCmd.AddCommand(commands.AnalyzeCmd())
	rootCmd.AddCommand(commands.WorkflowCmd())
	rootCmd.AddCommand(commands.SchedulerCmd())
	rootCmd.AddCommand(commands.ClusterCmd())
	rootCmd.AddCommand(commands.PluginCmd())
	rootCmd.AddCommand(commands.MitreCmd())
	rootCmd.AddCommand(commands.FuzzCmd())
	rootCmd.AddCommand(commands.OsintCmd())
	rootCmd.AddCommand(commands.ThreatCmd())
	rootCmd.AddCommand(commands.ReportCmd())
	rootCmd.AddCommand(commands.DashboardCmd())
	rootCmd.AddCommand(commands.KaliCmd())
	rootCmd.AddCommand(commands.DoctorCmd())
	rootCmd.AddCommand(commands.SessionCmd())
	rootCmd.AddCommand(commands.TUICmd())
	rootCmd.AddCommand(commands.BountyCmd())
	rootCmd.AddCommand(commands.CloudCmd())
	rootCmd.AddCommand(commands.ADCmd())
	rootCmd.AddCommand(commands.InstallDepsCmd())

	// Desktop-bridge commands (login/logout/status). These talk to the
	// locally-running Zypheron Desktop app via 127.0.0.1 — see
	// internal/desktopbridge/ + Phase 0/1 of the bridge architecture.
	bridge.Register(rootCmd, version)

	// Version
	rootCmd.Version = version

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
		os.Exit(1)
	}
}
