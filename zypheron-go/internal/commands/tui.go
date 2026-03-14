package commands

import (
	"fmt"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

// TUICmd returns the tui command for explicitly launching the TUI
func TUICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Launch the interactive TUI dashboard",
		Long: `Launch the Zypheron Terminal User Interface (TUI).

The TUI provides an interactive dashboard for:
  • Real-time scan monitoring
  • Vulnerability browsing
  • AI-powered analysis
  • Scan history management

KEYBOARD SHORTCUTS:
  S         Switch to Scan view
  R         Switch to Recon view
  A         Focus AI assistant panel
  T         Switch to Tools view
  H         Switch to History view
  D         Switch to Dashboard view
  :         Open command palette
  /         Search/filter
  ?         Show help
  q         Quit

NOTE: Running 'zypheron' without any command also launches the TUI.
Use 'zypheron --no-tui' to disable this behavior.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := tui.Start(); err != nil {
				fmt.Println(ui.Error(fmt.Sprintf("TUI error: %v", err)))
				return err
			}
			return nil
		},
	}

	return cmd
}
