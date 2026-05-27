package bridge

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/desktopbridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
)

// StatusCmd reports on the bridge connection: is the desktop reachable, what
// protocol it speaks, and whether this CLI is paired.
func StatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report Zypheron Desktop bridge status and pairing state",
		RunE:  runStatus,
	}
}

func runStatus(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
	defer cancel()

	ep, err := desktopbridge.LoadEndpoint()
	if err != nil {
		if errors.Is(err, desktopbridge.ErrEndpointMissing) {
			fmt.Println(ui.WarningMsg("Zypheron Desktop: not running"))
			fmt.Println(ui.InfoMsg("Start the desktop app to enable the CLI bridge."))
			return nil
		}
		fmt.Println(ui.WarningMsg("Endpoint file unreadable: " + err.Error()))
		return nil
	}
	if err := ep.Reach(); err != nil {
		fmt.Println(ui.WarningMsg("Zypheron Desktop: unreachable (endpoint file stale)"))
		fmt.Printf("  url:      %s\n", ep.URL)
		fmt.Printf("  pid:      %d (may have exited)\n", ep.PID)
		return nil
	}

	hs, err := desktopbridge.Handshake(ctx, ep)
	if err != nil {
		fmt.Println(ui.WarningMsg("Handshake failed: " + err.Error()))
		return nil
	}

	fmt.Println(ui.SuccessMsg("Zypheron Desktop: connected"))
	fmt.Printf("  url:              %s\n", ep.URL)
	fmt.Printf("  product:          v%s\n", hs.ProductVersion)
	fmt.Printf("  protocol:         %s\n", hs.ProtocolVersion)
	fmt.Printf("  min CLI version:  %s\n", hs.MinClientVersion)
	fmt.Printf("  features:         %v\n", hs.Features)

	if _, err := desktopbridge.LoadAccessToken(); errors.Is(err, desktopbridge.ErrNoCredentials) {
		fmt.Println(ui.WarningMsg("Not paired. Run `zypheron login` to pair this CLI."))
		return nil
	}

	fmt.Println(ui.SuccessMsg("Paired — credentials available."))
	return nil
}
