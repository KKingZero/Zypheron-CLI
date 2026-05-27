// Package bridge contains Cobra commands that interact with the local
// Zypheron Desktop app via the Control API. These commands are the entry
// points for the desktop-primary product model — `zypheron login` and
// friends. Codegened siblings will live in the `generated/` sub-package
// once Phase 2 lands.
package bridge

import (
	"github.com/spf13/cobra"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/commands/bridge/generated"
)

// cliVersion is set by Register so individual commands can advertise their
// version in pair/handshake metadata without crossing import boundaries
// back to cmd/zypheron/main.go.
var cliVersion = "0.0.0-dev"

// Register wires the bridge commands into the supplied root Cobra command.
// Pass the CLI's build-stamped version string so bridge commands can include
// it in pair-request metadata shown in the desktop modal.
func Register(root *cobra.Command, version string) {
	if version != "" {
		cliVersion = version
	}
	root.AddCommand(
		LoginCmd(),
		LogoutCmd(),
		StatusCmd(),
	)
	// Mount the codegen-produced bridge subtrees (scope, scans, findings,
	// approvals, sessions). The generator emits a single RegisterGenerated
	// entrypoint per the cobragen template.
	generated.RegisterGenerated(root)
}
