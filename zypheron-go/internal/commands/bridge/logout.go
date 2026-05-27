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

// LogoutCmd revokes the CLI's pairing with the desktop and wipes local
// credentials. If the desktop is unreachable we still purge local state so
// the user isn't trapped with stale creds.
func LogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke the CLI's pairing with the desktop and wipe stored credentials",
		RunE:  runLogout,
	}
}

func runLogout(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
	defer cancel()

	access, accessErr := desktopbridge.LoadAccessToken()
	if errors.Is(accessErr, desktopbridge.ErrNoCredentials) {
		fmt.Println(ui.InfoMsg("Already logged out — no stored credentials."))
		return nil
	}

	ep, epErr := desktopbridge.LoadEndpoint()
	if epErr == nil && accessErr == nil {
		if err := desktopbridge.RevokeSelf(ctx, ep, access); err != nil {
			fmt.Println(ui.WarningMsg("Could not reach desktop to revoke; wiping local credentials anyway."))
		}
	} else if epErr != nil {
		fmt.Println(ui.WarningMsg("Desktop unreachable; wiping local credentials only."))
	}

	if err := desktopbridge.DeleteTokens(); err != nil {
		return fmt.Errorf("wipe credentials: %w", err)
	}

	fmt.Println(ui.SuccessMsg("Logged out — credentials wiped from keyring."))
	return nil
}
