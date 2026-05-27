package bridge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/desktopbridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
)

// LoginCmd pairs this CLI with the locally-running Zypheron Desktop app.
// Per architecture decision 2: this command does NOT touch Supabase / cloud
// licensing — that's `zypheron auth login`. This binds the CLI to *this
// desktop instance* via a loopback bearer token.
func LoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Pair this CLI with the local Zypheron Desktop app",
		Long: `Pair this CLI with the Zypheron Desktop app running on this machine.

The CLI mints a nonce, opens the deep link zypheron://pair?nonce=..., and
the desktop pops a modal asking the user to approve. Once approved, the
desktop returns a token pair that's stored in the OS keyring.

This is local-only — no traffic leaves 127.0.0.1.`,
		RunE: runLogin,
	}
}

func runLogin(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), desktopbridge.PairTimeout+30*time.Second)
	defer cancel()

	ep, err := desktopbridge.LoadEndpoint()
	if err != nil {
		if errors.Is(err, desktopbridge.ErrEndpointMissing) {
			fmt.Println(ui.WarningMsg("Zypheron Desktop is not running."))
			fmt.Println(ui.InfoMsg("Start the desktop app, then run `zypheron login` again."))
			return fmt.Errorf("desktop not running")
		}
		return err
	}
	if err := ep.Reach(); err != nil {
		fmt.Println(ui.WarningMsg("Desktop endpoint file exists but the server isn't responding."))
		fmt.Println(ui.InfoMsg("Restart the Zypheron Desktop app and retry."))
		return err
	}

	hs, err := desktopbridge.Handshake(ctx, ep)
	if err != nil {
		if errors.Is(err, desktopbridge.ErrClientTooOld) {
			fmt.Println(ui.WarningMsg(fmt.Sprintf("This CLI is too old for the running desktop (cli=%s).", desktopbridge.ClientVersion)))
			fmt.Println(ui.InfoMsg("Upgrade the CLI and retry."))
		}
		return err
	}

	nonce, err := desktopbridge.GenerateNonce()
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "zypheron-cli"
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	url := desktopbridge.BuildPairURL(nonce, hostname, cliVersion, platform)

	fmt.Println(ui.InfoMsg(fmt.Sprintf("Pairing with desktop v%s (protocol %s)...", hs.ProductVersion, hs.ProtocolVersion)))

	if err := desktopbridge.OpenDeepLink(url); err != nil {
		// Headless or launcher missing — fall back to printing the URL.
		// H1 from the 2026-05-27 security review: refuse to print a
		// nonce-bearing URL in CI environments where stdout is harvested
		// into log collectors. The CI operator must run `zypheron login`
		// from an interactive terminal instead.
		if isHostedCI() {
			fmt.Println(ui.WarningMsg("Cannot pair from a CI environment — the deep-link URL carries a one-shot nonce that would be persisted in build logs."))
			fmt.Println(ui.InfoMsg("Run `zypheron login` from an interactive terminal on the same machine as the desktop."))
			return fmt.Errorf("refusing to print pairing nonce in CI environment")
		}
		fmt.Println(ui.WarningMsg("Could not auto-open the pairing link; open the URL below in a browser on this machine:"))
		fmt.Println()
		fmt.Println("  " + url)
		fmt.Println()
	} else {
		fmt.Println(ui.InfoMsg("Approve the pairing request in the desktop modal."))
	}

	pair, err := desktopbridge.RequestPair(ctx, ep, nonce, hostname, cliVersion, platform)
	if err != nil {
		switch {
		case errors.Is(err, desktopbridge.ErrPairDenied):
			fmt.Println(ui.WarningMsg("Pairing denied by the desktop user."))
		case errors.Is(err, desktopbridge.ErrPairExpired):
			fmt.Println(ui.WarningMsg("Pairing nonce expired before the modal could be approved."))
		case errors.Is(err, desktopbridge.ErrPairTimeout):
			fmt.Println(ui.WarningMsg("Pairing timed out waiting for user approval."))
		}
		return err
	}

	if err := desktopbridge.SaveTokens(*pair); err != nil {
		return fmt.Errorf("save tokens: %w", err)
	}

	fmt.Println(ui.SuccessMsg(fmt.Sprintf(
		"Paired — access token expires in %dm, refresh in %dd.",
		pair.AccessExpiresIn/60,
		pair.RefreshExpiresIn/86400,
	)))
	return nil
}

// isHostedCI returns true when conventional CI env signals are set. Used to
// refuse printing the nonce-bearing deep-link URL where stdout might be
// captured into log retention.
func isHostedCI() bool {
	for _, k := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "BUILDKITE", "JENKINS_URL", "TF_BUILD"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}
