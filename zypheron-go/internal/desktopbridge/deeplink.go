package desktopbridge

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// ErrLauncherUnavailable signals the caller should fall back to printing the
// URL for the user to open manually (SSH session, no DISPLAY, missing helper).
var ErrLauncherUnavailable = errors.New("no usable URL launcher available")

// OpenDeepLink hands `url` to the OS to dispatch to whichever handler is
// registered for `zypheron://`. Non-blocking — we exit the helper as soon as
// it has been spawned (`cmd.Start`, not `cmd.Run`) so the CLI can move on to
// the long-polling `/v1/auth/pair` call.
//
// Headless sessions (no DISPLAY/WAYLAND_DISPLAY on Linux, SSH connection
// anywhere) return ErrLauncherUnavailable so the caller can print the URL
// instead of silently spawning a helper that can never succeed.
func OpenDeepLink(url string) error {
	if IsHeadless() {
		return ErrLauncherUnavailable
	}
	prog, args, err := launcherFor(runtime.GOOS, url)
	if err != nil {
		return err
	}
	cmd := exec.Command(prog, args...)
	// Don't inherit stdio — `xdg-open` and friends sometimes spam to stderr.
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%w: %v", ErrLauncherUnavailable, err)
	}
	// Release the helper so it can outlive us and don't accumulate zombies.
	go func() { _ = cmd.Wait() }()
	return nil
}

// launcherFor returns the (program, args) pair to dispatch `url` on goos.
// Pulled out for unit testability.
func launcherFor(goos, url string) (string, []string, error) {
	switch goos {
	case "linux", "freebsd", "openbsd", "netbsd":
		if path, err := exec.LookPath("xdg-open"); err == nil {
			return path, []string{url}, nil
		}
		return "", nil, fmt.Errorf("%w: xdg-open not found in PATH", ErrLauncherUnavailable)
	case "darwin":
		if path, err := exec.LookPath("open"); err == nil {
			return path, []string{url}, nil
		}
		return "", nil, fmt.Errorf("%w: 'open' not found in PATH", ErrLauncherUnavailable)
	case "windows":
		// Avoid `cmd /c start` here — `cmd.exe` re-parses its arg list with
		// its own quoting rules (different from CRT argv), and characters
		// like `&`, `|`, `>` in the URL bypass standard escaping. We don't
		// build URLs from raw user input today, but a future caller might;
		// FileProtocolHandler is invoked directly with CommandLineToArgvW
		// semantics and treats the URL as a single opaque argument.
		// (M3 from the 2026-05-27 security review.)
		return "rundll32.exe", []string{"url.dll,FileProtocolHandler", url}, nil
	default:
		return "", nil, fmt.Errorf("%w: unsupported GOOS %q", ErrLauncherUnavailable, goos)
	}
}

// IsHeadless returns true when no GUI is reachable — SSH session, no X/Wayland
// display, or running under a CI/cron environment. The caller should print the
// deep-link URL for the user to open manually.
func IsHeadless() bool {
	if os.Getenv("SSH_TTY") != "" || os.Getenv("SSH_CONNECTION") != "" {
		return true
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "freebsd" {
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return true
		}
	}
	return false
}
