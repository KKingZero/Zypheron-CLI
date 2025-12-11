//go:build unix

package aibridge

import (
	"fmt"
	"os"
	"syscall"
)

// validateSocketOwnership validates the socket is owned by the current user (Unix/Linux)
func validateSocketOwnership(socketPath string) error {
	info, err := os.Stat(socketPath)
	if err != nil {
		return fmt.Errorf("cannot stat socket: %w", err)
	}

	// Check if it's a socket
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("path is not a socket")
	}

	// Get file system info
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("failed to get socket ownership info")
	}

	// Verify ownership
	currentUID := uint32(os.Getuid())
	if stat.Uid != currentUID {
		return fmt.Errorf("socket owned by UID %d, current UID is %d", stat.Uid, currentUID)
	}

	// Verify permissions are restrictive (owner-only)
	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		return fmt.Errorf("socket has insecure permissions: %o", perm)
	}

	return nil
}

