//go:build unix

package aibridge

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// validateSocketOwnership validates the socket is owned by the current user (Unix/Linux)
// Security: Ensures socket has owner-only permissions (0600) to prevent unauthorized access
func validateSocketOwnership(socketPath string) error {
	// SECURITY: Resolve symlinks before any checks to prevent symlink attacks
	resolvedPath, err := filepath.EvalSymlinks(socketPath)
	if err != nil {
		return fmt.Errorf("cannot resolve socket path (possible symlink attack): %w", err)
	}
	if resolvedPath != socketPath {
		return fmt.Errorf("socket path contains symlinks: %s -> %s (security risk)", socketPath, resolvedPath)
	}

	// SECURITY: Validate parent directory ownership and permissions
	parentDir := filepath.Dir(resolvedPath)
	parentInfo, err := os.Stat(parentDir)
	if err != nil {
		return fmt.Errorf("cannot stat socket parent directory: %w", err)
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("failed to get parent directory ownership info")
	}
	currentUID := uint32(os.Getuid())
	if parentStat.Uid != currentUID {
		return fmt.Errorf("socket parent directory owned by UID %d, current UID is %d (security risk)", parentStat.Uid, currentUID)
	}
	parentPerm := parentInfo.Mode().Perm()
	if parentPerm&0077 != 0 {
		return fmt.Errorf("socket parent directory has insecure permissions: %03o (expected 0700)", uint32(parentPerm))
	}

	info, err := os.Lstat(resolvedPath)
	if err != nil {
		return fmt.Errorf("cannot stat socket: %w", err)
	}

	// Check if it's a socket (not a symlink or regular file)
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("path is not a socket: %s", resolvedPath)
	}

	// Get file system info
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("failed to get socket ownership info")
	}

	// Verify ownership - socket must be owned by current user
	if stat.Uid != currentUID {
		return fmt.Errorf("socket owned by UID %d, current UID is %d (security risk)", stat.Uid, currentUID)
	}

	// Verify permissions are restrictive (owner-only, no group or other)
	// 0600 = owner read/write only
	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		return fmt.Errorf("socket has insecure permissions: %03o (expected 0600, got group/other access)", uint32(perm))
	}

	return nil
}

