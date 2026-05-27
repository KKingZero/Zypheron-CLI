//go:build !windows

package desktopbridge

import (
	"fmt"
	"os"
	"syscall"
)

// verifyEndpointFilePerms enforces three invariants:
//  1. The file is owned by the current effective UID. A different-UID file
//     in our home dir signals tampering by another local user — refuse it.
//  2. The mode disallows group/other write (the desktop writes 0600;
//     anything looser was changed by a third party or a careless tool).
//  3. The path is a regular file, not a symlink to elsewhere. Use Lstat so
//     a symlink swap can't redirect us at a path with weaker perms.
func verifyEndpointFilePerms(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrEndpointMissing
		}
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrEndpointInsecure, path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrEndpointInsecure, path)
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: stat syscall payload missing on this platform", ErrEndpointInsecure)
	}
	if sys.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("%w: %s is owned by uid %d, expected %d", ErrEndpointInsecure, path, sys.Uid, os.Getuid())
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s mode %v allows group/other access", ErrEndpointInsecure, path, fi.Mode().Perm())
	}
	return nil
}
