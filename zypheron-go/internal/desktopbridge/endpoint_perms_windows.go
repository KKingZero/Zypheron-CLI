//go:build windows

package desktopbridge

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// verifyEndpointFilePerms on Windows can't use POSIX UID/mode checks. Instead
// we enforce that the endpoint file resolves inside the current user's home
// directory (no symlink escape) and exists as a regular file. The Windows
// per-user profile dir is ACL-protected by the OS so cross-user tampering
// is mostly precluded by the surrounding filesystem.
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
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("%w: resolve home: %v", ErrEndpointInsecure, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("%w: resolve abs path: %v", ErrEndpointInsecure, err)
	}
	if !strings.HasPrefix(strings.ToLower(abs), strings.ToLower(home)) {
		return fmt.Errorf("%w: %s is not inside user home %s", ErrEndpointInsecure, abs, home)
	}
	return nil
}
