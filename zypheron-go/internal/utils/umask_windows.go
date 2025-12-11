//go:build windows

package utils

// syscallUmask is a no-op on Windows (umask doesn't exist)
// Windows uses different permission model (ACLs instead of Unix permissions)
func syscallUmask(mask int) int {
	_ = mask // Unused on Windows
	// Return 0 to indicate no previous mask
	return 0
}
