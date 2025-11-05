//go:build windows

package aibridge

import (
	"fmt"
	"os"
)

// validateSocketOwnership validates the socket exists and is accessible (Windows)
// Note: Windows has different permission model, so we do basic checks
func validateSocketOwnership(socketPath string) error {
	info, err := os.Stat(socketPath)
	if err != nil {
		return fmt.Errorf("cannot stat socket: %w", err)
	}

	// On Windows, just verify the file exists and is accessible
	// Windows uses ACLs instead of Unix permissions
	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a socket")
	}

	// Additional Windows-specific checks could be added here
	// For now, if we can stat it, we assume it's accessible

	return nil
}

