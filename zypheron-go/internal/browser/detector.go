package browser

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// CheckChromiumInstalled checks if Chromium is installed and returns installation instructions
func CheckChromiumInstalled() (bool, string, []string) {
	var installInstructions []string

	// Try to find chromium/chrome binary
	possibleNames := []string{"chromium", "chromium-browser", "chrome", "google-chrome", "chromium-browser-stable"}
	var foundBinary string

	for _, name := range possibleNames {
		if path, err := exec.LookPath(name); err == nil {
			foundBinary = path
			break
		}
	}

	if foundBinary != "" {
		// Verify it's actually chromium/chrome by checking version
		cmd := exec.Command(foundBinary, "--version")
		if output, err := cmd.Output(); err == nil {
			version := strings.TrimSpace(string(output))
			return true, version, nil
		}
	}

	// Not found - provide platform-specific instructions
	switch runtime.GOOS {
	case "linux":
		installInstructions = []string{
			"Ubuntu/Debian: sudo apt-get update && sudo apt-get install chromium-browser",
			"Fedora/RHEL: sudo dnf install chromium",
			"Arch Linux: sudo pacman -S chromium",
			"Or download from: https://www.chromium.org/getting-involved/download-chromium",
		}
	case "darwin":
		installInstructions = []string{
			"Install via Homebrew: brew install --cask chromium",
			"Or download from: https://www.chromium.org/getting-involved/download-chromium",
		}
	case "windows":
		installInstructions = []string{
			"Download Chromium from: https://www.chromium.org/getting-involved/download-chromium",
			"Or install Chrome: https://www.google.com/chrome/",
		}
	default:
		installInstructions = []string{
			"Install Chromium from: https://www.chromium.org/getting-involved/download-chromium",
		}
	}

	return false, "", installInstructions
}

// GetChromiumInstallMessage returns a formatted error message with installation instructions
func GetChromiumInstallMessage() string {
	installed, version, instructions := CheckChromiumInstalled()
	if installed {
		return fmt.Sprintf("Chromium found: %s", version)
	}

	var msg strings.Builder
	msg.WriteString("Chromium is not installed or not found in PATH.\n\n")
	msg.WriteString("Installation instructions:\n")
	for _, instruction := range instructions {
		msg.WriteString(fmt.Sprintf("  • %s\n", instruction))
	}
	msg.WriteString("\nAfter installation, verify with: chromium --version")

	return msg.String()
}

