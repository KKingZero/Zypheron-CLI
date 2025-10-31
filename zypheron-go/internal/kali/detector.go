package kali

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Environment represents the Kali Linux environment
type Environment struct {
	IsKali       bool
	IsWSL        bool
	Version      string
	Distribution string
	WSLVersion   string
}

// DetectEnvironment detects if running on Kali Linux and/or WSL
func DetectEnvironment() (*Environment, error) {
	env := &Environment{}

	// Check if Kali Linux
	env.IsKali = isKaliLinux()
	if env.IsKali {
		env.Version = getKaliVersion()
	}

	// Check if WSL
	env.IsWSL = isWSL()
	if env.IsWSL {
		env.Distribution = getWSLDistribution()
		env.WSLVersion = getWSLVersion()
	}

	return env, nil
}

// isKaliLinux checks if running on Kali Linux
func isKaliLinux() bool {
	// Check /etc/os-release
	data, err := os.ReadFile("/etc/os-release")
	if err == nil {
		content := string(data)
		if strings.Contains(content, "Kali") || strings.Contains(content, "kali") {
			return true
		}
	}

	// Check for Kali-specific files
	if _, err := os.Stat("/etc/apt/sources.list.d/kali.list"); err == nil {
		return true
	}

	// Check dpkg for kali packages
	cmd := exec.Command("dpkg", "-l")
	output, err := cmd.Output()
	if err == nil {
		if strings.Contains(string(output), "kali-linux") {
			return true
		}
	}

	return false
}

// getKaliVersion gets the Kali Linux version
func getKaliVersion() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "Unknown"
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VERSION=") {
			version := strings.TrimPrefix(line, "VERSION=")
			version = strings.Trim(version, "\"")
			return version
		}
	}

	return "Unknown"
}

// isWSL checks if running in Windows Subsystem for Linux
func isWSL() bool {
	// Check /proc/version for Microsoft
	data, err := os.ReadFile("/proc/version")
	if err == nil {
		content := strings.ToLower(string(data))
		if strings.Contains(content, "microsoft") || strings.Contains(content, "wsl") {
			return true
		}
	}

	// Check for WSL interop
	if _, err := os.Stat("/proc/sys/fs/binfmt_misc/WSLInterop"); err == nil {
		return true
	}

	// Check environment variable
	if os.Getenv("WSL_DISTRO_NAME") != "" {
		return true
	}

	return false
}

// getWSLDistribution gets the WSL distribution name
func getWSLDistribution() string {
	if distro := os.Getenv("WSL_DISTRO_NAME"); distro != "" {
		return distro
	}
	return "Unknown"
}

// getWSLVersion gets the WSL version
func getWSLVersion() string {
	cmd := exec.Command("wsl.exe", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "WSL 1"
	}
	return strings.TrimSpace(string(output))
}

// PrintEnvironmentInfo prints the detected environment information
func (e *Environment) PrintInfo() {
	fmt.Println("╔═══ ENVIRONMENT DETECTED ═══════════════════════════╗")
	
	if e.IsKali {
		fmt.Printf("║  ✓ Kali Linux: %-40s║\n", e.Version)
	} else {
		fmt.Println("║  ⚠  Not running on Kali Linux                      ║")
	}

	if e.IsWSL {
		fmt.Printf("║  ℹ  WSL Environment: %-33s║\n", e.Distribution)
	}

	fmt.Println("╚════════════════════════════════════════════════════╝")
	fmt.Println()
}

