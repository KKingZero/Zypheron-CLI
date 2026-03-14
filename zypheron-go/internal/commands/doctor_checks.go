package commands

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tools"
)

// HealthCheck represents the result of a single health check
type HealthCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`  // "ok", "warning", "error"
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
	DocURL  string `json:"doc_url,omitempty"`
}

// DoctorReport represents the full system health report
type DoctorReport struct {
	Timestamp   string        `json:"timestamp"`
	OS          string        `json:"os"`
	Arch        string        `json:"arch"`
	GoVersion   string        `json:"go_version"`
	Checks      []HealthCheck `json:"checks"`
	Summary     Summary       `json:"summary"`
	Suggestions []string      `json:"suggestions,omitempty"`
}

// Summary provides aggregated health check statistics
type Summary struct {
	Total    int `json:"total"`
	Passed   int `json:"passed"`
	Warnings int `json:"warnings"`
	Errors   int `json:"errors"`
}

// checkPython verifies Python installation
func checkPython(verbose bool) HealthCheck {
	check := HealthCheck{
		Name:   "Python",
		DocURL: "https://docs.zypheron.io/setup/python",
	}

	// Try python3 first, then python
	for _, cmd := range []string{"python3", "python"} {
		path, err := exec.LookPath(cmd)
		if err != nil {
			continue
		}

		out, err := exec.Command(cmd, "--version").Output()
		if err != nil {
			continue
		}

		version := strings.TrimSpace(string(out))
		check.Status = "ok"
		check.Message = fmt.Sprintf("%s found", version)
		if verbose {
			check.Details = fmt.Sprintf("Path: %s, Version: %s", path, version)
		}
		return check
	}

	check.Status = "error"
	check.Message = "Python not found"
	check.Details = "Install Python 3.8+ from https://python.org"
	return check
}

// checkPythonDeps verifies Python dependencies are installed
func checkPythonDeps(verbose bool) HealthCheck {
	check := HealthCheck{
		Name:   "Python Dependencies",
		DocURL: "https://docs.zypheron.io/setup/python",
	}

	// Try to import key modules
	cmd := exec.Command("python3", "-c", "import zmq; import anthropic; print('ok')")
	out, err := cmd.Output()
	if err != nil {
		check.Status = "warning"
		check.Message = "Some Python dependencies may be missing"
		check.Details = "Run: pip install -r zypheron-ai/requirements.txt"
		return check
	}

	if strings.TrimSpace(string(out)) == "ok" {
		check.Status = "ok"
		check.Message = "Core dependencies installed"
		if verbose {
			check.Details = "zmq, anthropic modules verified"
		}
	} else {
		check.Status = "warning"
		check.Message = "Python dependencies check inconclusive"
		check.Details = "Run: pip install -r zypheron-ai/requirements.txt"
	}

	return check
}

// checkAIEngine verifies the AI engine is running
func checkAIEngine(verbose bool) HealthCheck {
	check := HealthCheck{
		Name:   "AI Engine",
		DocURL: "https://docs.zypheron.io/ai/engine",
	}

	// Check if AI engine socket exists
	homeDir, _ := os.UserHomeDir()
	socketPath := filepath.Join(homeDir, ".zypheron", "ai.sock")

	if _, err := os.Stat(socketPath); err == nil {
		check.Status = "ok"
		check.Message = "AI Engine socket found"
		if verbose {
			check.Details = fmt.Sprintf("Socket: %s", socketPath)
		}
	} else {
		check.Status = "warning"
		check.Message = "AI Engine is not running"
		check.Details = "Start with: cd zypheron-ai && python server.py"
	}

	return check
}

// checkSecurityTools verifies security tools are installed
func checkSecurityTools(verbose bool) HealthCheck {
	check := HealthCheck{
		Name:   "Security Tools",
		DocURL: "https://docs.zypheron.io/tools/installation",
	}

	allTools := tools.CheckAllTools()
	installed := 0
	for _, t := range allTools {
		if t.Installed {
			installed++
		}
	}

	total := len(allTools)
	if installed == total {
		check.Status = "ok"
		check.Message = fmt.Sprintf("All %d tools installed", total)
	} else if installed > total/2 {
		check.Status = "warning"
		check.Message = fmt.Sprintf("%d/%d tools installed", installed, total)
	} else {
		check.Status = "error"
		check.Message = fmt.Sprintf("Only %d/%d tools installed", installed, total)
	}

	if verbose {
		missing := tools.GetMissingTools()
		names := make([]string, 0, len(missing))
		for _, m := range missing {
			names = append(names, m.Tool.Name)
		}
		if len(names) > 0 {
			check.Details = fmt.Sprintf("Missing: %s", strings.Join(names, ", "))
		}
	}

	return check
}

// checkConfigDir verifies the configuration directory
func checkConfigDir(verbose bool) HealthCheck {
	check := HealthCheck{
		Name:   "Configuration",
		DocURL: "https://docs.zypheron.io/getting-started/setup",
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		check.Status = "error"
		check.Message = "Cannot determine home directory"
		return check
	}

	configDir := filepath.Join(homeDir, ".zypheron")
	if info, err := os.Stat(configDir); err == nil && info.IsDir() {
		check.Status = "ok"
		check.Message = "Configuration directory exists"
		if verbose {
			check.Details = fmt.Sprintf("Path: %s", configDir)
		}
	} else {
		check.Status = "warning"
		check.Message = "Configuration directory not found"
		check.Details = "Run: zypheron setup"
	}

	return check
}

// checkAPIKeys verifies AI provider API keys are configured
func checkAPIKeys(verbose bool) HealthCheck {
	check := HealthCheck{
		Name:   "API Keys",
		DocURL: "https://docs.zypheron.io/configuration/api-keys",
	}

	providers := map[string]string{
		"Claude":   "ANTHROPIC_API_KEY",
		"OpenAI":   "OPENAI_API_KEY",
		"Google":   "GOOGLE_API_KEY",
		"DeepSeek": "DEEPSEEK_API_KEY",
	}

	configured := []string{}
	for name, envVar := range providers {
		if os.Getenv(envVar) != "" {
			configured = append(configured, name)
		}
	}

	if len(configured) == 0 {
		check.Status = "warning"
		check.Message = "No API keys configured (BYOK requires at least one)"
		check.Details = "Set via: zypheron config set-key <provider> <key>"
	} else if len(configured) == 1 {
		check.Status = "ok"
		check.Message = fmt.Sprintf("%s API key configured", configured[0])
	} else {
		check.Status = "ok"
		check.Message = fmt.Sprintf("Configured: %s", strings.Join(configured, ", "))
	}

	return check
}

// checkNetworkConnectivity verifies basic network connectivity
func checkNetworkConnectivity(verbose bool) HealthCheck {
	check := HealthCheck{
		Name:   "Network",
		DocURL: "https://docs.zypheron.io/troubleshooting/network",
	}

	conn, err := net.DialTimeout("tcp", "api.github.com:443", 5*time.Second)
	if err != nil {
		check.Status = "warning"
		check.Message = "Network connectivity limited"
		check.Details = fmt.Sprintf("Cannot reach api.github.com: %v", err)
		return check
	}
	conn.Close()

	check.Status = "ok"
	check.Message = "Network connectivity OK"
	if verbose {
		check.Details = "Successfully connected to api.github.com:443"
	}

	return check
}

// checkDiskSpace verifies available disk space
func checkDiskSpace(verbose bool) HealthCheck {
	check := HealthCheck{
		Name:   "Disk Space",
		DocURL: "https://docs.zypheron.io/troubleshooting",
	}

	homeDir, _ := os.UserHomeDir()
	var stat syscall.Statfs_t
	if err := syscall.Statfs(homeDir, &stat); err != nil {
		check.Status = "warning"
		check.Message = "Cannot determine disk space"
		return check
	}

	availableGB := float64(stat.Bavail*uint64(stat.Bsize)) / (1024 * 1024 * 1024)

	if availableGB < 1.0 {
		check.Status = "warning"
		check.Message = fmt.Sprintf("Low disk space: %.1f GB available", availableGB)
	} else {
		check.Status = "ok"
		check.Message = fmt.Sprintf("%.1f GB available", availableGB)
	}

	if verbose {
		check.Details = fmt.Sprintf("Path: %s, Available: %.2f GB", homeDir, availableGB)
	}

	return check
}

// generateSuggestions creates actionable suggestions based on health check results
func generateSuggestions(checks []HealthCheck) []string {
	var suggestions []string

	for _, check := range checks {
		if check.Status == "ok" {
			continue
		}

		switch check.Name {
		case "Python":
			suggestions = append(suggestions, "Install Python 3.8+ from https://python.org")
		case "Python Dependencies":
			suggestions = append(suggestions, "Install Python dependencies: pip install -r zypheron-ai/requirements.txt")
		case "AI Engine":
			suggestions = append(suggestions, "Start the AI engine: cd zypheron-ai && python server.py")
		case "Security Tools":
			suggestions = append(suggestions, "Install missing tools: zypheron tools install-all")
		case "Configuration":
			suggestions = append(suggestions, "Run initial setup: zypheron setup")
		case "API Keys":
			suggestions = append(suggestions, "Configure API keys: zypheron config set-key <provider> <key>")
		case "Network":
			suggestions = append(suggestions, "Check network connectivity and firewall settings")
		case "Disk Space":
			suggestions = append(suggestions, "Free up disk space for scan results and reports")
		}
	}

	return suggestions
}
