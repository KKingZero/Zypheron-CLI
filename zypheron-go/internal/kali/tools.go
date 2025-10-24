package kali

import (
	"fmt"
	"os/exec"
	"strings"
)

// Tool represents a Kali security tool
type Tool struct {
	Name        string
	Command     string
	Description string
	Category    string
	Priority    string
	Installed   bool
	Version     string
	InstallCmd  string
	RequiredFor []string
	Aliases     []string
}

// ToolManager manages Kali tools
type ToolManager struct {
	tools []Tool
}

// NewToolManager creates a new ToolManager
func NewToolManager() *ToolManager {
	return &ToolManager{
		tools: getDefaultTools(),
	}
}

// DetectTools detects which tools are installed
func (tm *ToolManager) DetectTools() error {
	for i := range tm.tools {
		tool := &tm.tools[i]
		
		// Check if command exists
		_, err := exec.LookPath(tool.Command)
		tool.Installed = err == nil
		
		if tool.Installed {
			// Get version
			tool.Version = getToolVersion(tool.Command)
		}
	}
	return nil
}

// GetStats returns statistics about installed tools
func (tm *ToolManager) GetStats() Stats {
	stats := Stats{}
	stats.Total = len(tm.tools)
	
	for _, tool := range tm.tools {
		if tool.Installed {
			stats.Installed++
		} else {
			stats.Missing++
			if tool.Priority == "critical" {
				stats.Critical++
			} else if tool.Priority == "high" {
				stats.High++
			}
		}
	}
	
	return stats
}

// Stats represents tool statistics
type Stats struct {
	Total     int
	Installed int
	Missing   int
	Critical  int
	High      int
}

// GetTool returns a tool by name
func (tm *ToolManager) GetTool(name string) *Tool {
	for i := range tm.tools {
		if tm.tools[i].Name == name || tm.tools[i].Command == name {
			return &tm.tools[i]
		}
		// Check aliases
		for _, alias := range tm.tools[i].Aliases {
			if alias == name {
				return &tm.tools[i]
			}
		}
	}
	return nil
}

// GetAllTools returns all tools
func (tm *ToolManager) GetAllTools() []Tool {
	return tm.tools
}

// IsInstalled checks if a tool is installed
func (tm *ToolManager) IsInstalled(name string) bool {
	tool := tm.GetTool(name)
	return tool != nil && tool.Installed
}

// GetInstallCommand returns the install command for a tool
func (tm *ToolManager) GetInstallCommand(name string) string {
	tool := tm.GetTool(name)
	if tool != nil {
		return tool.InstallCmd
	}
	return fmt.Sprintf("sudo apt-get install -y %s", name)
}

// Install installs a tool
func (tm *ToolManager) Install(name string) error {
	tool := tm.GetTool(name)
	if tool == nil {
		return fmt.Errorf("tool not found: %s", name)
	}

	fmt.Printf("Installing %s...\n", tool.Name)
	
	cmd := exec.Command("sh", "-c", tool.InstallCmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("installation failed: %s\n%s", err, string(output))
	}

	// Re-detect tools
	tm.DetectTools()
	
	return nil
}

// SuggestTool suggests the best tool for a task
func (tm *ToolManager) SuggestTool(task string) *Tool {
	taskMap := map[string]string{
		"scan":       "nmap",
		"portscan":   "nmap",
		"web":        "nikto",
		"webscan":    "nikto",
		"vuln":       "nuclei",
		"exploit":    "metasploit",
		"bruteforce": "hydra",
		"password":   "john",
		"recon":      "nmap",
		"osint":      "theharvester",
		"wireless":   "aircrack-ng",
		"fuzz":       "ffuf",
	}

	toolName, exists := taskMap[strings.ToLower(task)]
	if !exists {
		return nil
	}

	return tm.GetTool(toolName)
}

// getToolVersion gets the version of a tool
func getToolVersion(command string) string {
	// Try --version
	cmd := exec.Command(command, "--version")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) > 0 {
			return strings.TrimSpace(lines[0])
		}
	}

	// Try -v
	cmd = exec.Command(command, "-v")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) > 0 {
			return strings.TrimSpace(lines[0])
		}
	}

	return "installed"
}

// getDefaultTools returns the default list of tools
func getDefaultTools() []Tool {
	return []Tool{
		{
			Name:        "nmap",
			Command:     "nmap",
			Description: "Network exploration and security auditing",
			Category:    "scanner",
			Priority:    "critical",
			InstallCmd:  "sudo apt-get install -y nmap",
			RequiredFor: []string{"scan", "recon"},
			Aliases:     []string{},
		},
		{
			Name:        "nikto",
			Command:     "nikto",
			Description: "Web server scanner",
			Category:    "web",
			Priority:    "high",
			InstallCmd:  "sudo apt-get install -y nikto",
			RequiredFor: []string{"web-scan"},
			Aliases:     []string{},
		},
		{
			Name:        "nuclei",
			Command:     "nuclei",
			Description: "Fast vulnerability scanner",
			Category:    "scanner",
			Priority:    "high",
			InstallCmd:  "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
			RequiredFor: []string{"vuln-scan"},
			Aliases:     []string{},
		},
		{
			Name:        "masscan",
			Command:     "masscan",
			Description: "Fast TCP port scanner",
			Category:    "scanner",
			Priority:    "medium",
			InstallCmd:  "sudo apt-get install -y masscan",
			RequiredFor: []string{"fast-scan"},
			Aliases:     []string{},
		},
		{
			Name:        "sqlmap",
			Command:     "sqlmap",
			Description: "Automatic SQL injection tool",
			Category:    "web",
			Priority:    "high",
			InstallCmd:  "sudo apt-get install -y sqlmap",
			RequiredFor: []string{"sql-injection"},
			Aliases:     []string{},
		},
		{
			Name:        "hydra",
			Command:     "hydra",
			Description: "Network logon cracker",
			Category:    "bruteforce",
			Priority:    "high",
			InstallCmd:  "sudo apt-get install -y hydra",
			RequiredFor: []string{"bruteforce"},
			Aliases:     []string{"thc-hydra"},
		},
		{
			Name:        "john",
			Command:     "john",
			Description: "John the Ripper password cracker",
			Category:    "bruteforce",
			Priority:    "high",
			InstallCmd:  "sudo apt-get install -y john",
			RequiredFor: []string{"password-crack"},
			Aliases:     []string{"john-the-ripper"},
		},
		{
			Name:        "hashcat",
			Command:     "hashcat",
			Description: "Advanced password recovery",
			Category:    "bruteforce",
			Priority:    "medium",
			InstallCmd:  "sudo apt-get install -y hashcat",
			RequiredFor: []string{"password-crack"},
			Aliases:     []string{},
		},
		{
			Name:        "metasploit",
			Command:     "msfconsole",
			Description: "Penetration testing framework",
			Category:    "exploit",
			Priority:    "critical",
			InstallCmd:  "sudo apt-get install -y metasploit-framework",
			RequiredFor: []string{"exploit"},
			Aliases:     []string{"msf", "msfconsole"},
		},
		{
			Name:        "gobuster",
			Command:     "gobuster",
			Description: "Directory/file & DNS busting tool",
			Category:    "web",
			Priority:    "medium",
			InstallCmd:  "sudo apt-get install -y gobuster",
			RequiredFor: []string{"web-scan"},
			Aliases:     []string{},
		},
		{
			Name:        "ffuf",
			Command:     "ffuf",
			Description: "Fast web fuzzer",
			Category:    "web",
			Priority:    "medium",
			InstallCmd:  "go install github.com/ffuf/ffuf/v2@latest",
			RequiredFor: []string{"fuzz"},
			Aliases:     []string{},
		},
		{
			Name:        "subfinder",
			Command:     "subfinder",
			Description: "Subdomain discovery tool",
			Category:    "recon",
			Priority:    "medium",
			InstallCmd:  "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
			RequiredFor: []string{"recon"},
			Aliases:     []string{},
		},
		{
			Name:        "amass",
			Command:     "amass",
			Description: "In-depth DNS enumeration",
			Category:    "recon",
			Priority:    "medium",
			InstallCmd:  "sudo apt-get install -y amass",
			RequiredFor: []string{"recon"},
			Aliases:     []string{},
		},
		{
			Name:        "theharvester",
			Command:     "theharvester",
			Description: "E-mail, subdomain harvester",
			Category:    "osint",
			Priority:    "medium",
			InstallCmd:  "sudo apt-get install -y theharvester",
			RequiredFor: []string{"osint"},
			Aliases:     []string{"harvester"},
		},
		{
			Name:        "aircrack-ng",
			Command:     "aircrack-ng",
			Description: "WiFi security auditing tools",
			Category:    "wireless",
			Priority:    "low",
			InstallCmd:  "sudo apt-get install -y aircrack-ng",
			RequiredFor: []string{"wireless"},
			Aliases:     []string{},
		},
	}
}

