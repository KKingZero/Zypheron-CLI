package tools

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ToolInfo contains information about a security tool
type ToolInfo struct {
	Name        string
	Command     string   // command to check existence
	InstallCmd  string   // apt/brew install command
	ManualURL   string   // manual install URL
	Description string
	Required    bool     // true = critical, false = optional
	Categories  []string // scan, web, exploit, recon
}

// ToolStatus represents the installation status of a tool
type ToolStatus struct {
	Tool      ToolInfo
	Installed bool
	Version   string
	Path      string
}

// Registry of supported security tools
var ToolRegistry = []ToolInfo{
	{
		Name:        "nmap",
		Command:     "nmap",
		InstallCmd:  "nmap",
		ManualURL:   "https://nmap.org/download.html",
		Description: "Network scanner & service detection",
		Required:    true,
		Categories:  []string{"scan", "recon"},
	},
	{
		Name:        "nikto",
		Command:     "nikto",
		InstallCmd:  "nikto",
		ManualURL:   "https://github.com/sullo/nikto",
		Description: "Web vulnerability scanner",
		Required:    false,
		Categories:  []string{"web", "scan"},
	},
	{
		Name:        "nuclei",
		Command:     "nuclei",
		InstallCmd:  "nuclei", // go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
		ManualURL:   "https://github.com/projectdiscovery/nuclei",
		Description: "Template-based vulnerability scanner",
		Required:    false,
		Categories:  []string{"web", "scan"},
	},
	{
		Name:        "httpx",
		Command:     "httpx",
		InstallCmd:  "httpx",
		ManualURL:   "https://github.com/projectdiscovery/httpx",
		Description: "HTTP probing and tech detection",
		Required:    false,
		Categories:  []string{"web", "recon"},
	},
	{
		Name:        "katana",
		Command:     "katana",
		InstallCmd:  "katana",
		ManualURL:   "https://github.com/projectdiscovery/katana",
		Description: "Web crawler/spider",
		Required:    false,
		Categories:  []string{"web", "recon"},
	},
	{
		Name:        "gau",
		Command:     "gau",
		InstallCmd:  "gau",
		ManualURL:   "https://github.com/lc/gau",
		Description: "GetAllUrls from public sources",
		Required:    false,
		Categories:  []string{"web", "recon"},
	},
	{
		Name:        "waybackurls",
		Command:     "waybackurls",
		InstallCmd:  "waybackurls",
		ManualURL:   "https://github.com/tomnomnom/waybackurls",
		Description: "Archive URL discovery (Wayback)",
		Required:    false,
		Categories:  []string{"web", "recon"},
	},
	{
		Name:        "assetfinder",
		Command:     "assetfinder",
		InstallCmd:  "assetfinder",
		ManualURL:   "https://github.com/tomnomnom/assetfinder",
		Description: "Subdomain discovery",
		Required:    false,
		Categories:  []string{"recon"},
	},
	{
		Name:        "gobuster",
		Command:     "gobuster",
		InstallCmd:  "gobuster",
		ManualURL:   "https://github.com/OJ/gobuster",
		Description: "Directory/DNS bruteforcing",
		Required:    false,
		Categories:  []string{"web", "recon"},
	},
	{
		Name:        "ffuf",
		Command:     "ffuf",
		InstallCmd:  "ffuf",
		ManualURL:   "https://github.com/ffuf/ffuf",
		Description: "Fast web fuzzer",
		Required:    false,
		Categories:  []string{"web"},
	},
	{
		Name:        "feroxbuster",
		Command:     "feroxbuster",
		InstallCmd:  "feroxbuster",
		ManualURL:   "https://github.com/epi052/feroxbuster",
		Description: "Fast directory discovery",
		Required:    false,
		Categories:  []string{"web", "scan"},
	},
	{
		Name:        "dirsearch",
		Command:     "dirsearch",
		InstallCmd:  "dirsearch",
		ManualURL:   "https://github.com/maurosoria/dirsearch",
		Description: "Web path discovery",
		Required:    false,
		Categories:  []string{"web", "scan"},
	},
	{
		Name:        "wfuzz",
		Command:     "wfuzz",
		InstallCmd:  "wfuzz",
		ManualURL:   "https://github.com/xmendez/wfuzz",
		Description: "Web/API fuzzing",
		Required:    false,
		Categories:  []string{"web", "api"},
	},
	{
		Name:        "kiterunner",
		Command:     "kr",
		InstallCmd:  "kiterunner",
		ManualURL:   "https://github.com/assetnote/kiterunner",
		Description: "API endpoint discovery (kiterunner)",
		Required:    false,
		Categories:  []string{"api", "recon"},
	},
	{
		Name:        "sqlmap",
		Command:     "sqlmap",
		InstallCmd:  "sqlmap",
		ManualURL:   "https://sqlmap.org",
		Description: "SQL injection automation",
		Required:    false,
		Categories:  []string{"exploit", "web"},
	},
	{
		Name:        "newman",
		Command:     "newman",
		InstallCmd:  "newman",
		ManualURL:   "https://github.com/postmanlabs/newman",
		Description: "Postman collection runner (API testing)",
		Required:    false,
		Categories:  []string{"api", "test"},
	},
	{
		Name:        "schemathesis",
		Command:     "schemathesis",
		InstallCmd:  "schemathesis",
		ManualURL:   "https://github.com/schemathesis/schemathesis",
		Description: "OpenAPI-driven API testing",
		Required:    false,
		Categories:  []string{"api", "test"},
	},
	{
		Name:        "jwt-tool",
		Command:     "jwt-tool",
		InstallCmd:  "jwt-tool",
		ManualURL:   "https://github.com/ticarpi/jwt_tool",
		Description: "JWT testing and manipulation",
		Required:    false,
		Categories:  []string{"api", "web", "auth"},
	},
	{
		Name:        "hydra",
		Command:     "hydra",
		InstallCmd:  "hydra",
		ManualURL:   "https://github.com/vanhauser-thc/thc-hydra",
		Description: "Password cracking",
		Required:    false,
		Categories:  []string{"exploit"},
	},
	{
		Name:        "masscan",
		Command:     "masscan",
		InstallCmd:  "masscan",
		ManualURL:   "https://github.com/robertdavidgraham/masscan",
		Description: "Fast port scanner",
		Required:    false,
		Categories:  []string{"scan", "recon"},
	},
	{
		Name:        "amass",
		Command:     "amass",
		InstallCmd:  "amass",
		ManualURL:   "https://github.com/owasp-amass/amass",
		Description: "Subdomain enumeration",
		Required:    false,
		Categories:  []string{"recon"},
	},
	{
		Name:        "subfinder",
		Command:     "subfinder",
		InstallCmd:  "subfinder",
		ManualURL:   "https://github.com/projectdiscovery/subfinder",
		Description: "Subdomain discovery",
		Required:    false,
		Categories:  []string{"recon"},
	},
	{
		Name:        "whatweb",
		Command:     "whatweb",
		InstallCmd:  "whatweb",
		ManualURL:   "https://github.com/urbanadventurer/WhatWeb",
		Description: "Web technology fingerprinting",
		Required:    false,
		Categories:  []string{"web", "recon"},
	},
	{
		Name:        "wpscan",
		Command:     "wpscan",
		InstallCmd:  "wpscan",
		ManualURL:   "https://wpscan.com",
		Description: "WordPress vulnerability scanner",
		Required:    false,
		Categories:  []string{"web", "scan"},
	},
	{
		Name:        "metasploit",
		Command:     "msfconsole",
		InstallCmd:  "metasploit-framework",
		ManualURL:   "https://www.metasploit.com/download",
		Description: "Metasploit Framework console",
		Required:    false,
		Categories:  []string{"exploit", "post", "framework"},
	},
	{
		Name:        "msfconsole",
		Command:     "msfconsole",
		InstallCmd:  "metasploit-framework",
		ManualURL:   "https://www.metasploit.com/download",
		Description: "Metasploit console (alias)",
		Required:    false,
		Categories:  []string{"exploit", "post", "framework"},
	},
	{
		Name:        "msf",
		Command:     "msfconsole",
		InstallCmd:  "metasploit-framework",
		ManualURL:   "https://www.metasploit.com/download",
		Description: "Metasploit (msfconsole)",
		Required:    false,
		Categories:  []string{"exploit", "post", "framework"},
	},
	{
		Name:        "hashcat",
		Command:     "hashcat",
		InstallCmd:  "hashcat",
		ManualURL:   "https://hashcat.net/hashcat/",
		Description: "GPU password recovery",
		Required:    false,
		Categories:  []string{"password", "exploit"},
	},
	{
		Name:        "john",
		Command:     "john",
		InstallCmd:  "john",
		ManualURL:   "https://www.openwall.com/john/",
		Description: "John the Ripper password cracker",
		Required:    false,
		Categories:  []string{"password", "exploit"},
	},
	{
		Name:        "aircrack-ng",
		Command:     "aircrack-ng",
		InstallCmd:  "aircrack-ng",
		ManualURL:   "https://www.aircrack-ng.org/",
		Description: "WiFi security auditing suite",
		Required:    false,
		Categories:  []string{"wireless"},
	},
	{
		Name:        "theharvester",
		Command:     "theHarvester",
		InstallCmd:  "theharvester",
		ManualURL:   "https://github.com/laramies/theHarvester",
		Description: "OSINT email/subdomain harvesting",
		Required:    false,
		Categories:  []string{"osint", "recon"},
	},
	{
		Name:        "sublist3r",
		Command:     "sublist3r",
		InstallCmd:  "sublist3r",
		ManualURL:   "https://github.com/aboul3la/Sublist3r",
		Description: "Subdomain enumeration",
		Required:    false,
		Categories:  []string{"recon"},
	},
	{
		Name:        "dirb",
		Command:     "dirb",
		InstallCmd:  "dirb",
		ManualURL:   "https://dirb.sourceforge.net/",
		Description: "Web content scanner",
		Required:    false,
		Categories:  []string{"web", "scan"},
	},
	{
		Name:        "sliver",
		Command:     "sliver",
		InstallCmd:  "sliver",
		ManualURL:   "https://github.com/BishopFox/sliver",
		Description: "C2 framework",
		Required:    false,
		Categories:  []string{"c2", "post"},
	},
	{
		Name:        "covenant",
		Command:     "covenant",
		InstallCmd:  "covenant",
		ManualURL:   "https://github.com/cobbr/Covenant",
		Description: "C2 framework (Covenant)",
		Required:    false,
		Categories:  []string{"c2", "post"},
	},
	{
		Name:        "empire",
		Command:     "empire",
		InstallCmd:  "powershell-empire",
		ManualURL:   "https://github.com/BC-SECURITY/Empire",
		Description: "PowerShell Empire C2",
		Required:    false,
		Categories:  []string{"c2", "post"},
	},
	{
		Name:        "havoc",
		Command:     "havoc",
		InstallCmd:  "havoc",
		ManualURL:   "https://github.com/HavocFramework/Havoc",
		Description: "Havoc C2 framework",
		Required:    false,
		Categories:  []string{"c2", "post"},
	},
	{
		Name:        "bloodhound",
		Command:     "bloodhound",
		InstallCmd:  "bloodhound",
		ManualURL:   "https://github.com/BloodHoundAD/BloodHound",
		Description: "Active Directory attack path analysis",
		Required:    false,
		Categories:  []string{"post", "active_directory"},
	},
	{
		Name:        "mimikatz",
		Command:     "mimikatz",
		InstallCmd:  "mimikatz",
		ManualURL:   "https://github.com/gentilkiwi/mimikatz",
		Description: "Credential extraction (Windows/AD)",
		Required:    false,
		Categories:  []string{"post", "active_directory"},
	},
}

// CheckTool checks if a specific tool is installed
func CheckTool(name string) *ToolStatus {
	for _, tool := range ToolRegistry {
		if strings.EqualFold(tool.Name, name) {
			return checkToolStatus(tool)
		}
	}
	return nil
}

// CheckAllTools checks all registered tools
func CheckAllTools() []ToolStatus {
	var results []ToolStatus
	for _, tool := range ToolRegistry {
		results = append(results, *checkToolStatus(tool))
	}
	return results
}

// CheckRequiredTools checks only required tools
func CheckRequiredTools() []ToolStatus {
	var results []ToolStatus
	for _, tool := range ToolRegistry {
		if tool.Required {
			results = append(results, *checkToolStatus(tool))
		}
	}
	return results
}

// CheckToolsByCategory checks tools in a specific category
func CheckToolsByCategory(category string) []ToolStatus {
	var results []ToolStatus
	for _, tool := range ToolRegistry {
		for _, cat := range tool.Categories {
			if strings.EqualFold(cat, category) {
				results = append(results, *checkToolStatus(tool))
				break
			}
		}
	}
	return results
}

// GetMissingTools returns tools that are not installed
func GetMissingTools() []ToolStatus {
	var missing []ToolStatus
	for _, tool := range ToolRegistry {
		status := checkToolStatus(tool)
		if !status.Installed {
			missing = append(missing, *status)
		}
	}
	return missing
}

// GetMissingRequiredTools returns required tools that are not installed
func GetMissingRequiredTools() []ToolStatus {
	var missing []ToolStatus
	for _, tool := range ToolRegistry {
		if tool.Required {
			status := checkToolStatus(tool)
			if !status.Installed {
				missing = append(missing, *status)
			}
		}
	}
	return missing
}

func checkToolStatus(tool ToolInfo) *ToolStatus {
	status := &ToolStatus{
		Tool:      tool,
		Installed: false,
	}

	// Check if command exists
	path, err := exec.LookPath(tool.Command)
	if err != nil {
		return status
	}

	status.Installed = true
	status.Path = path

	// Try to get version
	status.Version = getToolVersion(tool.Command)

	return status
}

func getToolVersion(command string) string {
	// Try common version flags
	versionFlags := []string{"--version", "-V"}

	for _, flag := range versionFlags {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cmd := exec.CommandContext(ctx, command, flag)
		output, err := cmd.CombinedOutput()
		cancel()
		if err == nil && len(output) > 0 {
			// Extract first line and clean it up
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 {
				version := strings.TrimSpace(lines[0])
				// Limit length
				if len(version) > 50 {
					version = version[:50] + "..."
				}
				return version
			}
		}
	}

	return "unknown"
}

// GetInstallCommand returns the appropriate install command for the OS
func GetInstallCommand(tool ToolInfo) string {
	switch runtime.GOOS {
	case "linux":
		// Check for package manager
		if _, err := exec.LookPath("apt"); err == nil {
			return fmt.Sprintf("sudo apt install -y %s", tool.InstallCmd)
		}
		if _, err := exec.LookPath("dnf"); err == nil {
			return fmt.Sprintf("sudo dnf install -y %s", tool.InstallCmd)
		}
		if _, err := exec.LookPath("pacman"); err == nil {
			return fmt.Sprintf("sudo pacman -S %s", tool.InstallCmd)
		}
		// Fallback for Go tools
		if isGoTool(tool.Name) {
			return getGoInstallCommand(tool.Name)
		}
		return fmt.Sprintf("# Install %s from: %s", tool.Name, tool.ManualURL)

	case "darwin":
		if _, err := exec.LookPath("brew"); err == nil {
			return fmt.Sprintf("brew install %s", tool.InstallCmd)
		}
		return fmt.Sprintf("# Install %s from: %s", tool.Name, tool.ManualURL)

	default:
		return fmt.Sprintf("# Install %s from: %s", tool.Name, tool.ManualURL)
	}
}

// GetBulkInstallCommand returns a command to install multiple tools
func GetBulkInstallCommand(tools []ToolInfo) string {
	if len(tools) == 0 {
		return ""
	}

	var names []string
	for _, t := range tools {
		names = append(names, t.InstallCmd)
	}

	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("apt"); err == nil {
			return fmt.Sprintf("sudo apt install -y %s", strings.Join(names, " "))
		}
		if _, err := exec.LookPath("dnf"); err == nil {
			return fmt.Sprintf("sudo dnf install -y %s", strings.Join(names, " "))
		}
		if _, err := exec.LookPath("pacman"); err == nil {
			return fmt.Sprintf("sudo pacman -S %s", strings.Join(names, " "))
		}
	case "darwin":
		if _, err := exec.LookPath("brew"); err == nil {
			return fmt.Sprintf("brew install %s", strings.Join(names, " "))
		}
	}

	return ""
}

func isGoTool(name string) bool {
	goTools := []string{"nuclei", "subfinder", "httpx", "dnsx", "naabu", "ffuf", "gobuster"}
	for _, t := range goTools {
		if strings.EqualFold(name, t) {
			return true
		}
	}
	return false
}

func getGoInstallCommand(name string) string {
	goPackages := map[string]string{
		"nuclei":    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		"subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		"httpx":     "github.com/projectdiscovery/httpx/cmd/httpx@latest",
		"dnsx":      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
		"naabu":     "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
		"ffuf":      "github.com/ffuf/ffuf/v2@latest",
		"gobuster":  "github.com/OJ/gobuster/v3@latest",
	}

	if pkg, ok := goPackages[strings.ToLower(name)]; ok {
		return fmt.Sprintf("go install %s", pkg)
	}
	return ""
}

// IsToolInstalled quickly checks if a tool is available
func IsToolInstalled(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// RequireTool checks if a tool is installed, returns error if not
func RequireTool(name string) error {
	if !IsToolInstalled(name) {
		tool := CheckTool(name)
		if tool != nil {
			return fmt.Errorf("tool '%s' is not installed.\n  Install with: %s\n  Or visit: %s",
				name, GetInstallCommand(tool.Tool), tool.Tool.ManualURL)
		}
		return fmt.Errorf("tool '%s' is not installed", name)
	}
	return nil
}
