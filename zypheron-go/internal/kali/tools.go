package kali

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/platform"
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
	// Get user's home directory for Go binaries
	homeDir, _ := os.UserHomeDir()
	goBinPath := filepath.Join(homeDir, "go", "bin")

	for i := range tm.tools {
		tool := &tm.tools[i]

		// Check if command exists in PATH
		_, err := exec.LookPath(tool.Command)
		tool.Installed = err == nil

		// If not found and Go bin path exists, check there too
		if !tool.Installed && goBinPath != "" {
			goToolPath := filepath.Join(goBinPath, tool.Command)
			if _, err := os.Stat(goToolPath); err == nil {
				tool.Installed = true
			}
		}

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

// GetMissingTools returns a list of tools that are not installed
func (tm *ToolManager) GetMissingTools() []Tool {
	var missing []Tool
	for _, tool := range tm.tools {
		if !tool.Installed {
			missing = append(missing, tool)
		}
	}
	return missing
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
		return getInstallCommandString(*tool)
	}
	return fmt.Sprintf("sudo apt-get install -y %s", name)
}

func getInstallCommandString(tool Tool) string {
	env, err := platform.DetectEnvironment()
	if err == nil && env.IsBlackArch {
		if pkg := blackArchPackage(tool.Name); pkg != "" {
			return fmt.Sprintf("sudo pacman -S --needed --noconfirm %s", pkg)
		}
	}
	return tool.InstallCmd
}

func blackArchPackage(toolName string) string {
	packages := map[string]string{
		"nmap":         "nmap",
		"nikto":        "nikto",
		"nuclei":       "nuclei",
		"httpx":        "httpx",
		"katana":       "katana",
		"gau":          "gau",
		"waybackurls":  "waybackurls",
		"assetfinder":  "assetfinder",
		"masscan":      "masscan",
		"sqlmap":       "sqlmap",
		"hydra":        "hydra",
		"metasploit":   "metasploit",
		"msfconsole":   "metasploit",
		"gobuster":     "gobuster",
		"ffuf":         "ffuf",
		"feroxbuster":  "feroxbuster",
		"dirsearch":    "dirsearch",
		"wfuzz":        "wfuzz",
		"kiterunner":   "kiterunner",
		"kr":           "kiterunner",
		"aircrack-ng":  "aircrack-ng",
		"john":         "john",
		"hashcat":      "hashcat",
		"theharvester": "theharvester",
		"ghidra":       "ghidra",
		"radare2":      "radare2",
		"gdb":          "gdb",
		"strings":      "binutils",
		"objdump":      "binutils",
		"readelf":      "binutils",
		"file":         "file",
		"checksec":     "checksec",
		"autopsy":      "autopsy",
		"sleuthkit":    "sleuthkit",
		"binwalk":      "binwalk",
		"foremost":     "foremost",
	}
	return packages[strings.ToLower(toolName)]
}

// getInstallCommand returns safe install command for a tool
func getInstallCommand(toolName string) (string, []string, error) {
	env, err := platform.DetectEnvironment()
	if err == nil && env.IsBlackArch {
		if pkg := blackArchPackage(toolName); pkg != "" {
			return "sudo", []string{"pacman", "-S", "--needed", "--noconfirm", pkg}, nil
		}
	}

	// Hardcoded install commands - never use user input
	installCommands := map[string]struct {
		cmd  string
		args []string
	}{
		// Network/Web scanners
		"nmap":         {"sudo", []string{"apt-get", "install", "-y", "nmap"}},
		"nikto":        {"sudo", []string{"apt-get", "install", "-y", "nikto"}},
		"httpx":        {"go", []string{"install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"}},
		"katana":       {"go", []string{"install", "-v", "github.com/projectdiscovery/katana/cmd/katana@latest"}},
		"gau":          {"go", []string{"install", "-v", "github.com/lc/gau/v2/cmd/gau@latest"}},
		"waybackurls":  {"go", []string{"install", "-v", "github.com/tomnomnom/waybackurls@latest"}},
		"assetfinder":  {"go", []string{"install", "-v", "github.com/tomnomnom/assetfinder@latest"}},
		"masscan":      {"sudo", []string{"apt-get", "install", "-y", "masscan"}},
		"sqlmap":       {"sudo", []string{"apt-get", "install", "-y", "sqlmap"}},
		"hydra":        {"sudo", []string{"apt-get", "install", "-y", "hydra"}},
		"metasploit":   {"sudo", []string{"apt-get", "install", "-y", "metasploit-framework"}},
		"msfconsole":   {"sudo", []string{"apt-get", "install", "-y", "metasploit-framework"}},
		"msf":          {"sudo", []string{"apt-get", "install", "-y", "metasploit-framework"}},
		"gobuster":     {"sudo", []string{"apt-get", "install", "-y", "gobuster"}},
		"ffuf":         {"sudo", []string{"apt-get", "install", "-y", "ffuf"}},
		"feroxbuster":  {"sudo", []string{"apt-get", "install", "-y", "feroxbuster"}},
		"dirsearch":    {"python3", []string{"-m", "pip", "install", "--user", "dirsearch"}},
		"wfuzz":        {"python3", []string{"-m", "pip", "install", "--user", "wfuzz"}},
		"kiterunner":   {"go", []string{"install", "-v", "github.com/assetnote/kiterunner/cmd/kr@latest"}},
		"kr":           {"go", []string{"install", "-v", "github.com/assetnote/kiterunner/cmd/kr@latest"}},
		"aircrack-ng":  {"sudo", []string{"apt-get", "install", "-y", "aircrack-ng"}},
		"john":         {"sudo", []string{"apt-get", "install", "-y", "john"}},
		"hashcat":      {"sudo", []string{"apt-get", "install", "-y", "hashcat"}},
		"newman":       {"sudo", []string{"npm", "install", "-g", "newman"}},
		"schemathesis": {"python3", []string{"-m", "pip", "install", "--user", "schemathesis"}},
		"jwt-tool":     {"python3", []string{"-m", "pip", "install", "--user", "jwt-tool"}},
		"jwt_tool":     {"python3", []string{"-m", "pip", "install", "--user", "jwt-tool"}},

		// Go-based tools - require Go to be installed first
		"nuclei":    {"go", []string{"install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}},
		"subfinder": {"go", []string{"install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"}},
		"amass":     {"go", []string{"install", "-v", "github.com/owasp-amass/amass/v4/...@master"}},

		// Python-based tools
		"theharvester": {"sudo", []string{"apt-get", "install", "-y", "theharvester"}},
		"ropper":       {"python3", []string{"-m", "pip", "install", "--user", "ropper"}},
		"volatility":   {"sudo", []string{"apt-get", "install", "-y", "volatility3"}},
		"pwntools":     {"python3", []string{"-m", "pip", "install", "--user", "pwntools"}},

		// Ruby-based tools
		"one_gadget": {"gem", []string{"install", "--user-install", "one_gadget"}},

		// Reverse Engineering
		"ghidra":  {"sudo", []string{"apt-get", "install", "-y", "ghidra"}},
		"radare2": {"sudo", []string{"apt-get", "install", "-y", "radare2"}},
		"gdb":     {"sudo", []string{"apt-get", "install", "-y", "gdb"}},
		"strings": {"sudo", []string{"apt-get", "install", "-y", "binutils"}},
		"objdump": {"sudo", []string{"apt-get", "install", "-y", "binutils"}},
		"readelf": {"sudo", []string{"apt-get", "install", "-y", "binutils"}},
		"file":    {"sudo", []string{"apt-get", "install", "-y", "file"}},

		// Pwn tools
		"checksec": {"sudo", []string{"apt-get", "install", "-y", "checksec"}},

		// Forensics
		"autopsy":   {"sudo", []string{"apt-get", "install", "-y", "autopsy"}},
		"sleuthkit": {"sudo", []string{"apt-get", "install", "-y", "sleuthkit"}},
		"binwalk":   {"sudo", []string{"apt-get", "install", "-y", "binwalk"}},
		"foremost":  {"sudo", []string{"apt-get", "install", "-y", "foremost"}},
	}

	cmdInfo, exists := installCommands[strings.ToLower(toolName)]
	if !exists {
		return "", nil, fmt.Errorf("no install command defined for tool: %s", toolName)
	}

	return cmdInfo.cmd, cmdInfo.args, nil
}

// Install installs a tool
func (tm *ToolManager) Install(name string) error {
	tool := tm.GetTool(name)
	if tool == nil {
		return fmt.Errorf("tool not found: %s", name)
	}

	fmt.Printf("Installing %s...\n", tool.Name)

	// Get safe install command
	cmdName, args, err := getInstallCommand(tool.Name)
	if err != nil {
		return err
	}

	// Execute with direct command (no shell interpretation)
	cmd := exec.Command(cmdName, args...)
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
		"scan":        "nmap",
		"portscan":    "nmap",
		"web":         "nikto",
		"webscan":     "nikto",
		"vuln":        "nuclei",
		"bruteforce":  "hydra",
		"password":    "john",
		"recon":       "nmap",
		"osint":       "theharvester",
		"wireless":    "aircrack-ng",
		"fuzz":        "ffuf",
		"reverse-eng": "radare2",
		"pwn":         "pwntools",
		"forensics":   "volatility",
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
			Name:        "httpx",
			Command:     "httpx",
			Description: "HTTP probing and tech detection",
			Category:    "web",
			Priority:    "medium",
			InstallCmd:  "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
			RequiredFor: []string{"web-recon"},
			Aliases:     []string{},
		},
		{
			Name:        "katana",
			Command:     "katana",
			Description: "Web crawler/spider",
			Category:    "web",
			Priority:    "medium",
			InstallCmd:  "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
			RequiredFor: []string{"web-recon"},
			Aliases:     []string{},
		},
		{
			Name:        "gau",
			Command:     "gau",
			Description: "GetAllUrls from public sources",
			Category:    "web",
			Priority:    "low",
			InstallCmd:  "go install -v github.com/lc/gau/v2/cmd/gau@latest",
			RequiredFor: []string{"web-recon"},
			Aliases:     []string{},
		},
		{
			Name:        "waybackurls",
			Command:     "waybackurls",
			Description: "Archive URL discovery (Wayback)",
			Category:    "web",
			Priority:    "low",
			InstallCmd:  "go install -v github.com/tomnomnom/waybackurls@latest",
			RequiredFor: []string{"web-recon"},
			Aliases:     []string{},
		},
		{
			Name:        "assetfinder",
			Command:     "assetfinder",
			Description: "Subdomain discovery",
			Category:    "recon",
			Priority:    "low",
			InstallCmd:  "go install -v github.com/tomnomnom/assetfinder@latest",
			RequiredFor: []string{"recon"},
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
			Name:        "newman",
			Command:     "newman",
			Description: "Postman collection runner (API testing)",
			Category:    "api",
			Priority:    "medium",
			InstallCmd:  "npm install -g newman",
			RequiredFor: []string{"api-test"},
			Aliases:     []string{},
		},
		{
			Name:        "schemathesis",
			Command:     "schemathesis",
			Description: "OpenAPI-driven API testing",
			Category:    "api",
			Priority:    "medium",
			InstallCmd:  "python3 -m pip install --user schemathesis",
			RequiredFor: []string{"api-test"},
			Aliases:     []string{},
		},
		{
			Name:        "jwt-tool",
			Command:     "jwt-tool",
			Description: "JWT testing and manipulation",
			Category:    "api",
			Priority:    "low",
			InstallCmd:  "python3 -m pip install --user jwt-tool",
			RequiredFor: []string{"auth-test"},
			Aliases:     []string{"jwt_tool"},
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
			Name:        "feroxbuster",
			Command:     "feroxbuster",
			Description: "Fast directory discovery",
			Category:    "web",
			Priority:    "medium",
			InstallCmd:  "sudo apt-get install -y feroxbuster",
			RequiredFor: []string{"web-scan"},
			Aliases:     []string{},
		},
		{
			Name:        "dirsearch",
			Command:     "dirsearch",
			Description: "Web path discovery",
			Category:    "web",
			Priority:    "medium",
			InstallCmd:  "python3 -m pip install --user dirsearch",
			RequiredFor: []string{"web-scan"},
			Aliases:     []string{},
		},
		{
			Name:        "wfuzz",
			Command:     "wfuzz",
			Description: "Web/API fuzzing",
			Category:    "web",
			Priority:    "medium",
			InstallCmd:  "python3 -m pip install --user wfuzz",
			RequiredFor: []string{"fuzz"},
			Aliases:     []string{},
		},
		{
			Name:        "kiterunner",
			Command:     "kr",
			Description: "API endpoint discovery (kiterunner)",
			Category:    "api",
			Priority:    "medium",
			InstallCmd:  "go install -v github.com/assetnote/kiterunner/cmd/kr@latest",
			RequiredFor: []string{"api-recon"},
			Aliases:     []string{"kr"},
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
		// Reverse Engineering Tools
		{
			Name:        "ghidra",
			Command:     "ghidra",
			Description: "Software reverse engineering framework",
			Category:    "reverse-engineering",
			Priority:    "high",
			InstallCmd:  "sudo apt-get install -y ghidra",
			RequiredFor: []string{"reverse-eng"},
			Aliases:     []string{},
		},
		{
			Name:        "radare2",
			Command:     "r2",
			Description: "Command-line reverse engineering framework",
			Category:    "reverse-engineering",
			Priority:    "high",
			InstallCmd:  "sudo apt-get install -y radare2",
			RequiredFor: []string{"reverse-eng"},
			Aliases:     []string{"r2", "radare2"},
		},
		{
			Name:        "gdb",
			Command:     "gdb",
			Description: "GNU debugger",
			Category:    "reverse-engineering",
			Priority:    "critical",
			InstallCmd:  "sudo apt-get install -y gdb",
			RequiredFor: []string{"reverse-eng", "pwn"},
			Aliases:     []string{"gdb"},
		},
		{
			Name:        "pwntools",
			Command:     "python3",
			Description: "CTF framework and exploit development library",
			Category:    "pwn",
			Priority:    "high",
			InstallCmd:  "pip3 install pwntools",
			RequiredFor: []string{"pwn", "reverse-eng"},
			Aliases:     []string{"pwn", "pwntools"},
		},
		{
			Name:        "strings",
			Command:     "strings",
			Description: "Print sequences of printable characters",
			Category:    "reverse-engineering",
			Priority:    "medium",
			InstallCmd:  "sudo apt-get install -y binutils",
			RequiredFor: []string{"reverse-eng", "forensics"},
			Aliases:     []string{},
		},
		{
			Name:        "objdump",
			Command:     "objdump",
			Description: "Display information from object files",
			Category:    "reverse-engineering",
			Priority:    "medium",
			InstallCmd:  "sudo apt-get install -y binutils",
			RequiredFor: []string{"reverse-eng"},
			Aliases:     []string{},
		},
		{
			Name:        "readelf",
			Command:     "readelf",
			Description: "Display information about ELF files",
			Category:    "reverse-engineering",
			Priority:    "medium",
			InstallCmd:  "sudo apt-get install -y binutils",
			RequiredFor: []string{"reverse-eng"},
			Aliases:     []string{},
		},
		{
			Name:        "file",
			Command:     "file",
			Description: "Determine file type",
			Category:    "reverse-engineering",
			Priority:    "medium",
			InstallCmd:  "sudo apt-get install -y file",
			RequiredFor: []string{"reverse-eng", "forensics"},
			Aliases:     []string{},
		},
		// Pwn Tools
		{
			Name:        "checksec",
			Command:     "checksec",
			Description: "Check security properties of executables",
			Category:    "pwn",
			Priority:    "high",
			InstallCmd:  "sudo apt-get install -y checksec",
			RequiredFor: []string{"pwn"},
			Aliases:     []string{},
		},
		{
			Name:        "ropper",
			Command:     "ropper",
			Description: "ROP gadget finder and binary information tool",
			Category:    "pwn",
			Priority:    "medium",
			InstallCmd:  "pip3 install ropper",
			RequiredFor: []string{"pwn"},
			Aliases:     []string{},
		},
		{
			Name:        "one_gadget",
			Command:     "one_gadget",
			Description: "Find one-gadget RCE in libc",
			Category:    "pwn",
			Priority:    "medium",
			InstallCmd:  "gem install one_gadget",
			RequiredFor: []string{"pwn"},
			Aliases:     []string{"one-gadget"},
		},
		// Forensics Tools
		{
			Name:        "volatility",
			Command:     "volatility",
			Description: "Memory forensics framework",
			Category:    "forensics",
			Priority:    "high",
			InstallCmd:  "sudo apt-get install -y volatility",
			RequiredFor: []string{"forensics"},
			Aliases:     []string{"vol"},
		},
		{
			Name:        "autopsy",
			Command:     "autopsy",
			Description: "Digital forensics platform",
			Category:    "forensics",
			Priority:    "medium",
			InstallCmd:  "sudo apt-get install -y autopsy",
			RequiredFor: []string{"forensics"},
			Aliases:     []string{},
		},
		{
			Name:        "sleuthkit",
			Command:     "tsk_loaddb",
			Description: "Command-line forensics tools",
			Category:    "forensics",
			Priority:    "high",
			InstallCmd:  "sudo apt-get install -y sleuthkit",
			RequiredFor: []string{"forensics"},
			Aliases:     []string{"tsk", "sleuthkit"},
		},
		{
			Name:        "binwalk",
			Command:     "binwalk",
			Description: "Firmware analysis tool",
			Category:    "forensics",
			Priority:    "medium",
			InstallCmd:  "sudo apt-get install -y binwalk",
			RequiredFor: []string{"forensics"},
			Aliases:     []string{},
		},
		{
			Name:        "foremost",
			Command:     "foremost",
			Description: "File carving and recovery tool",
			Category:    "forensics",
			Priority:    "medium",
			InstallCmd:  "sudo apt-get install -y foremost",
			RequiredFor: []string{"forensics"},
			Aliases:     []string{},
		},
	}
}
