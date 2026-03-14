package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ToolChain represents a chain of tools with priorities
type ToolChain struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Tools       []ChainTool `yaml:"tools"`
}

// ChainTool represents a single tool in a chain with priority and parameters
type ChainTool struct {
	Tool     string                 `yaml:"tool"`
	Priority int                   `yaml:"priority"`
	Params   map[string]interface{} `yaml:"params"`
}

// ToolChainConfig represents the complete tool chain configuration
type ToolChainConfig struct {
	NetworkDiscovery          []ChainTool `yaml:"network_discovery"`
	VulnerabilityAssessment   []ChainTool `yaml:"vulnerability_assessment"`
	ComprehensiveNetworkPentest []ChainTool `yaml:"comprehensive_network_pentest"`
	ReverseEngineering        []ChainTool `yaml:"reverse_engineering"`
	Pwn                      []ChainTool `yaml:"pwn"`
	Forensics                []ChainTool `yaml:"forensics"`
	APIPentest               []ChainTool `yaml:"api_pentest"`
	Dorking                  []ChainTool `yaml:"dorking"`
}

// LoadToolChains loads tool chain configuration from a YAML file
func LoadToolChains(configPath string) (*ToolChainConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config ToolChainConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &config, nil
}

// GetDefaultToolChains returns the default tool chain configuration
func GetDefaultToolChains() *ToolChainConfig {
	return &ToolChainConfig{
		NetworkDiscovery: []ChainTool{
			{Tool: "arp-scan", Priority: 1, Params: map[string]interface{}{"local_network": true}},
			{Tool: "rustscan", Priority: 2, Params: map[string]interface{}{"ulimit": 5000, "scripts": true}},
			{Tool: "nmap", Priority: 3, Params: map[string]interface{}{"scan_type": "-sS", "os_detection": true, "version_detection": true}},
			{Tool: "masscan", Priority: 4, Params: map[string]interface{}{"rate": 1000, "ports": "1-65535", "banners": true}},
			{Tool: "enum4linux-ng", Priority: 5, Params: map[string]interface{}{"shares": true, "users": true, "groups": true}},
			{Tool: "nbtscan", Priority: 6, Params: map[string]interface{}{"verbose": true}},
			{Tool: "smbmap", Priority: 7, Params: map[string]interface{}{"recursive": true}},
			{Tool: "rpcclient", Priority: 8, Params: map[string]interface{}{"commands": "enumdomusers;enumdomgroups;querydominfo"}},
		},
		VulnerabilityAssessment: []ChainTool{
			{Tool: "nuclei", Priority: 1, Params: map[string]interface{}{"severity": "critical,high,medium", "update": true}},
			{Tool: "jaeles", Priority: 2, Params: map[string]interface{}{"threads": 20, "timeout": 20}},
			{Tool: "dalfox", Priority: 3, Params: map[string]interface{}{"mining_dom": true, "mining_dict": true}},
			{Tool: "nikto", Priority: 4, Params: map[string]interface{}{"comprehensive": true}},
			{Tool: "sqlmap", Priority: 5, Params: map[string]interface{}{"crawl": 2, "batch": true}},
		},
		ComprehensiveNetworkPentest: []ChainTool{
			{Tool: "autorecon", Priority: 1, Params: map[string]interface{}{"port_scans": "top-1000-ports", "service_scans": "default"}},
			{Tool: "rustscan", Priority: 2, Params: map[string]interface{}{"ulimit": 5000, "scripts": true}},
			{Tool: "nmap", Priority: 3, Params: map[string]interface{}{"aggressive": true, "nse_scripts": "vuln,exploit"}},
			{Tool: "enum4linux-ng", Priority: 4, Params: map[string]interface{}{"shares": true, "users": true, "groups": true, "policy": true}},
			{Tool: "responder", Priority: 5, Params: map[string]interface{}{"wpad": true, "duration": 180}},
		},
		ReverseEngineering: []ChainTool{
			{Tool: "file", Priority: 1, Params: map[string]interface{}{"detailed": true}},
			{Tool: "strings", Priority: 2, Params: map[string]interface{}{"min_length": 4}},
			{Tool: "objdump", Priority: 3, Params: map[string]interface{}{"disassemble": true, "headers": true}},
			{Tool: "readelf", Priority: 4, Params: map[string]interface{}{"headers": true, "sections": true}},
			{Tool: "radare2", Priority: 5, Params: map[string]interface{}{"analysis": true, "auto": true}},
			{Tool: "ghidra", Priority: 6, Params: map[string]interface{}{"headless": true, "analysis": true}},
		},
		Pwn: []ChainTool{
			{Tool: "checksec", Priority: 1, Params: map[string]interface{}{"file": true}},
			{Tool: "strings", Priority: 2, Params: map[string]interface{}{"min_length": 4}},
			{Tool: "gdb", Priority: 3, Params: map[string]interface{}{"batch": true, "ex": "commands"}},
			{Tool: "pwntools", Priority: 4, Params: map[string]interface{}{"context": true, "gdb": true}},
			{Tool: "ropper", Priority: 5, Params: map[string]interface{}{"all": true}},
			{Tool: "one_gadget", Priority: 6, Params: map[string]interface{}{"raw": true}},
		},
		Forensics: []ChainTool{
			{Tool: "file", Priority: 1, Params: map[string]interface{}{"detailed": true}},
			{Tool: "strings", Priority: 2, Params: map[string]interface{}{"min_length": 4, "all": true}},
			{Tool: "binwalk", Priority: 3, Params: map[string]interface{}{"extract": true, "entropy": true}},
			{Tool: "foremost", Priority: 4, Params: map[string]interface{}{"recover": true}},
			{Tool: "volatility", Priority: 5, Params: map[string]interface{}{"profile": "auto", "plugins": true}},
			{Tool: "sleuthkit", Priority: 6, Params: map[string]interface{}{"analysis": true}},
		},
		APIPentest: []ChainTool{
			{Tool: "nmap", Priority: 1, Params: map[string]interface{}{"ports": "443,8443", "ssl": true}},
			{Tool: "nikto", Priority: 2, Params: map[string]interface{}{"ssl": true}},
			{Tool: "nuclei", Priority: 3, Params: map[string]interface{}{"severity": "critical,high", "tags": "api"}},
		},
		Dorking: []ChainTool{
			{Tool: "browser-agent", Priority: 1, Params: map[string]interface{}{"engine": "google", "ai_guided": true}},
		},
	}
}

// GetToolChain returns a specific tool chain by name
func (c *ToolChainConfig) GetToolChain(name string) []ChainTool {
	switch name {
	case "network_discovery":
		return c.NetworkDiscovery
	case "vulnerability_assessment":
		return c.VulnerabilityAssessment
	case "comprehensive_network_pentest":
		return c.ComprehensiveNetworkPentest
	case "reverse_engineering":
		return c.ReverseEngineering
	case "pwn":
		return c.Pwn
	case "forensics":
		return c.Forensics
	case "api_pentest":
		return c.APIPentest
	case "dorking":
		return c.Dorking
	default:
		return nil
	}
}

// SaveToolChains saves tool chain configuration to a YAML file
func SaveToolChains(config *ToolChainConfig, configPath string) error {
	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetConfigPath returns the default config file path
func GetConfigPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".zypheron/toolchains.yaml"
	}
	return filepath.Join(homeDir, ".zypheron", "toolchains.yaml")
}

