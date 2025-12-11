# 🔗 Tool Chains Configuration Guide

Complete guide to Zypheron's tool chain system.

## 📋 Overview

Tool chains allow you to define sequences of security tools with priorities and parameters for automated testing workflows.

## 📂 Configuration File

Tool chains are defined in `~/.zypheron/toolchains.yaml` or `zypheron-go/config/toolchains.yaml`.

### File Structure
```yaml
chain_name:
  - tool: tool_name
    priority: 1
    params:
      key: value
```

## 🛠️ Available Tool Chains

### 1. Network Discovery

Comprehensive network reconnaissance.

```yaml
network_discovery:
  - tool: arp-scan
    priority: 1
    params:
      local_network: true
  - tool: rustscan
    priority: 2
    params:
      ulimit: 5000
      scripts: true
  - tool: nmap
    priority: 3
    params:
      scan_type: "-sS"
      os_detection: true
      version_detection: true
  - tool: masscan
    priority: 4
    params:
      rate: 1000
      ports: "1-65535"
      banners: true
```

**Usage:**
```bash
zypheron scan example.com --chain network_discovery
```

### 2. Vulnerability Assessment

Automated vulnerability scanning.

```yaml
vulnerability_assessment:
  - tool: nuclei
    priority: 1
    params:
      severity: "critical,high,medium"
      update: true
  - tool: jaeles
    priority: 2
    params:
      threads: 20
      timeout: 20
  - tool: dalfox
    priority: 3
    params:
      mining_dom: true
      mining_dict: true
  - tool: nikto
    priority: 4
    params:
      comprehensive: true
  - tool: sqlmap
    priority: 5
    params:
      crawl: 2
      batch: true
```

**Usage:**
```bash
zypheron scan https://example.com --chain vulnerability_assessment
```

### 3. Reverse Engineering

Binary analysis workflow.

```yaml
reverse_engineering:
  - tool: file
    priority: 1
    params:
      detailed: true
  - tool: strings
    priority: 2
    params:
      min_length: 4
  - tool: objdump
    priority: 3
    params:
      disassemble: true
      headers: true
  - tool: readelf
    priority: 4
    params:
      headers: true
      sections: true
  - tool: radare2
    priority: 5
    params:
      analysis: true
      auto: true
  - tool: ghidra
    priority: 6
    params:
      headless: true
      analysis: true
```

**Usage:**
```bash
zypheron reverse-eng /path/to/binary --chain reverse_engineering
```

### 4. Binary Exploitation (PWN)

CTF and exploitation workflow.

```yaml
pwn:
  - tool: checksec
    priority: 1
    params:
      file: true
  - tool: strings
    priority: 2
    params:
      min_length: 4
  - tool: gdb
    priority: 3
    params:
      batch: true
      ex: "commands"
  - tool: pwntools
    priority: 4
    params:
      context: true
      gdb: true
  - tool: ropper
    priority: 5
    params:
      all: true
  - tool: one_gadget
    priority: 6
    params:
      raw: true
```

**Usage:**
```bash
zypheron pwn /path/to/binary --chain pwn
```

### 5. Digital Forensics

Forensics analysis workflow.

```yaml
forensics:
  - tool: file
    priority: 1
    params:
      detailed: true
  - tool: strings
    priority: 2
    params:
      min_length: 4
      all: true
  - tool: binwalk
    priority: 3
    params:
      extract: true
      entropy: true
  - tool: foremost
    priority: 4
    params:
      recover: true
  - tool: volatility
    priority: 5
    params:
      profile: "auto"
      plugins: true
  - tool: sleuthkit
    priority: 6
    params:
      analysis: true
```

**Usage:**
```bash
zypheron forensics disk.img --chain forensics
```

### 6. API Security Testing

API penetration testing.

```yaml
api_pentest:
  - tool: nmap
    priority: 1
    params:
      ports: "443,8443"
      ssl: true
  - tool: nikto
    priority: 2
    params:
      ssl: true
  - tool: nuclei
    priority: 3
    params:
      severity: "critical,high"
      tags: "api"
```

**Usage:**
```bash
zypheron api-pentest https://api.example.com --chain api_pentest
```

### 7. AI-Powered Dorking

Search engine reconnaissance.

```yaml
dorking:
  - tool: browser-agent
    priority: 1
    params:
      engine: "google"
      ai_guided: true
```

**Usage:**
```bash
zypheron dork "site:example.com" --chain dorking
```

## 🎯 Creating Custom Tool Chains

### Basic Example
```yaml
my_custom_scan:
  - tool: nmap
    priority: 1
    params:
      ports: "80,443,8080"
  - tool: nikto
    priority: 2
    params:
      ssl: true
```

### Advanced Example
```yaml
webapp_pentest:
  - tool: nmap
    priority: 1
    params:
      ports: "1-1000"
      version_detection: true
  - tool: nikto
    priority: 2
    params:
      comprehensive: true
  - tool: nuclei
    priority: 3
    params:
      severity: "critical,high"
      templates: "web"
  - tool: sqlmap
    priority: 4
    params:
      crawl: 3
      batch: true
      level: 5
  - tool: ffuf
    priority: 5
    params:
      wordlist: "/usr/share/wordlists/dirb/common.txt"
      extensions: "php,html,js"
```

## 📝 Tool Chain Parameters

### Common Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `tool` | string | Tool name (required) |
| `priority` | int | Execution priority (1 = first) |
| `params` | object | Tool-specific parameters |

### Tool-Specific Parameters

#### nmap
```yaml
params:
  ports: "1-1000"
  scan_type: "-sS"
  os_detection: true
  version_detection: true
  aggressive: true
  nse_scripts: "vuln,exploit"
```

#### nikto
```yaml
params:
  comprehensive: true
  ssl: true
  no_ssl: false
```

#### nuclei
```yaml
params:
  severity: "critical,high,medium"
  tags: "web,api,cve"
  update: true
  templates: "custom-templates/"
```

#### radare2
```yaml
params:
  analysis: true
  auto: true
  debug: false
```

#### volatility
```yaml
params:
  profile: "Win7SP1x64"
  plugins: true
  output_dir: "./volatility-output"
```

## 🔧 Configuration Management

### Load Custom Configuration
```bash
# Use specific config file
zypheron scan example.com --chain my_chain --config custom-chains.yaml

# Set default config location
export ZYPHERON_CONFIG=~/.zypheron/toolchains.yaml
```

### Validate Configuration
```bash
# Check if config is valid
zypheron config validate

# Show current configuration
zypheron config show
```

### List Available Chains
```bash
# List all configured chains
zypheron config list-chains
```

## 💡 Best Practices

### 1. Priority Management
- Use priority 1 for reconnaissance tools
- Use priority 2-3 for scanning tools
- Use priority 4-5 for exploitation tools
- Higher priorities run first

### 2. Parameter Optimization
```yaml
# For fast scans
fast_scan:
  - tool: masscan
    priority: 1
    params:
      rate: 10000
      ports: "80,443"

# For comprehensive scans
deep_scan:
  - tool: nmap
    priority: 1
    params:
      ports: "1-65535"
      version_detection: true
      os_detection: true
```

### 3. Conditional Execution
```yaml
# Use conditions for specific scenarios
conditional_scan:
  - tool: nmap
    priority: 1
    params:
      ports: "1-1000"
    conditions:
      - network_type: "internal"
```

## 📊 Examples

### Comprehensive Web App Test
```yaml
full_webapp_test:
  - tool: nmap
    priority: 1
    params:
      ports: "80,443,8080,8443"
      version_detection: true
  - tool: nikto
    priority: 2
    params:
      comprehensive: true
  - tool: nuclei
    priority: 3
    params:
      severity: "all"
      tags: "web,owasp"
  - tool: sqlmap
    priority: 4
    params:
      crawl: 3
      batch: true
  - tool: ffuf
    priority: 5
    params:
      wordlist: "common.txt"
```

Usage:
```bash
zypheron scan https://example.com --chain full_webapp_test
```

### Quick CTF Binary Analysis
```yaml
ctf_binary:
  - tool: file
    priority: 1
    params:
      detailed: true
  - tool: checksec
    priority: 2
    params:
      file: true
  - tool: strings
    priority: 3
    params:
      min_length: 8
  - tool: ropper
    priority: 4
    params:
      all: true
```

Usage:
```bash
zypheron pwn challenge --chain ctf_binary
```

### Memory Forensics Workflow
```yaml
memory_forensics:
  - tool: volatility
    priority: 1
    params:
      profile: "auto"
      plugins: "pslist,netscan,hivelist"
  - tool: strings
    priority: 2
    params:
      min_length: 6
      all: true
```

Usage:
```bash
zypheron forensics memory.dump --chain memory_forensics
```

## 🔍 Tool Reference

### Supported Tools

| Tool | Category | Priority | Description |
|------|----------|----------|-------------|
| **nmap** | Scanner | Critical | Network scanner |
| **masscan** | Scanner | Medium | Fast port scanner |
| **nikto** | Web | High | Web server scanner |
| **nuclei** | Scanner | High | Vulnerability scanner |
| **sqlmap** | Web | High | SQL injection tool |
| **radare2** | Reverse Eng | High | RE framework |
| **ghidra** | Reverse Eng | High | RE platform |
| **gdb** | Reverse Eng | Critical | Debugger |
| **checksec** | PWN | High | Security checker |
| **pwntools** | PWN | High | CTF framework |
| **volatility** | Forensics | High | Memory forensics |
| **binwalk** | Forensics | Medium | Firmware analysis |

## 🆘 Troubleshooting

### Chain Not Found
```bash
# List available chains
zypheron config list-chains

# Check configuration file
cat ~/.zypheron/toolchains.yaml
```

### Tool Not Installed
```bash
# Check what tools are missing
zypheron tools check

# Install missing tool
zypheron tools install <tool>
```

### Invalid Configuration
```bash
# Validate configuration
zypheron config validate

# Show parsing errors
zypheron config validate --verbose
```

## 📚 Additional Resources

- [CLI_GUIDE.md](CLI_GUIDE.md) - Complete command reference
- [SETUP.md](SETUP.md) - Installation guide
- [DEV_STATUS.md](DEV_STATUS.md) - Feature status

---

**Example Configuration**: See `zypheron-go/config/toolchains.yaml`

