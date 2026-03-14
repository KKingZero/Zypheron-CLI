# Zypheron Setup and Usage Guide

Complete guide to configuring and using Zypheron for penetration testing.

## Table of Contents

- [First-Time Setup](#first-time-setup)
- [Environment Detection](#environment-detection)
- [Tool Installation](#tool-installation)
- [Configuration](#configuration)
- [Basic Usage](#basic-usage)
- [Advanced Usage](#advanced-usage)
- [Workflows](#workflows)
- [Best Practices](#best-practices)

---

## First-Time Setup

After installation, run the setup wizard:

```bash
# Run initial setup
zypheron setup
```

This will:
1. Detect your environment (Kali, WSL, etc.)
2. Check installed security tools
3. Configure basic settings
4. Verify everything works

### Manual Setup

If you prefer manual configuration:

```bash
# 1. Check environment
zypheron kali detect

# 2. Check tools
zypheron tools check

# 3. Install critical tools
zypheron tools install-all --critical-only -y

# 4. Configure settings
zypheron config wizard
```

---

## Environment Detection

Zypheron automatically detects your environment:

### Check Environment

```bash
zypheron kali detect
```

Output shows:
- Operating system (Kali, Ubuntu, etc.)
- WSL status (if running in Windows Subsystem for Linux)
- Available security tools

### Supported Environments

| Environment | Support Level | Notes |
|-------------|--------------|-------|
| **Kali Linux** | Full | All tools available |
| **Ubuntu/Debian** | Good | Most tools via apt |
| **macOS** | Good | Tools via Homebrew |
| **WSL2** | Good | Same as Ubuntu |
| **Windows Native** | Limited | Use WSL2 instead |

---

## Tool Installation

### Check Tool Status

```bash
# See all tools and their status
zypheron tools check

# Output shows:
#  ✓ nmap (installed)
#  ✗ nikto (not installed)
#  ✓ nuclei (installed)
#  ...
```

### Install Individual Tools

```bash
zypheron tools install nmap
zypheron tools install nikto
zypheron tools install nuclei
```

### Install Tool Categories

```bash
# Critical tools only (nmap, gdb, etc.)
zypheron tools install-all --critical-only -y

# High priority tools (includes web scanners)
zypheron tools install-all --high-priority -y

# All tools
zypheron tools install-all -y
```

### Tool Categories

| Category | Tools | Priority |
|----------|-------|----------|
| **Network Scanning** | nmap, masscan | Critical |
| **Web Application** | nikto, nuclei, sqlmap, gobuster, ffuf, feroxbuster, dirsearch, wfuzz | High |
| **Web Recon** | httpx, katana, gau, waybackurls, assetfinder | Medium |
| **API Testing** | kiterunner, newman, schemathesis, jwt-tool | Medium |
| **Password Cracking** | hydra, john, hashcat | High |
| **Reconnaissance** | subfinder, amass, theharvester | Medium |
| **Reverse Engineering** | gdb, radare2, ghidra, strings, objdump | High |
| **Forensics** | volatility, sleuthkit, binwalk, foremost | Medium |
| **Pwn/Exploitation** | pwntools, checksec, ropper | High |

### Manual Tool Installation

If automatic installation fails:

```bash
# Kali/Debian/Ubuntu
sudo apt update
sudo apt install nmap nikto sqlmap

# Go-based tools
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Python-based tools
pip3 install pwntools
pip3 install dirsearch wfuzz schemathesis jwt-tool

# Node/NPM-based tools
npm install -g newman

# Add Go bin to PATH
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

---

## Configuration

### Configuration Wizard

```bash
zypheron config wizard
```

### View Configuration

```bash
# Show all settings
zypheron config get

# Show specific setting
zypheron config get api.url
zypheron config get scanning.timeout
```

### Set Configuration

```bash
# API settings
zypheron config set api.url http://localhost:3001
zypheron config set api.timeout 30000

# Scanning defaults
zypheron config set scanning.default_ports "1-1000"
zypheron config set scanning.timeout 300

# Output preferences
zypheron config set output.format json
zypheron config set output.colorize true

# AI settings
zypheron config set ai.provider anthropic
zypheron config set ai.model claude-opus-4-6
```

### API Key Storage

```bash
# Store API keys securely (uses system keyring)
zypheron config set-key anthropic
zypheron config set-key openai
zypheron config set-key google

# View configured providers
zypheron config get-providers
```

### Configuration File Location

- Linux/macOS: `~/.zypheron/config.json`
- Windows: `%APPDATA%\zypheron\config.json`

---

## Basic Usage

### Network Scanning

```bash
# Quick scan (top 1000 ports)
zypheron scan example.com

# Specific ports
zypheron scan example.com --ports 80,443,8080

# Port range
zypheron scan example.com --ports 1-1000

# Full port scan
zypheron scan example.com --ports 1-65535

# Fast scan (uses masscan, requires root)
sudo zypheron scan 192.168.1.0/24 --fast

# Scan with specific tool
zypheron scan example.com --tool nmap
```

### Web Application Scanning

```bash
# Web scan mode (nikto, nuclei)
zypheron scan https://example.com --web

# Full pentest suite
zypheron scan https://example.com --full

# Specific web tool
zypheron scan https://example.com --tool nikto
zypheron scan https://example.com --tool nuclei
```

### Tool Management

```bash
# List all tools
zypheron tools list

# List installed only
zypheron tools list --installed

# List missing only
zypheron tools list --missing

# Get tool info
zypheron tools info nmap

# Get recommendation
zypheron tools suggest "web scan"
```

### AI Chat

```bash
# Interactive chat
zypheron chat

# Quick question
zypheron chat "How do I test for XSS?"

# Security analysis
zypheron chat "I found port 3389 open. What are the security implications?"
```

---

## Advanced Usage

### AI-Enhanced Scanning

```bash
# AI-guided (AI suggests what to scan)
zypheron scan example.com --ai-guided

# AI analysis of results
zypheron scan example.com --ai-analysis

# Combined
zypheron scan example.com --ai-guided --ai-analysis
```

### Reverse Engineering

```bash
# Analyze a binary
zypheron reverse-eng /path/to/binary

# Use specific tool
zypheron reverse-eng /path/to/binary --tool radare2
zypheron reverse-eng /path/to/binary --tool strings
zypheron reverse-eng /path/to/binary --tool objdump

# Check file type first
zypheron reverse-eng /path/to/binary --tool file
```

### Digital Forensics

```bash
# Analyze file/image
zypheron forensics /path/to/file

# Memory forensics
zypheron forensics memory.dump --tool volatility

# Disk forensics
zypheron forensics disk.img --tool sleuthkit

# Firmware analysis
zypheron forensics firmware.bin --tool binwalk
```

### Binary Exploitation Analysis

```bash
# Check security features
zypheron pwn /path/to/binary --tool checksec

# Find ROP gadgets
zypheron pwn /path/to/binary --tool ropper

# Find one_gadgets
zypheron pwn /lib/x86_64-linux-gnu/libc.so.6 --tool one_gadget
```

### Google Dorking

```bash
# Search with dorks
zypheron dork "site:example.com filetype:pdf"
zypheron dork "inurl:admin site:example.com"
```

### Output Options

```bash
# JSON output
zypheron scan example.com --format json

# Save to file
zypheron scan example.com --output results.txt
zypheron scan example.com --output results.json --format json

# Disable colors (for piping)
zypheron scan example.com --no-color

# Quiet mode (less output)
zypheron scan example.com --quiet
```

---

## Workflows

### Basic Security Assessment

```bash
# 1. Initial reconnaissance
zypheron recon example.com

# 2. Port scan
zypheron scan example.com --ports 1-10000

# 3. Web application scan (if web services found)
zypheron scan https://example.com --web

# 4. AI analysis
zypheron chat "Analyze my findings from scanning example.com"
```

### Web Application Pentest

```bash
# 1. Subdomain enumeration
zypheron osint subdomain example.com

# 2. Port scan discovered subdomains
zypheron scan discovered-subdomain.example.com

# 3. Web vulnerability scan
zypheron scan https://example.com --tool nuclei

# 4. Directory bruteforce
zypheron fuzz https://example.com

# 5. SQL injection testing
zypheron scan https://example.com --tool sqlmap
```

### Binary Analysis

```bash
# 1. Identify file
zypheron reverse-eng suspicious_file --tool file

# 2. Extract strings
zypheron reverse-eng suspicious_file --tool strings

# 3. Check security features
zypheron pwn suspicious_file --tool checksec

# 4. Disassemble
zypheron reverse-eng suspicious_file --tool objdump

# 5. Full analysis (if needed)
zypheron reverse-eng suspicious_file --tool radare2
```

### Incident Response

```bash
# 1. Identify suspicious files
zypheron forensics /evidence/file --tool file

# 2. Extract strings
zypheron reverse-eng /evidence/file --tool strings

# 3. Memory analysis
zypheron forensics /evidence/memory.dump --tool volatility

# 4. Disk analysis
zypheron forensics /evidence/disk.img --tool sleuthkit
```

---

## Best Practices

### Security

1. **Always get authorization** before testing any system
2. **Use VPN/proxy** for sensitive operations
3. **Store API keys securely** using keyring, not plaintext
4. **Review scan results** before sharing - they may contain sensitive info

### Performance

1. **Use `--fast` mode** for large networks (requires root)
2. **Limit port ranges** when possible
3. **Use `--timeout`** to prevent hanging scans
4. **Run resource-intensive tools** (hashcat, etc.) on appropriate hardware

### Workflow

1. **Start with reconnaissance** before active scanning
2. **Document everything** using output files
3. **Use AI analysis** to understand complex results
4. **Verify findings** before reporting

### Tool Selection

| Task | Recommended Tool |
|------|-----------------|
| Quick port scan | nmap |
| Fast network scan | masscan (requires root) |
| Web vulnerabilities | nuclei |
| Web server analysis | nikto |
| HTTP probing | httpx |
| Web crawling | katana |
| URL discovery | gau, waybackurls |
| SQL injection | sqlmap |
| Directory bruteforce | gobuster, ffuf, feroxbuster |
| API endpoint discovery | kiterunner |
| API testing | newman, schemathesis |
| JWT testing | jwt-tool |
| Password cracking | hashcat (GPU), john (CPU) |
| Binary analysis | radare2, ghidra |
| Memory forensics | volatility |

---

## Getting Help

### In-CLI Help

```bash
# General help
zypheron --help

# Command-specific help
zypheron scan --help
zypheron tools --help
zypheron chat --help
```

### Documentation

- [INSTALL.md](INSTALL.md) - Installation
- [GO_GUIDE.md](GO_GUIDE.md) - CLI reference
- [AI_GUIDE.md](AI_GUIDE.md) - AI features

### Troubleshooting

```bash
# Debug mode
zypheron --debug scan example.com

# Check tool status
zypheron tools check

# Test AI connection
zypheron ai status
```

### Support

- GitHub Issues: https://github.com/KKingZero/Cobra-AI/issues
- See [HELP.md](../HELP.md) for common issues
