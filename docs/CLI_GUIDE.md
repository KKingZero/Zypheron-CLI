# 📖 Zypheron CLI Guide

Complete command reference for the Zypheron CLI.

## 📋 Table of Contents

- [Getting Started](#getting-started)
- [Global Flags](#global-flags)
- [Network Security](#network-security)
- [Web Security](#web-security)
- [Binary Analysis](#binary-analysis)
- [API Security](#api-security)
- [AI Features](#ai-features)
- [Tool Management](#tool-management)
- [Configuration](#configuration)
- [Examples](#examples)

## 🚀 Getting Started

### Basic Usage
```bash
zypheron [command] [arguments] [flags]
```

### Get Help
```bash
zypheron --help                # Main help
zypheron [command] --help      # Command-specific help
```

### Quick Examples
```bash
zypheron scan example.com                    # Basic scan
zypheron reverse-eng /path/to/binary         # Analyze binary
zypheron api-pentest https://api.example.com # Test API
zypheron dork "site:example.com"             # Search dorking
```

## 🌐 Global Flags

Available for all commands:

| Flag | Short | Description |
|------|-------|-------------|
| `--debug` | `-d` | Enable debug mode with verbose output |
| `--no-color` | | Disable colored output |
| `--no-banner` | | Disable ASCII banner |
| `--help` | `-h` | Show help for command |
| `--version` | `-v` | Show version information |

## 🔍 Network Security

### `scan` - Security Scanning

Perform security scans using integrated Kali tools.

```bash
zypheron scan [target] [flags]
```

**Flags:**
- `-t, --tool <name>` - Specific tool (nmap, nikto, nuclei, masscan)
- `-p, --ports <range>` - Port range (default: 1-1000)
- `--web` - Web application scanning mode
- `--full` - Full pentest suite
- `--fast` - Quick scan mode
- `--stream` - Stream output in real-time (default: true)
- `--ai-guided` - AI-guided scanning with ML predictions
- `--ai-analysis` - AI-powered vulnerability analysis
- `--timeout <seconds>` - Timeout (default: 300)
- `-o, --output <file>` - Output file
- `--format <type>` - Output format (text, json, xml)
- `-y, --yes` - Assume yes for prompts
- `--no-input` - Non-interactive mode

**Examples:**
```bash
# Basic scan
zypheron scan example.com

# Specific tool
zypheron scan example.com --tool nmap

# Web scan
zypheron scan https://example.com --web

# Fast scan with AI analysis
zypheron scan example.com --fast --ai-analysis

# Custom ports, non-interactive
zypheron scan example.com -p 1-65535 --yes --no-input
```

### `recon` - Reconnaissance

OSINT and reconnaissance operations.

```bash
zypheron recon [target]
```

**Features:**
- Subdomain enumeration
- DNS discovery
- OSINT gathering

## 🌐 Web Security

### `fuzz` - Web Fuzzing

Directory and file fuzzing operations.

```bash
zypheron fuzz [target] [flags]
```

**Tools**: ffuf, gobuster

### `osint` - OSINT Gathering

Open-source intelligence operations.

```bash
zypheron osint [type] [target]
```

**Tools**: theharvester, subfinder, amass

## 🔧 Binary Analysis

### `reverse-eng` - Reverse Engineering

Analyze binaries for reverse engineering.

```bash
zypheron reverse-eng [binary] [flags]
```

**Flags:**
- `-t, --tool <name>` - Tool (file, strings, objdump, readelf, radare2, gdb, ghidra)
- `-c, --chain <name>` - Use tool chain (reverse_engineering)
- `--stream` - Stream output (default: true)
- `--timeout <seconds>` - Timeout (default: 600)
- `-o, --output <file>` - Save output
- `-y, --yes` - Non-interactive
- `--no-input` - No prompts

**Examples:**
```bash
# Quick analysis
zypheron reverse-eng /path/to/binary

# Specific tool
zypheron reverse-eng binary --tool radare2

# Use tool chain
zypheron reverse-eng binary --chain reverse_engineering

# Save output
zypheron reverse-eng binary --tool strings -o strings.txt
```

**Supported Tools:**
- `file` - Determine file type
- `strings` - Extract printable strings
- `objdump` - Display object file information
- `readelf` - Display ELF file information
- `radare2` - Advanced reverse engineering
- `gdb` - GNU debugger
- `ghidra` - Software reverse engineering framework

### `pwn` - Binary Exploitation

Binary exploitation and pwnable analysis.

```bash
zypheron pwn [binary] [flags]
```

**Flags:** Same as `reverse-eng`

**Examples:**
```bash
# Security checks
zypheron pwn binary --tool checksec

# Find ROP gadgets
zypheron pwn binary --tool ropper

# GDB analysis
zypheron pwn binary --tool gdb

# Use pwn tool chain
zypheron pwn binary --chain pwn
```

**Supported Tools:**
- `checksec` - Check security properties
- `strings` - String extraction
- `gdb` - Debugging and analysis
- `pwntools` - CTF framework
- `ropper` - ROP gadget finder
- `one_gadget` - One-gadget RCE finder

### `forensics` - Digital Forensics

Digital forensics analysis for disk images and files.

```bash
zypheron forensics [target] [flags]
```

**Flags:**
- `--tool <name>` - Tool (file, strings, binwalk, foremost, volatility, sleuthkit)
- `-t, --target <file>` - Target file/image
- `-c, --chain <name>` - Use tool chain
- `--timeout <seconds>` - Timeout (default: 1800)

**Examples:**
```bash
# Memory forensics
zypheron forensics memory.dump --tool volatility

# File carving
zypheron forensics disk.img --tool foremost

# Firmware analysis
zypheron forensics firmware.bin --tool binwalk

# Use forensics chain
zypheron forensics evidence.dd --chain forensics
```

**Supported Tools:**
- `file` - File type identification
- `strings` - String extraction
- `binwalk` - Firmware analysis and extraction
- `foremost` - File carving
- `volatility` - Memory forensics
- `sleuthkit` - Disk forensics

## 🔒 API Security

### `api-pentest` - API Security Testing

Test APIs for OWASP API Security Top 10 vulnerabilities.

```bash
zypheron api-pentest [url] [flags]
```

**Flags:**
- `-u, --url <url>` - API base URL
- `--timeout <seconds>` - Timeout (default: 30)
- `-o, --output <file>` - Save results
- `--bola` - Test for BOLA (Broken Object Level Authorization)
- `--bfla` - Test for BFLA (Broken Function Level Authorization)
- `--rate-limit` - Test rate limiting
- `-y, --yes` - Non-interactive
- `--no-input` - No prompts

**Examples:**
```bash
# Full API scan
zypheron api-pentest https://api.example.com

# Specific tests
zypheron api-pentest https://api.example.com --bola --bfla

# With output
zypheron api-pentest https://api.example.com -o report.txt
```

**Tests Performed:**
- API endpoint discovery
- BOLA (Broken Object Level Authorization)
- BFLA (Broken Function Level Authorization)
- Rate limiting
- Excessive data exposure
- Security misconfiguration

## 🤖 AI Features

### `chat` - AI Chat Assistant

Interactive AI security assistant.

```bash
zypheron chat [message] [flags]
```

**Examples:**
```bash
# Ask a question
zypheron chat "What is SQL injection?"

# Get methodology guidance
zypheron chat "How do I test for OWASP Top 10?"

# Technical help
zypheron chat "Explain buffer overflow exploitation"
```

### `ai` - AI Engine Management

Manage the AI engine backend.

```bash
zypheron ai [command]
```

**Subcommands:**
- `start` - Start AI engine
- `stop` - Stop AI engine
- `status` - Check status
- `providers` - List providers
- `test` - Test AI connection

**Examples:**
```bash
# Start AI engine
zypheron ai start

# Check status
zypheron ai status

# List providers
zypheron ai providers

# Test specific provider
zypheron ai test --provider claude
```

### `dork` - AI-Powered Dorking

Google/Bing dorking with AI enhancement.

```bash
zypheron dork [query] [flags]
```

**Flags:**
- `-q, --query <text>` - Search query
- `-e, --engine <name>` - Search engine (google, bing)
- `-m, --max-results <n>` - Maximum results (default: 10)
- `--ai-guided` - Use AI to enhance query
- `-o, --output <file>` - Save results
- `-y, --yes` - Non-interactive

**Examples:**
```bash
# Basic dorking
zypheron dork "site:example.com inurl:admin"

# AI-enhanced query
zypheron dork "find admin panels" --ai-guided

# Bing search
zypheron dork "site:example.com" --engine bing

# Save results
zypheron dork "site:example.com" -o results.txt
```

## 🛠️ Tool Management

### `tools` - Manage Security Tools

Check, install, and manage security tools.

```bash
zypheron tools [command]
```

**Subcommands:**

#### `check` - Check Installed Tools
```bash
zypheron tools check [--category <cat>]
```

#### `list` - List All Tools
```bash
zypheron tools list [--category <cat>] [--installed] [--missing]
```

#### `info` - Tool Information
```bash
zypheron tools info <tool>
```

#### `suggest` - Suggest Tool for Task
```bash
zypheron tools suggest <task>
```

#### `install` - Install Tool
```bash
zypheron tools install <tool> [-y]
```

#### `install-all` - Install All Tools
```bash
zypheron tools install-all [--critical-only] [--high-priority] [-y]
```

**Examples:**
```bash
# Check all tools
zypheron tools check

# List installed tools
zypheron tools list --installed

# Get tool info
zypheron tools info nmap

# Suggest tool for scanning
zypheron tools suggest scan

# Install specific tool
zypheron tools install radare2

# Install all critical tools
zypheron tools install-all --critical-only
```

## ⚙️ Configuration

### `config` - Configuration Management

Manage Zypheron configuration.

```bash
zypheron config [command]
```

**Common Tasks:**
```bash
# Set AI provider
zypheron config set ai.provider claude

# Set default timeout
zypheron config set timeout 600

# View configuration
zypheron config show
```

## 📚 Examples

### Complete Penetration Test
```bash
# 1. Reconnaissance
zypheron osint email target@example.com
zypheron recon example.com

# 2. Network scan
zypheron scan example.com --full

# 3. Web application test
zypheron scan https://example.com --web --ai-analysis

# 4. API testing
zypheron api-pentest https://api.example.com

# 5. Generate report
zypheron report --format pdf
```

### Binary Analysis Workflow
```bash
# 1. Identify file type
zypheron reverse-eng binary --tool file

# 2. Extract strings
zypheron reverse-eng binary --tool strings -o strings.txt

# 3. Check security features
zypheron pwn binary --tool checksec

# 4. Full analysis
zypheron reverse-eng binary --chain reverse_engineering
```

### API Security Assessment
```bash
# 1. Discover endpoints
zypheron api-pentest https://api.example.com

# 2. Test authorization
zypheron api-pentest https://api.example.com --bola --bfla

# 3. Test rate limiting
zypheron api-pentest https://api.example.com --rate-limit

# 4. Full assessment
zypheron api-pentest https://api.example.com --all
```

## 💡 Tips & Tricks

### Performance
```bash
# Fast scan for quick results
zypheron scan example.com --fast

# Parallel scanning (use tools separately)
zypheron scan example.com --tool masscan &
zypheron scan example.com --tool nmap &
```

### Automation
```bash
# Non-interactive mode
zypheron scan example.com --yes --no-input

# Save all outputs
zypheron scan example.com -o scan.txt 2>&1 | tee full-log.txt
```

### AI Integration
```bash
# Always use AI analysis for better insights
zypheron scan example.com --ai-analysis

# Get AI guidance before testing
zypheron chat "Best approach for testing example.com?"
```

---

**For more information, see:**
- [SETUP.md](SETUP.md) - Installation guide
- [DEV_STATUS.md](DEV_STATUS.md) - Feature status
- [TOOL_CHAINS.md](TOOL_CHAINS.md) - Tool chain configuration

