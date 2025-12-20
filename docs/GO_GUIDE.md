# Zypheron Go CLI Guide

Complete reference for the Zypheron Go CLI - commands, options, and examples.

## Table of Contents

- [Overview](#overview)
- [Command Reference](#command-reference)
- [Scanning](#scanning)
- [Tool Management](#tool-management)
- [Configuration](#configuration)
- [Reverse Engineering](#reverse-engineering)
- [Forensics](#forensics)
- [Pwn/Exploitation Analysis](#pwnexploitation-analysis)
- [Output Formats](#output-formats)
- [Development](#development)

---

## Overview

The Zypheron CLI is written in Go for maximum performance and minimal footprint:

| Metric | Value |
|--------|-------|
| **Binary Size** | ~10 MB |
| **Startup Time** | 5-10 ms |
| **Memory Usage** | 10-20 MB |
| **Dependencies** | 0 (single binary) |

### Basic Usage

```bash
zypheron [command] [flags]
zypheron [command] --help
```

### Global Flags

| Flag | Description |
|------|-------------|
| `--debug`, `-d` | Enable debug output |
| `--no-banner` | Disable ASCII banner |
| `--no-color` | Disable colored output |
| `--help`, `-h` | Show help |
| `--version` | Show version |

---

## Command Reference

### All Commands

| Command | Description |
|---------|-------------|
| `scan` | Security scanning with Kali tools |
| `tools` | Manage and check security tools |
| `chat` | AI chat assistant |
| `config` | Configuration management |
| `setup` | Initial setup and environment detection |
| `recon` | Reconnaissance operations |
| `bruteforce` | Credential/password attacks |
| `fuzz` | Web fuzzing |
| `osint` | Open source intelligence |
| `threat` | Threat intelligence lookups |
| `dork` | Google/Bing dorking |
| `reverse-eng` | Reverse engineering analysis |
| `forensics` | Digital forensics |
| `pwn` | Binary exploitation analysis |
| `mcp` | MCP (Model Context Protocol) server |
| `ai` | AI engine management |
| `report` | Report generation |
| `dashboard` | Real-time monitoring |
| `kali` | Kali-specific operations |
| `completion` | Shell completion scripts |

---

## Scanning

### Basic Scans

```bash
# Quick scan with nmap
zypheron scan example.com

# Scan with specific ports
zypheron scan example.com --ports 80,443,8080

# Scan a port range
zypheron scan example.com --ports 1-1000

# Full port scan
zypheron scan example.com --ports 1-65535
```

### Scan Types

```bash
# Web application scan (uses nikto, nuclei)
zypheron scan https://example.com --web

# Fast scan (uses masscan)
zypheron scan 192.168.1.0/24 --fast

# Full pentest suite (multiple tools)
zypheron scan example.com --full

# Use specific tool
zypheron scan example.com --tool nuclei
zypheron scan example.com --tool nikto
zypheron scan example.com --tool nmap
```

### AI-Enhanced Scanning

```bash
# AI-guided scanning (AI suggests what to scan)
zypheron scan example.com --ai-guided

# Scan with AI analysis of results
zypheron scan example.com --ai-analysis
```

### Scan Options

| Flag | Description |
|------|-------------|
| `--ports`, `-p` | Port specification (e.g., "80,443" or "1-1000") |
| `--tool`, `-t` | Specific tool to use |
| `--web`, `-w` | Web application scan mode |
| `--fast`, `-f` | Fast scan mode (uses masscan) |
| `--full` | Full pentest suite |
| `--ai-guided` | AI-guided scanning |
| `--ai-analysis` | AI analysis of results |
| `--timeout` | Scan timeout in seconds |
| `--output`, `-o` | Output file path |
| `--format` | Output format (text, json, xml) |

---

## Tool Management

### Checking Tools

```bash
# Check all installed tools
zypheron tools check

# Check specific category
zypheron tools check --category web
zypheron tools check --category scanner
zypheron tools check --category bruteforce
```

### Listing Tools

```bash
# List all available tools
zypheron tools list

# List only installed tools
zypheron tools list --installed

# List only missing tools
zypheron tools list --missing

# Filter by category
zypheron tools list --category forensics
```

### Tool Information

```bash
# Get detailed info about a tool
zypheron tools info nmap
zypheron tools info nuclei
zypheron tools info radare2
```

### Installing Tools

```bash
# Install a specific tool
zypheron tools install nmap
zypheron tools install nuclei

# Install with confirmation skip
zypheron tools install nmap -y

# Install all missing tools
zypheron tools install-all

# Install only critical tools
zypheron tools install-all --critical-only

# Install critical and high priority
zypheron tools install-all --high-priority
```

### Tool Suggestions

```bash
# Get tool recommendation for a task
zypheron tools suggest "port scan"
zypheron tools suggest "web scan"
zypheron tools suggest "password crack"
zypheron tools suggest "reverse engineering"
```

### Available Tool Categories

| Category | Tools |
|----------|-------|
| **scanner** | nmap, masscan, nuclei |
| **web** | nikto, sqlmap, gobuster, ffuf |
| **bruteforce** | hydra, john, hashcat |
| **recon** | subfinder, amass, theharvester |
| **wireless** | aircrack-ng |
| **reverse-engineering** | radare2, ghidra, gdb, strings, objdump |
| **forensics** | volatility, autopsy, sleuthkit, binwalk |
| **pwn** | pwntools, checksec, ropper, one_gadget |

---

## Configuration

### View Configuration

```bash
# Show all config
zypheron config get

# Show specific value
zypheron config get api.url

# Show config file path
zypheron config path
```

### Set Configuration

```bash
# Set a value
zypheron config set api.url http://localhost:3001
zypheron config set scanning.timeout 300
zypheron config set output.format json

# Run configuration wizard
zypheron config wizard
```

### API Key Management

```bash
# Store API key securely (uses system keyring)
zypheron config set-key anthropic
zypheron config set-key openai

# List configured providers
zypheron config get-providers
```

### Configuration File

Location: `~/.config/zypheron/config.yaml`

```yaml
api:
  url: http://localhost:3001
  timeout: 30000

scanning:
  default_ports: "1-1000"
  timeout: 300

ai:
  provider: claude
  model: claude-3-sonnet-20240229

output:
  format: text
  colorize: true
```

---

## Reverse Engineering

Analyze binaries with integrated RE tools:

```bash
# Auto-detect and analyze binary
zypheron reverse-eng /path/to/binary

# Use specific tool
zypheron reverse-eng /path/to/binary --tool radare2
zypheron reverse-eng /path/to/binary --tool strings
zypheron reverse-eng /path/to/binary --tool objdump

# With timeout
zypheron reverse-eng /path/to/binary --timeout 120
```

### Available RE Tools

| Tool | Description |
|------|-------------|
| `file` | Identify file type |
| `strings` | Extract printable strings |
| `objdump` | Disassemble binary |
| `readelf` | Display ELF information |
| `radare2` | Full RE framework |
| `ghidra` | NSA RE tool (GUI) |
| `gdb` | GNU debugger |

---

## Forensics

Digital forensics and incident response:

```bash
# Analyze file/image
zypheron forensics /path/to/file

# Use specific tool
zypheron forensics /path/to/image --tool volatility
zypheron forensics /path/to/disk.img --tool sleuthkit
zypheron forensics /path/to/firmware.bin --tool binwalk
```

### Available Forensics Tools

| Tool | Description |
|------|-------------|
| `volatility` | Memory forensics |
| `sleuthkit` | Disk forensics |
| `autopsy` | Digital forensics platform |
| `binwalk` | Firmware analysis |
| `foremost` | File carving |
| `strings` | String extraction |
| `file` | File identification |

---

## Pwn/Exploitation Analysis

Binary exploitation analysis tools:

```bash
# Analyze binary for exploitation
zypheron pwn /path/to/binary

# Check security features
zypheron pwn /path/to/binary --tool checksec

# Find ROP gadgets
zypheron pwn /path/to/binary --tool ropper

# Find one_gadgets in libc
zypheron pwn /path/to/libc.so.6 --tool one_gadget
```

### Available Pwn Tools

| Tool | Description |
|------|-------------|
| `checksec` | Check binary security features |
| `ropper` | ROP gadget finder |
| `one_gadget` | Find one-shot RCE in libc |
| `pwntools` | Python pwn library (for scripts) |
| `gdb` | Debugger |

---

## Output Formats

### Text Output (Default)

```bash
zypheron scan example.com
```

### JSON Output

```bash
zypheron scan example.com --format json
zypheron scan example.com --format json --output results.json
```

### Save to File

```bash
zypheron scan example.com --output scan-results.txt
zypheron scan example.com --output results.json --format json
```

---

## Development

### Building from Source

```bash
cd zypheron-go

# Standard build
go build -o zypheron ./cmd/zypheron

# Optimized build (smaller binary)
go build -ldflags="-s -w" -o zypheron ./cmd/zypheron

# With race detection (for testing)
go build -race -o zypheron ./cmd/zypheron
```

### Cross-Compilation

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o zypheron-linux-amd64 ./cmd/zypheron

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -o zypheron-linux-arm64 ./cmd/zypheron

# macOS Intel
GOOS=darwin GOARCH=amd64 go build -o zypheron-darwin-amd64 ./cmd/zypheron

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o zypheron-darwin-arm64 ./cmd/zypheron

# Windows
GOOS=windows GOARCH=amd64 go build -o zypheron-windows-amd64.exe ./cmd/zypheron
```

### Running Tests

```bash
cd zypheron-go
go test ./...
go test -v ./internal/...
```

### Project Structure

```
zypheron-go/
├── cmd/zypheron/       # Main entry point
├── internal/
│   ├── commands/       # CLI commands
│   ├── kali/          # Kali tool integration
│   ├── tools/         # Tool execution
│   ├── validation/    # Input validation
│   ├── ui/            # Terminal UI
│   ├── aibridge/      # AI engine communication
│   ├── storage/       # Data persistence
│   └── config/        # Configuration
├── pkg/               # Public packages
│   └── types/         # Shared types
└── go.mod             # Go module file
```

---

## Examples

### Full Workflow Example

```bash
# 1. Check environment
zypheron setup

# 2. Check and install tools
zypheron tools check
zypheron tools install-all --critical-only -y

# 3. Run reconnaissance
zypheron recon example.com

# 4. Scan for vulnerabilities
zypheron scan example.com --full

# 5. Analyze specific service
zypheron scan example.com --tool nikto --ports 443

# 6. Get AI analysis
zypheron chat "Analyze these findings and suggest next steps"
```

### Quick Security Assessment

```bash
# Fast scan + AI analysis
zypheron scan target.com --fast --ai-analysis
```

### Binary Analysis

```bash
# Check binary security
zypheron pwn suspicious_binary --tool checksec

# Extract strings
zypheron reverse-eng suspicious_binary --tool strings

# Full RE analysis
zypheron reverse-eng suspicious_binary --tool radare2
```

---

## See Also

- [INSTALL.md](INSTALL.md) - Installation instructions
- [AI_GUIDE.md](AI_GUIDE.md) - AI features
- [SETUP_AND_USE.md](SETUP_AND_USE.md) - Setup and usage
