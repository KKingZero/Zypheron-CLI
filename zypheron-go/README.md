# ⚡ Zypheron CLI - Go Edition (FREE VERSION)

> AI-Powered Penetration Testing Platform with Native Kali Linux Tool Integration

**Rewritten in Go for maximum performance, security, and OPSEC.**

> **⚠️ FREE VERSION**: This version focuses on vulnerability discovery, scanning, and analysis.
> Automated exploit execution is available in Zypheron Pro.

```
╔═══════════════════════════════════════════════════════════╗
║  ███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗║
║  ╚══███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔═══██╗
║    ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝██║   ██║║
║   ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║║
║  ███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║╚██████╔╝║
║  ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ║
╚═══════════════════════════════════════════════════════════╝
```

## 🎯 Why Go?

- **🚀 10-20x Faster Startup** - ~5-10ms vs 100-150ms (Node.js)
- **📦 Single Binary** - 7-15 MB vs 400+ MB with node_modules
- **🔒 Better OPSEC** - No runtime dependencies, harder to reverse engineer
- **⚡ Native Performance** - Compiled, not interpreted
- **🎯 Perfect for Kali** - Integrates directly with system tools

## 📦 Installation

### From Source

```bash
# Install Go (if not already installed)
sudo apt-get install -y golang-go

# Clone and build
git clone https://github.com/yourusername/zypheron.git
cd zypheron/zypheron-go

# Install dependencies
make deps

# Build
make build

# Install to system
sudo make install
```

### Quick Install Script

```bash
curl -sSL https://zypheron.io/install.sh | bash
```

### Pre-built Binaries

Download from [Releases](https://github.com/yourusername/zypheron/releases):

```bash
# Linux (amd64)
wget https://github.com/yourusername/zypheron/releases/download/v1.0.0/zypheron-linux-amd64.tar.gz
tar -xzf zypheron-linux-amd64.tar.gz
sudo mv zypheron /usr/local/bin/
```

## 🚀 Quick Start

### Initial Setup

```bash
# Detect Kali environment and tools
zypheron setup

# Check installed tools
zypheron tools check
```

### Basic Scanning

```bash
# Quick scan with nmap
zypheron scan example.com

# Web application scan
zypheron scan https://example.com --web

# Full pentest suite
zypheron scan example.com --full

# Fast scan with masscan
zypheron scan 192.168.1.0/24 --fast

# AI-guided scanning
zypheron scan example.com --ai-guided
```

### Tool Management

```bash
# List all tools
zypheron tools list

# Check what's installed
zypheron tools check

# Get tool info
zypheron tools info nmap

# Install a tool
zypheron tools install nikto

# Install all critical tools
zypheron tools install-all --critical-only

# Suggest best tool for a task
zypheron tools suggest web
```

### AI Chat Assistant

```bash
# Interactive chat
zypheron chat

# Quick question
zypheron chat "How do I test for SQL injection?"

# Continue previous conversation
zypheron chat --continue session-123
```

## 📋 Available Commands

| Command | Description | Example |
|---------|-------------|---------|
| `scan` | Security scanning with Kali tools | `zypheron scan example.com` |
| `tools` | Manage Kali security tools | `zypheron tools check` |
| `chat` | AI chat for security assistance | `zypheron chat "test findings"` |
| `config` | Configuration management | `zypheron config set api.url http://localhost:3001` |
| `setup` | Initial setup and configuration | `zypheron setup` |
| `recon` | Reconnaissance operations | `zypheron recon example.com` |
| `bruteforce` | Credential attacks | `zypheron bruteforce ssh 192.168.1.1` |
| `exploit` | Exploitation framework | `zypheron exploit --module ms17_010` |
| `fuzz` | Web fuzzing | `zypheron fuzz https://example.com` |
| `osint` | OSINT operations | `zypheron osint email user@example.com` |
| `threat` | Threat intelligence | `zypheron threat ip 8.8.8.8` |
| `report` | Generate reports | `zypheron report generate` |
| `dashboard` | Real-time monitoring | `zypheron dashboard` |
| `kali` | Kali-specific operations | `zypheron kali` |

## 🛠️ Integrated Kali Tools

### Network Scanners
- **nmap** - Network exploration and security auditing
- **masscan** - Fast TCP port scanner
- **nuclei** - Fast vulnerability scanner

### Web Application Tools
- **nikto** - Web server scanner
- **sqlmap** - Automatic SQL injection tool
- **gobuster** - Directory/file & DNS busting
- **ffuf** - Fast web fuzzer

### Exploitation
- **metasploit** - Penetration testing framework

### Bruteforce
- **hydra** - Network logon cracker
- **john** - Password cracker (John the Ripper)
- **hashcat** - Advanced password recovery

### Reconnaissance
- **subfinder** - Subdomain discovery tool
- **amass** - In-depth DNS enumeration
- **theharvester** - E-mail, subdomain harvester

### Wireless
- **aircrack-ng** - WiFi security auditing tools

## ⚙️ Configuration

Configuration file: `~/.config/zypheron/config.yaml`

```yaml
api:
  url: http://localhost:3001
  timeout: 30000

scanning:
  default_ports: "1-1000"
  timeout: 300

output:
  format: text
  colorize: true
```

### Configuration Commands

```bash
# View all config
zypheron config get

# Set a value
zypheron config set api.url http://localhost:3001

# Run configuration wizard
zypheron config wizard

# Show config file path
zypheron config path
```

## 🐚 Bash Wrappers (Ultra-Fast)

For ultra-fast execution without Go overhead:

```bash
# Quick scan (direct tool execution)
./scripts/bash/zscan example.com
./scripts/bash/zscan example.com nikto

# Quick tool check
./scripts/bash/ztools
```

## 🏗️ Development

### Build from Source

```bash
# Install dependencies
make deps

# Build for current platform
make build

# Cross-compile for all platforms
make build-all

# Run tests
make test

# Format code
make fmt

# Development mode (hot reload)
make dev
```

### Project Structure

```
zypheron-go/
├── cmd/zypheron/          # Main entry point
├── internal/
│   ├── commands/          # CLI commands
│   ├── kali/             # Kali integration
│   ├── tools/            # Tool execution
│   ├── ui/               # Terminal UI
│   └── api/              # Backend API client
├── pkg/                  # Public packages
├── scripts/bash/         # Bash wrappers
└── Makefile             # Build automation
```

## 📊 Performance Comparison

| Metric | TypeScript/Node.js | Go | Improvement |
|--------|-------------------|-----|-------------|
| **Binary Size** | 400+ MB | 7-15 MB | **96% smaller** |
| **Startup Time** | ~100-150ms | ~5-10ms | **10-20x faster** |
| **Memory Usage** | 50-100 MB | 10-20 MB | **3-5x less** |
| **Dependencies** | 2,847 files | 1 file | **∞ better** |

## 🔐 OPSEC Benefits

### Before (TypeScript)
```bash
$ find . -type f | wc -l
2,847 files  # Easy to detect and analyze

$ du -sh node_modules/
423M node_modules/  # Massive footprint
```

### After (Go)
```bash
$ ls -lh zypheron
-rwxr-xr-x 1 root root 12M Oct 23 14:30 zypheron

$ file zypheron
zypheron: ELF 64-bit LSB executable, statically linked, stripped

# Single binary - minimal OPSEC footprint
```

## 🎓 Examples

### Example 1: Basic Security Scan

```bash
zypheron scan example.com
```

### Example 2: Full Web Application Test

```bash
zypheron scan https://example.com \
  --web \
  --ai-analysis \
  --output report.json \
  --format json
```

### Example 3: Custom Nmap Scan

```bash
zypheron scan 192.168.1.0/24 \
  --tool nmap \
  --ports 1-65535 \
  --fast
```

### Example 4: Tool Installation

```bash
# Install all critical tools
zypheron tools install-all --critical-only -y

# Install specific tool
zypheron tools install nuclei
```

### Example 5: AI-Assisted Analysis

```bash
# Interactive chat
zypheron chat

# Quick question
zypheron chat "I found port 8080 open with Tomcat. What should I check?"
```

## 🤝 Integration with Backend

Zypheron CLI integrates seamlessly with your existing TypeScript backend:

```bash
# Configure backend URL
zypheron config set api.url https://your-backend.com/api

# Use backend for AI analysis
zypheron scan example.com --ai-analysis

# Backend-powered chat
zypheron chat "analyze these findings"
```

The CLI acts as a lightweight, portable frontend to your powerful backend infrastructure.

## 📝 Migration from TypeScript CLI

The Go version provides **feature parity** with the TypeScript CLI:

✅ All commands implemented  
✅ Tool detection and management  
✅ Real-time output streaming  
✅ Kali Linux integration  
✅ Backend API integration  
✅ Configuration management  
✅ AI chat support  

**What's improved:**
- 10-20x faster startup
- 96% smaller footprint
- No runtime dependencies
- Better OPSEC
- Native performance

## 🔧 Troubleshooting

### Go Not Installed

```bash
# Install Go 1.21+
sudo apt-get update
sudo apt-get install -y golang-go

# Verify installation
go version
```

### Build Errors

```bash
# Clean and rebuild
make clean
make deps
make build
```

### Tool Not Found

```bash
# Check tool status
zypheron tools check

# Install missing tool
zypheron tools install <tool-name>
```

## 📄 License

MIT License - see [LICENSE](../LICENSE) for details.

## ⚠️ Legal Disclaimer

Zypheron CLI is intended exclusively for authorized security testing and educational purposes. Users are solely responsible for ensuring compliance with applicable laws, regulations, and organizational policies. Always obtain explicit written authorization before conducting penetration tests on any systems.

## 🛡️ Stay Secure

Built by security professionals, for security professionals.

---

**⚡ Happy Pentesting with Zypheron CLI (Go Edition)!**

For the full web platform and advanced features, see the main [Zypheron project](../README.md).

