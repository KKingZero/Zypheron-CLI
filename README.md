# ⚡ Zypheron - AI-Powered Penetration Testing CLI (FREE VERSION)

[![Go Tests](https://github.com/KKingZero/Cobra-AI/actions/workflows/go-tests.yml/badge.svg)](https://github.com/KKingZero/Cobra-AI/actions/workflows/go-tests.yml)
[![Python Tests](https://github.com/KKingZero/Cobra-AI/actions/workflows/python-tests.yml/badge.svg)](https://github.com/KKingZero/Cobra-AI/actions/workflows/python-tests.yml)
[![Security Scan](https://github.com/KKingZero/Cobra-AI/actions/workflows/security.yml/badge.svg)](https://github.com/KKingZero/Cobra-AI/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/KKingZero/Cobra-AI/branch/main/graph/badge.svg)](https://codecov.io/gh/KKingZero/Cobra-AI)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)
[![Python Version](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> High-performance, OPSEC-focused penetration testing command-line tool written in Go
> 
> **⚠️ FREE VERSION**: This is the free version of Zypheron. Automated exploit execution is not included.
> Zypheron FREE focuses on vulnerability discovery, analysis, and reporting.

```
╔═══════════════════════════════════════════════════════════╗
║  ███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗║
║  ╚══███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔═══██╗
║    ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝██║   ██║║
║   ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║║
║  ███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║╚██████╔╝║
║  ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ║
╚═══════════════════════════════════════════════════════════╝
    AI-Powered Penetration Testing Platform
```

## 🚀 Quick Start

```bash
cd zypheron-go

# Install dependencies
make deps
# in case you had any errros  run this
go mod tidy
# Build
make build

# Install system-wide
sudo make install

# Start pentesting!
zypheron scan example.com
```

## 📖 Full Documentation

**All documentation is in the `zypheron-go/` directory:**

- **[README.md](zypheron-go/README.md)** - Complete documentation
- **[QUICK_START.md](zypheron-go/QUICK_START.md)** - Get started in 5 minutes
- **[MIGRATION_GUIDE.md](zypheron-go/MIGRATION_GUIDE.md)** - Migrating from older versions

## ⚡ What is Zypheron?

Zypheron is a **high-performance penetration testing CLI** built in Go that integrates directly with Kali Linux tools. It provides:

- 🚀 **10-20x faster** than Node.js alternatives
- 📦 **Single 7-15 MB binary** (no dependencies)
- 🔒 **Excellent OPSEC** (minimal footprint)
- 🛠️ **20+ integrated Kali tools**
- 🤖 **AI-powered analysis** (optional backend integration)
- ⚡ **Real-time streaming** output
- 🎯 **Cross-platform** (Linux, macOS, Windows)

## 🎯 Key Features

### Security Scanning
```bash
# Quick scan
zypheron scan example.com

# Web application test
zypheron scan https://example.com --web

# Full pentest suite
zypheron scan example.com --full
```

### Tool Management
```bash
# Check installed tools
zypheron tools check

# List all available tools
zypheron tools list

# Install missing tools
zypheron tools install-all --critical-only
```

### AI Integration
```bash
# AI chat assistant
zypheron chat "How do I test for SQL injection?"

# AI-guided scanning
zypheron scan example.com --ai-guided
```

## 📊 Performance

| Metric | Value |
|--------|-------|
| **Startup Time** | 5-10ms |
| **Binary Size** | 7-15 MB |
| **Memory Usage** | 10-20 MB |
| **Dependencies** | 0 |
| **OPSEC Rating** | Excellent |

## 🛠️ Integrated Tools

- **nmap** - Network scanning
- **nikto** - Web server scanning
- **nuclei** - Vulnerability scanning
- **masscan** - Fast port scanning
- **sqlmap** - SQL injection testing
- **hydra** - Bruteforce attacks
- **gobuster** - Directory busting
- **ffuf** - Web fuzzing
- **subfinder** - Subdomain enumeration
- And 10+ more...

**Note**: Metasploit and automated exploit execution are not available in the FREE version.

## 🎓 Examples

```bash
# Basic security scan
zypheron scan example.com

# Web application pentest
zypheron scan https://example.com --web --ai-analysis

# Fast network scan
zypheron scan 192.168.1.0/24 --fast

# Bruteforce SSH
zypheron bruteforce ssh 192.168.1.1

# OSINT gathering
zypheron osint email target@example.com

# Install all tools
zypheron tools install-all -y
```

## 🐚 Ultra-Fast Mode

For **instant execution**, use the bash wrappers:

```bash
# Direct tool execution (no overhead)
./zypheron-go/scripts/bash/zscan example.com
./zypheron-go/scripts/bash/ztools
```

## 📋 Available Commands

- `scan` - Security scanning
- `tools` - Tool management
- `chat` - AI assistant
- `config` - Configuration
- `recon` - Reconnaissance
- `bruteforce` - Credential attacks
- `fuzz` - Web fuzzing
- `osint` - OSINT operations
- `threat` - Threat intelligence
- `report` - Report generation
- `dashboard` - Real-time monitoring
- `setup` - Initial setup
- `kali` - Kali-specific operations

**Note**: `exploit` command is not available in the FREE version. Upgrade to Zypheron Pro for automated exploit execution.

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│      Zypheron CLI (Single Binary)      │
│       - No dependencies                 │
│       - Statically linked               │
│       - Cross-platform                  │
└──────────────┬──────────────────────────┘
               │
       ┌───────┴────────┐
       │                │
  ┌────▼────┐      ┌────▼────┐
  │  Kali   │      │Optional │
  │  Tools  │      │Backend  │
  └─────────┘      └─────────┘
```

## 📦 Installation

### Prerequisites
- Go 1.21+ (for building from source)
- Linux, macOS, or Windows
- Kali Linux (recommended for tool integration)

### From Source
```bash
git clone https://github.com/yourusername/zypheron.git
cd zypheron/zypheron-go
make deps
make build
sudo make install
```

### Pre-built Binaries
Download from [Releases](https://github.com/yourusername/zypheron/releases)

## 🔒 OPSEC Features

- ✅ **Single binary** - No installation traces
- ✅ **No dependencies** - Statically linked
- ✅ **Stripped symbols** - Harder to reverse engineer
- ✅ **Minimal footprint** - 7-15 MB only
- ✅ **Portable** - Copy and run anywhere

## 🌟 Why Zypheron?

Traditional pentesting CLIs are slow, bloated, and leave traces. Zypheron is:

- **Fast** - Native Go performance
- **Lightweight** - Single small binary
- **Stealthy** - Minimal OPSEC footprint
- **Powerful** - Full Kali tool integration
- **Smart** - Optional AI assistance
- **Professional** - Built for security pros

## 📞 Support & Documentation

- **Main Documentation**: See `zypheron-go/README.md`
- **Security Policy**: [SECURITY.md](SECURITY.md)
- **Testing Guide**: [TESTING.md](TESTING.md)
- **Quick Start**: [zypheron-go/QUICK_START.md](zypheron-go/QUICK_START.md)
- **Issues**: GitHub Issues
- **Security**: Report vulnerabilities responsibly

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## ⚠️ Legal Disclaimer

Zypheron is intended **exclusively for authorized security testing and educational purposes**. Users are solely responsible for ensuring compliance with applicable laws, regulations, and organizational policies. **Always obtain explicit written authorization** before conducting penetration tests on any systems.

Unauthorized access to computer systems is illegal and unethical.

## 🛡️ Security Features

Zypheron implements comprehensive security measures:

### Input Validation & Injection Prevention
- ✅ **Command injection protection** - All user inputs validated against allowlists
- ✅ **Target validation** - Strict validation of IPs, domains, and CIDR ranges
- ✅ **Port validation** - Range checking (1-65535)
- ✅ **Path sanitization** - Prevents directory traversal attacks

### Secure IPC Communication
- 🔐 **Authentication tokens** - 256-bit token for Go ↔ Python communication
- 🔐 **Socket permissions** - Unix socket restricted to owner (0600)
- 🔐 **Token persistence** - Secure storage in `~/.zypheron/ipc.token`

### API Key Storage
- 🔑 **System keyring integration** - Uses OS credential manager
- 🔑 **No plain text storage** - API keys never stored in .env files
- 🔑 **Cross-platform** - Keychain (macOS), Secret Service (Linux), Credential Manager (Windows)

```bash
# Securely store API keys
zypheron config set-key anthropic
zypheron config get-providers
```

### Scan Data Protection
- 💾 **Encrypted storage** - Scan results stored with 0600 permissions
- 💾 **Audit logging** - All scans logged with timestamps
- 💾 **Data isolation** - User-specific storage directories

**For more details, see [SECURITY.md](SECURITY.md)**

## 🛡️ Security Notice

This tool is designed for professional penetration testers, security researchers, and system administrators. Misuse of this software may violate laws in your jurisdiction. The authors assume no liability for any misuse or damage caused by this software.

**Report security vulnerabilities responsibly** - see [SECURITY.md](SECURITY.md) for our security policy.

---

**⚡ Built for security professionals who demand performance and stealth.**

For detailed documentation, installation instructions, and examples, see **[zypheron-go/README.md](zypheron-go/README.md)**

