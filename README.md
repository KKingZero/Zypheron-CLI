# ⚡ Zypheron - AI-Powered Penetration Testing CLI

> High-performance, OPSEC-focused penetration testing command-line tool written in Go

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
- **sqlmap** - SQL injection
- **hydra** - Bruteforce attacks
- **metasploit** - Exploitation framework
- **gobuster** - Directory busting
- **ffuf** - Web fuzzing
- **subfinder** - Subdomain enumeration
- And 10+ more...

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
- `exploit` - Exploitation
- `fuzz` - Web fuzzing
- `osint` - OSINT operations
- `threat` - Threat intelligence
- `report` - Report generation
- `dashboard` - Real-time monitoring
- `setup` - Initial setup
- `kali` - Kali-specific operations

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

## 📞 Support

- **Documentation**: See `zypheron-go/README.md`
- **Issues**: GitHub Issues
- **Security**: Report vulnerabilities responsibly

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## ⚠️ Legal Disclaimer

Zypheron is intended **exclusively for authorized security testing and educational purposes**. Users are solely responsible for ensuring compliance with applicable laws, regulations, and organizational policies. **Always obtain explicit written authorization** before conducting penetration tests on any systems.

Unauthorized access to computer systems is illegal and unethical.

## 🛡️ Security Notice

This tool is designed for professional penetration testers, security researchers, and system administrators. Misuse of this software may violate laws in your jurisdiction. The authors assume no liability for any misuse or damage caused by this software.

---

**⚡ Built for security professionals who demand performance and stealth.**

For detailed documentation, installation instructions, and examples, see **[zypheron-go/README.md](zypheron-go/README.md)**

