# Zypheron - AI-Powered Penetration Testing CLI

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)
[![Python Version](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> High-performance penetration testing CLI written in Go with AI-powered analysis.

```
╔══════════════════════════════════════════════════════════════════════╗
║  ███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗ ██╗   ██╗ ║
║  ╚══███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔═══██╗████╗ ██║ ║
║    ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝██║   ██║██╔██╗██║ ║
║   ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║██║╚████║ ║
║  ███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚███║ ║
║  ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝ ║
║                AI-Powered Penetration Testing Platform               ║
╚══════════════════════════════════════════════════════════════════════╝
```

## Quick Start

```bash
# Clone and build
git clone https://github.com/KKingZero/Zypheron-CLI.git
cd Zypheron-CLI/zypheron-go
go mod tidy && go build -o zypheron ./cmd/zypheron

# Install system-wide (optional)
sudo cp zypheron /usr/local/bin/

# Start scanning
zypheron scan example.com
```

## Features

- **Fast** - Single ~10MB binary, 5-10ms startup
- **30+ Security Tools** - nmap, nuclei, nikto, sqlmap, radare2, and more
- **AI-Powered** - Chat assistant, scan analysis, guided scanning
- **Cross-Platform** - Linux, macOS, Windows (WSL)
- **OPSEC-Friendly** - Minimal footprint, no dependencies

## Documentation

| Guide | Description |
|-------|-------------|
| **[Quick Start](QUICKSTART.md)** | Get running in under 5 minutes |
| **[Installation](docs/INSTALL.md)** | Full installation guide with all options |
| **[Setup & Usage](docs/SETUP_AND_USE.md)** | Configuration and usage guide |
| **[Go CLI Reference](docs/GO_GUIDE.md)** | Complete command reference |
| **[AI Features](docs/AI_GUIDE.md)** | AI setup and usage |
| **[MCP Integration](docs/MCP_INTEGRATION.md)** | Connect AI agents to security tools |
| **[Troubleshooting](HELP.md)** | Common issues and solutions |

## Commands

```bash
# Scanning
zypheron scan example.com              # Basic scan
zypheron scan example.com --web        # Web app scan
zypheron scan example.com --ai-guided  # AI-guided scan

# Tool Management
zypheron tools check                   # Check installed tools
zypheron tools install-all             # Install all tools

# AI Chat
zypheron chat "How do I test for SQLi?"

# Reverse Engineering
zypheron reverse-eng binary --tool radare2

# Forensics
zypheron forensics image.dd --tool volatility
```

## Integrated Tools

| Category | Tools |
|----------|-------|
| **Scanning** | nmap, masscan, nuclei |
| **Web** | nikto, sqlmap, gobuster, ffuf |
| **Password** | hydra, john, hashcat |
| **Recon** | subfinder, amass, theharvester |
| **RE/Pwn** | radare2, gdb, ghidra, pwntools, checksec |
| **Forensics** | volatility, sleuthkit, binwalk |

## Requirements

- Go 1.21+ (for building)
- Python 3.9+ (for AI features)
- Linux/macOS/WSL (Kali recommended)

## Legal

**For authorized security testing only.** Always obtain written permission before testing any systems. See [SECURITY.md](SECURITY.md) for our security policy.

## License

MIT License - see [LICENSE](LICENSE)
