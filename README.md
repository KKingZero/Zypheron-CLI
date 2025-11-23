# 🐍 Zypheron - AI-Powered Penetration Testing Platform

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)
[![Python Version](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> High-performance, AI-powered penetration testing platform with Kali Linux integration

```
╔═══════════════════════════════════════════════════════════╗
║  ███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗ ██╗   ██╗
║  ╚══███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔═══██╗████╗ ██║
║    ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝██║   ██║██╔██╗██║
║   ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║██║╚████║
║  ███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚███║
║  ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝
╚═══════════════════════════════════════════════════════════╝
    AI-Powered Penetration Testing Platform
```

## 📋 Table of Contents

- [Editions](#-editions)
- [Quick Start](#-quick-start)
- [Features](#-features)
- [Architecture](#-architecture)
- [Commands](#-commands)
- [Documentation](#-documentation)
- [Requirements](#-requirements)
- [Contributing](#-contributing)

## 🎯 Editions

Zypheron is available in two editions:

### Free Edition
Complete pre-exploitation toolkit including:
- ✅ OSINT & Reconnaissance
- ✅ Vulnerability Scanning
- ✅ AI-Powered Analysis
- ✅ Manual Security Tools
- ✅ Secrets Detection

[📖 Learn more about Free Edition →](README-FREE.md)

### Professional Edition
Full-featured penetration testing platform:
- ⚡ Everything in Free Edition
- ⚡ Automated Exploitation
- ⚡ Autopent Engine
- ⚡ Credential Attacks
- ⚡ Post-Exploitation
- ⚡ Priority Support

| Feature | Free | Pro |
|---------|------|-----|
| Network/Web Scanning | ✅ | ✅ |
| OSINT & Recon | ✅ | ✅ |
| AI Analysis | ✅ | ✅ |
| Automated Exploitation | ❌ | ✅ |
| Autopent Engine | ❌ | ✅ |
| Post-Exploitation | ❌ | ✅ |

[🚀 Upgrade to Pro →](https://zypheron.net/cli)

## 🚀 Quick Start

### Direct CLI Usage

```bash
# Clone repository
git clone https://github.com/KKingZero/Cobra-AI.git
cd Cobra-AI-Zypheron-CLI

# Build CLI
cd zypheron-go
make build

# Install system-wide (optional)
sudo make install

# Start pentesting!
zypheron scan example.com
zypheron reverse-eng /path/to/binary
zypheron api-pentest https://api.example.com
```

### MCP Integration (AI Agents)

Connect Claude Desktop, Cursor, or VS Code Copilot to Zypheron:

```bash
# Install MCP dependencies (in virtual environment)
cd zypheron-ai
python3 -m venv mcp-venv
source mcp-venv/bin/activate
pip install -r requirements-mcp.txt

# Generate MCP configuration
zypheron mcp config

# Start MCP server  
zypheron mcp start
```

**Quick setup:** Use the helper script:
```bash
cd zypheron-ai
source activate-mcp.sh  # Auto-creates venv and installs deps
```

Now your AI agent can execute Zypheron tools through natural language!

```
User: "Scan example.com for vulnerabilities using nuclei with high severity templates"
AI Agent: [Executes nuclei_scan automatically and analyzes results]
```

🤖 **[MCP Integration Guide →](docs/MCP_INTEGRATION.md)**

📖 **[Full Setup Guide →](docs/SETUP.md)**

## ⚡ Features

### 🎯 Core Capabilities
- **Network Scanning** - nmap, masscan, rustscan integration
- **Web Application Testing** - nikto, nuclei, sqlmap
- **API Security Testing** - OWASP API Security Top 10
- **Reverse Engineering** - ghidra, radare2, gdb, objdump
- **Binary Exploitation** - pwntools, checksec, ropper, one_gadget
- **Digital Forensics** - volatility, sleuthkit, binwalk, foremost
- **AI-Powered Dorking** - Google/Bing dorking with AI enhancement

### 🤖 AI Integration
- **7 AI Providers** - Claude, OpenAI, Gemini, DeepSeek, Grok, Kimi, Ollama
- **MCP Integration** - Connect AI agents (Claude Desktop, Cursor, Copilot) directly to Zypheron tools
- **Autonomous Agents** - Self-guided penetration testing
- **ML Vulnerability Prediction** - Pattern recognition & exploit prediction
- **AI Chat Assistant** - Security guidance and methodology
- **Natural Language Testing** - Execute security tools through conversational AI

### 🔒 Enterprise Features
- **Authenticated Scanning** - Session management & credential handling
- **Secrets Detection** - Find exposed API keys and credentials
- **Dependency Analysis** - CVE matching & SBOM generation
- **Compliance Reporting** - OWASP, PCI-DSS, HIPAA templates
- **Distributed Testing** - Multi-agent coordination

### ⚡ Performance & OPSEC
- **10-20x Faster** than Node.js alternatives
- **Single 7-15 MB Binary** - no dependencies
- **Stripped Symbols** - harder to reverse engineer
- **Minimal Footprint** - excellent operational security
- **Cross-Platform** - Linux, macOS, Windows, WSL

## 🏗️ Architecture

Zypheron uses a **hybrid architecture**:

```
┌─────────────────────────────────────────────┐
│  Go CLI (zypheron-go/)                      │
│  • Fast user-facing CLI                     │
│  • Native tool execution                    │
│  • Real-time streaming output               │
│  • 30+ integrated security tools            │
└─────────────────┬───────────────────────────┘
                  │ IPC (Unix Socket/Named Pipe)
┌─────────────────▼───────────────────────────┐
│  Python AI Engine (zypheron-ai/)            │
│  • Multi-provider AI support                │
│  • ML vulnerability prediction              │
│  • Autonomous pentesting agents             │
│  • API security testing                     │
└─────────────────────────────────────────────┘
```

**Why Hybrid?**
- **Go CLI**: Speed, single binary, excellent OPSEC
- **Python Backend**: AI/ML libraries, extensive security tools
- **Best of Both**: Performance + Intelligence

## 📦 Commands

### Network & Web Security
```bash
zypheron scan <target>              # Security scanning
zypheron recon <target>             # Reconnaissance
zypheron fuzz <target>              # Web fuzzing
zypheron osint <target>             # OSINT gathering
```

### API & Application Security
```bash
zypheron api-pentest <url>          # API security testing
zypheron authenticated-scan <url>   # Authenticated web scanning
zypheron secrets <path>             # Secret scanning
zypheron deps <path>                # Dependency analysis
```

### Binary Analysis & Exploitation
```bash
zypheron reverse-eng <binary>       # Reverse engineering
zypheron pwn <binary>               # Binary exploitation
zypheron forensics <file>           # Digital forensics
```

### AI & Automation
```bash
zypheron dork <query>               # AI-powered dorking
zypheron chat <message>             # AI chat assistant
zypheron ai start                   # Start AI engine
zypheron mcp start                  # Start MCP server for AI agents
zypheron mcp config                 # Generate MCP configuration
```

### Tool Management
```bash
zypheron tools check                # Check installed tools
zypheron tools list                 # List all tools
zypheron tools install <tool>       # Install specific tool
zypheron tools install-all          # Install all tools
```

## 📚 Documentation

| Document | Description |
|----------|-------------|
| **[SETUP.md](docs/SETUP.md)** | Installation and configuration guide |
| **[MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md)** | MCP integration for AI agents (Claude, Cursor, Copilot) |
| **[DEV_STATUS.md](docs/DEV_STATUS.md)** | Current development status |
| **[CLI_GUIDE.md](docs/CLI_GUIDE.md)** | Complete CLI command reference |
| **[API_GUIDE.md](docs/API_GUIDE.md)** | API testing guide |
| **[AI_INTEGRATION.md](docs/AI_INTEGRATION.md)** | AI features and configuration |
| **[TOOL_CHAINS.md](docs/TOOL_CHAINS.md)** | Tool chain configuration |
| **[SECURITY.md](SECURITY.md)** | Security policy |
| **[CHANGELOG.md](CHANGELOG.md)** | Version history |

## 💻 Requirements

### Minimum Requirements
- **Go**: 1.21 or higher
- **Python**: 3.9 or higher (for AI features)
- **OS**: Linux, macOS, Windows, or WSL

### Recommended
- **Kali Linux** 2023.3+ (for best tool integration)
- **8GB RAM** (16GB+ for AI features)
- **10GB Disk Space** (for all tools)

### Security Tools
Zypheron integrates with 30+ security tools. See [SETUP.md](docs/SETUP.md) for installation instructions.

## 🛠️ Development

```bash
# Clone repository
git clone https://github.com/KKingZero/Cobra-AI.git
cd Cobra-AI-Zypheron-CLI

# Build Go CLI
cd zypheron-go
make build

# Run tests
make test

# Install Python dependencies (for AI features)
cd ../zypheron-ai
pip install -r requirements.txt

# Start development
./zypheron --help
```

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This tool is designed for security professionals conducting authorized penetration tests. Always obtain proper authorization before testing any systems you don't own. Unauthorized access to computer systems is illegal.

## 🌟 Acknowledgments

- Kali Linux team for excellent security tools
- OWASP for security standards and methodologies
- OpenAI, Anthropic, Google, and other AI providers
- Open source security community

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/KKingZero/Cobra-AI/issues)
- **Discussions**: [GitHub Discussions](https://github.com/KKingZero/Cobra-AI/discussions)

---

**Built with ⚡ by the Zypheron team**
