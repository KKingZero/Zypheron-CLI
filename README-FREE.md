# 🐍 Zypheron CLI - Free Edition

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)
[![Python Version](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Professional penetration testing toolkit - Free Edition includes OSINT, Reconnaissance, and Vulnerability Scanning

```
╔═══════════════════════════════════════════════════════════╗
║  ███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗ ██╗   ██╗
║  ╚══███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔═══██╗████╗ ██║
║    ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝██║   ██║██╔██╗██║
║   ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║██║╚████║
║  ███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚███║
║  ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝
╚═══════════════════════════════════════════════════════════╝
    AI-Powered Penetration Testing Platform - FREE EDITION
```

## 🎯 Free Edition Overview

Zypheron Free Edition provides complete access to **pre-exploitation** phases of the Cyber Kill Chain:

- ✅ **OSINT & Reconnaissance** - Complete intelligence gathering
- ✅ **Vulnerability Scanning** - Professional-grade security scanning
- ✅ **AI-Powered Analysis** - Intelligent vulnerability assessment
- ✅ **All Manual Tools** - Full access to nmap, nuclei, nikto, and more
- ✅ **Secrets Detection** - Find exposed credentials and API keys
- ✅ **Dependency Analysis** - CVE matching and SBOM generation

### Cyber Kill Chain Coverage

```
┌─────────────────────────────────────────────────────────┐
│  CYBER KILL CHAIN - FREE EDITION COVERAGE               │
├─────────────────────────────────────────────────────────┤
│  ✅ Reconnaissance    │  Information gathering           │
│  ✅ Weaponization     │  Tool preparation                │
│  ✅ Delivery          │  Scan execution                  │
│  ✅ Exploitation      │  ❌ MANUAL ONLY (No automation) │
│  ❌ Installation      │  PRO ONLY                        │
│  ❌ Command & Control │  PRO ONLY                        │
│  ❌ Actions on Objective │ PRO ONLY                      │
└─────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Installation

```bash
# Download Free Edition
curl -sSL https://zypheron.com/install-free.sh | bash

# Or build from source
cd zypheron-go
make build-free
sudo make install-free
```

### First Scan

```bash
# Run vulnerability scan
zypheron-free scan example.com

# OSINT gathering
zypheron-free osint domain example.com

# Reconnaissance
zypheron-free recon example.com

# Secret scanning
zypheron-free secrets /path/to/code
```

## ⚡ Features

### 🔍 Included Features

#### Network & Web Scanning
```bash
# Comprehensive nmap scan
zypheron-free scan example.com --ports 1-65535

# Fast masscan
zypheron-free scan 192.168.1.0/24 --fast

# Web vulnerability scanning
zypheron-free scan https://example.com --web

# Nuclei templates
zypheron-free scan example.com --tool nuclei
```

#### OSINT & Reconnaissance
```bash
# Domain intelligence
zypheron-free osint domain example.com

# Email harvesting
zypheron-free osint email user@example.com

# Subdomain enumeration
zypheron-free recon example.com

# DNS discovery
zypheron-free recon example.com --dns
```

#### AI-Powered Analysis
```bash
# Vulnerability analysis with AI
zypheron-free scan example.com --ai-analysis

# ML-based predictions
zypheron-free scan example.com --ai-guided

# Interactive AI chat
zypheron-free chat "Explain these findings"
```

#### Security Analysis
```bash
# Secret detection
zypheron-free secrets /path/to/repo

# Dependency analysis
zypheron-free deps /path/to/project

# API security testing (scan mode)
zypheron-free api-pentest https://api.example.com

# Static binary analysis
zypheron-free reverse-eng /path/to/binary
```

### ❌ Pro-Only Features

The following features require Zypheron Professional Edition:

- **Automated Exploitation** - `zypheron exploit`
- **Credential Attacks** - `zypheron bruteforce`
- **Binary Exploitation** - `zypheron pwn` 
- **Autopent Engine** - Autonomous penetration testing
- **Post-Exploitation** - Privilege escalation, lateral movement
- **Active Scanning** - Burp Suite/ZAP active scans
- **Full MCP Integration** - Complete AI agent automation

## 🛠️ Available Tools

### Scanning Tools
| Tool | Purpose | Free Edition |
|------|---------|--------------|
| **nmap** | Network scanning | ✅ Full |
| **masscan** | Fast port scanning | ✅ Full |
| **nuclei** | Vulnerability templates | ✅ Full |
| **nikto** | Web server scanning | ✅ Full |
| **gobuster** | Directory fuzzing | ✅ Full |
| **ffuf** | Web fuzzing | ✅ Full |

### Reconnaissance Tools
| Tool | Purpose | Free Edition |
|------|---------|--------------|
| **subfinder** | Subdomain discovery | ✅ Full |
| **amass** | DNS enumeration | ✅ Full |
| **theharvester** | Email/domain harvesting | ✅ Full |
| **whois** | Domain information | ✅ Full |

### Analysis Tools
| Tool | Purpose | Free Edition |
|------|---------|--------------|
| **AI Analysis** | Vulnerability assessment | ✅ Full |
| **Secret Scanner** | Credential detection | ✅ Full |
| **Dependency Scan** | CVE matching | ✅ Full |
| **SBOM Generator** | Software bill of materials | ✅ Full |

### Exploitation Tools (Pro Only)
| Tool | Purpose | Free Edition |
|------|---------|--------------|
| **metasploit** | Exploitation framework | ❌ Pro Only |
| **hydra** | Credential attacks | ❌ Pro Only |
| **sqlmap** | SQL injection | ❌ Pro Only |
| **autopent** | Autonomous testing | ❌ Pro Only |

## 📊 Feature Comparison

| Feature | Free Edition | Pro Edition |
|---------|--------------|-------------|
| **Network Scanning** | ✅ Unlimited | ✅ Unlimited |
| **Web Scanning** | ✅ Unlimited | ✅ Unlimited |
| **OSINT Tools** | ✅ Full Access | ✅ Full Access |
| **Reconnaissance** | ✅ Full Access | ✅ Full Access |
| **AI Analysis** | ✅ Results Only | ✅ + Exploitation |
| **Secrets Detection** | ✅ Full Access | ✅ Full Access |
| **API Testing** | ✅ Scan Mode | ✅ + Exploitation |
| **Binary Analysis** | ✅ Static Only | ✅ + Exploitation |
| **Manual Tools** | ✅ All Tools | ✅ All Tools |
| **Automated Exploitation** | ❌ | ✅ |
| **Credential Attacks** | ❌ | ✅ |
| **Autopent Engine** | ❌ | ✅ |
| **Post-Exploitation** | ❌ | ✅ |
| **MCP Integration** | ✅ Recon Only | ✅ Full |
| **Burp/ZAP Integration** | ✅ Passive | ✅ Active |
| **Tool Chains** | ✅ Recon Chains | ✅ All Chains |
| **Support** | Community | Priority |

## 🤖 AI Integration

### Free Edition AI Features

```bash
# Analyze scan results with AI
zypheron-free scan example.com --ai-analysis

# ML vulnerability predictions
zypheron-free scan example.com --ai-guided

# Interactive security guidance
zypheron-free chat

# Natural language queries
zypheron-free chat "What should I test next?"
```

### MCP Integration (Limited)

Free Edition includes MCP integration for reconnaissance tools only:

```bash
# Start MCP server
zypheron-free mcp start

# Available MCP tools in Free Edition:
# - nmap_scan
# - nuclei_scan
# - subfinder
# - osint_domain
# - secrets_scan
# - dependency_scan
```

**Pro Edition MCP** includes exploitation automation, autopent commands, and full tool access.

## 📖 Usage Examples

### Example 1: Basic Security Assessment

```bash
# Step 1: Reconnaissance
zypheron-free recon example.com

# Step 2: Port scanning
zypheron-free scan example.com

# Step 3: Vulnerability scanning
zypheron-free scan https://example.com --web --ai-analysis

# Step 4: Secret detection (if you have source code)
zypheron-free secrets /path/to/code
```

### Example 2: OSINT Investigation

```bash
# Domain intelligence
zypheron-free osint domain target.com

# Email harvesting
zypheron-free osint email @target.com

# Social media (requires API keys)
zypheron-free osint social target.com
```

### Example 3: API Security Testing

```bash
# Scan API endpoints
zypheron-free api-pentest https://api.example.com

# AI-powered analysis
zypheron-free api-pentest https://api.example.com --ai-analysis
```

## 🔄 Upgrading to Pro

### Why Upgrade?

Zypheron Pro adds complete automation and exploitation capabilities:

- ⚡ **Autopent Engine** - Fully autonomous penetration testing
- ⚡ **Exploit Automation** - Metasploit integration
- ⚡ **Credential Attacks** - Hydra, John the Ripper
- ⚡ **Binary Exploitation** - Pwntools, ROP chains
- ⚡ **Post-Exploitation** - Privilege escalation, pivoting
- ⚡ **Active Scanning** - Full Burp/ZAP integration
- ⚡ **Priority Support** - Direct technical assistance

### Upgrade Now

```bash
# Visit our website
https://zypheron.com/upgrade

# Or contact sales
sales@zypheron.com
```

## 💻 System Requirements

### Minimum
- **OS**: Linux, macOS, Windows, or WSL
- **Go**: 1.21+ (for building from source)
- **Python**: 3.9+ (for AI features)
- **RAM**: 4GB
- **Disk**: 5GB

### Recommended
- **OS**: Kali Linux 2023.3+
- **RAM**: 8GB+
- **Disk**: 10GB+

## 📚 Documentation

- **[Setup Guide](docs/SETUP.md)** - Installation and configuration
- **[CLI Guide](docs/CLI_GUIDE.md)** - Command reference
- **[MCP Integration](docs/MCP_INTEGRATION.md)** - AI agent integration
- **[Tool Chains](docs/TOOL_CHAINS.md)** - Automated workflows

## 🤝 Community

- **GitHub Issues**: [Report bugs](https://github.com/KKingZero/Cobra-AI/issues)
- **Discussions**: [Ask questions](https://github.com/KKingZero/Cobra-AI/discussions)
- **Discord**: [Join community](https://discord.gg/zypheron)

## ⚠️ Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

Zypheron is designed for security professionals conducting authorized penetration tests. Always obtain proper written authorization before testing any systems you don't own. Unauthorized access to computer systems is illegal.

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Ready to upgrade?** Visit [zypheron.com/upgrade](https://zypheron.com/upgrade) for Zypheron Pro!

