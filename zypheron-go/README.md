# Zypheron CLI - Open Source Edition

> AI-Enhanced Reconnaissance & OSINT Platform for Security Professionals

**Command-line only. No GUI. Maximum control.**

```
 ███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗ ███╗   ██╗
 ╚══███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔═══██╗████╗  ██║
   ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝██║   ██║██╔██╗ ██║
  ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║██║╚██╗██║
 ███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚████║
 ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
```

## What is This?

Zypheron OSS is a **free, open-source** reconnaissance and OSINT tool with optional AI enhancement. It's designed for:

- **Pentesters** who prefer CLI over GUI
- **Red teamers** who need scriptable, automatable tools
- **Bug bounty hunters** doing recon at scale
- **Security researchers** who want full control

Think **Metasploit Community** meets **AI-powered recon**.

## Features

### Core Capabilities
- Network scanning (nmap, masscan)
- Web vulnerability scanning (nikto, nuclei, wpscan)
- Directory/file enumeration (gobuster, ffuf, dirb)
- Subdomain enumeration (subfinder, amass)
- SQL injection testing (sqlmap)
- Technology fingerprinting (whatweb)

### AI Enhancement (Optional)
- **Local AI**: Ollama (default) - 100% offline, no API keys needed
- **BYOK**: Bring Your Own Key for cloud providers (Anthropic, OpenAI, DeepSeek)
- AI-assisted scan planning and result analysis
- Intelligent vulnerability prioritization

### Session & History
- Session save/resume for long-running operations
- Scan history with search and statistics
- JSON report export
- Offline mode with graceful degradation

## Installation

### Prerequisites
```bash
# Required
sudo apt install nmap

# Recommended
sudo apt install nikto masscan gobuster whatweb

# Go tools (optional)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Build from Source
```bash
git clone https://github.com/KKingZero/Cobra-AI.git
cd Cobra-AI/zypheron-go

# Build
go build -o zypheron ./cmd/zypheron

# Install system-wide
sudo mv zypheron /usr/local/bin/
```

### Verify Installation
```bash
zypheron doctor
```

## Quick Start

### Basic Scanning
```bash
# Port scan
zypheron scan 192.168.1.1

# Web vulnerability scan
zypheron scan example.com --tool nikto

# Full recon
zypheron recon example.com
```

### AI-Enhanced (with Ollama)
```bash
# Install Ollama and pull a model
ollama pull codellama

# Run AI-assisted scan
zypheron scan example.com --ai
```

### AI-Enhanced (BYOK)
```bash
# Set your API key
export DEEPSEEK_API_KEY=sk-your-key
export ZYPHERON_AI_PROVIDER=deepseek

# Run with cloud AI
zypheron scan example.com --ai
```

## Commands

### Scanning
```bash
zypheron scan <target> [flags]     # Run security scan
zypheron recon <target> [flags]    # Reconnaissance gathering
zypheron ai <query>                # Direct AI query
```

### Session Management
```bash
zypheron session list              # List saved sessions
zypheron session resume <id>       # Resume a session
zypheron session export <id>       # Export to JSON
zypheron session delete <id>       # Delete session
```

### History
```bash
zypheron history                   # List recent scans
zypheron history stats             # Show statistics
zypheron history search <query>    # Search history
zypheron history clear             # Clear all history
```

### Configuration
```bash
zypheron config show               # Show all settings
zypheron config set <key> <value>  # Set a value
zypheron config reset              # Reset to defaults
zypheron doctor                    # System health check
```

## Configuration

Config file: `~/.zypheron/config.json`

### AI Providers

| Provider | Env Variable | Default |
|----------|--------------|---------|
| Ollama (local) | `OLLAMA_URL` | `http://localhost:11434` |
| DeepSeek | `DEEPSEEK_API_KEY` | - |
| Anthropic | `ANTHROPIC_API_KEY` | - |
| OpenAI | `OPENAI_API_KEY` | - |

### Example .env
```bash
# Local AI (default, no key needed)
ZYPHERON_AI_PROVIDER=ollama
OLLAMA_MODEL=codellama

# Or use cloud AI (BYOK)
ZYPHERON_AI_PROVIDER=deepseek
DEEPSEEK_API_KEY=sk-your-key-here
```

## Directory Structure

```
~/.zypheron/
├── config.json      # Configuration
├── sessions/        # Saved scan sessions
├── history/         # Scan history
├── reports/         # Exported reports
├── cache/           # AI response cache
└── logs/            # Error logs
```

## For Advanced Users

This tool is designed for **skilled users** who:
- Prefer command-line interfaces
- Want full control over tool behavior
- Need scriptable, automatable workflows
- Understand the security tools being used

### Scripting Example
```bash
#!/bin/bash
# Batch recon script
for target in $(cat targets.txt); do
    zypheron scan "$target" --tool nmap --output json > "results/${target}.json"
done
```

### Metasploit-Style Workflow
```bash
# Check system readiness
zypheron doctor

# Configure
zypheron config set ai_provider ollama
zypheron config set default_ports "1-10000"

# Run recon
zypheron recon target.com

# Review history
zypheron history stats

# Export results
zypheron session export latest
```

## Differences from Pro Version

| Feature | Open Source | Pro |
|---------|-------------|-----|
| Scanning & Recon | Full | Full |
| AI Enhancement | Local + BYOK | Cloud included |
| Post-exploitation | No | Yes |
| TUI Interface | No | Yes |
| Report Formats | JSON only | JSON, HTML, PDF |
| Support | Community | Priority |

## Contributing

Contributions welcome! This is open-source software.

1. Fork the repo
2. Create a feature branch
3. Submit a PR

## License

MIT License - See LICENSE file

## Disclaimer

This tool is for **authorized security testing only**. Users are responsible for obtaining proper authorization before scanning any systems. The developers assume no liability for misuse.

---

**Zypheron Open Source** - For those who prefer power over polish.
