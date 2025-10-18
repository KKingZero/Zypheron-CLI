# ⚡ Zypheron CLI - Kali Edition

AI-Powered Penetration Testing Platform with Native Kali Linux Tool Integration

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

## 🎯 Features

- **Kali Linux Integration**: Direct integration with 20+ Kali security tools (nmap, nikto, metasploit, etc.)
- **AI-Powered Analysis**: Claude-style streaming responses for security insights
- **Real-time Scanning**: Live output streaming from security tools
- **Intelligent Tool Detection**: Auto-detect installed tools and suggest alternatives
- **Professional UI**: Kali-inspired terminal colors with modern aesthetics
- **Shell Integration**: Full bash and zsh completion support
- **Flexible Configuration**: Profile-based configuration system
- **Export Capabilities**: Multiple output formats (JSON, XML, HTML, PDF)

## 📦 Installation

### From NPM (Recommended)
```bash
npm install -g @zypheron/cli
```

### From Source
```bash
git clone https://github.com/yourusername/zypheron-cli.git
cd zypheron-cli/cli
npm install
npm run build
npm link
```

### Initial Setup
```bash
zypheron setup
```

This will:
- Detect installed Kali tools
- Configure API endpoints
- Install shell completions
- Verify system compatibility

## 🚀 Quick Start

### Security Scanning
```bash
# Quick scan with nmap
zypheron scan example.com

# Full pentest suite
zypheron scan example.com --full

# Web application focus
zypheron scan https://example.com --web

# AI-guided scanning
zypheron scan example.com --ai-guided
```

### AI Chat Assistant
```bash
# Interactive mode
zypheron chat

# Quick question
zypheron chat "How do I test for SQL injection?"

# Continue previous conversation
zypheron chat --continue session-123
```

### Tool Management
```bash
# Check installed tools
zypheron tools check

# List all available tools
zypheron tools list

# Get tool information
zypheron tools info nmap

# Suggest best tool for task
zypheron tools suggest scan

# Install a specific tool
zypheron tools install nmap

# Install all missing tools
zypheron tools install-all

# Install only critical tools
zypheron tools install-all --critical-only

# Install critical and high priority tools
zypheron tools install-all --high-priority

# Skip confirmation prompts
zypheron tools install-all -y
```

## 📚 Commands

### Core Commands

| Command | Description | Example |
|---------|-------------|---------|
| `scan` | Security scanning with Kali tools | `zypheron scan example.com` |
| `chat` | AI chat for security assistance | `zypheron chat` |
| `threat` | Threat intelligence analysis | `zypheron threat ip 8.8.8.8` |
| `exploit` | Exploitation framework | `zypheron exploit --module ms17_010` |
| `recon` | Reconnaissance operations | `zypheron recon example.com` |
| `bruteforce` | Credential attacks | `zypheron bruteforce ssh 192.168.1.1` |
| `fuzz` | Web fuzzing | `zypheron fuzz https://example.com` |
| `osint` | OSINT operations | `zypheron osint email user@example.com` |
| `report` | Generate reports | `zypheron report generate --scan scan-123` |
| `dashboard` | Real-time monitoring | `zypheron dashboard` |
| `tools` | Manage Kali tools | `zypheron tools check`, `zypheron tools install-all` |
| `config` | Configuration management | `zypheron config wizard` |

### Scan Command Options

```bash
zypheron scan <target> [options]

Options:
  -t, --tool <tool>          Specific tool to use (nmap, nikto, nuclei)
  --tools <tools>            Comma-separated list of tools
  -p, --ports <ports>        Port range (default: 1-1000)
  --web                      Web application scanning
  --full                     Full pentest suite
  --fast                     Quick scan with masscan
  --ai-guided                AI-guided scanning
  --ai-analysis              Include AI analysis
  -o, --output <file>        Output file
  --format <format>          Output format (text, json, xml)
  --nmap-args <args>         Additional nmap arguments
  --timeout <seconds>        Timeout in seconds
  --stream                   Stream output in real-time
```

## 🛠️ Integrated Kali Tools

### Network Scanners
- **nmap** - Network exploration and security auditing
- **masscan** - Fast TCP port scanner
- **nuclei** - Fast vulnerability scanner based on templates

### Web Application Tools
- **nikto** - Web server scanner
- **sqlmap** - Automatic SQL injection tool
- **gobuster** - Directory/file & DNS busting tool
- **ffuf** - Fast web fuzzer
- **wfuzz** - Web application bruteforcer

### Exploitation Frameworks
- **metasploit** - Penetration testing framework
- **sqlmap** - SQL injection exploitation

### Bruteforce Tools
- **hydra** - Network logon cracker
- **john** - Password cracker (John the Ripper)
- **hashcat** - Advanced password recovery

### Reconnaissance Tools
- **subfinder** - Subdomain discovery tool
- **amass** - In-depth DNS enumeration
- **theharvester** - E-mail, subdomain harvester
- **recon-ng** - Web reconnaissance framework

### Wireless Tools
- **aircrack-ng** - WiFi security auditing tools suite

### Network Analysis
- **wireshark/tshark** - Network protocol analyzer

### Web Proxies
- **burpsuite** - Web application security testing
- **zaproxy** - OWASP Zed Attack Proxy

## ⚙️ Configuration

### Configuration File

Located at: `~/.config/zypheron-cli/config.json`

```json
{
  "api": {
    "url": "http://localhost:3001",
    "timeout": 30000
  },
  "ai": {
    "defaultModel": "gpt-4",
    "openai": {
      "apiKey": "sk-..."
    }
  },
  "scanning": {
    "defaultPorts": "1-1000",
    "timeout": 300,
    "maxThreads": 10
  },
  "output": {
    "format": "json",
    "colorize": true,
    "verbose": false
  }
}
```

### Configuration Commands

```bash
# Interactive wizard
zypheron config wizard

# Set individual values
zypheron config set ai.defaultModel gpt-4
zypheron config set api.url http://localhost:3001

# Get values
zypheron config get ai.defaultModel
zypheron config get  # Show all

# Show config file location
zypheron config path
```

## 🐚 Shell Integration

### Bash Completion

Add to `~/.bashrc`:
```bash
source /path/to/zypheron-cli/completions/zypheron.bash
```

Or install system-wide:
```bash
sudo cp completions/zypheron.bash /etc/bash_completion.d/zypheron
```

### Zsh Completion

Add to `~/.zshrc`:
```bash
fpath=(/path/to/zypheron-cli/completions $fpath)
autoload -Uz compinit && compinit
```

Or install system-wide:
```bash
sudo cp completions/zypheron.zsh /usr/share/zsh/site-functions/_zypheron
```

### Features
- Command completion
- Option completion
- Tool name completion
- Target completion
- File path completion
- Context-aware suggestions

## 🎨 Kali Terminal Aesthetics

The CLI uses Kali Linux's signature color scheme:

- **Primary**: Kali Green (#00FF00)
- **Secondary**: Cyan (#00FFFF)
- **Status Indicators**: Kali-style `[+]`, `[*]`, `[!]`, `[-]`
- **Threat Levels**: Color-coded (Critical=Red, High=Orange, Medium=Yellow, Low=Blue)

### Output Example
```
┌─[⚡ zypheron]─[~/projects]
└──╼ $ zypheron scan example.com

[*] Initializing Zypheron Security Scanner v1.0.0
[+] Target: example.com (93.184.216.34)
[+] Detected Tools: nmap ✓, nikto ✓, nuclei ✓

┌─────────────────────────────────────────────────┐
│ 🎯 Reconnaissance Phase                  [1/5] │
└─────────────────────────────────────────────────┘

[+] Running nmap -sV -sC example.com
    ├─ Port 80/tcp    open  http    nginx 1.19.0
    ├─ Port 443/tcp   open  https   nginx 1.19.0
    └─ Port 22/tcp    open  ssh     OpenSSH 8.2p1

[+] AI Analysis:
    ╭─────────────────────────────────────────────╮
    │ Based on the open ports, I've identified   │
    │ potential attack vectors...                 │
    ╰─────────────────────────────────────────────╯
```

## 📊 Examples

### Example 1: Basic Scan
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
  --nmap-args "-sS -T4 -A -Pn" \
  --output network-scan.xml \
  --format xml
```

### Example 4: AI-Assisted Security Analysis
```bash
# Start interactive chat
zypheron chat

# Ask about findings
You: I found port 8080 open with Tomcat. What should I check?

🤖 Zypheron: Based on Tomcat being exposed, I recommend...
```

### Example 5: Tool Management
```bash
# Check what's installed
zypheron tools check

# Get info about a specific tool
zypheron tools info nmap

# Suggest best tool for web scanning
zypheron tools suggest web
```

## 🔧 Development

### Project Structure
```
cli/
├── src/
│   ├── cli/
│   │   ├── commands/         # Command implementations
│   │   ├── core/             # Core functionality
│   │   │   ├── kali-tools.ts
│   │   │   └── tool-executor.ts
│   │   └── ui/               # UI components
│   │       ├── components/
│   │       └── themes/
│   ├── utils/                # Utilities
│   └── types/                # TypeScript types
├── completions/              # Shell completions
│   ├── zypheron.bash
│   └── zypheron.zsh
└── package.json
```

### Build from Source
```bash
npm install
npm run build
npm link
```

### Development Mode
```bash
npm run dev
```

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## ⚠️ Legal Disclaimer

Zypheron CLI is intended exclusively for authorized security testing and educational purposes. Users are solely responsible for ensuring compliance with applicable laws, regulations, and organizational policies. Always obtain explicit written authorization before conducting penetration tests on any systems. Unauthorized access to computer systems is illegal and unethical.

## 🛡️ Stay Secure

Built by security professionals, for security professionals.

---

**⚡ Happy Pentesting with Zypheron CLI!**

