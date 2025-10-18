# ⚡ Zypheron CLI - Quick Start Guide

## 🚀 Installation (5 minutes)

```bash
# Navigate to CLI directory
cd /home/zero/Downloads/Cobra-AI-Zypheron-CLI/cli

# Install dependencies
npm install

# Build the CLI
npm run build

# Link globally
npm link

# Run setup
zypheron setup
```

## 🎯 Essential Commands

### Check Your Setup
```bash
# Verify installation
zypheron --version

# Check installed Kali tools
zypheron tools check

# See all available tools
zypheron tools list
```

### Your First Scan
```bash
# Basic scan
zypheron scan scanme.nmap.org

# Web application scan
zypheron scan https://example.com --web

# Full pentest
zypheron scan example.com --full --ai-analysis
```

### AI Chat Assistant
```bash
# Interactive mode
zypheron chat

# Quick question
zypheron chat "How do I test for XSS?"
```

## 🐚 Shell Completions

### Bash
```bash
# Temporary (this session only)
source completions/zypheron.bash

# Permanent (add to ~/.bashrc)
echo 'source /path/to/cli/completions/zypheron.bash' >> ~/.bashrc
source ~/.bashrc
```

### Zsh
```bash
# Copy to zsh functions
sudo cp completions/zypheron.zsh /usr/share/zsh/site-functions/_zypheron

# Reload completions
autoload -U compinit && compinit
```

### Test Completions
```bash
# Type and press TAB
zypheron <TAB>
zypheron scan --<TAB>
zypheron tools <TAB>
```

## ⚙️ Configuration

### Quick Setup
```bash
# Interactive wizard
zypheron config wizard

# Set individual values
zypheron config set api.url http://localhost:3001
zypheron config set ai.defaultModel gpt-4
```

### Configuration File
```bash
# Show config location
zypheron config path

# Edit directly
nano ~/.config/zypheron-cli/config.json
```

## 🔧 Tool Management

```bash
# Check what's installed
zypheron tools check

# Get tool info
zypheron tools info nmap

# Suggest best tool for task
zypheron tools suggest scan

# List by category
zypheron tools list --category web

# Install a specific tool
zypheron tools install nmap

# Install all missing tools (interactive)
zypheron tools install-all

# Install all missing tools (skip prompts)
zypheron tools install-all -y

# Install only critical priority tools
zypheron tools install-all --critical-only

# Install critical and high priority tools
zypheron tools install-all --high-priority
```

## 📊 Scan Examples

### Network Scan
```bash
zypheron scan 192.168.1.1 --ports 1-1000
```

### Web Scan
```bash
zypheron scan https://example.com --web --output report.json
```

### Custom Nmap
```bash
zypheron scan example.com --tool nmap --nmap-args "-sS -T4 -A"
```

### AI-Guided
```bash
zypheron scan example.com --ai-guided --ai-analysis
```

## 🎨 Kali Terminal Style

Your terminal will display:
```
┌─[⚡ zypheron]─[~/projects]
└──╼ $ zypheron scan example.com

[*] Initializing Zypheron Security Scanner v1.0.0
[+] Target: example.com (93.184.216.34)
[*] Detected Tools: nmap ✓, nikto ✓, nuclei ✓

┌─[NMAP]────────────────────────────────────┐
[+] Running nmap -sV -sC example.com
    ├─ Port 80/tcp    open  http
    ├─ Port 443/tcp   open  https
    └─ Port 22/tcp    open  ssh
└────────────────────────────────────────────┘

🤖 AI Analysis:
    ╭─────────────────────────────────────╮
    │ Based on open ports, I recommend... │
    ╰─────────────────────────────────────╯
```

## 💡 Pro Tips

1. **Use Tab Completion**: Press TAB to auto-complete commands and options
2. **Stream Output**: Add `--stream` to see real-time results
3. **AI Analysis**: Add `--ai-analysis` for AI insights
4. **Export Results**: Use `--output file.json --format json`
5. **Tool Suggestions**: Run `zypheron tools suggest <task>` when unsure
6. **Interactive Chat**: Use `zypheron chat` for guidance

## 🔥 Power User Commands

```bash
# Full web pentest with all tools and AI
zypheron scan example.com --full --web --ai-guided --output full-report.json

# Check tools by category
zypheron tools list --category web --installed

# Interactive chat with specific model
zypheron chat --model claude-3-opus

# Custom nmap with AI analysis
zypheron scan 192.168.1.0/24 --tool nmap --nmap-args "-sS -sV -T4" --ai-analysis

# Export chat conversation
zypheron chat --export security-discussion.md
```

## 🐛 Troubleshooting

### Tool Not Found
```bash
# Check if tool is installed
which nmap

# Get installation instructions
zypheron tools info nmap

# Install with Zypheron (easiest)
zypheron tools install nmap

# Or install all missing tools
zypheron tools install-all

# Or install manually on Kali/Debian
sudo apt install nmap
```

### Permission Denied
```bash
# Some scans need root
sudo zypheron scan example.com

# Or configure sudo-less scanning
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap
```

### Configuration Issues
```bash
# Reset config
rm -rf ~/.config/zypheron-cli/

# Run wizard again
zypheron config wizard
```

## 📚 Learn More

- Full documentation: `cli/README.md`
- Implementation details: `CLI_IMPLEMENTATION_PLAN.md`
- Completion summary: `CLI_IMPLEMENTATION_COMPLETE.md`

## 🆘 Get Help

```bash
# General help
zypheron --help

# Command-specific help
zypheron scan --help
zypheron chat --help
zypheron tools --help
```

---

**⚡ You're Ready! Start with:** `zypheron scan scanme.nmap.org`

