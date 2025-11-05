# 🔧 Zypheron Setup Guide

Complete installation and configuration guide for Zypheron.

## 📋 Table of Contents

- [System Requirements](#system-requirements)
- [Quick Installation](#quick-installation)
- [Detailed Setup](#detailed-setup)
- [Tool Installation](#tool-installation)
- [AI Configuration](#ai-configuration)
- [Troubleshooting](#troubleshooting)

## 💻 System Requirements

### Minimum Requirements
- **Operating System**: Linux, macOS, Windows, or WSL
- **Go**: 1.21 or higher
- **Python**: 3.9 or higher (for AI features)
- **RAM**: 4GB minimum (8GB recommended)
- **Disk Space**: 5GB minimum (10GB recommended with all tools)

### Recommended Environment
- **Kali Linux** 2023.3 or newer
- **16GB RAM** (for AI features and large scans)
- **SSD** for faster tool execution
- **Terminal**: Modern terminal with color support

## 🚀 Quick Installation

### One-Line Install (Linux/macOS)
```bash
curl -fsSL https://raw.githubusercontent.com/KKingZero/Cobra-AI/main/install.sh | bash
```

### Manual Installation

#### 1. Clone Repository
```bash
git clone https://github.com/KKingZero/Cobra-AI.git
cd Cobra-AI-Zypheron-CLI
```

#### 2. Build Go CLI
```bash
cd zypheron-go
make build
```

#### 3. Install System-Wide (Optional)
```bash
sudo make install
```

#### 4. Verify Installation
```bash
zypheron --version
zypheron tools check
```

## 🔨 Detailed Setup

### Go CLI Setup

#### Build from Source
```bash
cd zypheron-go

# Install dependencies
make deps

# Fix any module issues
go mod tidy

# Build binary
make build

# The binary will be at: ./zypheron or ./build/zypheron
```

#### Install System-Wide
```bash
# Option 1: Using Makefile
sudo make install

# Option 2: Manual installation
sudo cp zypheron /usr/local/bin/
sudo chmod +x /usr/local/bin/zypheron

# Verify installation
which zypheron
zypheron --version
```

#### Build for Different Platforms
```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o zypheron-linux-amd64 ./cmd/zypheron

# macOS ARM64 (M1/M2)
GOOS=darwin GOARCH=arm64 go build -o zypheron-darwin-arm64 ./cmd/zypheron

# Windows AMD64
GOOS=windows GOARCH=amd64 go build -o zypheron-windows-amd64.exe ./cmd/zypheron
```

### Python AI Engine Setup

The Python AI engine is optional but provides advanced features.

#### 1. Install Python Dependencies
```bash
cd zypheron-ai

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install base dependencies
pip install -r requirements.txt

# Optional: ML features
pip install -r requirements-ml.txt

# Optional: Security tools
pip install -r requirements-security.txt
```

#### 2. Configure Environment
```bash
# Copy example configuration
cp env.example .env

# Edit configuration
nano .env
```

Add your AI provider API keys:
```bash
# OpenAI
OPENAI_API_KEY=sk-...

# Anthropic Claude
ANTHROPIC_API_KEY=sk-ant-...

# Google Gemini
GOOGLE_API_KEY=...

# DeepSeek
DEEPSEEK_API_KEY=...

# Local Ollama (no key needed)
OLLAMA_API_URL=http://localhost:11434
```

#### 3. Start AI Engine
```bash
# Start the AI engine server
python -m core.server

# Or use zypheron CLI
zypheron ai start
```

## 🛠️ Tool Installation

Zypheron integrates with 30+ security tools. Install them based on your needs.

### Check Installed Tools
```bash
zypheron tools check
```

### Install All Critical Tools
```bash
zypheron tools install-all --critical-only
```

### Install All Tools
```bash
zypheron tools install-all
```

### Install Specific Tools

#### Network Scanning Tools
```bash
sudo apt-get update
sudo apt-get install -y nmap masscan
go install github.com/RustScan/RustScan@latest
```

#### Web Application Tools
```bash
sudo apt-get install -y nikto sqlmap
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

#### Reverse Engineering Tools
```bash
sudo apt-get install -y radare2 gdb binutils
pip3 install pwntools ropper
```

#### Forensics Tools
```bash
sudo apt-get install -y volatility sleuthkit binwalk foremost
```

#### Complete Tool List
See [TOOL_CHAINS.md](TOOL_CHAINS.md) for the complete list of supported tools.

## 🤖 AI Configuration

### Choose Your AI Provider

#### Option 1: OpenAI (Recommended for beginners)
```bash
export OPENAI_API_KEY="sk-..."
zypheron ai test --provider openai
```

#### Option 2: Anthropic Claude (Best for security analysis)
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
zypheron ai test --provider claude
```

#### Option 3: Google Gemini (Good for general use)
```bash
export GOOGLE_API_KEY="..."
zypheron ai test --provider gemini
```

#### Option 4: Local Ollama (Free, private, offline)
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama2

# Configure Zypheron
export OLLAMA_API_URL="http://localhost:11434"
zypheron ai test --provider ollama
```

### Configure Default Provider
```bash
zypheron config set ai.provider claude
zypheron config set ai.model claude-3-sonnet-20240229
```

### Test AI Integration
```bash
# Test basic connectivity
zypheron ai status

# Test specific provider
zypheron ai test --provider claude

# Chat with AI
zypheron chat "What is SQL injection?"
```

### MCP Integration (Model Context Protocol)

Connect AI agents like Claude Desktop, Cursor, or VS Code Copilot directly to Zypheron tools.

#### Install MCP Dependencies

Create a virtual environment to avoid system package conflicts:

```bash
cd zypheron-ai

# Create and activate virtual environment
python3 -m venv mcp-venv
source mcp-venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements-mcp.txt
```

**Quick setup:** Use the helper script:
```bash
source activate-mcp.sh
```

#### Generate MCP Configuration

```bash
# Generate configuration file
zypheron mcp config

# Or save to specific location
zypheron mcp config -o ~/zypheron-mcp.json
```

#### Configure AI Clients

**Claude Desktop:**
1. Edit `~/.config/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows)
2. Add the Zypheron MCP server configuration from `zypheron mcp config` output
3. Restart Claude Desktop

**Cursor IDE:**
1. Open Cursor Settings
2. Search for "MCP" or "Model Context Protocol"
3. Add Zypheron server configuration
4. Restart Cursor

**VS Code Copilot:**
1. Add to `.vscode/settings.json` in your workspace
2. Use configuration from `zypheron mcp config` output
3. Reload VS Code

#### Start MCP Server

```bash
# Start MCP server
zypheron mcp start

# With custom backend
zypheron mcp start --backend http://localhost:8080

# With debug logging
zypheron mcp start --debug
```

#### Verify MCP Integration

In your AI client (Claude Desktop, Cursor, etc.), ask:
```
"What Zypheron security tools do you have access to?"
```

The AI agent should list available tools like nmap_scan, nuclei_scan, ghidra_analysis, etc.

#### Example Usage

```
User: "Scan example.com with nmap and show me what services are running"
AI Agent: [Executes nmap_scan tool automatically]
AI Agent: "I found the following services running on example.com:
- Port 80: HTTP (Apache 2.4.41)
- Port 443: HTTPS (TLS 1.3)
- Port 22: SSH (OpenSSH 8.2)
..."
```

📖 **Full MCP Guide:** [MCP_INTEGRATION.md](MCP_INTEGRATION.md)

## 🔧 Configuration

### Tool Chain Configuration

Create or edit `~/.zypheron/toolchains.yaml`:

```yaml
reverse_engineering:
  - tool: file
    priority: 1
    params:
      detailed: true
  - tool: strings
    priority: 2
    params:
      min_length: 4
  - tool: radare2
    priority: 3
    params:
      analysis: true
      auto: true

api_pentest:
  - tool: nmap
    priority: 1
    params:
      ports: "443,8443"
      ssl: true
  - tool: nuclei
    priority: 2
    params:
      severity: "critical,high"
      tags: "api"
```

### Shell Completion

#### Bash
```bash
zypheron completion bash > /etc/bash_completion.d/zypheron
source ~/.bashrc
```

#### Zsh
```bash
zypheron completion zsh > "${fpath[1]}/_zypheron"
source ~/.zshrc
```

#### Fish
```bash
zypheron completion fish > ~/.config/fish/completions/zypheron.fish
```

## 🐛 Troubleshooting

### Common Issues

#### "Tool not found" Error
```bash
# Check which tools are missing
zypheron tools check

# Install missing tools
zypheron tools install <tool-name>

# Or install all at once
zypheron tools install-all
```

#### AI Engine Not Starting
```bash
# Check Python installation
python3 --version

# Check if dependencies are installed
pip list | grep -E "(openai|anthropic|google)"

# Check if port is available
lsof -i :8765

# View AI engine logs
tail -f zypheron-ai/zypheron-ai.log
```

#### Permission Denied Errors
```bash
# Some tools require root privileges
sudo zypheron scan example.com

# Or give specific capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/zypheron
```

#### Go Build Failures
```bash
# Update Go version
go version  # Should be 1.21+

# Clean and rebuild
cd zypheron-go
go clean -cache
go mod tidy
make build
```

### WSL-Specific Issues

#### Network Tools Not Working
```bash
# Some tools need specific WSL configuration
# Add to /etc/wsl.conf:
[network]
generateResolvConf = false

# Restart WSL
wsl --shutdown
```

### Getting Help

If you encounter issues not covered here:

1. Check existing issues: https://github.com/KKingZero/Cobra-AI/issues
2. Enable debug mode: `zypheron --debug scan example.com`
3. Check logs: `cat zypheron-ai/zypheron-ai.log`
4. Ask for help: https://github.com/KKingZero/Cobra-AI/discussions

## 📚 Next Steps

After setup, check out:

- [CLI_GUIDE.md](CLI_GUIDE.md) - Complete command reference
- [DEV_STATUS.md](DEV_STATUS.md) - Current features and roadmap
- [AI_INTEGRATION.md](AI_INTEGRATION.md) - Advanced AI features
- [TOOL_CHAINS.md](TOOL_CHAINS.md) - Tool chain configuration

## 🎯 Quick Test

Verify everything works:

```bash
# Test basic scanning
zypheron scan scanme.nmap.org --fast

# Test AI integration
zypheron chat "Explain OWASP Top 10"

# Test tool management
zypheron tools list --installed

# Test a reverse engineering command
echo "Hello World" > test.txt
zypheron reverse-eng test.txt --tool file
```

---

**Need help?** Open an issue on [GitHub](https://github.com/KKingZero/Cobra-AI/issues)

