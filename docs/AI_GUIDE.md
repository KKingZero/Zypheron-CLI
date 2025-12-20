# Zypheron AI Guide

Complete guide for setting up and using AI features in Zypheron.

## Table of Contents

- [Overview](#overview)
- [AI Engine Setup](#ai-engine-setup)
- [Supported AI Providers](#supported-ai-providers)
- [Configuration](#configuration)
- [Using AI Features](#using-ai-features)
- [MCP Integration](#mcp-integration)
- [Troubleshooting](#troubleshooting)

---

## Overview

Zypheron's AI features are powered by a Python backend that communicates with the Go CLI via Unix socket. The AI engine provides:

- **AI Chat** - Security-focused chat assistant
- **Scan Analysis** - AI-powered vulnerability analysis
- **AI-Guided Scanning** - Intelligent scan recommendations
- **MCP Server** - Connect AI agents (Claude Desktop, Cursor, etc.) to security tools

### Architecture

```
┌─────────────────┐     Unix Socket      ┌─────────────────┐
│  Zypheron CLI   │ ◄──────────────────► │  Python AI      │
│  (Go Binary)    │                      │  Engine         │
└─────────────────┘                      └────────┬────────┘
                                                  │
                                         ┌────────▼────────┐
                                         │  AI Providers   │
                                         │  (Claude, GPT,  │
                                         │   Gemini, etc.) │
                                         └─────────────────┘
```

---

## AI Engine Setup

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- Virtual environment (recommended)

### Step 1: Navigate to AI Directory

```bash
cd Zypheron-CLI/zypheron-ai
```

### Step 2: Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\activate   # Windows
```

### Step 3: Install Dependencies

```bash
# Core dependencies
pip install -r requirements.txt

# Optional: ML features (larger download)
pip install -r requirements-ml.txt

# Optional: MCP server
pip install -r requirements-mcp.txt
```

### Step 4: Configure API Keys

You have two options for storing API keys:

**Option A: System Keyring (Recommended - More Secure)**

```bash
# Store in system keyring via CLI
zypheron config set-key anthropic
# Enter your API key when prompted

zypheron config set-key openai
# Enter your API key when prompted
```

**Option B: Environment Variables**

```bash
# Create .env file from template
cp env.example .env

# Edit .env and add your keys
nano .env
```

Add your API keys:

```bash
# Anthropic Claude (recommended for security analysis)
ANTHROPIC_API_KEY=sk-ant-api03-...

# OpenAI GPT
OPENAI_API_KEY=sk-...

# Google Gemini
GOOGLE_API_KEY=AIza...

# DeepSeek
DEEPSEEK_API_KEY=sk-...

# Local Ollama (no key needed)
OLLAMA_API_URL=http://localhost:11434
```

### Step 5: Start AI Engine

```bash
# From zypheron-ai directory with venv activated
python -m core.server

# Or via Zypheron CLI
zypheron ai start
```

### Step 6: Verify Connection

```bash
# Check AI engine status
zypheron ai status

# Test AI chat
zypheron chat "Hello, can you help with security testing?"
```

---

## Supported AI Providers

### Anthropic Claude (Recommended)

Best for security analysis with strong reasoning capabilities.

```bash
# Set as default
zypheron config set ai.provider claude
zypheron config set ai.model claude-3-sonnet-20240229

# Test
zypheron ai test --provider claude
```

**Available Models:**
- `claude-3-opus-20240229` - Most capable
- `claude-3-sonnet-20240229` - Balanced (recommended)
- `claude-3-haiku-20240307` - Fastest

### OpenAI GPT

```bash
zypheron config set ai.provider openai
zypheron config set ai.model gpt-4-turbo-preview

# Test
zypheron ai test --provider openai
```

**Available Models:**
- `gpt-4-turbo-preview` - Most capable
- `gpt-4` - Standard
- `gpt-3.5-turbo` - Faster/cheaper

### Google Gemini

```bash
zypheron config set ai.provider gemini
zypheron config set ai.model gemini-pro

# Test
zypheron ai test --provider gemini
```

### DeepSeek

```bash
zypheron config set ai.provider deepseek
zypheron config set ai.model deepseek-chat

# Test
zypheron ai test --provider deepseek
```

### Local Ollama (Free, Private, Offline)

Run AI models locally without API keys:

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama2
ollama pull codellama  # Good for code analysis
ollama pull mixtral    # Larger, more capable

# Configure Zypheron
zypheron config set ai.provider ollama
zypheron config set ai.model llama2

# Test
zypheron ai test --provider ollama
```

---

## Configuration

### View AI Configuration

```bash
# Show all AI settings
zypheron config get ai

# Show specific setting
zypheron config get ai.provider
zypheron config get ai.model
```

### Set AI Configuration

```bash
# Set provider
zypheron config set ai.provider claude

# Set model
zypheron config set ai.model claude-3-sonnet-20240229

# Set temperature (creativity)
zypheron config set ai.temperature 0.7

# Set max tokens
zypheron config set ai.max_tokens 4096
```

### Configuration File

Location: `~/.config/zypheron/config.yaml`

```yaml
ai:
  provider: claude
  model: claude-3-sonnet-20240229
  temperature: 0.7
  max_tokens: 4096
  timeout: 60
```

---

## Using AI Features

### AI Chat

Interactive security assistant:

```bash
# Start interactive chat
zypheron chat

# Quick question
zypheron chat "How do I test for SQL injection?"

# Continue previous session
zypheron chat --continue session-123
```

### AI-Powered Scan Analysis

```bash
# Scan with AI analysis
zypheron scan example.com --ai-analysis

# Analyze existing scan results
zypheron ai analyze --file scan-results.json
```

### AI-Guided Scanning

Let AI guide your scanning strategy:

```bash
# AI recommends what to scan
zypheron scan example.com --ai-guided
```

### Example Prompts for Security Testing

```bash
# Vulnerability analysis
zypheron chat "I found port 8080 open running Tomcat 8.5. What vulnerabilities should I check?"

# Code review
zypheron chat "Review this PHP code for SQL injection vulnerabilities: <?php query('SELECT * FROM users WHERE id='.$_GET['id']); ?>"

# Methodology guidance
zypheron chat "What's the methodology for testing a REST API for security issues?"

# Report writing
zypheron chat "Help me write an executive summary for finding critical SQL injection in a login form"
```

---

## MCP Integration

MCP (Model Context Protocol) allows AI agents like Claude Desktop, Cursor, or VS Code Copilot to directly use Zypheron's security tools.

### Setup MCP Server

```bash
# Install MCP dependencies
cd zypheron-ai
source venv/bin/activate
pip install -r requirements-mcp.txt

# Or use the helper script
source activate-mcp.sh
```

### Generate MCP Configuration

```bash
# Generate config
zypheron mcp config

# Save to file
zypheron mcp config -o ~/zypheron-mcp.json
```

### Configure Claude Desktop

1. Edit Claude Desktop config:
   - macOS: `~/.config/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`

2. Add Zypheron MCP server:

```json
{
  "mcpServers": {
    "zypheron": {
      "command": "python",
      "args": ["-m", "mcp.server"],
      "cwd": "/path/to/Zypheron-CLI/zypheron-ai",
      "env": {
        "PYTHONPATH": "/path/to/Zypheron-CLI/zypheron-ai"
      }
    }
  }
}
```

3. Restart Claude Desktop

### Configure Cursor IDE

1. Open Cursor Settings
2. Search for "MCP"
3. Add Zypheron server configuration
4. Restart Cursor

### Start MCP Server Manually

```bash
# Start MCP server
zypheron mcp start

# With debug logging
zypheron mcp start --debug

# With custom backend
zypheron mcp start --backend http://localhost:8080
```

### Verify MCP Integration

In Claude Desktop or your AI client:

```
"What Zypheron security tools do you have access to?"
```

The AI should list available tools like `nmap_scan`, `nuclei_scan`, etc.

### Example MCP Usage

In Claude Desktop:

```
User: "Scan example.com for open ports"
AI: [Executes nmap_scan tool]
AI: "I found the following open ports on example.com..."

User: "Check if there are any known vulnerabilities on port 443"
AI: [Executes nuclei_scan tool]
AI: "I detected the following vulnerabilities..."
```

---

## Troubleshooting

### "AI engine not running"

```bash
# Check if engine is running
zypheron ai status

# Start the engine
zypheron ai start

# Or manually
cd zypheron-ai
source venv/bin/activate
python -m core.server
```

### "Connection refused" Error

```bash
# Check socket file exists
ls -la /tmp/zypheron-ai.sock

# Check if process is running
ps aux | grep "core.server"

# Restart AI engine
zypheron ai stop
zypheron ai start
```

### "API key not found"

```bash
# Check if key is configured
zypheron config get-providers

# Set key again
zypheron config set-key anthropic

# Or check .env file
cat zypheron-ai/.env
```

### "Model not found"

```bash
# List available models for your provider
zypheron ai models

# Set a valid model
zypheron config set ai.model claude-3-sonnet-20240229
```

### Python/Dependency Errors

```bash
# Recreate virtual environment
cd zypheron-ai
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### MCP Not Working

```bash
# Check MCP dependencies
pip list | grep mcp

# Reinstall MCP dependencies
pip install -r requirements-mcp.txt

# Test MCP server manually
python -m mcp.server --debug
```

### Slow AI Responses

1. Use a faster model (`claude-3-haiku` or `gpt-3.5-turbo`)
2. Reduce `max_tokens` setting
3. Use local Ollama for privacy and no rate limits

### Debug Mode

```bash
# Enable debug logging
zypheron --debug chat "test"

# Check AI engine logs
tail -f zypheron-ai/zypheron-ai.log
```

---

## See Also

- [INSTALL.md](INSTALL.md) - Installation guide
- [GO_GUIDE.md](GO_GUIDE.md) - CLI reference
- [SETUP_AND_USE.md](SETUP_AND_USE.md) - Setup and usage
- [MCP_INTEGRATION.md](MCP_INTEGRATION.md) - Detailed MCP guide
