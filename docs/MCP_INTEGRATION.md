# Zypheron MCP Integration Guide

## Table of Contents

- [Overview](#overview)
- [What is MCP?](#what-is-mcp)
- [Why Use MCP with Zypheron?](#why-use-mcp-with-zypheron)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [AI Client Configuration](#ai-client-configuration)
- [Available Tools](#available-tools)
- [Example Workflows](#example-workflows)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)

## Overview

Zypheron's MCP (Model Context Protocol) integration enables AI agents like Claude Desktop, Cursor, and VS Code Copilot to directly access Zypheron's 30+ security tools through natural language commands.

This transforms security testing workflows by allowing AI agents to:
- Execute penetration testing tools autonomously
- Orchestrate complex attack chains
- Analyze results with AI-powered insights
- Generate comprehensive security reports

## What is MCP?

The Model Context Protocol (MCP) is an open standard developed by Anthropic that enables AI assistants to:
- Connect to external tools and services
- Execute commands with proper context
- Maintain state across interactions
- Provide structured responses

MCP acts as a bridge between AI agents and specialized tools, enabling seamless integration without custom API development.

## Why Use MCP with Zypheron?

### Traditional Workflow
```
User → Write commands manually → Execute tools → Interpret results → Repeat
```

### MCP-Enhanced Workflow
```
User → Natural language request → AI Agent → Zypheron MCP → Tools → AI Analysis → Report
```

### Benefits

1. **Natural Language Interface**: Describe what you want to test in plain English
2. **Autonomous Operation**: AI agents can chain multiple tools intelligently
3. **Context Awareness**: AI understands previous results and adapts testing strategy
4. **Instant Expertise**: Access penetration testing knowledge through AI
5. **Comprehensive Analysis**: AI-powered vulnerability correlation and impact analysis
6. **Faster Results**: Parallel execution and intelligent tool selection

## Installation

### Prerequisites

- Python 3.9 or higher
- Zypheron CLI installed (see [SETUP.md](SETUP.md))
- AI client (Claude Desktop, Cursor, or VS Code Copilot)

### Install MCP Dependencies

Due to Python's externally-managed environment protection, we need to use a virtual environment:

```bash
cd zypheron-ai

# Create and activate virtual environment
python3 -m venv mcp-venv
source mcp-venv/bin/activate  # Linux/macOS
# OR: mcp-venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements-mcp.txt
```

This installs:
- `fastmcp` - MCP server framework
- `requests` - HTTP client for backend communication
- `psutil` - System utilities
- `loguru` - Enhanced logging

### Quick Setup with Helper Script

```bash
cd zypheron-ai
source activate-mcp.sh  # Automatically creates venv and installs dependencies
```

### Verify Installation

```bash
python3 -c "import fastmcp; print('✅ MCP installed successfully')"
```

## Quick Start

### 1. Generate MCP Configuration

```bash
zypheron mcp config
```

This outputs the MCP configuration needed for your AI client.

### 2. Start MCP Server

```bash
zypheron mcp start
```

The server will display:
```
╔═══════════════════════════════════════════════════════════╗
║  ███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗ ██╗   ██╗
║  ╚══███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔═══██╗████╗ ██║
║    ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝██║   ██║██╔██╗██║
║   ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║██║╚████║
║  ███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚███║
║  ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝
╚═══════════════════════════════════════════════════════════╝
    MCP Server - AI-Powered Penetration Testing Platform
    Version 1.0.0 | 30+ Security Tools Available

🚀 Zypheron MCP Server ready for AI agents!
```

### 3. Configure Your AI Client

Follow the configuration steps for your specific AI client below.

### 4. Test the Integration

In your AI client, try:
```
"Can you scan example.com using nmap and tell me what services are running?"
```

## AI Client Configuration

### Claude Desktop

1. Locate your Claude Desktop config file:
   - **macOS**: `~/.config/Claude/claude_desktop_config.json`
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

2. Generate the config:
   ```bash
   zypheron mcp config -o ~/zypheron-mcp.json
   ```

3. Edit `claude_desktop_config.json` and add the Zypheron MCP server:
   ```json
   {
     "mcpServers": {
       "zypheron-ai": {
         "command": "python3",
         "args": [
           "/path/to/Cobra-AI-Zypheron-CLI/zypheron-ai/mcp/server.py",
           "--server",
           "http://localhost:8080"
         ],
         "description": "Zypheron AI - AI-Powered Penetration Testing Platform",
         "timeout": 300
       }
     }
   }
   ```

4. Restart Claude Desktop

5. Verify by asking Claude:
   ```
   "What Zypheron security tools do you have access to?"
   ```

### Cursor IDE

1. Open Cursor Settings (Cmd/Ctrl + ,)

2. Search for "MCP" or "Model Context Protocol"

3. Add Zypheron as an MCP server:
   ```json
   {
     "mcp.servers": {
       "zypheron-ai": {
         "command": "python3",
         "args": [
           "/path/to/Cobra-AI-Zypheron-CLI/zypheron-ai/mcp/server.py",
           "--server",
           "http://localhost:8080"
         ]
       }
     }
   }
   ```

4. Restart Cursor

5. Use Cursor's AI chat to invoke Zypheron tools

### VS Code Copilot

1. Open VS Code settings

2. Add to `.vscode/settings.json` in your workspace:
   ```json
   {
     "github.copilot.advanced": {
       "mcp": {
         "servers": {
           "zypheron-ai": {
             "command": "python3",
             "args": [
               "/path/to/Cobra-AI-Zypheron-CLI/zypheron-ai/mcp/server.py",
               "--server",
               "http://localhost:8080"
             ]
           }
         }
       }
     }
   }
   ```

3. Reload VS Code

4. Test using Copilot Chat

## Available Tools

The MCP server exposes 30+ security tools across multiple categories:

### Network Security (10 tools)
- `nmap_scan` - Advanced port scanning and service detection
- `rustscan_fast_scan` - Ultra-fast port scanning
- `masscan_high_speed` - Internet-scale port scanning
- `amass_enum` - Subdomain enumeration and OSINT
- `subfinder_scan` - Passive subdomain discovery
- `fierce_scan` - DNS reconnaissance
- `dnsenum_scan` - DNS information gathering
- `autorecon_scan` - Comprehensive reconnaissance
- `netexec_scan` - Network service exploitation
- `responder_credential_harvest` - Credential harvesting

### Web Application Security (12 tools)
- `gobuster_scan` - Directory and file enumeration
- `nuclei_scan` - Fast vulnerability scanning (4000+ templates)
- `nikto_scan` - Web server vulnerability scanner
- `sqlmap_scan` - SQL injection testing
- `wpscan_analyze` - WordPress security scanner
- `httpx_probe` - HTTP probing and tech detection
- `feroxbuster_scan` - Recursive content discovery
- `ffuf_scan` - Fast web fuzzing
- `katana_crawl` - Advanced web crawling
- `arjun_parameter_discovery` - Parameter discovery
- `dalfox_xss` - XSS vulnerability scanner
- `wafw00f_scan` - WAF fingerprinting

### Binary Analysis & Reverse Engineering (8 tools)
- `ghidra_analysis` - Software reverse engineering
- `radare2_analyze` - Advanced binary analysis
- `gdb_debug` - GNU debugger
- `checksec_analyze` - Binary security properties
- `strings_extract` - Extract printable strings
- `pwntools_exploit` - CTF framework
- `angr_symbolic_execution` - Symbolic execution
- `volatility_analyze` - Memory forensics

### Zypheron-Specific Features
- `zypheron_scan` - Comprehensive security scan
- `zypheron_api_pentest` - API security testing
- `zypheron_secrets_scan` - Secrets detection
- `zypheron_deps_analyze` - Dependency CVE analysis
- `zypheron_pwn` - Binary exploitation
- `server_health` - Health check
- `list_available_tools` - List all tools
- `check_tool_status` - Check tool availability

## Example Workflows

### 1. Comprehensive Web Application Testing

```
User: "I need to perform a comprehensive security assessment of https://example.com. 
Start with reconnaissance, then scan for vulnerabilities, and finally test for common 
web vulnerabilities like XSS and SQL injection."

AI Agent: I'll help you perform a comprehensive security assessment. Let me break this down:

1. First, I'll use subfinder and amass to discover subdomains
2. Then use nmap to scan for open ports and services
3. Run nuclei with high and critical severity templates
4. Use nikto for web server vulnerabilities
5. Test for SQL injection with sqlmap
6. Scan for XSS with dalfox

[AI executes tools autonomously and provides analysis]
```

### 2. API Security Testing

```
User: "Test the API at https://api.example.com/v1 for security issues. 
The OpenAPI spec is at https://api.example.com/swagger.json"

AI Agent: I'll perform comprehensive API security testing:

[Executes zypheron_api_pentest with schema URL]
[Analyzes results and provides recommendations]
```

### 3. Binary Exploitation

```
User: "Analyze this binary file at ./challenge and help me find exploitable vulnerabilities"

AI Agent: I'll analyze the binary for you:

1. First, let me check security properties with checksec
2. Extract strings to understand functionality
3. Use Ghidra for deep analysis
4. Run pwntools to identify exploitation opportunities

[AI executes analysis and generates exploit]
```

### 4. Secrets Scanning

```
User: "Scan my repository at /home/user/myproject for exposed secrets and credentials"

AI Agent: Running secrets scan with Zypheron...

[Executes zypheron_secrets_scan]
[Reports found secrets with severity and remediation]
```

### 5. Dependency Vulnerability Analysis

```
User: "Check my project dependencies for known vulnerabilities"

AI Agent: Analyzing dependencies and matching with CVE database...

[Executes zypheron_deps_analyze]
[Generates SBOM and vulnerability report]
```

## Troubleshooting

### MCP Server Won't Start

**Problem**: Error when starting MCP server

**Solution**:
```bash
# Check Python version
python3 --version  # Should be 3.9+

# Verify dependencies
pip install -r zypheron-ai/requirements-mcp.txt

# Try with debug mode
zypheron mcp start --debug
```

### AI Client Can't Connect

**Problem**: AI client shows "MCP server not responding"

**Solution**:
1. Verify MCP server is running:
   ```bash
   zypheron mcp status
   ```

2. Check the path in your AI client config is correct:
   ```bash
   zypheron mcp config  # Shows correct path
   ```

3. Ensure Python 3 is in PATH:
   ```bash
   which python3
   ```

### Tool Not Found Errors

**Problem**: MCP server reports tools not found

**Solution**:
```bash
# Check which tools are installed
zypheron tools check

# Install missing tools
zypheron tools install <tool-name>

# Or install all tools
zypheron tools install-all
```

### Timeout Errors

**Problem**: Commands timeout before completing

**Solution**:
1. Increase timeout in AI client config (default: 300 seconds)
2. Use faster scan options
3. Reduce scan scope

### Permission Errors

**Problem**: Permission denied when executing tools

**Solution**:
```bash
# Some tools require sudo
# Run with appropriate permissions or configure sudo NOPASSWD

# Check tool permissions
ls -l $(which nmap)
```

## Security Considerations

### Authentication

The MCP server uses Zypheron's existing authentication system:
- Token-based authentication via `~/.zypheron/ipc.token`
- Tokens are generated automatically on first run
- File permissions restrict access to owner only (chmod 600)

### Rate Limiting

Zypheron's safety controls apply to MCP requests:
- Rate limiting prevents abuse
- Tool execution validation
- Parameter sanitization

### Logging

All MCP tool executions are logged:
- Command executed
- User/agent identifier
- Timestamp
- Results summary

Logs are stored in `zypheron-ai/zypheron-ai.log`

### Tool Restrictions

Some tools require additional permissions:
- Network tools may need root/admin
- System tools may require elevated privileges
- File operations respect system permissions

Always:
- Run MCP server with minimum required privileges
- Review commands before execution
- Use in isolated/test environments
- Follow responsible disclosure practices

### Best Practices

1. **Scope Testing**: Always define clear testing scope
2. **Authorization**: Obtain written permission before testing
3. **Isolation**: Run in dedicated testing environment
4. **Monitoring**: Monitor AI agent actions
5. **Review**: Review results before taking action
6. **Logging**: Maintain audit trail of all activities

## Advanced Configuration

### Custom Backend URL

If Zypheron backend runs on a different host/port:

```bash
zypheron mcp start --backend http://192.168.1.100:8080
```

Update AI client config accordingly.

### Debug Mode

Enable detailed logging:

```bash
zypheron mcp start --debug
```

### Multiple AI Clients

You can configure multiple AI clients to use the same MCP server:
- Each client maintains its own connection
- Shared authentication token
- Independent request handling

## Support

For issues, questions, or contributions:

- **Documentation**: [docs/](.)
- **GitHub Issues**: [Issues](https://github.com/KKingZero/Cobra-AI/issues)
- **Discussions**: [GitHub Discussions](https://github.com/KKingZero/Cobra-AI/discussions)

## What's Next?

- Explore [CLI_GUIDE.md](CLI_GUIDE.md) for direct CLI usage
- Read [TOOL_CHAINS.md](TOOL_CHAINS.md) for tool chain configuration
- See [SECURITY.md](../SECURITY.md) for security policy
- Check [DEV_STATUS.md](DEV_STATUS.md) for development roadmap

---

**Happy Hacking! 🐍⚡**

