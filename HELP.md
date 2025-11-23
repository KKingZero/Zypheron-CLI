# Zypheron CLI - Help & Troubleshooting Guide

Complete guide for resolving common installation, API, and operational issues with Zypheron CLI.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Build and Compilation Issues](#build-and-compilation-issues)
- [Python and Virtual Environment Issues](#python-and-virtual-environment-issues)
- [API and Backend Issues](#api-and-backend-issues)
- [MCP Integration Issues](#mcp-integration-issues)
- [Tool Installation Issues](#tool-installation-issues)
- [Runtime and Execution Issues](#runtime-and-execution-issues)
- [Network and Connectivity Issues](#network-and-connectivity-issues)
- [Platform-Specific Issues](#platform-specific-issues)
- [Security and Permission Issues](#security-and-permission-issues)
- [Getting Further Help](#getting-further-help)

---

## Installation Issues

### Issue: Repository Clone Fails

**Symptoms:**
```
fatal: repository 'https://github.com/KKingZero/Cobra-AI.git' not found
```

**Solutions:**

1. **Verify the correct repository URL:**
   ```bash
   # Clone the repository
   git clone https://github.com/KKingZero/Zypheron-CLI.git

   # Or use SSH if you have GitHub SSH keys configured
   git clone git@github.com:KKingZero/Zypheron-CLI.git
   ```

2. **Check your network connection:**
   ```bash
   ping github.com
   curl -I https://github.com
   ```

3. **Use a different Git protocol:**
   ```bash
   # If HTTPS doesn't work, try GitHub CLI
   gh repo clone KKingZero/Zypheron-CLI
   ```

### Issue: Wrong Directory After Clone

**Symptoms:**
- Cannot find `zypheron-go` or `zypheron-ai` directories
- Commands fail with "No such file or directory"

**Solutions:**

1. **Verify you're in the correct directory:**
   ```bash
   # Check current directory structure
   ls -la

   # You should see both zypheron-go/ and zypheron-ai/ directories
   # If not, find the correct path
   find ~ -type d -name "zypheron-go" 2>/dev/null
   ```

2. **Navigate to the correct directory:**
   ```bash
   # Navigate to the cloned directory
   cd Zypheron-CLI
   ```

### Issue: Go Not Installed or Wrong Version

**Symptoms:**
```
bash: go: command not found
```
OR
```
go version go1.20 linux/amd64  # Version is too old
```

**Solutions:**

1. **Install Go 1.21 or higher:**

   **Ubuntu/Debian:**
   ```bash
   # Remove old Go version
   sudo apt remove golang-go

   # Install from official Go downloads
   wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
   sudo rm -rf /usr/local/go
   sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz

   # Add to PATH
   echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
   source ~/.bashrc

   # Verify installation
   go version
   ```

   **macOS:**
   ```bash
   brew install go@1.22
   ```

   **Windows:**
   - Download installer from https://go.dev/dl/
   - Run the installer
   - Restart your terminal

2. **Verify Go environment:**
   ```bash
   go env GOPATH
   go env GOROOT
   ```

---

## Build and Compilation Issues

### Issue: Go Build Fails with Module Errors

**Symptoms:**
```
go: module not found
missing go.sum entry
```

**Solutions:**

1. **Clean and rebuild Go modules:**
   ```bash
   cd zypheron-go

   # Clean build cache
   go clean -cache -modcache -testcache

   # Tidy modules
   go mod tidy

   # Download dependencies
   go mod download

   # Try building again
   make build
   ```

2. **Check Go module configuration:**
   ```bash
   # Ensure Go modules are enabled
   go env -w GO111MODULE=on

   # Verify go.mod exists
   cat go.mod
   ```

3. **Update dependencies:**
   ```bash
   go get -u ./...
   go mod tidy
   ```

### Issue: Make Command Not Found

**Symptoms:**
```
bash: make: command not found
```

**Solutions:**

1. **Install make:**

   **Ubuntu/Debian:**
   ```bash
   sudo apt update
   sudo apt install build-essential
   ```

   **macOS:**
   ```bash
   xcode-select --install
   ```

   **Windows (WSL):**
   ```bash
   sudo apt install make
   ```

2. **Build without make:**
   ```bash
   cd zypheron-go
   go build -o zypheron ./cmd/zypheron
   ```

### Issue: Build Succeeds but Binary Won't Run

**Symptoms:**
```
bash: ./zypheron: No such file or directory
# OR
bash: ./zypheron: Permission denied
```

**Solutions:**

1. **Check if binary exists:**
   ```bash
   ls -la zypheron
   ls -la build/zypheron
   ```

2. **Make binary executable:**
   ```bash
   chmod +x zypheron
   # OR
   chmod +x build/zypheron
   ```

3. **Check architecture compatibility:**
   ```bash
   file zypheron
   uname -m

   # If architecture mismatch, rebuild for your platform
   GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) go build -o zypheron ./cmd/zypheron
   ```

### Issue: System-Wide Installation Fails

**Symptoms:**
```
cp: cannot create regular file '/usr/local/bin/zypheron': Permission denied
```

**Solutions:**

1. **Use sudo for system-wide installation:**
   ```bash
   sudo make install
   # OR
   sudo cp zypheron /usr/local/bin/
   sudo chmod +x /usr/local/bin/zypheron
   ```

2. **Install to user directory (no sudo required):**
   ```bash
   # Create local bin directory
   mkdir -p ~/.local/bin

   # Copy binary
   cp zypheron ~/.local/bin/
   chmod +x ~/.local/bin/zypheron

   # Add to PATH if not already there
   echo 'export PATH=$PATH:~/.local/bin' >> ~/.bashrc
   source ~/.bashrc
   ```

3. **Verify installation:**
   ```bash
   which zypheron
   zypheron --version
   ```

---

## Python and Virtual Environment Issues

### Issue: Python Version Too Old

**Symptoms:**
```
Python 3.8 is installed, but 3.9+ is required
```

**Solutions:**

1. **Install Python 3.9 or higher:**

   **Ubuntu/Debian:**
   ```bash
   sudo apt update
   sudo apt install python3.11 python3.11-venv python3.11-dev

   # Set as default (optional)
   sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1
   ```

   **macOS:**
   ```bash
   brew install python@3.11
   ```

2. **Verify Python version:**
   ```bash
   python3 --version
   ```

### Issue: Virtual Environment Creation Fails

**Symptoms:**
```
error: externally-managed-environment
The virtual environment was not created successfully
```

**Solutions:**

1. **Use python3 -m venv (recommended):**
   ```bash
   cd zypheron-ai
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Install venv package:**
   ```bash
   # Ubuntu/Debian
   sudo apt install python3-venv python3-pip

   # Then create venv
   python3 -m venv venv
   ```

3. **If externally-managed-environment error persists:**
   ```bash
   # Option 1: Use virtual environment (preferred)
   python3 -m venv --system-site-packages venv
   source venv/bin/activate

   # Option 2: Use pipx for isolated installations
   sudo apt install pipx
   pipx install <package-name>
   ```

### Issue: pip install Fails with Permission Error

**Symptoms:**
```
error: externally-managed-environment
Could not install packages due to an OSError
```

**Solutions:**

1. **Always use virtual environment (recommended):**
   ```bash
   cd zypheron-ai
   python3 -m venv venv
   source venv/bin/activate  # Linux/macOS
   # OR: venv\Scripts\activate  # Windows

   pip install -r requirements.txt
   ```

2. **Never use sudo with pip (this breaks your system Python):**
   ```bash
   # WRONG - DO NOT DO THIS
   sudo pip install package

   # RIGHT - Use virtual environment
   python3 -m venv venv
   source venv/bin/activate
   pip install package
   ```

### Issue: Package Installation Fails

**Symptoms:**
```
ERROR: Could not find a version that satisfies the requirement
Building wheel for package failed
```

**Solutions:**

1. **Update pip and setuptools:**
   ```bash
   source venv/bin/activate
   pip install --upgrade pip setuptools wheel
   ```

2. **Install system dependencies:**
   ```bash
   # Ubuntu/Debian
   sudo apt install python3-dev build-essential libssl-dev libffi-dev

   # macOS
   xcode-select --install
   ```

3. **Install packages one by one:**
   ```bash
   # Identify which package is failing
   pip install -r requirements.txt 2>&1 | tee install.log

   # Install problematic packages separately with verbose output
   pip install -v <package-name>
   ```

### Issue: MCP Virtual Environment Issues

**Symptoms:**
- MCP dependencies conflict with main dependencies
- Cannot import fastmcp

**Solutions:**

1. **Create separate MCP virtual environment:**
   ```bash
   cd zypheron-ai

   # Create MCP-specific venv
   python3 -m venv mcp-venv
   source mcp-venv/bin/activate

   # Install only MCP requirements
   pip install -r requirements-mcp.txt

   # Verify installation
   python3 -c "import fastmcp; print('MCP installed successfully')"
   ```

2. **Use the helper script:**
   ```bash
   cd zypheron-ai
   source activate-mcp.sh
   ```

3. **Check for conflicting packages:**
   ```bash
   pip list | grep -E "(fastmcp|mcp)"
   ```

---

## API and Backend Issues

### Issue: AI Engine Won't Start

**Symptoms:**
```
Connection refused: localhost:8765
AI engine not responding
```

**Solutions:**

1. **Check if Python backend is running:**
   ```bash
   # Check if process is running
   ps aux | grep "python.*server"

   # Check if port is in use
   lsof -i :8765
   netstat -tulpn | grep 8765
   ```

2. **Start the AI engine manually:**
   ```bash
   cd zypheron-ai
   source venv/bin/activate
   python -m core.server
   ```

3. **Check for port conflicts:**
   ```bash
   # If port 8765 is already in use, kill the process
   lsof -ti:8765 | xargs kill -9

   # Or use a different port
   export ZYPHERON_PORT=8766
   python -m core.server
   ```

4. **Check AI engine logs:**
   ```bash
   cat zypheron-ai/zypheron-ai.log
   tail -f zypheron-ai/zypheron-ai.log
   ```

### Issue: API Key Not Working

**Symptoms:**
```
Invalid API key
Authentication failed
401 Unauthorized
```

**Solutions:**

1. **Verify API keys are set:**
   ```bash
   echo $OPENAI_API_KEY
   echo $ANTHROPIC_API_KEY
   ```

2. **Set API keys properly:**
   ```bash
   # Create .env file in zypheron-ai directory
   cd zypheron-ai
   cp env.example .env

   # Edit .env file
   nano .env
   ```

   Add your keys:
   ```bash
   OPENAI_API_KEY=sk-...
   ANTHROPIC_API_KEY=sk-ant-...
   GOOGLE_API_KEY=...
   DEEPSEEK_API_KEY=...
   ```

3. **Test API connection:**
   ```bash
   zypheron ai test --provider openai
   zypheron ai test --provider claude
   ```

4. **Verify key format:**
   - OpenAI keys start with `sk-`
   - Anthropic keys start with `sk-ant-`
   - Ensure no extra spaces or quotes

### Issue: API Pentest Command Not Found

**Symptoms:**
```
Error: unknown command "api-pentest" for "zypheron"
```

**Solutions:**

1. **Verify Zypheron version:**
   ```bash
   zypheron --version

   # Ensure you're running the latest version
   cd zypheron-go
   git pull
   make build
   ```

2. **Check available commands:**
   ```bash
   zypheron --help
   ```

3. **Ensure Python backend is running:**
   ```bash
   # API pentest requires Python backend
   zypheron ai status
   zypheron ai start
   ```

### Issue: Backend Communication Failures

**Symptoms:**
```
Failed to communicate with backend
Backend timeout
```

**Solutions:**

1. **Check backend is accessible:**
   ```bash
   curl http://localhost:8765/health
   ```

2. **Increase timeout:**
   ```bash
   # Set longer timeout
   export ZYPHERON_TIMEOUT=600

   # Or use command flag
   zypheron scan example.com --timeout 600
   ```

3. **Check firewall:**
   ```bash
   # Allow local connections
   sudo ufw allow 8765/tcp
   ```

4. **Restart both components:**
   ```bash
   # Stop AI engine
   pkill -f "python.*server"

   # Start fresh
   cd zypheron-ai
   source venv/bin/activate
   python -m core.server
   ```

---

## MCP Integration Issues

### Issue: MCP Server Won't Start

**Symptoms:**
```
Failed to start MCP server
ModuleNotFoundError: No module named 'fastmcp'
```

**Solutions:**

1. **Install MCP dependencies in virtual environment:**
   ```bash
   cd zypheron-ai

   # Create MCP-specific virtual environment
   python3 -m venv mcp-venv
   source mcp-venv/bin/activate

   # Install dependencies
   pip install -r requirements-mcp.txt

   # Verify
   python3 -c "import fastmcp; print('Success!')"
   ```

2. **Use the activation script:**
   ```bash
   cd zypheron-ai
   source activate-mcp.sh
   ```

3. **Start MCP server manually:**
   ```bash
   cd zypheron-ai
   source mcp-venv/bin/activate
   python mcp/server.py --server http://localhost:8765
   ```

### Issue: AI Client Can't Connect to MCP Server

**Symptoms:**
- Claude Desktop shows "MCP server not responding"
- Cursor can't find Zypheron tools

**Solutions:**

1. **Verify MCP server is running:**
   ```bash
   ps aux | grep "mcp/server.py"
   ```

2. **Check configuration path:**
   ```bash
   # Generate config to see correct path
   zypheron mcp config

   # Make sure this matches your AI client config
   ```

3. **Update AI client configuration with absolute paths:**

   For Claude Desktop (`~/.config/Claude/claude_desktop_config.json`):
   ```json
   {
     "mcpServers": {
       "zypheron-ai": {
         "command": "/usr/bin/python3",
         "args": [
           "/home/YOUR_USERNAME/Zypheron-CLI/zypheron-ai/mcp/server.py",
           "--server",
           "http://localhost:8765"
         ],
         "env": {
           "PYTHONPATH": "/home/YOUR_USERNAME/Zypheron-CLI/zypheron-ai"
         }
       }
     }
   }
   ```

4. **Ensure Python is in PATH:**
   ```bash
   which python3
   # Use the full path in your config
   ```

5. **Check MCP server logs:**
   ```bash
   tail -f zypheron-ai/mcp.log
   ```

### Issue: MCP Tools Not Available

**Symptoms:**
- AI agent says "I don't have access to Zypheron tools"
- Tools return errors

**Solutions:**

1. **Verify backend is running:**
   ```bash
   curl http://localhost:8765/health
   ```

2. **Check tool availability:**
   ```bash
   zypheron tools check
   zypheron tools list --installed
   ```

3. **Install missing tools:**
   ```bash
   zypheron tools install-all --critical-only
   ```

4. **Test MCP connection:**
   Ask your AI agent:
   ```
   "What Zypheron security tools do you have access to?"
   ```

---

## Tool Installation Issues

### Issue: Tools Not Found

**Symptoms:**
```
Error: nmap not found
Tool 'nuclei' is not installed
```

**Solutions:**

1. **Check which tools are missing:**
   ```bash
   zypheron tools check
   ```

2. **Install all critical tools:**
   ```bash
   zypheron tools install-all --critical-only
   ```

3. **Install specific tool:**
   ```bash
   # Via zypheron
   zypheron tools install nmap

   # Or manually
   sudo apt install nmap  # Ubuntu/Debian
   brew install nmap      # macOS
   ```

4. **Add tools to PATH:**
   ```bash
   # If tools are installed but not found, check PATH
   echo $PATH

   # Add Go binaries to PATH
   export PATH=$PATH:$(go env GOPATH)/bin

   # Make permanent
   echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
   source ~/.bashrc
   ```

### Issue: Tool Installation Requires Sudo

**Symptoms:**
```
Permission denied
E: Could not open lock file
```

**Solutions:**

1. **Use sudo for system tool installation:**
   ```bash
   sudo apt update
   sudo apt install nmap nikto sqlmap
   ```

2. **Install Go tools to user directory:**
   ```bash
   # Go tools install to ~/go/bin by default (no sudo needed)
   go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

   # Ensure ~/go/bin is in PATH
   export PATH=$PATH:~/go/bin
   ```

### Issue: Nuclei Templates Not Updating

**Symptoms:**
```
nuclei templates are outdated
```

**Solutions:**

```bash
# Update nuclei templates
nuclei -update-templates

# Or force update
nuclei -ut -duc
```

---

## Runtime and Execution Issues

### Issue: Scan Times Out

**Symptoms:**
```
Error: context deadline exceeded
Scan timed out after 300 seconds
```

**Solutions:**

1. **Increase timeout:**
   ```bash
   zypheron scan example.com --timeout 600
   ```

2. **Use faster scan mode:**
   ```bash
   zypheron scan example.com --fast
   ```

3. **Reduce scan scope:**
   ```bash
   # Scan fewer ports
   zypheron scan example.com -p 1-1000

   # Use specific tool
   zypheron scan example.com --tool nmap
   ```

### Issue: Permission Denied Running Tools

**Symptoms:**
```
Error: You don't have permission to run this command
nmap: socket: Operation not permitted
```

**Solutions:**

1. **Run with sudo for network tools:**
   ```bash
   sudo zypheron scan example.com
   ```

2. **Set capabilities (preferred):**
   ```bash
   # Allow zypheron to run network tools without sudo
   sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service=+eip /usr/local/bin/zypheron

   # For specific tools
   sudo setcap cap_net_raw,cap_net_admin=+eip /usr/bin/nmap
   ```

3. **Add user to relevant groups:**
   ```bash
   sudo usermod -aG sudo $USER
   # Log out and back in
   ```

### Issue: Output Not Streaming

**Symptoms:**
- No output appears until command completes
- Real-time output not showing

**Solutions:**

1. **Ensure streaming is enabled:**
   ```bash
   # Streaming is enabled by default
   zypheron scan example.com --stream

   # If not working, check your terminal supports it
   echo $TERM
   ```

2. **Disable buffering:**
   ```bash
   # Use unbuffered output
   stdbuf -oL zypheron scan example.com
   ```

---

## Network and Connectivity Issues

### Issue: Cannot Reach Target

**Symptoms:**
```
Error: no route to host
Connection timed out
```

**Solutions:**

1. **Verify network connectivity:**
   ```bash
   ping example.com
   curl -I https://example.com
   ```

2. **Check firewall:**
   ```bash
   # Check firewall status
   sudo ufw status

   # Temporarily disable (testing only!)
   sudo ufw disable
   ```

3. **Check VPN/proxy:**
   ```bash
   # If using VPN, ensure it's connected
   # Check proxy settings
   echo $HTTP_PROXY
   echo $HTTPS_PROXY
   ```

### Issue: DNS Resolution Fails

**Symptoms:**
```
Error: could not resolve host
DNS lookup failed
```

**Solutions:**

1. **Test DNS:**
   ```bash
   nslookup example.com
   dig example.com
   ```

2. **Try different DNS:**
   ```bash
   # Use Google DNS temporarily
   echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
   ```

3. **Use IP address directly:**
   ```bash
   zypheron scan 1.2.3.4
   ```

---

## Platform-Specific Issues

### WSL-Specific Issues

#### Issue: Network Tools Don't Work in WSL

**Solutions:**

1. **Configure WSL networking:**
   ```bash
   # Add to /etc/wsl.conf
   sudo nano /etc/wsl.conf
   ```

   Add:
   ```
   [network]
   generateResolvConf = false
   ```

2. **Restart WSL:**
   ```bash
   # From Windows PowerShell
   wsl --shutdown
   wsl
   ```

3. **Install required packages:**
   ```bash
   sudo apt update
   sudo apt install net-tools iproute2
   ```

### macOS-Specific Issues

#### Issue: Permission Denied on macOS

**Solutions:**

1. **Allow in Security & Privacy:**
   - System Preferences > Security & Privacy
   - Allow zypheron to run

2. **Remove quarantine:**
   ```bash
   xattr -d com.apple.quarantine /usr/local/bin/zypheron
   ```

### Windows-Specific Issues

#### Issue: Antivirus Blocks Zypheron

**Solutions:**

1. **Add exclusion in Windows Defender:**
   - Windows Security > Virus & threat protection
   - Manage settings > Add exclusion
   - Add folder: C:\path\to\zypheron

---

## Security and Permission Issues

### Issue: IPC Token Errors

**Symptoms:**
```
Error: invalid IPC token
Authentication failed
```

**Solutions:**

1. **Regenerate token:**
   ```bash
   rm ~/.zypheron/ipc.token
   zypheron ai start
   ```

2. **Check token permissions:**
   ```bash
   ls -la ~/.zypheron/ipc.token
   # Should be 600 (rw-------)

   chmod 600 ~/.zypheron/ipc.token
   ```

### Issue: Cannot Write to Config Directory

**Symptoms:**
```
Error: failed to create config directory
Permission denied: ~/.zypheron
```

**Solutions:**

```bash
# Create directory with correct permissions
mkdir -p ~/.zypheron
chmod 755 ~/.zypheron

# Check ownership
ls -ld ~/.zypheron
```

---

## Getting Further Help

If your issue isn't covered here:

### 1. Enable Debug Mode

```bash
zypheron --debug scan example.com 2>&1 | tee debug.log
```

### 2. Check Logs

```bash
# Python backend logs
cat zypheron-ai/zypheron-ai.log
tail -f zypheron-ai/zypheron-ai.log

# MCP logs
cat zypheron-ai/mcp.log
```

### 3. Gather System Information

```bash
# Create diagnostic report
echo "System Info:"
uname -a
echo "\nGo Version:"
go version
echo "\nPython Version:"
python3 --version
echo "\nInstalled Tools:"
zypheron tools check
echo "\nZypheron Version:"
zypheron --version
```

### 4. Search Existing Issues

Visit: https://github.com/KKingZero/Zypheron-CLI/issues

### 5. Create New Issue

Include:
- Full error message
- Steps to reproduce
- System information (OS, versions)
- Relevant logs
- What you've already tried

### 6. Community Support

- GitHub Discussions: https://github.com/KKingZero/Zypheron-CLI/discussions
- Check Documentation: [docs/](docs/)

---

## Quick Reference

### Common Commands

```bash
# Check installation
zypheron --version
zypheron tools check

# Test AI integration
zypheron ai status
zypheron ai test

# Start services
zypheron ai start
zypheron mcp start

# Debug mode
zypheron --debug [command]

# View logs
tail -f zypheron-ai/zypheron-ai.log
```

### Important File Locations

```
~/.zypheron/                # Config directory
~/.zypheron/ipc.token       # Authentication token
~/.zypheron/config.yaml     # Main config
zypheron-ai/zypheron-ai.log # Backend logs
zypheron-ai/mcp.log         # MCP logs
zypheron-ai/.env            # API keys
```

### Environment Variables

```bash
export OPENAI_API_KEY=sk-...           # OpenAI API key
export ANTHROPIC_API_KEY=sk-ant-...    # Claude API key
export ZYPHERON_PORT=8765               # Backend port
export ZYPHERON_TIMEOUT=600             # Timeout in seconds
export ZYPHERON_DEBUG=1                 # Enable debug
```

---

**Need more help?** Check the main documentation at [docs/](docs/) or open an issue on GitHub.
