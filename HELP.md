# Zypheron CLI - Troubleshooting Guide

Start with `zypheron doctor` to diagnose most issues automatically.

## Installation

### Clone fails / repo not found
```bash
git clone https://github.com/KKingZero/Zypheron-CLI.git
```

### Go not installed or too old (need 1.24+)
```bash
# Ubuntu/Debian
wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc

# macOS
brew install go
```

### Python too old (need 3.9+)
```bash
# Ubuntu/Debian
sudo apt install python3.11 python3.11-venv python3.11-dev

# macOS
brew install python@3.11
```

## Build

### Module errors
```bash
cd zypheron-go
go clean -cache -modcache -testcache
go mod tidy && go mod download
make build
```

### `make` not found
```bash
sudo apt install build-essential   # Ubuntu/Debian
xcode-select --install             # macOS
# Or build directly: go build -o zypheron ./cmd/zypheron
```

### Binary won't run (permission denied / not found)
```bash
chmod +x build/zypheron
# Check architecture match:
file zypheron && uname -m
```

### System-wide install fails
```bash
# Option 1: sudo
sudo make install

# Option 2: user-local (no sudo)
mkdir -p ~/.local/bin && cp zypheron ~/.local/bin/ && chmod +x ~/.local/bin/zypheron
echo 'export PATH=$PATH:~/.local/bin' >> ~/.bashrc && source ~/.bashrc
```

## Python / Virtual Environment

### "externally-managed-environment" error
```bash
cd zypheron-ai
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Package install fails
```bash
source venv/bin/activate
pip install --upgrade pip setuptools wheel
sudo apt install python3-dev build-essential libssl-dev libffi-dev  # if needed
```

### ML/exploitation features missing
```bash
cd zypheron-ai && source venv/bin/activate
./install-heavy.sh
```

## AI Engine / API

### AI engine won't start (connection refused on :8765)
```bash
# Check if running
ps aux | grep "python.*server"
lsof -i :8765

# Start manually
cd zypheron-ai && source venv/bin/activate
python -m core.server

# Kill stale process if port is occupied
lsof -ti:8765 | xargs kill -9
```

### API key not working
```bash
# Check config
zypheron config get-providers

# Re-set key
zypheron config set-key anthropic

# Test
zypheron ai chat "Hello"
```
See [API_KEY_SETUP.md](API_KEY_SETUP.md) for full details.

### Backend timeout
```bash
zypheron scan example.com --timeout 600
# Or: export ZYPHERON_TIMEOUT=600
```

## MCP Integration

### MCP server won't start / "No module named 'fastmcp'"
```bash
cd zypheron-ai
python3 -m venv mcp-venv
source mcp-venv/bin/activate
pip install -r requirements-mcp.txt
# Or: source activate-mcp.sh
```

### AI client can't connect
```bash
# Verify server is running
ps aux | grep "mcp_interface/server.py"

# Regenerate config with correct paths
zypheron mcp config

# Use absolute paths in AI client config
```

### MCP tools not available
```bash
curl http://localhost:8765/health    # Verify backend
zypheron tools check                 # Check tool inventory
zypheron tools install-all --critical-only
```

## Tools

### Tool not found
```bash
zypheron tools check
zypheron tools install-all --critical-only

# Add Go tools to PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

### Nuclei templates outdated
```bash
nuclei -update-templates
```

## Runtime

### Scan times out
```bash
zypheron scan example.com --timeout 600
zypheron scan example.com --fast         # Or use fast mode
zypheron scan example.com -p 1-1000      # Or reduce scope
```

### Permission denied running tools
```bash
sudo zypheron scan example.com
# Or set capabilities:
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service=+eip /usr/local/bin/zypheron
```

## Network

### Cannot reach target / DNS fails
```bash
ping example.com
nslookup example.com
# Check firewall: sudo ufw status
# Check VPN/proxy: echo $HTTP_PROXY
```

## Platform-Specific

### WSL: network tools don't work
Add to `/etc/wsl.conf`:
```ini
[network]
generateResolvConf = false
```
Then restart WSL: `wsl --shutdown` from PowerShell.

### macOS: permission denied
```bash
xattr -d com.apple.quarantine /usr/local/bin/zypheron
```

### Windows: antivirus blocks zypheron
Add exclusion in Windows Security > Virus & threat protection > Manage settings.

## Security

### IPC token errors
```bash
rm ~/.zypheron/ipc.token
zypheron ai start
```

### Can't write to config directory
```bash
mkdir -p ~/.zypheron && chmod 755 ~/.zypheron
```

## Quick Reference

```bash
# Diagnostics
zypheron doctor
zypheron --debug [command] 2>&1 | tee debug.log

# Logs
tail -f zypheron-ai/zypheron-ai.log   # Backend
tail -f zypheron-ai/mcp.log           # MCP

# Key paths
~/.zypheron/config.json               # Config
~/.zypheron/ipc.token                 # IPC auth
zypheron-ai/.env                      # API keys (if using .env)
```

---

**Still stuck?** [GitHub Issues](https://github.com/KKingZero/Zypheron-CLI/issues) | [Discussions](https://github.com/KKingZero/Zypheron-CLI/discussions)
