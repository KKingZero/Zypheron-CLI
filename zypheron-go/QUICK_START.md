# 🚀 Zypheron CLI (Go) - Quick Start Guide

## Prerequisites

You need:
- Go 1.21 or later
- Kali Linux (recommended) or any Linux/macOS/Windows
- sudo access (for tool installation)

## 1️⃣ Install Go (if needed)

```bash
# Check if Go is installed
go version

# If not, install it
# Kali/Debian/Ubuntu:
sudo apt-get update
sudo apt-get install -y golang-go

# macOS:
brew install go

# Verify
go version  # Should show 1.21 or higher
```

## 2️⃣ Build Zypheron CLI

```bash
# Navigate to the Go CLI directory
cd zypheron-go

# Install dependencies
make deps

# Build the binary
make build

# You should see: build/zypheron
ls -lh build/zypheron
```

## 3️⃣ Install to System (Optional)

```bash
# Install to /usr/local/bin
sudo make install

# Verify installation
zypheron --version
```

**OR** run directly without installing:

```bash
# Run from build directory
./build/zypheron --version
```

## 4️⃣ Initial Setup

```bash
# Run setup wizard
zypheron setup

# Check which Kali tools are installed
zypheron tools check

# View configuration
zypheron config get
```

## 5️⃣ Your First Scan

```bash
# Basic scan
zypheron scan example.com

# Web application scan
zypheron scan https://example.com --web

# Fast scan
zypheron scan 192.168.1.1 --fast

# With AI analysis (requires backend)
zypheron scan example.com --ai-analysis
```

## 6️⃣ Manage Tools

```bash
# List all available tools
zypheron tools list

# Check what's installed
zypheron tools check

# Get info about a specific tool
zypheron tools info nmap

# Install a tool
zypheron tools install nikto

# Install all critical tools
zypheron tools install-all --critical-only -y
```

## 7️⃣ AI Chat Assistant

```bash
# Interactive chat
zypheron chat

# Quick question
zypheron chat "How do I test for SQL injection?"

# Requires backend API to be configured:
zypheron config set api.url http://localhost:3001
```

## 8️⃣ Configuration

```bash
# View all settings
zypheron config get

# Set backend URL
zypheron config set api.url http://localhost:3001

# Set default ports
zypheron config set scanning.default_ports "1-10000"

# Show config file location
zypheron config path
```

## 🐚 Ultra-Fast Mode (Bash Wrappers)

For instant execution without any overhead:

```bash
# Quick scan (bypasses Go CLI)
./scripts/bash/zscan example.com

# Quick tool check
./scripts/bash/ztools

# Add to PATH for system-wide access
sudo cp scripts/bash/{zscan,ztools} /usr/local/bin/
sudo chmod +x /usr/local/bin/{zscan,ztools}
```

## 🎯 Common Use Cases

### Security Assessment

```bash
# 1. Recon
zypheron scan example.com --full

# 2. Web testing
zypheron scan https://example.com --web --ai-analysis

# 3. Exploit search
zypheron exploit --search "apache 2.4"

# 4. Bruteforce
zypheron bruteforce ssh 192.168.1.1
```

### Tool Management

```bash
# Check missing tools
zypheron tools list --missing

# Install everything
zypheron tools install-all -y

# Suggest tool for task
zypheron tools suggest web
```

### Reporting

```bash
# Scan with output
zypheron scan example.com --output report.json --format json

# Generate report
zypheron report generate --scan scan-123
```

## 🔧 Troubleshooting

### Binary Not Found After Install

```bash
# Check if installed
which zypheron

# If not found, add to PATH
export PATH=$PATH:/usr/local/bin

# Or use absolute path
/usr/local/bin/zypheron --version
```

### Tool Not Found

```bash
# Check tool status
zypheron tools check

# Install the tool
zypheron tools install <tool-name>

# Or install all critical tools
zypheron tools install-all --critical-only
```

### Permission Denied

```bash
# Some tools need sudo
sudo zypheron scan 192.168.1.1 --tool masscan

# Or give binary capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/zypheron
```

### Backend Connection Failed

```bash
# Check backend URL
zypheron config get api.url

# Update if needed
zypheron config set api.url http://localhost:3001

# Test backend
curl http://localhost:3001/api/health
```

## 📚 Next Steps

1. **Read full docs**: `cat README.md`
2. **Check migration guide**: `cat MIGRATION_GUIDE.md`
3. **Explore commands**: `zypheron --help`
4. **Configure backend**: `zypheron config wizard`
5. **Start pentesting**: `zypheron scan <your-target>`

## 💡 Pro Tips

1. **Use `--help`** on any command for detailed options
2. **Stream output** with `--stream` for real-time results
3. **Save scans** with `--output` for later analysis
4. **Use bash wrappers** for ultra-fast execution
5. **Compress binary** with `make compress` to save space

## 🎓 Examples

```bash
# Full pentest workflow
zypheron scan example.com --full --ai-analysis --output scan.json

# Quick port check
./scripts/bash/zscan 192.168.1.1

# Install all tools
zypheron tools install-all --critical-only -y

# Interactive AI chat
zypheron chat
```

## 📞 Get Help

```bash
# Command help
zypheron --help
zypheron scan --help
zypheron tools --help

# Debug mode
zypheron scan example.com --debug

# Version info
zypheron --version
```

---

**🎉 You're ready to use Zypheron CLI!**

Start with: `zypheron scan example.com`

