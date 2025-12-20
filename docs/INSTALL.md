# Zypheron Installation Guide

Complete step-by-step installation instructions for Zypheron CLI.

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation Methods](#installation-methods)
  - [Method 1: Quick Install (Recommended)](#method-1-quick-install-recommended)
  - [Method 2: Build from Source](#method-2-build-from-source)
  - [Method 3: Pre-built Binaries](#method-3-pre-built-binaries)
- [Platform-Specific Instructions](#platform-specific-instructions)
- [Post-Installation](#post-installation)
- [Troubleshooting](#troubleshooting)

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Linux (Ubuntu 20.04+, Debian 11+, Kali 2023+), macOS 12+, Windows 10+ (WSL2) |
| **Go** | 1.21 or higher (for building from source) |
| **Python** | 3.9 or higher (for AI features only) |
| **RAM** | 4 GB minimum |
| **Disk** | 2 GB free space (10 GB with all security tools) |

### Recommended Setup

- **Kali Linux 2023.3+** - Best compatibility with security tools
- **8-16 GB RAM** - For AI features and large scans
- **SSD** - Faster tool execution
- **Modern terminal** - With Unicode and color support (e.g., GNOME Terminal, iTerm2, Windows Terminal)

### Checking Your System

```bash
# Check Go version (need 1.21+)
go version

# Check Python version (need 3.9+ for AI features)
python3 --version

# Check available disk space
df -h .

# Check RAM
free -h
```

---

## Installation Methods

### Method 1: Quick Install (Recommended)

The fastest way to get Zypheron running:

```bash
# 1. Clone the repository
git clone https://github.com/KKingZero/Zypheron-CLI.git
cd Zypheron-CLI

# 2. Build the Go CLI
cd zypheron-go
go mod tidy
go build -o zypheron ./cmd/zypheron

# 3. Verify it works
./zypheron --version

# 4. (Optional) Install system-wide
sudo cp zypheron /usr/local/bin/
```

That's it! You now have a working Zypheron installation.

---

### Method 2: Build from Source

Full build with all options using Make:

#### Step 1: Install Prerequisites

**Ubuntu/Debian/Kali:**
```bash
# Update package lists
sudo apt update

# Install Go (if not installed)
sudo apt install -y golang-go

# Verify Go version (must be 1.21+)
go version

# If Go is too old, install manually:
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

**macOS:**
```bash
# Using Homebrew
brew install go

# Verify
go version
```

**Windows (WSL2):**
```bash
# In WSL2 Ubuntu terminal
sudo apt update
sudo apt install -y golang-go
```

#### Step 2: Clone Repository

```bash
# Clone via HTTPS
git clone https://github.com/KKingZero/Zypheron-CLI.git

# Or clone via SSH (if you have SSH keys configured)
git clone git@github.com:KKingZero/Zypheron-CLI.git

# Enter the directory
cd Zypheron-CLI
```

#### Step 3: Build the Go CLI

```bash
cd zypheron-go

# Install Go dependencies
go mod tidy

# Build the binary
go build -ldflags="-s -w" -o zypheron ./cmd/zypheron

# The binary is now at ./zypheron
ls -lh zypheron
```

**Build Options:**

```bash
# Standard build
go build -o zypheron ./cmd/zypheron

# Optimized build (smaller binary, stripped symbols)
go build -ldflags="-s -w" -o zypheron ./cmd/zypheron

# Debug build (with debug symbols)
go build -gcflags="all=-N -l" -o zypheron-debug ./cmd/zypheron
```

#### Step 4: Install System-Wide (Optional)

```bash
# Copy to system path
sudo cp zypheron /usr/local/bin/

# Make executable (should already be, but just in case)
sudo chmod +x /usr/local/bin/zypheron

# Verify installation
which zypheron
zypheron --version
```

#### Step 5: Set Up Shell Completion (Optional)

```bash
# Bash
zypheron completion bash | sudo tee /etc/bash_completion.d/zypheron > /dev/null
source ~/.bashrc

# Zsh
zypheron completion zsh > "${fpath[1]}/_zypheron"
source ~/.zshrc

# Fish
zypheron completion fish > ~/.config/fish/completions/zypheron.fish
```

---

### Method 3: Pre-built Binaries

Download pre-compiled binaries from the releases page:

```bash
# Linux AMD64
wget https://github.com/KKingZero/Zypheron-CLI/releases/latest/download/zypheron-linux-amd64.tar.gz
tar -xzf zypheron-linux-amd64.tar.gz
sudo mv zypheron /usr/local/bin/

# Linux ARM64 (Raspberry Pi, etc.)
wget https://github.com/KKingZero/Zypheron-CLI/releases/latest/download/zypheron-linux-arm64.tar.gz
tar -xzf zypheron-linux-arm64.tar.gz
sudo mv zypheron /usr/local/bin/

# macOS AMD64 (Intel)
wget https://github.com/KKingZero/Zypheron-CLI/releases/latest/download/zypheron-darwin-amd64.tar.gz
tar -xzf zypheron-darwin-amd64.tar.gz
sudo mv zypheron /usr/local/bin/

# macOS ARM64 (Apple Silicon M1/M2/M3)
wget https://github.com/KKingZero/Zypheron-CLI/releases/latest/download/zypheron-darwin-arm64.tar.gz
tar -xzf zypheron-darwin-arm64.tar.gz
sudo mv zypheron /usr/local/bin/
```

---

## Platform-Specific Instructions

### Kali Linux

Kali is the recommended platform - all security tools are readily available:

```bash
# Install
cd Zypheron-CLI/zypheron-go
go mod tidy && go build -o zypheron ./cmd/zypheron
sudo cp zypheron /usr/local/bin/

# Install security tools
zypheron tools install-all --critical-only -y
```

### Ubuntu/Debian

```bash
# Install dependencies
sudo apt update
sudo apt install -y golang-go git

# Build Zypheron
cd Zypheron-CLI/zypheron-go
go mod tidy && go build -o zypheron ./cmd/zypheron
sudo cp zypheron /usr/local/bin/

# Install some security tools (may need to add Kali repos for others)
sudo apt install -y nmap nikto
```

### macOS

```bash
# Install Go via Homebrew
brew install go

# Build Zypheron
cd Zypheron-CLI/zypheron-go
go mod tidy && go build -o zypheron ./cmd/zypheron
sudo cp zypheron /usr/local/bin/

# Install security tools via Homebrew
brew install nmap nikto sqlmap
```

### Windows (WSL2)

Zypheron works best in WSL2 with a Linux distribution:

```bash
# In PowerShell (as Administrator)
wsl --install -d kali-linux

# In WSL2 Kali terminal
sudo apt update
sudo apt install -y golang-go git

# Clone and build
git clone https://github.com/KKingZero/Zypheron-CLI.git
cd Zypheron-CLI/zypheron-go
go mod tidy && go build -o zypheron ./cmd/zypheron
sudo cp zypheron /usr/local/bin/
```

---

## Post-Installation

### Verify Installation

```bash
# Check version
zypheron --version

# Check help
zypheron --help

# Check tool status
zypheron tools check
```

### Install Security Tools

```bash
# Check what's installed
zypheron tools check

# Install critical tools
zypheron tools install-all --critical-only

# Or install all tools
zypheron tools install-all
```

### Configure (Optional)

```bash
# Run setup wizard
zypheron setup

# Or configure manually
zypheron config wizard
```

### Test Your Installation

```bash
# Test a simple scan (uses scanme.nmap.org - a safe test target)
zypheron scan scanme.nmap.org --fast

# Test tool management
zypheron tools list --installed
```

---

## Troubleshooting

### "go: command not found"

Go is not installed or not in PATH:

```bash
# Check if Go is installed
which go

# If not found, install it:
# Ubuntu/Debian
sudo apt install -y golang-go

# Or download directly from https://go.dev/dl/
```

### "go.mod file not found"

You're not in the correct directory:

```bash
# Make sure you're in the zypheron-go directory
cd /path/to/Zypheron-CLI/zypheron-go
ls go.mod  # Should show go.mod file
```

### Build fails with "module requires Go 1.21"

Your Go version is too old:

```bash
# Check version
go version

# Upgrade Go (Ubuntu/Debian)
sudo apt remove golang-go
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

### "permission denied" when installing

Use sudo for system-wide installation:

```bash
sudo cp zypheron /usr/local/bin/
sudo chmod +x /usr/local/bin/zypheron
```

### Tools not found after installation

Some tools require root or special permissions:

```bash
# Run with sudo for tools that need it
sudo zypheron scan example.com

# Or grant capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/zypheron
```

### Need more help?

- Check the [HELP.md](../HELP.md) troubleshooting guide
- Open an issue: https://github.com/KKingZero/Zypheron-CLI/issues
- Enable debug mode: `zypheron --debug scan example.com`

---

## Next Steps

After installation, see:

- [SETUP_AND_USE.md](SETUP_AND_USE.md) - Configuration and usage guide
- [GO_GUIDE.md](GO_GUIDE.md) - Go CLI reference
- [AI_GUIDE.md](AI_GUIDE.md) - AI features setup
