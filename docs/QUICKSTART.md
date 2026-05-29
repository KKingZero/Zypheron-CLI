# Zypheron Quick Start Guide

Get Zypheron running in under 5 minutes.

---

## Prerequisites

You need **Go 1.24+** installed.

```bash
# Check if Go is installed
go version

# If not installed or version is too old:
# Download from https://go.dev/dl/ (recommended for 1.24+)
wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc

# macOS
brew install go
```

---

## Install Zypheron

### Option A: Bootstrap (Recommended)

```bash
git clone https://github.com/KKingZero/Zypheron-CLI.git
cd Zypheron-CLI
bash scripts/install/setup-hybrid.sh
```

This builds the CLI, installs dependencies, and sets up shell completion.

### Option B: Manual Build

```bash
git clone https://github.com/KKingZero/Zypheron-CLI.git
cd Zypheron-CLI/zypheron-go
go mod tidy
go build -o zypheron ./cmd/zypheron
sudo cp zypheron /usr/local/bin/
zypheron --version
```

---

## First Run

```bash
# Check what tools are installed
zypheron tools check

# Install critical security tools
zypheron tools install-all --critical-only -y

# Run your first scan
zypheron scan scanme.nmap.org
```

---

## Common Commands

```bash
# Network scan
zypheron scan example.com

# Web application scan
zypheron scan https://example.com --web

# AI chat assistant
zypheron chat "How do I test for SQL injection?"

# Check available tools
zypheron tools list

# Get help
zypheron --help
```

---

## AI Features (Optional)

If you want AI-powered analysis:

```bash
# Navigate to AI directory
cd ../zypheron-ai

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure API key
cd ../zypheron-go
./zypheron config set-key anthropic
# Enter your Anthropic API key when prompted

# Test AI
./zypheron chat "Hello"
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `go: command not found` | Install Go 1.24+ from https://go.dev/dl/ |
| `go.mod file not found` | Make sure you're in `zypheron-go/` directory |
| `module requires Go 1.24` | Upgrade Go from https://go.dev/dl/ |
| `permission denied` | Use `sudo cp` for system install |

---

## Next Steps

- **Full Installation Guide**: [docs/INSTALL.md](docs/INSTALL.md)
- **Setup & Configuration**: [docs/SETUP_AND_USE.md](docs/SETUP_AND_USE.md)
- **CLI Reference**: [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md)
- **AI Features**: [docs/AI_GUIDE.md](docs/AI_GUIDE.md)
- **Troubleshooting**: [HELP.md](HELP.md)

---

## One-Liner Install

```bash
git clone https://github.com/KKingZero/Zypheron-CLI.git && cd Zypheron-CLI && bash scripts/install/setup-hybrid.sh
```
