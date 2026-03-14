# Zypheron Quick Start Guide

Get Zypheron running in under 5 minutes.

---

## Prerequisites

You need **Go 1.21+** installed.

```bash
# Check if Go is installed
go version

# If not installed or version is too old:
# Ubuntu/Debian/Kali
sudo apt update && sudo apt install -y golang-go

# macOS
brew install go

# Or download from https://go.dev/dl/
```

---

## Install Zypheron

### Step 1: Clone the Repository

```bash
git clone https://github.com/KKingZero/Zypheron-CLI.git
cd Zypheron-CLI
```

### Step 2: Build

```bash
cd zypheron-go
go mod tidy
go build -o zypheron ./cmd/zypheron
```

### Step 3: Install (Optional)

```bash
# Install system-wide
sudo cp zypheron /usr/local/bin/

# Verify
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
| `go: command not found` | Install Go: `sudo apt install golang-go` |
| `go.mod file not found` | Make sure you're in `zypheron-go/` directory |
| `module requires Go 1.21` | Upgrade Go from https://go.dev/dl/ |
| `permission denied` | Use `sudo cp` for system install |

---

## Next Steps

- **Full Installation Guide**: [docs/INSTALL.md](docs/INSTALL.md)
- **Setup & Configuration**: [docs/SETUP_AND_USE.md](docs/SETUP_AND_USE.md)
- **CLI Reference**: [docs/GO_GUIDE.md](docs/GO_GUIDE.md)
- **AI Features**: [docs/AI_GUIDE.md](docs/AI_GUIDE.md)
- **Troubleshooting**: [HELP.md](HELP.md)

---

## One-Liner Install

```bash
git clone https://github.com/KKingZero/Zypheron-CLI.git && cd Zypheron-CLI/zypheron-go && go mod tidy && go build -o zypheron ./cmd/zypheron && sudo cp zypheron /usr/local/bin/ && zypheron --version
```
