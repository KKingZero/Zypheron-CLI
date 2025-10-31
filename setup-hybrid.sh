#!/bin/bash

# Zypheron Hybrid System Setup Script
# Sets up Go CLI + Python AI Engine

set -e

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  🐍 ZYPHERON HYBRID SETUP                                 ║"
echo "║  Go CLI + Python AI Engine                                ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}✗ Please do not run this script as root${NC}"
    exit 1
fi

# Detect OS
OS="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
fi

echo -e "${BLUE}[1/6]${NC} Checking prerequisites..."

# Check for Go
if ! command -v go &> /dev/null; then
    echo -e "${RED}✗ Go is not installed${NC}"
    echo "Install Go from: https://golang.org/dl/"
    exit 1
else
    GO_VERSION=$(go version | awk '{print $3}')
    echo -e "${GREEN}✓ Go found: $GO_VERSION${NC}"
fi

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python3 is not installed${NC}"
    exit 1
else
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    echo -e "${GREEN}✓ Python3 found: $PYTHON_VERSION${NC}"
fi

# Check for pip
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}✗ pip3 is not installed${NC}"
    exit 1
else
    echo -e "${GREEN}✓ pip3 found${NC}"
fi

echo ""
echo -e "${BLUE}[2/6]${NC} Building Go CLI..."

cd zypheron-go

# Install Go dependencies
echo "  Installing Go modules..."
go mod tidy

# Build the binary
echo "  Building binary..."
go build -o zypheron cmd/zypheron/main.go

# Install binary
echo "  Installing to /usr/local/bin..."
sudo mv zypheron /usr/local/bin/zypheron
sudo chmod +x /usr/local/bin/zypheron

echo -e "${GREEN}✓ Go CLI installed${NC}"

cd ..

echo ""
echo -e "${BLUE}[3/6]${NC} Setting up Python AI Engine..."

cd zypheron-ai

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "  Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo "  Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1

# Install Python dependencies
echo "  Installing Python packages (this may take a few minutes)..."
pip install -r requirements.txt > /dev/null 2>&1

echo -e "${GREEN}✓ Python AI Engine installed${NC}"

cd ..

echo ""
echo -e "${BLUE}[4/6]${NC} Setting up configuration..."

cd zypheron-ai

# Copy example env if .env doesn't exist
if [ ! -f ".env" ]; then
    cp env.example .env
    echo -e "${GREEN}✓ Created .env file${NC}"
    echo -e "${YELLOW}  ⚠  Edit zypheron-ai/.env to add your API keys${NC}"
else
    echo -e "${YELLOW}  ℹ  .env file already exists${NC}"
fi

cd ..

echo ""
echo -e "${BLUE}[5/6]${NC} Installing shell completions (optional)..."

# Bash completion
if [ -f "$HOME/.bashrc" ]; then
    if ! grep -q "zypheron completion bash" "$HOME/.bashrc"; then
        echo "" >> "$HOME/.bashrc"
        echo "# Zypheron CLI completion" >> "$HOME/.bashrc"
        echo 'eval "$(zypheron completion bash)"' >> "$HOME/.bashrc"
        echo -e "${GREEN}✓ Bash completion installed${NC}"
    else
        echo -e "${YELLOW}  ℹ  Bash completion already configured${NC}"
    fi
fi

# Zsh completion
if [ -f "$HOME/.zshrc" ]; then
    if ! grep -q "zypheron completion zsh" "$HOME/.zshrc"; then
        echo "" >> "$HOME/.zshrc"
        echo "# Zypheron CLI completion" >> "$HOME/.zshrc"
        echo 'eval "$(zypheron completion zsh)"' >> "$HOME/.zshrc"
        echo -e "${GREEN}✓ Zsh completion installed${NC}"
    else
        echo -e "${YELLOW}  ℹ  Zsh completion already configured${NC}"
    fi
fi

echo ""
echo -e "${BLUE}[6/6]${NC} Verifying installation..."

# Check if zypheron command works
if command -v zypheron &> /dev/null; then
    echo -e "${GREEN}✓ zypheron command available${NC}"
    
    # Show version
    ZYPHERON_VERSION=$(zypheron --version 2>&1 | head -n1)
    echo "  Version: $ZYPHERON_VERSION"
else
    echo -e "${RED}✗ zypheron command not found${NC}"
    exit 1
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  ✅ INSTALLATION COMPLETE                                 ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo ""
echo "1. Configure AI providers:"
echo "   ${YELLOW}nano zypheron-ai/.env${NC}"
echo "   Add your API keys for Claude, OpenAI, Gemini, etc."
echo ""
echo "2. Start the AI engine:"
echo "   ${YELLOW}zypheron ai start${NC}"
echo ""
echo "3. Run your first scan:"
echo "   ${YELLOW}zypheron scan example.com --ai-analysis${NC}"
echo ""
echo "4. Chat with AI:"
echo "   ${YELLOW}zypheron chat --interactive${NC}"
echo ""
echo -e "${BLUE}Documentation:${NC}"
echo "   • Quick Start: ./AI_HYBRID_README.md"
echo "   • CLI Guide: ./zypheron-go/README.md"
echo ""
echo -e "${GREEN}Happy hacking! 🎯${NC}"
echo ""

