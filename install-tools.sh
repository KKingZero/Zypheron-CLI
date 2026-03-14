#!/bin/bash
# Zypheron Security Tools Installer
# Run with: sudo bash install-tools.sh

set -e

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     ZYPHERON SECURITY TOOLS INSTALLER                     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root: sudo bash install-tools.sh"
    exit 1
fi

echo "[*] Updating package lists..."
apt-get update -qq

# APT packages
echo ""
echo "[1/8] Installing APT packages..."
apt-get install -y \
    hydra \
    john \
    theharvester \
    wordlists \
    seclists \
    2>/dev/null || echo "  Some APT packages not available, continuing..."

# Nuclei (Go-based, use go install)
echo ""
echo "[2/8] Installing Nuclei..."
if ! command -v nuclei &> /dev/null; then
    if command -v go &> /dev/null; then
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && \
        cp ~/go/bin/nuclei /usr/local/bin/ 2>/dev/null || true
        echo "  ✓ Nuclei installed"
    else
        echo "  [!] Go not found, skipping nuclei"
    fi
else
    echo "  ✓ Nuclei already installed"
fi

# Amass
echo ""
echo "[3/8] Installing Amass..."
if ! command -v amass &> /dev/null; then
    snap install amass 2>/dev/null || \
    apt-get install -y amass 2>/dev/null || \
    echo "  [!] Could not install amass"
else
    echo "  ✓ Amass already installed"
fi

# Metasploit Framework
echo ""
echo "[4/8] Installing Metasploit Framework..."
if ! command -v msfconsole &> /dev/null; then
    echo "  Downloading Metasploit installer..."
    curl -sL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
    chmod 755 /tmp/msfinstall
    /tmp/msfinstall 2>/dev/null || echo "  [!] Metasploit install failed - try manual install"
    rm -f /tmp/msfinstall
else
    echo "  ✓ Metasploit already installed"
fi

# Python tools
echo ""
echo "[5/8] Installing Python tools (ropper, volatility3)..."
pip3 install --quiet ropper volatility3 2>/dev/null || \
python3 -m pip install --quiet ropper volatility3 2>/dev/null || \
echo "  [!] Some Python tools failed"

# Ruby tools
echo ""
echo "[6/8] Installing Ruby tools (one_gadget)..."
if command -v gem &> /dev/null; then
    gem install one_gadget 2>/dev/null || echo "  [!] one_gadget install failed"
else
    apt-get install -y ruby-dev 2>/dev/null
    gem install one_gadget 2>/dev/null || echo "  [!] one_gadget install failed"
fi

# Ghidra
echo ""
echo "[7/8] Checking Ghidra..."
if ! command -v ghidra &> /dev/null && [ ! -d "/opt/ghidra" ]; then
    echo "  [!] Ghidra not installed"
    echo "  Download from: https://github.com/NationalSecurityAgency/ghidra/releases"
    echo "  Or: sudo apt install ghidra (if available)"
else
    echo "  ✓ Ghidra available"
fi

# SecLists wordlists
echo ""
echo "[8/8] Setting up wordlists..."
if [ ! -d "/usr/share/wordlists" ]; then
    mkdir -p /usr/share/wordlists
fi

if [ ! -d "/usr/share/seclists" ] && [ ! -d "/usr/share/wordlists/seclists" ]; then
    echo "  Downloading SecLists (this may take a while)..."
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null || \
    echo "  [!] SecLists download failed"
fi

# Create symlinks for common wordlists
if [ -d "/usr/share/seclists" ]; then
    ln -sf /usr/share/seclists/Discovery/Web-Content/common.txt /usr/share/wordlists/common.txt 2>/dev/null || true
    ln -sf /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt /usr/share/wordlists/dirb-medium.txt 2>/dev/null || true
    echo "  ✓ Wordlists configured"
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     INSTALLATION COMPLETE                                 ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Run 'zypheron tools check' to verify installation."
echo ""
