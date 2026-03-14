#!/usr/bin/env bash
#
# Zypheron Tab Completion Installer
# Automatically detects shell and installs tab completion
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored messages
info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
}

# Detect shell
detect_shell() {
    if [ -n "$ZSH_VERSION" ]; then
        echo "zsh"
    elif [ -n "$BASH_VERSION" ]; then
        echo "bash"
    elif [ -n "$FISH_VERSION" ]; then
        echo "fish"
    else
        # Fallback to checking $SHELL
        case "$SHELL" in
            */zsh)
                echo "zsh"
                ;;
            */bash)
                echo "bash"
                ;;
            */fish)
                echo "fish"
                ;;
            *)
                echo "unknown"
                ;;
        esac
    fi
}

# Check if zypheron is in PATH
check_zypheron() {
    if ! command -v zypheron &> /dev/null; then
        error "zypheron command not found in PATH"
        info "Make sure zypheron is installed and in your PATH"
        info "Try: which zypheron"
        exit 1
    fi
    success "Found zypheron at: $(which zypheron)"
}

# Install bash completion
install_bash() {
    info "Installing bash completion..."

    # Determine completion directory
    if [ -d "$HOME/.bash_completion.d" ]; then
        COMP_DIR="$HOME/.bash_completion.d"
    elif [ -d "/usr/local/etc/bash_completion.d" ]; then
        COMP_DIR="/usr/local/etc/bash_completion.d"
        warning "Installing to system directory (may require sudo)"
    elif [ -d "/etc/bash_completion.d" ]; then
        COMP_DIR="/etc/bash_completion.d"
        warning "Installing to system directory (may require sudo)"
    else
        # Create user directory
        COMP_DIR="$HOME/.bash_completion.d"
        mkdir -p "$COMP_DIR"
        info "Created directory: $COMP_DIR"
    fi

    # Generate and install completion
    COMP_FILE="$COMP_DIR/zypheron"
    zypheron completion bash > "$COMP_FILE"
    success "Installed bash completion to: $COMP_FILE"

    # Update bashrc if needed
    if ! grep -q "bash_completion.d/zypheron" "$HOME/.bashrc" 2>/dev/null; then
        echo "" >> "$HOME/.bashrc"
        echo "# Zypheron tab completion" >> "$HOME/.bashrc"
        echo "[ -f $COMP_FILE ] && source $COMP_FILE" >> "$HOME/.bashrc"
        success "Added completion source to ~/.bashrc"
    fi

    info "To activate now, run: source $COMP_FILE"
}

# Install zsh completion
install_zsh() {
    info "Installing zsh completion..."

    # Determine completion directory
    if [ -d "$HOME/.zsh/completions" ]; then
        COMP_DIR="$HOME/.zsh/completions"
    else
        COMP_DIR="$HOME/.zsh/completions"
        mkdir -p "$COMP_DIR"
        info "Created directory: $COMP_DIR"
    fi

    # Generate and install completion
    COMP_FILE="$COMP_DIR/_zypheron"
    zypheron completion zsh > "$COMP_FILE"
    success "Installed zsh completion to: $COMP_FILE"

    # Update zshrc if needed
    if ! grep -q "fpath.*\.zsh/completions" "$HOME/.zshrc" 2>/dev/null; then
        echo "" >> "$HOME/.zshrc"
        echo "# Zypheron tab completion" >> "$HOME/.zshrc"
        echo "fpath=($HOME/.zsh/completions \$fpath)" >> "$HOME/.zshrc"
        echo "autoload -Uz compinit && compinit" >> "$HOME/.zshrc"
        success "Added completion configuration to ~/.zshrc"
    fi

    info "To activate now, run: source ~/.zshrc"
}

# Install fish completion
install_fish() {
    info "Installing fish completion..."

    # Determine completion directory
    COMP_DIR="$HOME/.config/fish/completions"
    mkdir -p "$COMP_DIR"

    # Generate and install completion
    COMP_FILE="$COMP_DIR/zypheron.fish"
    zypheron completion fish > "$COMP_FILE"
    success "Installed fish completion to: $COMP_FILE"

    info "Fish will automatically load completions on next startup"
}

# Main installation
main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════╗"
    echo "║  Zypheron Tab Completion Installer                ║"
    echo "╚═══════════════════════════════════════════════════╝"
    echo ""

    # Check if zypheron is available
    check_zypheron

    # Detect shell
    DETECTED_SHELL=$(detect_shell)
    info "Detected shell: $DETECTED_SHELL"

    # Allow override
    SHELL_TYPE="${1:-$DETECTED_SHELL}"

    # Install for detected/specified shell
    case "$SHELL_TYPE" in
        bash)
            install_bash
            ;;
        zsh)
            install_zsh
            ;;
        fish)
            install_fish
            ;;
        *)
            error "Unsupported shell: $SHELL_TYPE"
            echo ""
            echo "Usage: $0 [bash|zsh|fish]"
            echo ""
            echo "Manually install completion:"
            echo "  Bash:  zypheron completion bash > ~/.bash_completion.d/zypheron"
            echo "  Zsh:   zypheron completion zsh > ~/.zsh/completions/_zypheron"
            echo "  Fish:  zypheron completion fish > ~/.config/fish/completions/zypheron.fish"
            exit 1
            ;;
    esac

    echo ""
    success "Tab completion installed successfully!"
    echo ""
    info "Restart your shell or source the completion file to activate"
    echo ""
}

# Run main
main "$@"
