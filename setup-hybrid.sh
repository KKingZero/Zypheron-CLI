#!/bin/bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT_DIR"

EXTRAS_RAW=""
PYTHON_BIN="python3"
USE_LOCK=true

usage() {
    cat <<'EOF'
Usage: ./setup-hybrid.sh [options]

Options:
  --python PATH        Use a specific Python interpreter (default: python3)
  --extras LIST        Comma-separated optional packs: ml,security,web
  --no-lock            Install from .txt manifests instead of *.lock
  -h, --help           Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --python)
            [[ $# -lt 2 ]] && { echo "Missing argument for --python"; exit 1; }
            PYTHON_BIN="$2"
            shift 2
            ;;
        --extras)
            [[ $# -lt 2 ]] && { echo "Missing argument for --extras"; exit 1; }
            EXTRAS_RAW="$2"
            shift 2
            ;;
        --no-lock)
            USE_LOCK=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

IFS=',' read -r -a RAW_EXTRAS <<< "$EXTRAS_RAW"
EXTRAS=()
for raw_extra in "${RAW_EXTRAS[@]}"; do
    trimmed=$(echo "$raw_extra" | tr '[:upper:]' '[:lower:]' | xargs)
    if [[ -n "$trimmed" ]]; then
        EXTRAS+=("$trimmed")
    fi
done

STEP_COLOR='\033[0;34m'
SUCCESS_COLOR='\033[0;32m'
WARN_COLOR='\033[1;33m'
ERROR_COLOR='\033[0;31m'
NC='\033[0m'

print_step() {
    local idx="$1"
    local message="$2"
    printf "%b[%s]%b %s\n" "$STEP_COLOR" "$idx" "$NC" "$message"
}

print_banner() {
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║  ZYPHERON HYBRID SETUP                                    ║"
    echo "║  Go CLI + Python AI Engine                                ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    if ((${#EXTRAS[@]} > 0)); then
        echo "Optional packs: ${EXTRAS[*]}"
    else
        echo "Optional packs: (none)"
    fi
    if [[ "$USE_LOCK" == false ]]; then
        echo -e "${WARN_COLOR}⚠ Installing from floating manifests (no lockfile)${NC}"
    fi
    echo ""
}

ensure_not_root() {
    if [[ "$EUID" -eq 0 ]]; then
        echo -e "${ERROR_COLOR}Please do not run this script as root${NC}"
        exit 1
    fi
}

check_go() {
    if ! command -v go >/dev/null 2>&1; then
        echo -e "${ERROR_COLOR}Go is not installed${NC}"
        echo "Install Go from https://golang.org/dl/"
        exit 1
    fi

    local raw_version
    raw_version=$(go version | awk '{print $3}')
    local version=${raw_version#go}
    local major=${version%%.*}
    local minor_patch=${version#*.}
    local minor=${minor_patch%%.*}

    echo -e "${SUCCESS_COLOR}✓ Go found: ${raw_version}${NC}"
    if (( major < 1 || minor < 21 )); then
        echo -e "${WARN_COLOR}Go ${version} detected. Zypheron works best with Go >= 1.21${NC}"
    fi
}

check_python() {
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
        echo -e "${ERROR_COLOR}${PYTHON_BIN} is not installed${NC}"
        exit 1
    fi

    local py_version
    py_version=$("$PYTHON_BIN" -c 'import sys; print("{}.{}.{}".format(*sys.version_info[:3]))')
    IFS='.' read -r py_major py_minor py_patch <<< "$py_version"

    echo -e "${SUCCESS_COLOR}✓ Python found: ${PYTHON_BIN} (${py_version})${NC}"
    if (( py_major != 3 || py_minor < 11 || py_minor >= 13 )); then
        echo -e "${ERROR_COLOR}Zypheron targets Python >=3.11,<3.13 (detected ${py_version})${NC}"
        exit 1
    fi
}

install_go_cli() {
    print_step "2/6" "Building Go CLI"
    pushd "$ROOT_DIR/zypheron-go" >/dev/null
    echo "  Installing Go modules..."
    go mod tidy
    echo "  Building binary..."
    go build -o zypheron cmd/zypheron/main.go
    echo "  Installing to /usr/local/bin (sudo required)..."
    sudo mv zypheron /usr/local/bin/zypheron
    sudo chmod +x /usr/local/bin/zypheron
    popd >/dev/null
    echo -e "${SUCCESS_COLOR}✓ Go CLI installed${NC}"
    echo ""
}

install_python_engine() {
    print_step "3/6" "Setting up Python AI Engine"
    pushd "$ROOT_DIR/zypheron-ai" >/dev/null

    local venv_dir=".venv"
    if [[ -d "venv" && ! -d "$venv_dir" ]]; then
        echo "  Migrating legacy venv/ directory to .venv"
        mv venv "$venv_dir"
    fi

    if [[ ! -d "$venv_dir" ]]; then
        echo "  Creating virtual environment at $venv_dir"
        "$PYTHON_BIN" -m venv "$venv_dir"
    fi

    # shellcheck disable=SC1091
    source "$venv_dir/bin/activate"

    local installer="pip"
    if command -v uv >/dev/null 2>&1; then
        installer="uv"
        echo "  Using uv for dependency installation"
    else
        echo "  Upgrading pip and build tooling"
        python -m pip install --upgrade pip setuptools wheel >/dev/null
    fi

    local base_manifest="requirements.txt"
    local lock_manifest="requirements.lock"

    if [[ "$USE_LOCK" == true && -f "$lock_manifest" ]]; then
        if [[ "$installer" == "uv" ]]; then
            uv pip sync "$lock_manifest"
        else
            python -m pip install -r "$lock_manifest"
        fi
    else
        if [[ "$installer" == "uv" ]]; then
            uv pip install -r "$base_manifest"
        else
            python -m pip install -r "$base_manifest"
        fi
    fi

    for extra in "${EXTRAS[@]}"; do
        local extra_manifest="requirements-${extra}.txt"
        local extra_lock="requirements-${extra}.lock"
        if [[ "$USE_LOCK" == true && -f "$extra_lock" ]]; then
            echo "  Installing optional pack: $extra (lock)"
            if [[ "$installer" == "uv" ]]; then
                uv pip install -r "$extra_lock"
            else
                python -m pip install -r "$extra_lock"
            fi
        elif [[ -f "$extra_manifest" ]]; then
            echo "  Installing optional pack: $extra"
            if [[ "$installer" == "uv" ]]; then
                uv pip install -r "$extra_manifest"
            else
                python -m pip install -r "$extra_manifest"
            fi
        else
            echo -e "${WARN_COLOR}  Skipping unknown optional pack: ${extra}${NC}"
        fi
    done

    echo "  Running pip check"
    if ! python -m pip check; then
        echo -e "${WARN_COLOR}  pip check reported issues; review output above.${NC}"
    fi

    deactivate || true
    popd >/dev/null
    echo -e "${SUCCESS_COLOR}✓ Python AI Engine installed${NC}"
    echo ""
}

configure_env() {
    print_step "4/6" "Configuring environment"
    pushd "$ROOT_DIR/zypheron-ai" >/dev/null
    if [[ ! -f ".env" ]]; then
        cp env.example .env
        echo -e "${SUCCESS_COLOR}✓ Created .env file${NC}"
        echo -e "${WARN_COLOR}  Edit zypheron-ai/.env to add your API keys${NC}"
    else
        echo "  .env already present"
    fi
    popd >/dev/null
    echo ""
}

install_completions() {
    print_step "5/6" "Installing shell completions (optional)"
    if [[ -f "$HOME/.bashrc" ]]; then
        if ! grep -q "zypheron completion bash" "$HOME/.bashrc"; then
            {
                echo ""
                echo "# Zypheron CLI completion"
                echo 'eval "$(zypheron completion bash)"'
            } >> "$HOME/.bashrc"
            echo -e "${SUCCESS_COLOR}✓ Bash completion installed${NC}"
        else
            echo "  Bash completion already configured"
        fi
    else
        echo "  Bash shell profile not detected"
    fi

    if [[ -f "$HOME/.zshrc" ]]; then
        if ! grep -q "zypheron completion zsh" "$HOME/.zshrc"; then
            {
                echo ""
                echo "# Zypheron CLI completion"
                echo 'eval "$(zypheron completion zsh)"'
            } >> "$HOME/.zshrc"
            echo -e "${SUCCESS_COLOR}✓ Zsh completion installed${NC}"
        else
            echo "  Zsh completion already configured"
        fi
    else
        echo "  Zsh shell profile not detected"
    fi
    echo ""
}

verify_install() {
    print_step "6/6" "Verifying installation"
    if command -v zypheron >/dev/null 2>&1; then
        echo -e "${SUCCESS_COLOR}✓ zypheron command available${NC}"
        local version
        version=$(zypheron --version 2>&1 | head -n1)
        echo "  Version: ${version}"
    else
        echo -e "${ERROR_COLOR}zypheron command not found${NC}"
        exit 1
    fi
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║  INSTALLATION COMPLETE                                    ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    echo -e "${SUCCESS_COLOR}Next steps:${NC}"
    echo "1. Configure AI providers in zypheron-ai/.env"
    echo "2. Start the AI engine: zypheron ai start"
    echo "3. Run your first scan: zypheron scan example.com --ai-analysis"
    echo "4. Chat with the AI engine: zypheron chat --provider claude"
    echo ""
}

main() {
    print_banner
    ensure_not_root
    print_step "1/6" "Checking prerequisites"
    check_go
    check_python
    echo ""

    install_go_cli
    install_python_engine
    configure_env
    install_completions
    verify_install
}

main "$@"

