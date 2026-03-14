#!/usr/bin/env bash

# Zypheron bootstrap
# Pasteable usage after clone:
#   git clone -b Zypheron-CLI https://github.com/KKingZero/Cobra-AI.git && cd Cobra-AI && bash ./setup-hybrid.sh
#
# Options:
#   ZYPHERON_INSTALL_DIR=/path        Install directory for the CLI binary
#   ZYPHERON_INSTALL_TOOLS=critical   Install critical missing tools (default)
#   ZYPHERON_INSTALL_TOOLS=all        Install all missing tools
#   ZYPHERON_INSTALL_TOOLS=none       Skip system tool installation
#   ZYPHERON_DEP_PACKS=all            Dependency packs: all (default), core

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
fail()  { printf "${RED}[-]${NC} %s\n" "$*" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_DIR="${ROOT_DIR}/zypheron-go"
AI_DIR="${ROOT_DIR}/zypheron-ai"
INSTALL_DIR="${ZYPHERON_INSTALL_DIR:-${HOME}/.local/bin}"
TOOLS_MODE="${ZYPHERON_INSTALL_TOOLS:-critical}"
DEP_PACKS="${ZYPHERON_DEP_PACKS:-all}"

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

ensure_path_notice() {
    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            warn "${INSTALL_DIR} is not on PATH"
            printf "    Add this to your shell profile:\n"
            printf "    export PATH=\"%s:\$PATH\"\n" "${INSTALL_DIR}"
            ;;
    esac
}

install_cli() {
    info "Building Zypheron CLI"
    mkdir -p "${INSTALL_DIR}"
    (
        cd "${GO_DIR}"
        go build -o "${INSTALL_DIR}/zypheron" ./cmd/zypheron
    )
    chmod +x "${INSTALL_DIR}/zypheron"
    info "CLI installed to ${INSTALL_DIR}/zypheron"
}

install_python_deps() {
    info "Installing Python dependencies"
    local dep_args=()
    if [[ "${DEP_PACKS}" == "all" ]]; then
        dep_args+=(--all)
    fi

    (
        cd "${GO_DIR}"
        "${INSTALL_DIR}/zypheron" install-deps "${dep_args[@]}"
    )
}

install_shell_completion() {
    info "Installing shell completion"
    mkdir -p "${HOME}/.local/share/zypheron"

    if [[ "${SHELL:-}" == *"bash"* ]]; then
        local target="${HOME}/.local/share/zypheron/completion.bash"
        "${INSTALL_DIR}/zypheron" completion bash > "${target}"
        if [[ -f "${HOME}/.bashrc" ]] && ! grep -q "${target}" "${HOME}/.bashrc"; then
            printf "\n# Zypheron CLI completion\nsource %s\n" "${target}" >> "${HOME}/.bashrc"
        fi
    elif [[ "${SHELL:-}" == *"zsh"* ]]; then
        mkdir -p "${HOME}/.zsh/completion"
        local target="${HOME}/.zsh/completion/_zypheron"
        "${INSTALL_DIR}/zypheron" completion zsh > "${target}"
        if [[ -f "${HOME}/.zshrc" ]] && ! grep -q ".zsh/completion" "${HOME}/.zshrc"; then
            printf "\n# Zypheron CLI completion\nfpath=(%s $fpath)\nautoload -Uz compinit && compinit\n" "${HOME}/.zsh/completion" >> "${HOME}/.zshrc"
        fi
    else
        warn "Shell completion auto-install skipped for ${SHELL:-unknown shell}"
    fi
}

install_tools() {
    case "${TOOLS_MODE}" in
        none)
            info "Skipping system tool installation"
            return
            ;;
        critical)
            info "Installing critical tools"
            "${INSTALL_DIR}/zypheron" tools install-all --critical-only --yes || warn "Critical tool installation reported issues"
            ;;
        all)
            info "Installing all missing tools"
            "${INSTALL_DIR}/zypheron" tools install-all --yes || warn "Tool installation reported issues"
            ;;
        *)
            fail "Unsupported ZYPHERON_INSTALL_TOOLS value: ${TOOLS_MODE}"
            ;;
    esac
}

main() {
    printf "${CYAN}== Zypheron Bootstrap ==${NC}\n"
    printf "Root:    %s\n" "${ROOT_DIR}"
    printf "Install: %s\n" "${INSTALL_DIR}"
    printf "Deps:    %s\n" "${DEP_PACKS}"
    printf "Tools:   %s\n\n" "${TOOLS_MODE}"

    [[ -d "${GO_DIR}" ]] || fail "Missing ${GO_DIR}"
    [[ -d "${AI_DIR}" ]] || fail "Missing ${AI_DIR}"

    require_cmd go
    require_cmd python3

    install_cli
    ensure_path_notice
    install_python_deps
    install_shell_completion
    install_tools

    printf "\n"
    info "Bootstrap complete"
    printf "    Version: %s\n" "$("${INSTALL_DIR}/zypheron" --version | head -n1)"
    printf "    Launch:  %s\n" "${INSTALL_DIR}/zypheron"
    printf "    Check:   %s\n" "${INSTALL_DIR}/zypheron doctor"
}

main "$@"
