#!/usr/bin/env bash
# Zypheron CLI - Universal installer
# Usage: curl -sSfL https://download.zypheron.net/install.sh | bash
#
# Options (via env vars):
#   ZYPHERON_VERSION=v2.0.0   Install specific version (default: latest)
#   ZYPHERON_INSTALL_DIR=/path Install to custom directory (default: /usr/local/bin)

set -euo pipefail

DOWNLOAD_BASE="https://download.zypheron.net"
BINARY_NAME="zypheron"
DEFAULT_INSTALL_DIR="/usr/local/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

# Detect OS
detect_os() {
    local os
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$os" in
        linux*)  echo "linux" ;;
        darwin*) echo "darwin" ;;
        mingw*|msys*|cygwin*) echo "windows" ;;
        *) error "Unsupported OS: $os" ;;
    esac
}

# Detect architecture
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        armv7l|armhf)   echo "arm" ;;
        *) error "Unsupported architecture: $arch" ;;
    esac
}

# Detect download tool
detect_downloader() {
    if command -v curl &>/dev/null; then
        echo "curl"
    elif command -v wget &>/dev/null; then
        echo "wget"
    else
        error "Neither curl nor wget found. Install one and retry."
    fi
}

# Download a URL to a file
download() {
    local url="$1" dest="$2"
    local downloader
    downloader=$(detect_downloader)

    case "$downloader" in
        curl) curl -sSfL -o "$dest" "$url" ;;
        wget) wget -qO "$dest" "$url" ;;
    esac
}

# Fetch latest version tag
get_latest_version() {
    local tmpfile
    tmpfile=$(mktemp)
    download "${DOWNLOAD_BASE}/latest/version.txt" "$tmpfile"
    local version
    version=$(tr -d '[:space:]' < "$tmpfile")
    rm -f "$tmpfile"

    if [[ -z "$version" ]]; then
        error "Failed to determine latest version."
    fi
    echo "$version"
}

# Verify SHA256 checksum
verify_checksum() {
    local file="$1" expected="$2"

    local actual
    if command -v sha256sum &>/dev/null; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    elif command -v shasum &>/dev/null; then
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        warn "No sha256sum or shasum found. Skipping checksum verification."
        return 0
    fi

    if [[ "$actual" != "$expected" ]]; then
        error "Checksum mismatch!\n  Expected: $expected\n  Actual:   $actual"
    fi
    info "Checksum verified."
}

main() {
    echo -e "${CYAN}"
    echo "  ______           _                            "
    echo " |___  /          | |                           "
    echo "    / / _   _ _ __| |__   ___ _ __ ___  _ __   "
    echo "   / / | | | | '_ | '_ \ / _ | '__/ _ \| '_ \  "
    echo "  / /__| |_| | |_)| | | |  __| | | (_) | | | | "
    echo " /_____|\__, | .__/|_| |_|\___|_|  \___/|_| |_| "
    echo "         __/ | |                                "
    echo "        |___/|_|  CLI Installer                 "
    echo -e "${NC}"

    local os arch version install_dir
    os=$(detect_os)
    arch=$(detect_arch)
    version="${ZYPHERON_VERSION:-}"
    install_dir="${ZYPHERON_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"

    if [[ -z "$version" ]]; then
        info "Fetching latest version..."
        version=$(get_latest_version)
    fi

    info "OS:       $os"
    info "Arch:     $arch"
    info "Version:  $version"
    info "Install:  $install_dir"
    echo ""

    # Build download URLs
    local ext="tar.gz"
    [[ "$os" == "windows" ]] && ext="zip"

    local binary_file="${BINARY_NAME}-${os}-${arch}"
    local archive_file="${binary_file}.${ext}"
    local archive_url="${DOWNLOAD_BASE}/${version}/${archive_file}"
    local checksums_url="${DOWNLOAD_BASE}/${version}/SHA256SUMS"

    # Create temp directory
    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    # Download archive
    info "Downloading ${archive_file}..."
    download "$archive_url" "${tmpdir}/${archive_file}"

    # Download and verify checksums
    info "Verifying checksum..."
    download "$checksums_url" "${tmpdir}/SHA256SUMS"
    local expected_sum
    expected_sum=$(grep "${archive_file}" "${tmpdir}/SHA256SUMS" | awk '{print $1}')
    if [[ -n "$expected_sum" ]]; then
        verify_checksum "${tmpdir}/${archive_file}" "$expected_sum"
    else
        warn "Checksum not found for ${archive_file} in SHA256SUMS. Skipping verification."
    fi

    # Extract
    info "Extracting..."
    cd "$tmpdir"
    if [[ "$ext" == "tar.gz" ]]; then
        tar -xzf "${archive_file}"
    else
        unzip -q "${archive_file}"
    fi

    # Install - find the binary (may be extracted with or without platform suffix)
    local src_binary="${binary_file}"
    [[ "$os" == "windows" ]] && src_binary="${binary_file}.exe"

    if [[ ! -f "$src_binary" ]]; then
        # Fallback: look for the binary by name pattern in extracted files
        local found
        found=$(find . -maxdepth 1 -name "${BINARY_NAME}*" -type f ! -name "*.tar.gz" ! -name "*.zip" | head -1)
        if [[ -n "$found" ]]; then
            src_binary="$found"
            warn "Binary found as '$found' (expected '$src_binary')"
        else
            error "Binary not found after extraction: $src_binary"
        fi
    fi

    chmod +x "$src_binary"

    local dest_binary="${install_dir}/${BINARY_NAME}"
    [[ "$os" == "windows" ]] && dest_binary="${install_dir}/${BINARY_NAME}.exe"

    # Check if we need sudo
    if [[ -w "$install_dir" ]]; then
        mv "$src_binary" "$dest_binary"
    else
        info "Requesting sudo to install to ${install_dir}..."
        sudo mv "$src_binary" "$dest_binary"
        sudo chmod +x "$dest_binary"
    fi

    echo ""
    info "Zypheron ${version} installed to ${dest_binary}"
    info "Run 'zypheron --version' to verify."
    echo ""
}

main "$@"
