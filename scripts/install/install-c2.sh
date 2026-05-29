#!/bin/bash
# Optional Zypheron C2 framework installer.
# Run only when you explicitly want C2 tooling:
#   sudo bash scripts/install/install-c2.sh

set -u
set -o pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

LOG_FILE="${ZYPHERON_C2_INSTALL_LOG:-/var/log/zypheron-install-c2.log}"
ASSUME_YES="${ZYPHERON_ASSUME_YES:-0}"
EMPIRE_DIR="${ZYPHERON_EMPIRE_DIR:-/opt/Empire}"

touch "$LOG_FILE" 2>/dev/null || LOG_FILE=/tmp/zypheron-install-c2.log
log()  { printf '[%s] %s\n' "$(date -Is)" "$*" | tee -a "$LOG_FILE" >/dev/null; }
info() { printf '[*] %s\n' "$*"; log "INFO  $*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; log "OK    $*"; }
warn() { printf '  \033[33m[!]\033[0m %s\n' "$*"; log "WARN  $*"; }
err()  { printf '  \033[31m[✗]\033[0m %s\n' "$*"; log "ERROR $*"; }
die()  { err "$*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash scripts/install/install-c2.sh"

ask_yes() {
    local prompt="$1"
    if [ "$ASSUME_YES" = "1" ]; then
        return 0
    fi
    local answer
    read -r -p "$prompt [y/N] " answer
    case "$answer" in
        y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

apt_install_if_available() {
    local pkg="$1"
    if ! command -v apt-get >/dev/null 2>&1 || ! apt-cache show "$pkg" >/dev/null 2>&1; then
        return 1
    fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o=Dpkg::Use-Pty=0 "$pkg" >>"$LOG_FILE" 2>&1
}

# Sliver install strategy:
#   1. Kali/Parrot apt `sliver` pkg (distro-signed) — preferred when available.
#   2. Pinned GitHub release tarball with SHA256 verification.
#   3. Upstream `curl | bash` only with explicit ZYPHERON_ALLOW_UNVERIFIED_SLIVER=1
#      opt-in (prints loud warning).
# Update SLIVER_VERSION + SLIVER_SHA256_AMD64/ARM64 when bumping. Hashes below
# were verified at time of writing against BishopFox/sliver GitHub releases.
SLIVER_VERSION="${ZYPHERON_SLIVER_VERSION:-v1.7.3}"
# SHA256 of sliver-server_<os>-<arch> binaries from BishopFox/sliver GitHub
# releases. Verified at release time. Bump in lockstep with SLIVER_VERSION.
SLIVER_SHA256_AMD64="${ZYPHERON_SLIVER_SHA256_AMD64:-e3216ecd12f6e7e97cb4588bb6d85c70eca3bdfad8b0818ffd53ccb2e357ccc8}"
SLIVER_SHA256_ARM64="${ZYPHERON_SLIVER_SHA256_ARM64:-69b9b9ec58a030416750cf0ec1a6a67d01044ee0f2172599049cc8d43a982447}"

install_sliver_release_binary() {
    local arch hashvar url tmp got
    case "$(uname -m)" in
        x86_64|amd64) arch=amd64; hashvar="$SLIVER_SHA256_AMD64" ;;
        aarch64|arm64) arch=arm64; hashvar="$SLIVER_SHA256_ARM64" ;;
        *) warn "Unsupported arch for Sliver: $(uname -m)"; return 1 ;;
    esac
    if [ -z "$hashvar" ]; then
        warn "No SHA256 pin for Sliver ${arch}. Set ZYPHERON_SLIVER_SHA256_${arch^^} to enable verified release install."
        return 1
    fi
    # Asset naming since v1.7.x: sliver-server_linux-<arch>
    url="https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}/sliver-server_linux-${arch}"
    tmp=$(mktemp /tmp/sliver-dl.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN
    info "Downloading Sliver ${SLIVER_VERSION} (${arch}) from GitHub releases..."
    curl -fsSL --max-time 300 "$url" -o "$tmp" || { warn "Sliver download failed ($url)"; return 1; }
    got=$(sha256sum "$tmp" | awk '{print $1}')
    if [ "$got" != "$hashvar" ]; then
        err "Sliver SHA256 mismatch (expect=$hashvar got=$got)"
        return 1
    fi
    ok "Sliver server SHA256 verified"
    install -m 0755 -o root -g root "$tmp" /usr/local/bin/sliver-server
    # Also install client binary (best-effort; not fatal if missing)
    url="https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}/sliver-client_linux-${arch}"
    if curl -fsSL --max-time 300 "$url" -o "$tmp" 2>/dev/null; then
        install -m 0755 -o root -g root "$tmp" /usr/local/bin/sliver-client
        ok "Sliver client installed"
    fi
    return 0
}

install_sliver() {
    if command -v sliver-server >/dev/null 2>&1 || command -v sliver >/dev/null 2>&1; then
        ok "Sliver already installed"
        return 0
    fi

    # 1. apt (Kali/Parrot have signed sliver pkg)
    if apt_install_if_available sliver; then
        ok "Sliver installed from apt"
        return 0
    fi

    # 2. Verified GitHub release
    if install_sliver_release_binary; then
        ok "Sliver ${SLIVER_VERSION} installed from verified release"
        return 0
    fi

    # 3. Upstream curl|bash — only with explicit opt-in
    if [ "${ZYPHERON_ALLOW_UNVERIFIED_SLIVER:-0}" = "1" ]; then
        warn "Using UNVERIFIED upstream installer: https://sliver.sh/install"
        warn "This runs a remote script as root with no integrity checks."
        if curl -fsSL https://sliver.sh/install | bash >>"$LOG_FILE" 2>&1; then
            ok "Sliver installed (unverified)"
            return 0
        fi
        warn "Sliver install failed. See $LOG_FILE"
        return 1
    fi

    err "Sliver install skipped: no verified path available."
    err "  Options:"
    err "    - Install from Kali/Parrot apt (re-run this script on that distro)"
    err "    - Pin a release: set ZYPHERON_SLIVER_VERSION and ZYPHERON_SLIVER_SHA256_<AMD64|ARM64>"
    err "    - Accept upstream curl|bash risk: set ZYPHERON_ALLOW_UNVERIFIED_SLIVER=1"
    return 1
}

# Validate EMPIRE_DIR against path-traversal + require either non-existent or
# a clean BC-SECURITY/Empire clone. Prevents env-override pointing at a
# pre-populated malicious setup/install.sh.
validate_empire_dir() {
    local d="$1" real
    if ! [[ "$d" =~ ^/[A-Za-z0-9._/+=@-]+$ ]]; then
        err "Refusing unsafe EMPIRE_DIR: $d"
        return 1
    fi
    if [ -e "$d" ]; then
        real=$(realpath -m "$d" 2>/dev/null || echo "$d")
        # Require existing dir to be a BC-SECURITY/Empire git checkout.
        if [ ! -d "$d/.git" ]; then
            err "EMPIRE_DIR exists but is not a git checkout: $d"
            err "Refusing to run setup/install.sh from an untrusted tree."
            return 1
        fi
        local origin
        origin=$(git -C "$d" config --get remote.origin.url 2>/dev/null || echo "")
        if [[ "$origin" != *BC-SECURITY/Empire* ]]; then
            err "EMPIRE_DIR git origin is not BC-SECURITY/Empire: $origin"
            return 1
        fi
    fi
    return 0
}

install_empire() {
    if command -v empire >/dev/null 2>&1 || command -v empire-server >/dev/null 2>&1; then
        ok "Empire already installed"
        return 0
    fi

    info "Trying Empire from Kali/Parrot apt package: powershell-empire"
    if apt_install_if_available powershell-empire; then
        ok "Empire installed from apt"
        return 0
    fi

    warn "powershell-empire was not available via apt"
    if ! ask_yes "Clone Empire to $EMPIRE_DIR and run ./setup/install.sh?"; then
        warn "Empire git fallback skipped"
        return 0
    fi

    validate_empire_dir "$EMPIRE_DIR" || return 1

    command -v git >/dev/null 2>&1 || apt_install_if_available git || die "git is required for Empire fallback"
    if [ ! -d "$EMPIRE_DIR/.git" ]; then
        git clone --depth 1 https://github.com/BC-SECURITY/Empire.git "$EMPIRE_DIR" >>"$LOG_FILE" 2>&1 || {
            warn "Empire clone failed. See $LOG_FILE"
            return 1
        }
    else
        info "Empire checkout already exists at $EMPIRE_DIR"
    fi

    # Re-validate after clone (defense-in-depth) before executing setup.
    validate_empire_dir "$EMPIRE_DIR" || return 1

    if [ -x "$EMPIRE_DIR/setup/install.sh" ]; then
        (cd "$EMPIRE_DIR" && ./setup/install.sh) >>"$LOG_FILE" 2>&1 && {
            ok "Empire installed from git fallback"
            return 0
        }
    fi
    warn "Empire setup failed or setup/install.sh was missing. See $LOG_FILE"
    return 1
}

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     ZYPHERON OPTIONAL C2 INSTALLER                       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
warn "Only install C2 frameworks on systems and networks you are authorized to operate."
warn "Havoc is intentionally not installed by this script."
echo ""

failures=0
if ask_yes "Install Sliver C2?"; then
    install_sliver || failures=$((failures+1))
else
    warn "Sliver skipped"
fi

if ask_yes "Install Empire C2?"; then
    install_empire || failures=$((failures+1))
else
    warn "Empire skipped"
fi

echo ""
echo "Log: $LOG_FILE"
if [ "$failures" -gt 0 ]; then
    err "$failures C2 install step(s) failed"
    exit 1
fi
ok "Optional C2 installer complete"
exit 0
