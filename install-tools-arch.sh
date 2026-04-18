#!/bin/bash
# Zypheron Security Tools Installer — Arch family
# Run with: sudo bash install-tools-arch.sh
#
# Supported: Arch Linux, Manjaro, EndeavourOS, Garuda, Artix, BlackArch (ID_LIKE=arch).
# Uses pacman for official repos + an AUR helper (paru/yay) for AUR packages.
# If BlackArch repo is enabled, more pentest tools install from binary pacman.
#
# Env overrides:
#   ZYPHERON_INSTALL_LOG=<path>         Log file (default /var/log/zypheron-install.log)
#   ZYPHERON_MIN_FREE_MB=<mb>           Disk preflight (default 3072)
#   ZYPHERON_BUILD_GO=1                 Opt-in: build zypheron-go
#   ZYPHERON_GO_DL_VERSION=<ver>        Go tarball version (default 1.24.2)
#   ZYPHERON_ENABLE_BLACKARCH=1         Enable BlackArch repo for richer tool set
#   ZYPHERON_AUR_HELPER=paru|yay        Preferred AUR helper (default: paru, fallback yay)
#   ZYPHERON_ALLOW_REMOTE_INSTALLERS=1  Allow Rapid7 omnibus for metasploit fallback

set -u
set -o pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

LOG_FILE="${ZYPHERON_INSTALL_LOG:-/var/log/zypheron-install.log}"
MIN_FREE_MB="${ZYPHERON_MIN_FREE_MB:-3072}"
BUILD_GO="${ZYPHERON_BUILD_GO:-0}"
GO_DL_VERSION="${ZYPHERON_GO_DL_VERSION:-1.24.2}"
ENABLE_BLACKARCH="${ZYPHERON_ENABLE_BLACKARCH:-0}"
AUR_HELPER="${ZYPHERON_AUR_HELPER:-}"
ALLOW_REMOTE_INSTALLERS="${ZYPHERON_ALLOW_REMOTE_INSTALLERS:-0}"
NUCLEI_VERSION="${ZYPHERON_NUCLEI_VERSION:-v3.6.2}"
AMASS_VERSION="${ZYPHERON_AMASS_VERSION:-v4.2.0}"
ROPPER_PIP_SPEC="${ZYPHERON_ROPPER_PIP_SPEC:-ropper==1.13.13}"
VOLATILITY3_PIP_SPEC="${ZYPHERON_VOLATILITY3_PIP_SPEC:-volatility3==2.27.0}"
THEHARVESTER_PIP_SPEC="${ZYPHERON_THEHARVESTER_PIP_SPEC:-theHarvester}"
ONE_GADGET_VERSION="${ZYPHERON_ONE_GADGET_VERSION:-1.10.0}"

declare -A RESULTS
declare -a STEP_ORDER

touch "$LOG_FILE" 2>/dev/null || LOG_FILE=/tmp/zypheron-install.log
log()  { printf '[%s] %s\n' "$(date -Is)" "$*" | tee -a "$LOG_FILE" >/dev/null; }
info() { printf '[*] %s\n' "$*"; log "INFO  $*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; log "OK    $*"; }
warn() { printf '  \033[33m[!]\033[0m %s\n' "$*"; log "WARN  $*"; }
err()  { printf '  \033[31m[✗]\033[0m %s\n' "$*"; log "ERROR $*"; }
die()  { err "$*"; exit 1; }
record() {
    local s="$1" st="$2"; RESULTS[$s]="$st"
    [[ ! " ${STEP_ORDER[*]:-} " =~ " $s " ]] && STEP_ORDER+=("$s")
}

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     ZYPHERON SECURITY TOOLS INSTALLER (Arch)              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
log "=== Zypheron arch installer start (pid=$$) ==="

# ─── preflight ──────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash install-tools-arch.sh"
[ -r /etc/os-release ] || die "/etc/os-release missing"
# shellcheck disable=SC1091
. /etc/os-release
DISTRO_ID="${ID:-unknown}"
DISTRO_LIKE="${ID_LIKE:-}"
DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"

is_arch_family() {
    case "$DISTRO_ID" in
        arch|manjaro|endeavouros|garuda|artix|blackarch|cachyos|arcolinux|parabola) return 0 ;;
    esac
    [[ "$DISTRO_LIKE" == *arch* ]]
}

has_blackarch_repo() {
    pacman -Sl blackarch >/dev/null 2>&1
}

is_arch_family || die "Unsupported distro: $DISTRO_NAME. Arch/Manjaro/EndeavourOS/etc required."
info "Detected: $DISTRO_NAME"

for bin in pacman curl git sudo; do
    command -v "$bin" >/dev/null || die "Required binary not found: $bin"
done

# Invoking user (needed for AUR builds — makepkg refuses root)
BUILD_USER="${SUDO_USER:-}"
if [ -z "$BUILD_USER" ] || [ "$BUILD_USER" = "root" ]; then
    # Look for any normal user
    BUILD_USER=$(awk -F: '$3>=1000 && $3<65534 {print $1; exit}' /etc/passwd)
    [ -z "$BUILD_USER" ] && warn "No non-root user found — AUR builds will be unavailable"
fi
BUILD_HOME=$(getent passwd "$BUILD_USER" 2>/dev/null | cut -d: -f6)
[ -n "$BUILD_USER" ] && info "AUR builds will run as: $BUILD_USER"

# Network probe
info "Checking network..."
net_ok=0
for host in github.com archlinux.org aur.archlinux.org; do
    curl -fsSIL --max-time 5 "https://$host" >/dev/null 2>&1 && { net_ok=1; break; }
done
[ $net_ok -eq 1 ] || die "No network reachable"
ok "Network reachable"

# Disk
free_mb=$(df -Pm /usr /var /tmp 2>/dev/null | awk 'NR>1 {print $4}' | sort -n | head -1)
free_mb=${free_mb:-0}
[ "$free_mb" -ge "$MIN_FREE_MB" ] || die "Insufficient disk: ${free_mb}MB < ${MIN_FREE_MB}MB"
ok "Disk OK (${free_mb}MB free)"

# ─── step 1: sync pacman ────────────────────────────────────────────────────
info "[1/11] Syncing pacman databases..."
if pacman -Syy --noconfirm >>"$LOG_FILE" 2>&1; then
    ok "pacman -Syy"
    record pacman-sync ok
else
    warn "pacman sync failed (continuing with stale index)"
    record pacman-sync warn
fi

# ─── step 2: base toolchain + BlackArch repo (optional) ─────────────────────
info "[2/11] Installing base toolchain..."
pacman_install() {
    local step="$1"; shift
    if pacman -S --noconfirm --needed "$@" >>"$LOG_FILE" 2>&1; then
        ok "pacman: $*"
        record "$step" ok
    else
        warn "pacman install failed: $*"
        record "$step" warn
    fi
}

pacman_install base base-devel git curl wget python python-pip ruby go unzip

enable_blackarch() {
    # BlackArch strap.sh SHA256 — verified at time of writing. User must update
    # and re-verify this pin from a trusted source when they want a newer strap.
    # See: https://blackarch.org/downloads.html (strap.sh + published signature).
    # Pinned SHA256 of blackarch.org/strap.sh, verified at release time.
    # If upstream changes legitimately, re-verify against BlackArch's PGP-signed
    # manifest before bumping.
    local EXPECT_SHA256="${ZYPHERON_BLACKARCH_STRAP_SHA256:-58ce783cf584d9000d42f78b51780e0b58fb2d1671abf9bca1f2a486d5368dd4}"
    local tmp rc=1
    tmp=$(mktemp /tmp/strap.sh.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN

    if ! curl -fsSL --max-time 60 https://blackarch.org/strap.sh -o "$tmp"; then
        warn "Could not fetch blackarch/strap.sh"
        record blackarch warn
        return 1
    fi
    local got
    got=$(sha256sum "$tmp" | awk '{print $1}')
    if [ "$got" != "$EXPECT_SHA256" ]; then
        err "BlackArch strap.sh SHA256 mismatch (expect=$EXPECT_SHA256 got=$got)"
        err "If upstream changed legitimately, verify manually and set ZYPHERON_BLACKARCH_STRAP_SHA256"
        record blackarch fail
        return 1
    fi
    ok "BlackArch strap.sh SHA256 verified"
    chmod +x "$tmp"
    if "$tmp" >>"$LOG_FILE" 2>&1; then
        pacman -Syy >>"$LOG_FILE" 2>&1 || true
        ok "BlackArch repo enabled"
        record blackarch ok
        rc=0
    else
        warn "strap.sh execution failed"
        record blackarch warn
    fi
    return $rc
}

if [ "$ENABLE_BLACKARCH" = "1" ] && ! has_blackarch_repo; then
    info "Enabling BlackArch repo (per ZYPHERON_ENABLE_BLACKARCH=1)"
    enable_blackarch || true
fi

# ─── step 3: AUR helper bootstrap ───────────────────────────────────────────
info "[3/11] Ensuring AUR helper..."
pick_aur_helper() {
    for h in "$AUR_HELPER" paru yay; do
        [ -z "$h" ] && continue
        command -v "$h" >/dev/null 2>&1 && { echo "$h"; return 0; }
    done
    return 1
}

# Explicit PATH — never inherit $SUDO_USER's PATH (attacker-controlled shims
# would reach root via makepkg -si's nested sudo back to pacman).
SAFE_USER_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

run_as_build_user() {
    [ -z "$BUILD_USER" ] && return 1
    sudo -u "$BUILD_USER" env HOME="$BUILD_HOME" PATH="$SAFE_USER_PATH" "$@"
}

# Chdir-then-run as user, without `bash -c "cd '...'"`. Uses `env --chdir`.
run_as_build_user_in() {
    local dir="$1"; shift
    [ -z "$BUILD_USER" ] && return 1
    if ! [[ "$dir" =~ ^[A-Za-z0-9._/+=@-]+$ ]]; then
        err "Refusing chdir: unsafe chars in path: $dir"
        return 2
    fi
    sudo -u "$BUILD_USER" env --chdir="$dir" HOME="$BUILD_HOME" PATH="$SAFE_USER_PATH" "$@"
}

AUR_HELPER_BIN=""
if helper=$(pick_aur_helper); then
    AUR_HELPER_BIN="$helper"
    ok "AUR helper present: $helper"
    record aur-helper ok
elif [ -n "$BUILD_USER" ]; then
    info "Bootstrapping paru (AUR helper) via makepkg..."
    tmpd=$(sudo -u "$BUILD_USER" mktemp -d) || tmpd=""
    if [ -n "$tmpd" ] && \
       run_as_build_user git clone https://aur.archlinux.org/paru-bin.git "$tmpd/paru-bin" >>"$LOG_FILE" 2>&1 && \
       run_as_build_user_in "$tmpd/paru-bin" makepkg -si --noconfirm >>"$LOG_FILE" 2>&1; then
        AUR_HELPER_BIN="paru"
        ok "paru installed"
        record aur-helper ok
    else
        warn "AUR helper bootstrap failed — AUR-only tools will be skipped"
        record aur-helper warn
    fi
    [ -n "$tmpd" ] && rm -rf "$tmpd"
else
    warn "No non-root user — cannot bootstrap AUR helper"
    record aur-helper skip
fi

# AUR packages back-sudo to root via makepkg -> pacman -U. PKGBUILDs are
# unvetted community content, so require explicit consent to skip review.
# Default: install with review (interactive) unless ZYPHERON_ALLOW_AUR_SKIPREVIEW=1.
AUR_SKIPREVIEW="${ZYPHERON_ALLOW_AUR_SKIPREVIEW:-0}"

aur_install() {
    local step="$1"; shift
    if [ -z "$AUR_HELPER_BIN" ] || [ -z "$BUILD_USER" ]; then
        warn "AUR install unavailable for: $*"
        record "$step" skip
        return 1
    fi
    local -a opts=(-S --noconfirm --needed)
    if [ "$AUR_SKIPREVIEW" = "1" ]; then
        opts+=(--skipreview)
    else
        warn "AUR install for $*: PKGBUILD review enabled (set ZYPHERON_ALLOW_AUR_SKIPREVIEW=1 to skip)"
    fi
    if run_as_build_user "$AUR_HELPER_BIN" "${opts[@]}" "$@" >>"$LOG_FILE" 2>&1; then
        ok "AUR: $*"
        record "$step" ok
    else
        warn "AUR install failed: $*"
        record "$step" warn
        return 1
    fi
}

# ─── step 4: core pentest pacman packages ───────────────────────────────────
info "[4/11] Installing core pentest tools (pacman)..."
pacman_install core-pentest hydra john nmap

# ─── step 5: theHarvester ───────────────────────────────────────────────────
info "[5/11] Installing theHarvester..."
if pacman -Si theharvester >/dev/null 2>&1; then
    pacman_install theharvester theharvester
elif has_blackarch_repo && pacman -Si theharvester-git >/dev/null 2>&1; then
    pacman_install theharvester theharvester-git
elif aur_install theharvester theharvester; then
    :
else
    info "Falling back to pip for theHarvester"
    if pip install --break-system-packages --quiet "$THEHARVESTER_PIP_SPEC" >>"$LOG_FILE" 2>&1 \
       || pip install --quiet "$THEHARVESTER_PIP_SPEC" >>"$LOG_FILE" 2>&1; then
        ok "theHarvester (pip)"
        record theharvester ok
    else
        warn "theHarvester install failed"
        record theharvester warn
    fi
fi

# ─── step 6: nuclei ─────────────────────────────────────────────────────────
info "[6/11] Installing Nuclei..."
if command -v nuclei >/dev/null 2>&1; then
    ok "Nuclei already installed"
    record nuclei ok
elif has_blackarch_repo && pacman -Si nuclei >/dev/null 2>&1; then
    pacman_install nuclei nuclei
elif command -v go >/dev/null 2>&1; then
    if GOBIN=/usr/local/bin go install -v "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}" >>"$LOG_FILE" 2>&1; then
        ok "Nuclei (go install ${NUCLEI_VERSION})"
        record nuclei ok
    else
        warn "go install nuclei failed"
        record nuclei warn
    fi
else
    warn "Go unavailable — nuclei skipped"
    record nuclei skip
fi

# ─── step 7: amass ──────────────────────────────────────────────────────────
info "[7/11] Installing Amass..."
if command -v amass >/dev/null 2>&1; then
    ok "Amass already installed"
    record amass ok
elif has_blackarch_repo && pacman -Si amass >/dev/null 2>&1; then
    pacman_install amass amass
elif aur_install amass amass; then
    :
elif command -v go >/dev/null 2>&1 && GOBIN=/usr/local/bin go install -v "github.com/owasp-amass/amass/v4/...@${AMASS_VERSION}" >>"$LOG_FILE" 2>&1; then
    ok "Amass (go install ${AMASS_VERSION})"
    record amass ok
else
    warn "Amass unavailable"
    record amass warn
fi

# ─── step 8: metasploit ─────────────────────────────────────────────────────
info "[8/11] Installing Metasploit..."
if command -v msfconsole >/dev/null 2>&1; then
    ok "Metasploit already installed"
    record metasploit ok
elif has_blackarch_repo && pacman -Si metasploit >/dev/null 2>&1; then
    pacman_install metasploit metasploit
elif aur_install metasploit metasploit; then
    :
elif [ "$ALLOW_REMOTE_INSTALLERS" = "1" ]; then
    # Pinned commit (+ optional sha256) — never fetch master branch.
    MSF_COMMIT="${ZYPHERON_MSF_COMMIT:-96f5f937d52ea95bc05d39b7859e8592a91f8a2d}"
    MSF_SHA256="${ZYPHERON_MSF_SHA256:-d12fea4d1339ebecb09d8cc36920d9f5e5e7e9fffbe092b1e1cd09255cc16825}"
    MSF_URL="https://raw.githubusercontent.com/rapid7/metasploit-omnibus/${MSF_COMMIT}/config/templates/metasploit-framework-wrappers/msfupdate.erb"
    install_msf_omnibus() {
        local tmp rc=1
        tmp=$(mktemp /tmp/msfinstall.XXXXXX) || return 1
        # shellcheck disable=SC2064
        trap "rm -f '$tmp'" RETURN
        curl -fsSL --max-time 60 "$MSF_URL" -o "$tmp" || { warn "msf download failed"; return 1; }
        if [ -n "$MSF_SHA256" ]; then
            local got; got=$(sha256sum "$tmp" | awk '{print $1}')
            [ "$got" = "$MSF_SHA256" ] || { err "msf SHA256 mismatch"; return 1; }
            ok "msf omnibus SHA256 verified"
        else
            warn "ZYPHERON_MSF_SHA256 not set — proceeding with commit-pin only"
        fi
        chmod 755 "$tmp" && "$tmp" >>"$LOG_FILE" 2>&1 && rc=0
        return $rc
    }
    if install_msf_omnibus; then
        ok "Metasploit (omnibus, commit $MSF_COMMIT)"
        record metasploit ok
    else
        warn "Metasploit omnibus failed"
        record metasploit warn
    fi
else
    warn "Metasploit unavailable. Enable BlackArch (ZYPHERON_ENABLE_BLACKARCH=1), set ZYPHERON_ALLOW_REMOTE_INSTALLERS=1, or install via AUR manually"
    record metasploit skip
fi

# ─── step 9: python + ruby tools ────────────────────────────────────────────
info "[9/11] Installing Python tools (ropper, volatility3)..."
if pip install --break-system-packages --quiet "$ROPPER_PIP_SPEC" "$VOLATILITY3_PIP_SPEC" >>"$LOG_FILE" 2>&1 \
   || pip install --quiet "$ROPPER_PIP_SPEC" "$VOLATILITY3_PIP_SPEC" >>"$LOG_FILE" 2>&1; then
    ok "ropper, volatility3"
    record python-tools ok
else
    warn "pip install failed"
    record python-tools warn
fi

info "Installing Ruby tools (one_gadget)..."
if command -v gem >/dev/null 2>&1 && gem install one_gadget -v "$ONE_GADGET_VERSION" >>"$LOG_FILE" 2>&1; then
    ok "one_gadget"
    record one_gadget ok
else
    warn "one_gadget install failed"
    record one_gadget warn
fi

# ─── step 10: ghidra + wordlists ────────────────────────────────────────────
info "[10/11] Ghidra + wordlists..."
if command -v ghidra >/dev/null 2>&1 || [ -d /opt/ghidra ] || ls /opt/ghidra_* >/dev/null 2>&1; then
    ok "Ghidra available"
    record ghidra ok
elif pacman -Si ghidra >/dev/null 2>&1; then
    pacman_install ghidra ghidra
else
    warn "Ghidra not in repos. Download: https://github.com/NationalSecurityAgency/ghidra/releases"
    record ghidra skip
fi

mkdir -p /usr/share/wordlists
SECLISTS_DIR=""
for cand in /usr/share/seclists /usr/share/wordlists/seclists /usr/share/wordlists/SecLists; do
    [ -d "$cand" ] && { SECLISTS_DIR="$cand"; break; }
done
if [ -z "$SECLISTS_DIR" ]; then
    if has_blackarch_repo && pacman -Si seclists >/dev/null 2>&1 && pacman -S --noconfirm --needed seclists >>"$LOG_FILE" 2>&1; then
        SECLISTS_DIR=/usr/share/seclists
    elif aur_install seclists seclists; then
        SECLISTS_DIR=/usr/share/seclists
    else
        info "Cloning SecLists (~1GB)..."
        if git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists >>"$LOG_FILE" 2>&1; then
            SECLISTS_DIR=/usr/share/seclists
        else
            warn "SecLists clone failed"
        fi
    fi
fi
if [ -n "$SECLISTS_DIR" ]; then
    ln -sf "$SECLISTS_DIR/Discovery/Web-Content/common.txt" /usr/share/wordlists/common.txt 2>/dev/null || true
    ln -sf "$SECLISTS_DIR/Discovery/Web-Content/directory-list-2.3-medium.txt" /usr/share/wordlists/dirb-medium.txt 2>/dev/null || true
    ok "SecLists at $SECLISTS_DIR"
    record wordlists ok
else
    record wordlists warn
fi

# ─── step 11: zypheron-go build (opt-in) ────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_SRC=""
for cand in "$SCRIPT_DIR/zypheron-go" "$PWD/zypheron-go" "$SCRIPT_DIR/../zypheron-go"; do
    [ -f "$cand/go.mod" ] && { GO_SRC="$cand"; break; }
done

install_go_tarball() {
    local ver="$1" arch tar_url tmp
    case "$(uname -m)" in
        x86_64|amd64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        armv7l|armv6l) arch=armv6l ;;
        i386|i686) arch=386 ;;
        *) return 1 ;;
    esac
    tar_url="https://go.dev/dl/go${ver}.linux-${arch}.tar.gz"
    tmp=$(mktemp /tmp/go-dl.XXXXXX.tar.gz) || return 1
    trap 'rm -f "$tmp"' RETURN
    curl -fsSL --max-time 300 "$tar_url" -o "$tmp" || { warn "Go download failed"; return 1; }
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$tmp" && export PATH="/usr/local/go/bin:$PATH"
}

check_go_ver() {
    command -v go >/dev/null 2>&1 || return 1
    local gv maj min
    gv=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
    maj=$(echo "$gv" | cut -d. -f1); min=$(echo "$gv" | cut -d. -f2)
    [[ "$maj" =~ ^[0-9]+$ ]] || maj=0
    [[ "$min" =~ ^[0-9]+$ ]] || min=0
    [ "$maj" -gt 1 ] || { [ "$maj" -eq 1 ] && [ "$min" -ge 24 ]; }
}

if [ -z "$GO_SRC" ]; then
    info "[11/11] zypheron-go source not found — skipping build"
    record go-build skip
elif [ "$BUILD_GO" != "1" ]; then
    warn "[11/11] zypheron-go at $GO_SRC — rerun with ZYPHERON_BUILD_GO=1 to build"
    record go-build skip
else
    info "[11/11] Building zypheron-go at $GO_SRC ..."
    go_ok=0
    if check_go_ver; then
        go_ok=1
    else
        pacman -S --noconfirm --needed go >>"$LOG_FILE" 2>&1 || true
        check_go_ver && go_ok=1
    fi
    if [ $go_ok -eq 0 ]; then
        warn "pacman go version <1.24 — fetching tarball ${GO_DL_VERSION}"
        install_go_tarball "$GO_DL_VERSION" && check_go_ver && go_ok=1
    fi
    if [ $go_ok -eq 1 ]; then
        if ! [[ "$GO_SRC" =~ ^[A-Za-z0-9._/+=@-]+$ ]]; then
            err "Refusing to build: unsafe chars in GO_SRC: $GO_SRC"
            record go-build fail
            exit 3
        fi
        SAFE_PATH="/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        run_in_src() {
            if [ -n "$BUILD_USER" ] && [ "$BUILD_USER" != "root" ]; then
                sudo -u "$BUILD_USER" \
                    env --chdir="$GO_SRC" HOME="$BUILD_HOME" PATH="$SAFE_PATH" \
                    GOPRIVATE="${GOPRIVATE:-}" GOPROXY="${GOPROXY:-}" \
                    "$@"
            else
                env --chdir="$GO_SRC" HOME="${BUILD_HOME:-/root}" PATH="$SAFE_PATH" \
                    GOPRIVATE="${GOPRIVATE:-}" GOPROXY="${GOPROXY:-}" \
                    "$@"
            fi
        }
        mod_path=$(awk '/^module /{print $2; exit}' "$GO_SRC/go.mod")
        [[ "$mod_path" == github.com/KKingZero/* ]] && [ -z "${GOPRIVATE:-}" ] && \
            export GOPRIVATE="github.com/KKingZero/*"

        if run_in_src go mod download >>"$LOG_FILE" 2>&1; then
            run_in_src go mod tidy >>"$LOG_FILE" 2>&1 || true
            if run_in_src go build ./... >>"$LOG_FILE" 2>&1; then
                ok "zypheron-go built"
                record go-build ok
            else
                err "go build failed"
                record go-build fail
            fi
        else
            warn "go mod download failed"
            record go-build fail
        fi
    else
        warn "Go >=1.24 unavailable — skipping build"
        record go-build skip
    fi
fi

# ─── verification ───────────────────────────────────────────────────────────
echo ""
info "Verifying installed tools..."
declare -A TOOL_CHECK=(
    [hydra]=hydra [john]=john [theHarvester]=theHarvester
    [nuclei]=nuclei [amass]=amass [msfconsole]=msfconsole
    [ropper]=ropper [volatility3]=vol [one_gadget]=one_gadget
)
verified=0; verified_fail=0
for n in "${!TOOL_CHECK[@]}"; do
    if command -v "${TOOL_CHECK[$n]}" >/dev/null 2>&1; then
        ok "$n"; verified=$((verified+1))
    else
        warn "$n not on PATH"; verified_fail=$((verified_fail+1))
    fi
done

# ─── summary ────────────────────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     INSTALLATION SUMMARY                                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
fail_count=0; warn_count=0; ok_count=0
for step in "${STEP_ORDER[@]}"; do
    case "${RESULTS[$step]}" in
        ok)   printf '  \033[32m✓\033[0m %-20s ok\n' "$step"; ok_count=$((ok_count+1)) ;;
        warn) printf '  \033[33m!\033[0m %-20s warn\n' "$step"; warn_count=$((warn_count+1)) ;;
        fail) printf '  \033[31m✗\033[0m %-20s FAIL\n' "$step"; fail_count=$((fail_count+1)) ;;
        skip) printf '  \033[90m·\033[0m %-20s skip\n' "$step" ;;
    esac
done
echo ""
echo "  Verified on PATH: $verified  |  Missing: $verified_fail"
echo "  Log: $LOG_FILE"
echo ""
log "=== end (ok=$ok_count warn=$warn_count fail=$fail_count) ==="

[ $fail_count -gt 0 ] && exit 1
[ "$verified" -lt 3 ] && { err "Fewer than 3 core tools verified"; exit 2; }
exit 0
