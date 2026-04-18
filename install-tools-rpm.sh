#!/bin/bash
# Zypheron Security Tools Installer — RedHat family
# Run with: sudo bash install-tools-rpm.sh
#
# Supported: Fedora, RHEL 8+, CentOS Stream, Rocky, AlmaLinux, Oracle Linux,
# Amazon Linux 2023 (ID_LIKE=rhel / fedora). EPEL enabled automatically on RHEL-likes.
#
# Env overrides match install-tools.sh:
#   ZYPHERON_INSTALL_LOG, ZYPHERON_MIN_FREE_MB, ZYPHERON_ALLOW_REMOTE_INSTALLERS,
#   ZYPHERON_BUILD_GO, ZYPHERON_GO_DL_VERSION, ZYPHERON_NUCLEI_VERSION,
#   ZYPHERON_AMASS_VERSION, ZYPHERON_ROPPER_PIP_SPEC, ZYPHERON_VOLATILITY3_PIP_SPEC,
#   ZYPHERON_THEHARVESTER_PIP_SPEC, ZYPHERON_ONE_GADGET_VERSION

set -u
set -o pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

LOG_FILE="${ZYPHERON_INSTALL_LOG:-/var/log/zypheron-install.log}"
MIN_FREE_MB="${ZYPHERON_MIN_FREE_MB:-3072}"
ALLOW_REMOTE_INSTALLERS="${ZYPHERON_ALLOW_REMOTE_INSTALLERS:-0}"
BUILD_GO="${ZYPHERON_BUILD_GO:-0}"
GO_DL_VERSION="${ZYPHERON_GO_DL_VERSION:-1.24.2}"
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
echo "║     ZYPHERON SECURITY TOOLS INSTALLER (RedHat)            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
log "=== Zypheron rpm installer start (pid=$$) ==="

# ─── preflight ──────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash install-tools-rpm.sh"
[ -r /etc/os-release ] || die "/etc/os-release missing"
# shellcheck disable=SC1091
. /etc/os-release
DISTRO_ID="${ID:-unknown}"
DISTRO_LIKE="${ID_LIKE:-}"
DISTRO_VER="${VERSION_ID:-unknown}"
DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID $DISTRO_VER}"

is_redhat_family() {
    case "$DISTRO_ID" in
        rhel|fedora|centos|rocky|almalinux|ol|amzn|scientific) return 0 ;;
    esac
    [[ "$DISTRO_LIKE" == *rhel* || "$DISTRO_LIKE" == *fedora* ]]
}

is_rhel_like() {
    # RHEL-lineage that needs EPEL (not Fedora, which has most pkgs native)
    [[ "$DISTRO_ID" =~ ^(rhel|centos|rocky|almalinux|ol|scientific)$ ]]
}

is_fedora() { [[ "$DISTRO_ID" == "fedora" ]]; }

is_redhat_family || die "Unsupported distro: $DISTRO_NAME"
info "Detected: $DISTRO_NAME"

# Prefer dnf, fall back to yum
PKG_MGR=""
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR=dnf
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR=yum
else
    die "Neither dnf nor yum found"
fi
info "Using package manager: $PKG_MGR"

for bin in curl git; do
    command -v "$bin" >/dev/null || $PKG_MGR install -y "$bin" >>"$LOG_FILE" 2>&1 || die "Missing required: $bin"
done

# Network
info "Checking network..."
net_ok=0
for host in github.com mirrors.fedoraproject.org dl.fedoraproject.org; do
    curl -fsSIL --max-time 5 "https://$host" >/dev/null 2>&1 && { net_ok=1; break; }
done
[ $net_ok -eq 1 ] || die "No network reachable"
ok "Network reachable"

# Disk
free_mb=$(df -Pm /usr /var /tmp 2>/dev/null | awk 'NR>1 {print $4}' | sort -n | head -1)
free_mb=${free_mb:-0}
[ "$free_mb" -ge "$MIN_FREE_MB" ] || die "Insufficient disk: ${free_mb}MB < ${MIN_FREE_MB}MB"
ok "Disk OK (${free_mb}MB free)"

DNF_OPTS=(-y --setopt=install_weak_deps=False)

rpm_install() {
    local step="$1"; shift
    local -a available=() missing=()
    for pkg in "$@"; do
        if $PKG_MGR list --available "$pkg" >/dev/null 2>&1 \
           || $PKG_MGR list --installed "$pkg" >/dev/null 2>&1; then
            available+=("$pkg")
        else
            missing+=("$pkg")
        fi
    done
    if [ ${#available[@]} -gt 0 ]; then
        if $PKG_MGR install "${DNF_OPTS[@]}" "${available[@]}" >>"$LOG_FILE" 2>&1; then
            ok "$PKG_MGR: ${available[*]}"
        else
            err "$PKG_MGR install failed: ${available[*]}"
            record "$step" fail
            return 1
        fi
    fi
    if [ ${#missing[@]} -gt 0 ]; then
        warn "not available: ${missing[*]}"
        [ ${#available[@]} -eq 0 ] && { record "$step" warn; return 0; }
    fi
    record "$step" ok
}

ensure_pip3() {
    command -v pip3 >/dev/null 2>&1 && return 0
    rpm_install python3-pip python3-pip >/dev/null 2>&1 || true
    command -v pip3 >/dev/null 2>&1
}

# ─── step 1: sync + enable EPEL ─────────────────────────────────────────────
info "[1/10] Syncing $PKG_MGR metadata..."
$PKG_MGR makecache -y >>"$LOG_FILE" 2>&1 || warn "$PKG_MGR makecache had issues"
record pkg-sync ok

if is_rhel_like; then
    info "Enabling EPEL repo..."
    if ! rpm -q epel-release >/dev/null 2>&1; then
        # Major version from VERSION_ID (e.g. "9.3" → "9")
        major="${DISTRO_VER%%.*}"
        EPEL_URL="https://dl.fedoraproject.org/pub/epel/epel-release-latest-${major}.noarch.rpm"
        if $PKG_MGR install -y "$EPEL_URL" >>"$LOG_FILE" 2>&1; then
            ok "EPEL enabled"
            record epel ok
        else
            warn "EPEL enable failed — some pkgs will be missing"
            record epel warn
        fi
    else
        ok "EPEL already enabled"
        record epel ok
    fi

    # RHEL-likes also need CRB/PowerTools for devel headers
    if command -v dnf >/dev/null 2>&1; then
        dnf config-manager --set-enabled crb >>"$LOG_FILE" 2>&1 || \
        dnf config-manager --set-enabled powertools >>"$LOG_FILE" 2>&1 || true
    fi
fi

# ─── step 2: base toolchain ─────────────────────────────────────────────────
info "[2/10] Installing base toolchain..."
# dnf group "Development Tools" gives gcc/make etc. Also python3, ruby, go.
$PKG_MGR groupinstall -y "Development Tools" >>"$LOG_FILE" 2>&1 || \
    warn "groupinstall 'Development Tools' not available — continuing"

rpm_install base git curl wget python3 python3-pip ruby ruby-devel golang \
    openssl-devel libffi-devel which tar unzip

# ─── step 3: core pentest pkgs ──────────────────────────────────────────────
info "[3/10] Installing core pentest pkgs..."
# nmap in base. hydra/john in EPEL on RHEL, native in Fedora.
rpm_install core-pentest hydra john-the-ripper nmap || true

# ─── step 4: theHarvester ───────────────────────────────────────────────────
info "[4/10] Installing theHarvester..."
if $PKG_MGR list --available theHarvester >/dev/null 2>&1; then
    rpm_install theharvester theHarvester
else
    info "theHarvester not in repos — installing via pip"
    if ensure_pip3 && pip3 install --quiet --break-system-packages "$THEHARVESTER_PIP_SPEC" >>"$LOG_FILE" 2>&1 \
       || pip3 install --quiet "$THEHARVESTER_PIP_SPEC" >>"$LOG_FILE" 2>&1; then
        ok "theHarvester (pip)"
        record theharvester ok
    else
        warn "theHarvester install failed"
        record theharvester warn
    fi
fi

# ─── step 5: nuclei ─────────────────────────────────────────────────────────
info "[5/10] Installing Nuclei..."
if command -v nuclei >/dev/null 2>&1; then
    ok "Nuclei already installed"
    record nuclei ok
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

# ─── step 6: amass ──────────────────────────────────────────────────────────
info "[6/10] Installing Amass..."
if command -v amass >/dev/null 2>&1; then
    ok "Amass already installed"
    record amass ok
elif command -v go >/dev/null 2>&1 && GOBIN=/usr/local/bin go install -v "github.com/owasp-amass/amass/v4/...@${AMASS_VERSION}" >>"$LOG_FILE" 2>&1; then
    ok "Amass (go install ${AMASS_VERSION})"
    record amass ok
else
    warn "Amass unavailable"
    record amass warn
fi

# ─── step 7: metasploit ─────────────────────────────────────────────────────
info "[7/10] Installing Metasploit..."
if command -v msfconsole >/dev/null 2>&1; then
    ok "Metasploit already installed"
    record metasploit ok
elif [ "$ALLOW_REMOTE_INSTALLERS" = "1" ]; then
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
    warn "Metasploit not in RPM repos. Set ZYPHERON_ALLOW_REMOTE_INSTALLERS=1 for Rapid7 omnibus (commit+sha256 pinned)."
    record metasploit skip
fi

# ─── step 8: python + ruby tools ────────────────────────────────────────────
info "[8/10] Installing Python tools (ropper, volatility3)..."
if ensure_pip3 && pip3 install --quiet --break-system-packages "$ROPPER_PIP_SPEC" "$VOLATILITY3_PIP_SPEC" >>"$LOG_FILE" 2>&1 \
   || pip3 install --quiet "$ROPPER_PIP_SPEC" "$VOLATILITY3_PIP_SPEC" >>"$LOG_FILE" 2>&1; then
    ok "ropper, volatility3"
    record python-tools ok
else
    warn "pip install failed"
    record python-tools warn
fi

info "Installing Ruby tools (one_gadget)..."
if ! command -v gem >/dev/null 2>&1; then
    rpm_install ruby ruby ruby-devel >/dev/null 2>&1 || true
fi
if command -v gem >/dev/null 2>&1 && gem install one_gadget -v "$ONE_GADGET_VERSION" >>"$LOG_FILE" 2>&1; then
    ok "one_gadget"
    record one_gadget ok
else
    warn "one_gadget install failed"
    record one_gadget warn
fi

# ─── step 9: ghidra + wordlists ─────────────────────────────────────────────
info "[9/10] Ghidra + wordlists..."
if command -v ghidra >/dev/null 2>&1 || [ -d /opt/ghidra ] || ls /opt/ghidra_* >/dev/null 2>&1; then
    ok "Ghidra available"
    record ghidra ok
elif is_fedora && $PKG_MGR list --available ghidra >/dev/null 2>&1; then
    rpm_install ghidra ghidra
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
    info "Cloning SecLists (~1GB)..."
    if git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists >>"$LOG_FILE" 2>&1; then
        SECLISTS_DIR=/usr/share/seclists
    else
        warn "SecLists clone failed"
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

# ─── step 10: zypheron-go build (opt-in) ────────────────────────────────────
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
    info "[10/10] zypheron-go source not found — skipping build"
    record go-build skip
elif [ "$BUILD_GO" != "1" ]; then
    warn "[10/10] zypheron-go at $GO_SRC — rerun with ZYPHERON_BUILD_GO=1 to build"
    record go-build skip
else
    info "[10/10] Building zypheron-go at $GO_SRC ..."
    go_ok=0
    check_go_ver && go_ok=1
    if [ $go_ok -eq 0 ]; then
        rpm_install golang golang >/dev/null 2>&1 || true
        check_go_ver && go_ok=1
    fi
    if [ $go_ok -eq 0 ]; then
        warn "rpm go version <1.24 — fetching tarball ${GO_DL_VERSION}"
        install_go_tarball "$GO_DL_VERSION" && check_go_ver && go_ok=1
    fi
    if [ $go_ok -eq 1 ]; then
        BUILD_USER="${SUDO_USER:-root}"
        BUILD_HOME=$(getent passwd "$BUILD_USER" 2>/dev/null | cut -d: -f6)
        [ -z "$BUILD_HOME" ] && BUILD_HOME="/root"
        if ! [[ "$GO_SRC" =~ ^[A-Za-z0-9._/+=@-]+$ ]]; then
            err "Refusing to build: unsafe chars in GO_SRC: $GO_SRC"
            record go-build fail
            exit 3
        fi
        SAFE_PATH="/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        run_in_src() {
            if [ "$BUILD_USER" = "root" ]; then
                env --chdir="$GO_SRC" HOME="$BUILD_HOME" PATH="$SAFE_PATH" \
                    GOPRIVATE="${GOPRIVATE:-}" GOPROXY="${GOPROXY:-}" \
                    "$@"
            else
                sudo -u "$BUILD_USER" \
                    env --chdir="$GO_SRC" HOME="$BUILD_HOME" PATH="$SAFE_PATH" \
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
