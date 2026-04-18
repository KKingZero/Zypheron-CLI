#!/bin/bash
# Zypheron Security Tools Installer
# Run with: sudo bash install-tools.sh
#
# Supported: Debian 11+, Ubuntu 20.04+, Kali, Parrot, Linux Mint, Pop!_OS,
# elementary OS, and other Debian-family distros (ID_LIKE=debian).
# Arch/RedHat support planned (see install-tools-arch.sh / install-tools-rpm.sh).

set -u
set -o pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

LOG_FILE="${ZYPHERON_INSTALL_LOG:-/var/log/zypheron-install.log}"
MIN_FREE_MB="${ZYPHERON_MIN_FREE_MB:-3072}"  # ~3GB (SecLists + msf + go bin)
ASSUME_YES="${ZYPHERON_ASSUME_YES:-0}"
ALLOW_REMOTE_INSTALLERS="${ZYPHERON_ALLOW_REMOTE_INSTALLERS:-0}"
BUILD_GO="${ZYPHERON_BUILD_GO:-0}"                 # opt-in: build zypheron-go Go CLI
GO_DL_VERSION="${ZYPHERON_GO_DL_VERSION:-1.24.2}"  # official go.dev tarball fallback
NUCLEI_VERSION="${ZYPHERON_NUCLEI_VERSION:-v3.6.2}"
AMASS_VERSION="${ZYPHERON_AMASS_VERSION:-v4.2.0}"
THEHARVESTER_PIP_SPEC="${ZYPHERON_THEHARVESTER_PIP_SPEC:-theHarvester}"
ROPPER_PIP_SPEC="${ZYPHERON_ROPPER_PIP_SPEC:-ropper==1.13.13}"
VOLATILITY3_PIP_SPEC="${ZYPHERON_VOLATILITY3_PIP_SPEC:-volatility3==2.27.0}"
ONE_GADGET_VERSION="${ZYPHERON_ONE_GADGET_VERSION:-1.10.0}"

# Result tracking: name -> status (ok|warn|fail|skip)
declare -A RESULTS
declare -a STEP_ORDER

# ─── logging ────────────────────────────────────────────────────────────────
touch "$LOG_FILE" 2>/dev/null || LOG_FILE=/tmp/zypheron-install.log
log()  { printf '[%s] %s\n' "$(date -Is)" "$*" | tee -a "$LOG_FILE" >/dev/null; }
info() { printf '[*] %s\n' "$*"; log "INFO  $*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; log "OK    $*"; }
warn() { printf '  \033[33m[!]\033[0m %s\n' "$*"; log "WARN  $*"; }
err()  { printf '  \033[31m[✗]\033[0m %s\n' "$*"; log "ERROR $*"; }
die()  { err "$*"; exit 1; }

record() {
    local step="$1" status="$2"
    RESULTS[$step]="$status"
    [[ ! " ${STEP_ORDER[*]:-} " =~ " $step " ]] && STEP_ORDER+=("$step")
}

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     ZYPHERON SECURITY TOOLS INSTALLER                     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log "=== Zypheron installer start (pid=$$, log=$LOG_FILE) ==="

# ─── preflight: root ────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash install-tools.sh"

# ─── preflight: distro detection ────────────────────────────────────────────
[ -r /etc/os-release ] || die "/etc/os-release missing — cannot detect distro"
# shellcheck disable=SC1091
. /etc/os-release
DISTRO_ID="${ID:-unknown}"
DISTRO_LIKE="${ID_LIKE:-}"
DISTRO_VER="${VERSION_ID:-unknown}"
DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID $DISTRO_VER}"

is_debian_family() {
    case "$DISTRO_ID" in
        debian|ubuntu|kali|parrot|linuxmint|pop|elementary|raspbian|zorin|mx|deepin) return 0 ;;
    esac
    [[ "$DISTRO_LIKE" == *debian* || "$DISTRO_LIKE" == *ubuntu* ]]
}

has_kali_repos() {
    [[ "$DISTRO_ID" == "kali" || "$DISTRO_ID" == "parrot" ]] || \
    grep -qsE 'kali|parrot' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null
}

if ! is_debian_family; then
    die "Unsupported distro: $DISTRO_NAME. Debian/Ubuntu/Kali/Parrot/Mint/etc required.
    Arch/RedHat installers coming soon."
fi
info "Detected: $DISTRO_NAME (id=$DISTRO_ID, like=$DISTRO_LIKE)"
has_kali_repos && info "Kali/Parrot-style security repos detected"

# ─── preflight: required binaries ───────────────────────────────────────────
for bin in apt-get dpkg curl; do
    command -v "$bin" >/dev/null || die "Required binary not found: $bin"
done

# ─── preflight: network ─────────────────────────────────────────────────────
info "Checking network (github.com, deb repos)..."
net_ok=0
for host in github.com deb.debian.org archive.ubuntu.com http.kali.org; do
    if curl -fsSIL --max-time 5 "https://$host" >/dev/null 2>&1; then
        net_ok=1
        break
    fi
done
[ $net_ok -eq 1 ] || die "No network reachable. Check DNS/proxy/firewall."
ok "Network reachable"

# ─── preflight: disk ────────────────────────────────────────────────────────
free_mb=$(df -Pm /usr /var /tmp 2>/dev/null | awk 'NR>1 {print $4}' | sort -n | head -1)
free_mb=${free_mb:-0}
if [ "$free_mb" -lt "$MIN_FREE_MB" ]; then
    die "Insufficient free space: ${free_mb}MB free, need ${MIN_FREE_MB}MB on /usr /var /tmp"
fi
ok "Disk OK (${free_mb}MB free)"

# ─── preflight: non-interactive apt ─────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
APT_OPTS=(-y -qq -o=Dpkg::Use-Pty=0)

# ─── step 1: apt update ─────────────────────────────────────────────────────
info "[1/10] Updating package lists..."
if apt-get update -qq 2>>"$LOG_FILE"; then
    ok "apt update"
    record apt-update ok
else
    rc=$?
    warn "apt-get update exited $rc (stale index may cause missing packages)"
    record apt-update warn
fi

# Helper: apt install a list, tolerating missing packages per-distro
apt_install_available() {
    local step="$1"; shift
    local -a missing=()
    local -a available=()
    for pkg in "$@"; do
        if apt-cache show "$pkg" >/dev/null 2>&1; then
            available+=("$pkg")
        else
            missing+=("$pkg")
        fi
    done
    if [ ${#available[@]} -gt 0 ]; then
        if apt-get install "${APT_OPTS[@]}" "${available[@]}" >>"$LOG_FILE" 2>&1; then
            ok "installed: ${available[*]}"
        else
            err "apt install failed: ${available[*]} (see $LOG_FILE)"
            record "$step" fail
            return 1
        fi
    fi
    if [ ${#missing[@]} -gt 0 ]; then
        warn "not in repos (skipped): ${missing[*]}"
        [ ${#available[@]} -eq 0 ] && { record "$step" warn; return 0; }
    fi
    record "$step" ok
}

ensure_pip3() {
    command -v pip3 >/dev/null 2>&1 && return 0
    warn "pip3 not found — installing python3-pip"
    apt_install_available python3-pip python3-pip || true
    command -v pip3 >/dev/null 2>&1
}

# ─── step 2: core APT packages ──────────────────────────────────────────────
info "[2/10] Installing APT packages..."
# Split by availability. wordlists/seclists/theharvester are Kali-native;
# on Debian/Ubuntu the former two ship as `wordlists` is absent — handled below.
apt_install_available apt-core hydra john git ruby curl ca-certificates python3-pip || true

# theharvester: package name is `theharvester` on Kali/Ubuntu-universe, else pip
if apt-cache show theharvester >/dev/null 2>&1; then
    apt_install_available theharvester theharvester || true
else
    info "theharvester not in repos — installing via pip"
    if ensure_pip3 && pip3 install --quiet --break-system-packages "$THEHARVESTER_PIP_SPEC" >>"$LOG_FILE" 2>&1 \
       || ensure_pip3 && pip3 install --quiet "$THEHARVESTER_PIP_SPEC" >>"$LOG_FILE" 2>&1; then
        ok "theHarvester (pip)"
        record theharvester ok
    else
        warn "theHarvester install failed"
        record theharvester warn
    fi
fi

# ─── step 3: nuclei (Go) ────────────────────────────────────────────────────
info "[3/10] Installing Nuclei..."
if command -v nuclei >/dev/null 2>&1; then
    ok "Nuclei already installed ($(nuclei -version 2>&1 | head -1))"
    record nuclei ok
elif command -v go >/dev/null 2>&1; then
    if GOBIN=/usr/local/bin go install -v "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}" >>"$LOG_FILE" 2>&1; then
        ok "Nuclei installed (${NUCLEI_VERSION})"
        record nuclei ok
    else
        warn "go install nuclei failed (see $LOG_FILE)"
        record nuclei warn
    fi
else
    warn "Go not found — installing via apt"
    if apt-get install "${APT_OPTS[@]}" golang-go >>"$LOG_FILE" 2>&1; then
        if GOBIN=/usr/local/bin go install -v "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}" >>"$LOG_FILE" 2>&1; then
            ok "Nuclei installed (${NUCLEI_VERSION}; go fetched via apt)"
            record nuclei ok
        else
            warn "Nuclei install failed after Go install"
            record nuclei warn
        fi
    else
        warn "Go unavailable — nuclei skipped"
        record nuclei skip
    fi
fi

# ─── step 4: amass ──────────────────────────────────────────────────────────
info "[4/10] Installing Amass..."
if command -v amass >/dev/null 2>&1; then
    ok "Amass already installed"
    record amass ok
elif apt-cache show amass >/dev/null 2>&1 && apt-get install "${APT_OPTS[@]}" amass >>"$LOG_FILE" 2>&1; then
    ok "Amass (apt)"
    record amass ok
elif command -v snap >/dev/null 2>&1 && snap install amass >>"$LOG_FILE" 2>&1; then
    ok "Amass (snap)"
    record amass ok
elif command -v go >/dev/null 2>&1 && GOBIN=/usr/local/bin go install -v "github.com/owasp-amass/amass/v4/...@${AMASS_VERSION}" >>"$LOG_FILE" 2>&1; then
    ok "Amass (go install ${AMASS_VERSION})"
    record amass ok
else
    warn "Amass unavailable via apt/snap/go"
    record amass warn
fi

# ─── step 5: metasploit ─────────────────────────────────────────────────────
info "[5/10] Installing Metasploit Framework..."
if command -v msfconsole >/dev/null 2>&1; then
    ok "Metasploit already installed"
    record metasploit ok
elif has_kali_repos && apt-cache show metasploit-framework >/dev/null 2>&1; then
    if apt-get install "${APT_OPTS[@]}" metasploit-framework >>"$LOG_FILE" 2>&1; then
        ok "Metasploit (kali/parrot repo)"
        record metasploit ok
    else
        warn "apt metasploit-framework failed"
        record metasploit warn
    fi
elif [ "$ALLOW_REMOTE_INSTALLERS" = "1" ]; then
    # Rapid7 omnibus installer (pinned commit + sha256).
    # Defaults below were verified at time of writing. Override via env if you
    # have updated expected values (commit SHA is required; hash optional but
    # strongly recommended).
    # Pinned to rapid7/metasploit-omnibus master HEAD at time of release.
    # Verify + bump when needed; both values must match the same commit.
    MSF_COMMIT="${ZYPHERON_MSF_COMMIT:-96f5f937d52ea95bc05d39b7859e8592a91f8a2d}"
    MSF_SHA256="${ZYPHERON_MSF_SHA256:-d12fea4d1339ebecb09d8cc36920d9f5e5e7e9fffbe092b1e1cd09255cc16825}"
    MSF_URL="https://raw.githubusercontent.com/rapid7/metasploit-omnibus/${MSF_COMMIT}/config/templates/metasploit-framework-wrappers/msfupdate.erb"
    install_msf_omnibus() {
        local tmp rc=1
        tmp=$(mktemp /tmp/msfinstall.XXXXXX) || return 1
        # shellcheck disable=SC2064
        trap "rm -f '$tmp'" RETURN
        if ! curl -fsSL --max-time 60 "$MSF_URL" -o "$tmp"; then
            warn "Metasploit omnibus download failed"
            return 1
        fi
        if [ -n "$MSF_SHA256" ]; then
            local got
            got=$(sha256sum "$tmp" | awk '{print $1}')
            if [ "$got" != "$MSF_SHA256" ]; then
                err "Metasploit omnibus SHA256 mismatch (want=$MSF_SHA256 got=$got)"
                return 1
            fi
            ok "MSF omnibus SHA256 verified"
        else
            warn "ZYPHERON_MSF_SHA256 not set — proceeding with commit-pin only"
        fi
        chmod 755 "$tmp" || return 1
        if "$tmp" >>"$LOG_FILE" 2>&1; then
            rc=0
        fi
        return $rc
    }
    if install_msf_omnibus; then
        ok "Metasploit (omnibus, commit $MSF_COMMIT)"
        record metasploit ok
    else
        warn "Metasploit omnibus install failed — install manually"
        record metasploit warn
    fi
else
    warn "Metasploit not in repos. Skipping remote installer; set ZYPHERON_ALLOW_REMOTE_INSTALLERS=1 to allow Rapid7 omnibus fallback (commit+sha256 pinned)."
    record metasploit skip
fi

# ─── step 6: python tools ───────────────────────────────────────────────────
info "[6/10] Installing Python tools (ropper, volatility3)..."
PIP_OPTS=(--quiet --disable-pip-version-check)
# PEP 668 distros (Debian 12+, Ubuntu 24.04+) need --break-system-packages or venv
if ensure_pip3 && pip3 install "${PIP_OPTS[@]}" --break-system-packages "$ROPPER_PIP_SPEC" "$VOLATILITY3_PIP_SPEC" >>"$LOG_FILE" 2>&1 \
   || ensure_pip3 && pip3 install "${PIP_OPTS[@]}" "$ROPPER_PIP_SPEC" "$VOLATILITY3_PIP_SPEC" >>"$LOG_FILE" 2>&1; then
    ok "ropper, volatility3"
    record python-tools ok
else
    warn "pip install failed for ropper/volatility3"
    record python-tools warn
fi

# ─── step 7: ruby tools ─────────────────────────────────────────────────────
info "[7/10] Installing Ruby tools (one_gadget)..."
if ! command -v gem >/dev/null 2>&1; then
    apt-get install "${APT_OPTS[@]}" ruby ruby-dev >>"$LOG_FILE" 2>&1 || true
fi
if command -v gem >/dev/null 2>&1 && gem install one_gadget -v "$ONE_GADGET_VERSION" >>"$LOG_FILE" 2>&1; then
    ok "one_gadget (${ONE_GADGET_VERSION})"
    record one_gadget ok
else
    warn "one_gadget install failed"
    record one_gadget warn
fi

# ─── step 8: ghidra ─────────────────────────────────────────────────────────
info "[8/10] Checking Ghidra..."
if command -v ghidra >/dev/null 2>&1 || [ -d /opt/ghidra ] || ls /opt/ghidra_* >/dev/null 2>&1; then
    ok "Ghidra available"
    record ghidra ok
elif apt-cache show ghidra >/dev/null 2>&1 && apt-get install "${APT_OPTS[@]}" ghidra >>"$LOG_FILE" 2>&1; then
    ok "Ghidra (apt)"
    record ghidra ok
else
    warn "Ghidra not installed. Download: https://github.com/NationalSecurityAgency/ghidra/releases"
    record ghidra skip
fi

# ─── step 9: wordlists ──────────────────────────────────────────────────────
info "[9/10] Setting up wordlists..."
mkdir -p /usr/share/wordlists

SECLISTS_DIR=""
for cand in /usr/share/seclists /usr/share/wordlists/seclists /usr/share/wordlists/SecLists; do
    [ -d "$cand" ] && { SECLISTS_DIR="$cand"; break; }
done

if [ -z "$SECLISTS_DIR" ] && apt-cache show seclists >/dev/null 2>&1; then
    if apt-get install "${APT_OPTS[@]}" seclists >>"$LOG_FILE" 2>&1; then
        SECLISTS_DIR=/usr/share/seclists
    fi
fi

if [ -z "$SECLISTS_DIR" ]; then
    info "  Cloning SecLists (~1GB, slow)..."
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

# rockyou (common for password cracking)
if [ ! -f /usr/share/wordlists/rockyou.txt ] && [ ! -f /usr/share/wordlists/rockyou.txt.gz ]; then
    if apt-cache show wordlists >/dev/null 2>&1 && apt-get install "${APT_OPTS[@]}" wordlists >>"$LOG_FILE" 2>&1; then
        [ -f /usr/share/wordlists/rockyou.txt.gz ] && gunzip -kf /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
    fi
fi

# ─── step 10: zypheron-go build (opt-in via ZYPHERON_BUILD_GO=1) ────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_SRC=""
for cand in "$SCRIPT_DIR/zypheron-go" "$PWD/zypheron-go" "$SCRIPT_DIR/../zypheron-go"; do
    [ -f "$cand/go.mod" ] && { GO_SRC="$cand"; break; }
done

# go.dev tarball fallback when apt golang-go is too old (Debian 12 ships 1.22)
install_go_tarball() {
    local ver="$1"
    local arch tar_url tmp
    case "$(uname -m)" in
        x86_64|amd64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        armv7l|armv6l) arch=armv6l ;;
        i386|i686) arch=386 ;;
        *) warn "Unknown arch $(uname -m) — cannot fetch Go tarball"; return 1 ;;
    esac
    tar_url="https://go.dev/dl/go${ver}.linux-${arch}.tar.gz"
    tmp=$(mktemp /tmp/go-dl.XXXXXX.tar.gz) || return 1
    trap 'rm -f "$tmp"' RETURN
    info "  fetching $tar_url"
    if ! curl -fsSL --max-time 300 "$tar_url" -o "$tmp"; then
        warn "Go tarball download failed"
        return 1
    fi
    # Overwrite /usr/local/go (official install layout)
    rm -rf /usr/local/go
    if tar -C /usr/local -xzf "$tmp"; then
        export PATH="/usr/local/go/bin:$PATH"
        ok "Go ${ver} installed to /usr/local/go"
        return 0
    fi
    warn "Go tarball extract failed"
    return 1
}

if [ -z "$GO_SRC" ]; then
    info "[10/10] zypheron-go source not found — skipping build"
    record go-build skip
elif [ "$BUILD_GO" != "1" ]; then
    warn "[10/10] zypheron-go source detected at $GO_SRC but build skipped."
    warn "       Rerun with ZYPHERON_BUILD_GO=1 to build, or run manually:"
    warn "         cd $GO_SRC && go mod download && go build ./..."
    record go-build skip
else
    info "[10/10] Building zypheron-go at $GO_SRC ..."

    go_ver_ok=0
    check_go_ver() {
        command -v go >/dev/null 2>&1 || return 1
        local gv maj min
        gv=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
        maj=$(echo "$gv" | cut -d. -f1)
        min=$(echo "$gv" | cut -d. -f2)
        # Defensive: handle non-numeric (dev builds, custom wrappers)
        [[ "$maj" =~ ^[0-9]+$ ]] || maj=0
        [[ "$min" =~ ^[0-9]+$ ]] || min=0
        [ "$maj" -gt 1 ] || { [ "$maj" -eq 1 ] && [ "$min" -ge 24 ]; }
    }

    if check_go_ver; then
        go_ver_ok=1
    else
        if command -v go >/dev/null 2>&1; then
            warn "Go $(go version | awk '{print $3}') too old (need >=1.24). Trying apt..."
        else
            info "  Go not found — trying apt golang-go"
        fi
        apt-get install "${APT_OPTS[@]}" golang-go >>"$LOG_FILE" 2>&1 || true
        if check_go_ver; then
            go_ver_ok=1
        else
            warn "apt Go version insufficient — fetching official tarball ${GO_DL_VERSION} from go.dev"
            if install_go_tarball "$GO_DL_VERSION" && check_go_ver; then
                go_ver_ok=1
            else
                warn "Go >=1.24 unavailable"
            fi
        fi
    fi

    if [ $go_ver_ok -eq 1 ]; then
        # Run as invoking user when sudo'd so module cache goes to user's GOPATH
        BUILD_USER="${SUDO_USER:-root}"
        BUILD_HOME=$(getent passwd "$BUILD_USER" | cut -d: -f6)
        [ -z "$BUILD_HOME" ] && BUILD_HOME="/root"

        # Validate GO_SRC before any chdir — no special chars that can escape quoting.
        if ! [[ "$GO_SRC" =~ ^[A-Za-z0-9._/+=@-]+$ ]]; then
            err "Refusing to build: unsafe characters in GO_SRC path: $GO_SRC"
            record go-build fail
            exit 3
        fi

        # run_in_src: chdir via `env --chdir` (GNU coreutils) — never `bash -c`.
        # Explicit PATH (no attacker inheritance). Only whitelisted Go env forwarded.
        SAFE_PATH="/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        run_in_src() {
            if [ "$BUILD_USER" = "root" ]; then
                env --chdir="$GO_SRC" HOME="$BUILD_HOME" PATH="$SAFE_PATH" \
                    GOPRIVATE="${GOPRIVATE:-}" GOPROXY="${GOPROXY:-}" GONOSUMCHECK="${GONOSUMCHECK:-}" \
                    "$@"
            else
                sudo -u "$BUILD_USER" \
                    env --chdir="$GO_SRC" HOME="$BUILD_HOME" PATH="$SAFE_PATH" \
                    GOPRIVATE="${GOPRIVATE:-}" GOPROXY="${GOPROXY:-}" GONOSUMCHECK="${GONOSUMCHECK:-}" \
                    "$@"
            fi
        }

        # Private module hint (repo path contains KKingZero org)
        mod_path=$(awk '/^module /{print $2; exit}' "$GO_SRC/go.mod")
        if [[ "$mod_path" == github.com/KKingZero/* ]] && [ -z "${GOPRIVATE:-}" ]; then
            export GOPRIVATE="github.com/KKingZero/*"
            info "  set GOPRIVATE=$GOPRIVATE for private module auth"
        fi

        build_ok=1
        info "  go mod download..."
        if ! run_in_src go mod download >>"$LOG_FILE" 2>&1; then
            warn "go mod download failed — check private-repo auth / GOPROXY / network"
            build_ok=0
        fi

        if [ $build_ok -eq 1 ]; then
            info "  go mod tidy..."
            run_in_src go mod tidy >>"$LOG_FILE" 2>&1 || \
                warn "go mod tidy reported issues (non-fatal)"

            info "  go build ./..."
            if run_in_src go build ./... >>"$LOG_FILE" 2>&1; then
                ok "zypheron-go built"
                record go-build ok
            else
                err "go build failed (see $LOG_FILE)"
                record go-build fail
            fi
        else
            record go-build fail
        fi
    else
        warn "Go >=1.24 unavailable — skipping build"
        record go-build skip
    fi
fi

# ─── verification pass ──────────────────────────────────────────────────────
echo ""
info "Verifying installed tools..."
declare -A TOOL_CHECK=(
    [hydra]=hydra
    [john]=john
    [theHarvester]=theHarvester
    [nuclei]=nuclei
    [amass]=amass
    [msfconsole]=msfconsole
    [ropper]=ropper
    [volatility3]=vol
    [one_gadget]=one_gadget
)
verified=0; verified_fail=0
for name in "${!TOOL_CHECK[@]}"; do
    bin="${TOOL_CHECK[$name]}"
    if command -v "$bin" >/dev/null 2>&1; then
        ok "$name ($(command -v "$bin"))"
        verified=$((verified+1))
    else
        warn "$name not on PATH"
        verified_fail=$((verified_fail+1))
    fi
done
[ -n "$SECLISTS_DIR" ] && ok "SecLists: $SECLISTS_DIR"

# ─── summary ────────────────────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     INSTALLATION SUMMARY                                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
fail_count=0; warn_count=0; ok_count=0
for step in "${STEP_ORDER[@]}"; do
    status="${RESULTS[$step]}"
    case "$status" in
        ok)   printf '  \033[32m✓\033[0m %-20s ok\n'   "$step"; ok_count=$((ok_count+1))   ;;
        warn) printf '  \033[33m!\033[0m %-20s warn\n' "$step"; warn_count=$((warn_count+1)) ;;
        fail) printf '  \033[31m✗\033[0m %-20s FAIL\n' "$step"; fail_count=$((fail_count+1)) ;;
        skip) printf '  \033[90m·\033[0m %-20s skip\n' "$step" ;;
    esac
done
echo ""
echo "  Verified on PATH: $verified  |  Missing: $verified_fail"
echo "  Steps: $ok_count ok, $warn_count warn, $fail_count fail"
echo "  Log: $LOG_FILE"
echo ""
echo "Run 'zypheron tools check' for full tool audit."
echo ""

log "=== Zypheron installer end (ok=$ok_count warn=$warn_count fail=$fail_count) ==="

# Exit code: 0 if no hard fails, 1 if any fail, 2 if critical (no core tools)
if [ $fail_count -gt 0 ]; then
    exit 1
elif [ "$verified" -lt 3 ]; then
    err "Fewer than 3 core tools verified — likely broken install"
    exit 2
fi
exit 0
