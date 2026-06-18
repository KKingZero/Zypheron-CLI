# Zypheron Installation Guide

This guide covers the current supported install paths for Zypheron CLI.

## Install Paths

There are four supported install paths:

1. Source bootstrap — [setup-hybrid.sh](../scripts/install/setup-hybrid.sh) (Zypheron CLI itself)
2. Release binary — [scripts/install.sh](../scripts/install.sh) (packaged CLI download)
3. Package managers — apt, Homebrew, AUR, and RPM/DNF artifacts from GoReleaser
4. Pentest tool ecosystem — per-distro installers (`install-tools.sh`, `install-tools-arch.sh`, `install-tools-rpm.sh`)
5. C2 frameworks — optional interactive [install-c2.sh](../scripts/install/install-c2.sh) (Sliver, Empire)

## Option 1: Bootstrap From Source

Use this when you want the repository, local build flow, and automated dependency setup.

```bash
git clone https://github.com/KKingZero/Zypheron-CLI.git
cd Zypheron-CLI
bash scripts/install/setup-hybrid.sh
```

By default, the bootstrap script:

- builds the CLI to `~/.local/bin/zypheron`
- runs `zypheron install-deps`
- installs shell completion when possible
- optionally installs external tools

Useful options:

```bash
ZYPHERON_INSTALL_DIR="$HOME/.local/bin" bash scripts/install/setup-hybrid.sh
ZYPHERON_INSTALL_TOOLS=none bash scripts/install/setup-hybrid.sh
ZYPHERON_INSTALL_TOOLS=critical bash scripts/install/setup-hybrid.sh
ZYPHERON_INSTALL_TOOLS=all bash scripts/install/setup-hybrid.sh
ZYPHERON_DEP_PACKS=core bash scripts/install/setup-hybrid.sh
```

## Option 2: Install a Release Binary

Use this when you want a packaged CLI without cloning the repo.

```bash
curl -sSfL https://download.zypheron.net/install.sh | bash
```

Useful options:

```bash
ZYPHERON_VERSION=v2.0.0 curl -sSfL https://download.zypheron.net/install.sh | bash
ZYPHERON_INSTALL_DIR="$HOME/.local/bin" curl -sSfL https://download.zypheron.net/install.sh | bash
```

The release installer:

- detects OS and architecture
- downloads the matching archive and `SHA256SUMS`
- verifies checksums when local checksum tools are available
- installs the `zypheron` binary into the target directory

## Option 3: Package Managers

Release tags build Linux package artifacts through GoReleaser:

- `.deb` packages for Debian, Ubuntu, Kali, Parrot, Mint, Pop!_OS, and other apt-based systems
- `.rpm` packages for Fedora, RHEL, Rocky, Alma, CentOS Stream, Oracle Linux, Amazon Linux 2023, and other RPM/DNF systems

Homebrew and AUR use source-build templates under [packaging/](../packaging/) so SQLite-backed features are built with CGO enabled on the user's system.

Until the external package repositories are published, install the package artifacts directly from the release or CDN:

```bash
# Debian / Ubuntu / Kali / Parrot
curl -LO https://download.zypheron.net/v2.0.0/zypheron_2.0.0_amd64.deb
sudo apt install ./zypheron_2.0.0_amd64.deb

# Fedora / RHEL-family
curl -LO https://download.zypheron.net/v2.0.0/zypheron-2.0.0-1.x86_64.rpm
sudo dnf install ./zypheron-2.0.0-1.x86_64.rpm
```

Once package repositories are live, the intended commands are:

```bash
sudo apt install zypheron
brew install KKingZero/zypheron/zypheron
yay -S zypheron
sudo dnf install zypheron
```

Publishing requirements:

- **apt** — upload generated `.deb` files to an apt repository provider such as Cloudsmith, Gemfury, Packagecloud, or a self-hosted signed apt repo.
- **Homebrew** — create `KKingZero/homebrew-zypheron`, fill `packaging/homebrew/Formula/zypheron.rb.template` with the release version and source tarball SHA256, then publish it as `Formula/zypheron.rb`.
- **AUR** — create the `zypheron` AUR package, fill `packaging/aur/PKGBUILD.template` with the release version and source tarball SHA256, then publish it with `.SRCINFO`.
- **DNF/RPM** — generated `.rpm` files can be installed directly now; `dnf install zypheron` requires publishing them to a signed yum/dnf repository.

## Option 4: Pentest Tool Ecosystem

Standalone installers that provision the external tools Zypheron workflows call (hydra, john, nuclei, amass, metasploit, ropper, volatility3, one_gadget, ghidra, SecLists, rockyou).

These are independent of the CLI install — run them on any supported distro after `setup-hybrid.sh` (or skip them entirely and install tools manually).

```bash
# Debian / Ubuntu / Kali / Parrot / Mint / Pop!_OS / elementary
sudo bash scripts/install/install-tools.sh

# Arch / Manjaro / EndeavourOS / Garuda / BlackArch
sudo bash scripts/install/install-tools-arch.sh

# Fedora / RHEL 8+ / CentOS Stream / Rocky / Alma / Oracle Linux / Amazon Linux 2023
sudo bash scripts/install/install-tools-rpm.sh
```

All three share the same env-flag surface:

| Flag | Default | Effect |
|---|---|---|
| `ZYPHERON_MIN_FREE_MB` | `3072` | Disk preflight threshold (MB, on `/usr /var /tmp`) |
| `ZYPHERON_INSTALL_LOG` | `/var/log/zypheron-install.log` | Log destination |
| `ZYPHERON_ALLOW_REMOTE_INSTALLERS` | `0` | Enable Rapid7 Metasploit omnibus fallback (commit-pinned + SHA256-verified) |
| `ZYPHERON_MSF_COMMIT` | embedded | Rapid7 metasploit-omnibus commit SHA used by the omnibus fallback |
| `ZYPHERON_MSF_SHA256` | embedded | Expected SHA256 of `msfupdate.erb` at that commit |
| `ZYPHERON_BUILD_GO` | `0` | Also build the `zypheron-go` Go CLI if sources are present |
| `ZYPHERON_GO_DL_VERSION` | `1.24.2` | Go tarball version fetched from go.dev when the distro package is too old |

Arch-only flags:

| Flag | Default | Effect |
|---|---|---|
| `ZYPHERON_ENABLE_BLACKARCH` | `0` | Enable BlackArch pacman repo (installs SHA256-verified `strap.sh`) |
| `ZYPHERON_BLACKARCH_STRAP_SHA256` | embedded | Expected SHA256 of `blackarch.org/strap.sh` |
| `ZYPHERON_AUR_HELPER` | `paru` | Preferred AUR helper (`paru` or `yay`); bootstraps `paru-bin` if neither present |
| `ZYPHERON_ALLOW_AUR_SKIPREVIEW` | `0` | Skip interactive PKGBUILD review before AUR installs (not recommended) |

Each installer writes a structured log to `$ZYPHERON_INSTALL_LOG`, tracks per-step status (ok / warn / fail / skip), and runs a verification pass confirming installed binaries resolve on `PATH`. Exit codes: `0` success, `1` any failed step, `2` fewer than three core tools verified.

## Option 5: C2 Frameworks (Sliver, Empire)

Never auto-installed. Run the interactive installer when you want them:

```bash
sudo bash scripts/install/install-c2.sh
```

Per-framework behavior:

- **Sliver** — Kali/Parrot apt `sliver` pkg → pinned GitHub release tarball (SHA256-verified) → upstream `curl | bash` with `ZYPHERON_ALLOW_UNVERIFIED_SLIVER=1`.
- **Empire** — `powershell-empire` apt pkg (Kali/Parrot) → git clone of `BC-SECURITY/Empire` into `/opt/Empire` (override with `ZYPHERON_EMPIRE_DIR`) and `./setup/install.sh` after consent.
- **Havoc** — intentionally excluded.

Override Sliver pin when bumping versions:

```bash
ZYPHERON_SLIVER_VERSION=v1.7.3 \
ZYPHERON_SLIVER_SHA256_AMD64=<sha256> \
ZYPHERON_SLIVER_SHA256_ARM64=<sha256> \
sudo -E bash scripts/install/install-c2.sh
```

Empire usage after install (via `zypheron exploit --c2 empire`):

```bash
export EMPIRE_HOST=https://127.0.0.1:1337
export EMPIRE_USER=<username>
export EMPIRE_PASS=<password>
# Optional (loopback / RFC1918 only — prints a warning on public IPs):
export EMPIRE_INSECURE_TLS=1
```

## Cross-Platform Builds

If building from source for a different platform:

```bash
cd zypheron-go

# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o zypheron-linux-amd64 ./cmd/zypheron

# macOS ARM64 (M1/M2)
GOOS=darwin GOARCH=arm64 go build -o zypheron-darwin-arm64 ./cmd/zypheron

# Windows AMD64
GOOS=windows GOARCH=amd64 go build -o zypheron-windows-amd64.exe ./cmd/zypheron
```

## System Requirements

Minimum requirements:

- Go `1.24+` for source builds
- Python `3.9+`
- Linux, macOS, or WSL

Recommended environment:

- Kali or a similarly equipped Linux distro
- a modern terminal with color and Unicode support
- enough disk space for the external security tools you plan to install

## Post-Install Checks

After installation:

```bash
zypheron --version
zypheron doctor
```

For source installs, if `~/.local/bin` is not already on `PATH`, add it:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Installing Dependencies Later

If you skip parts of setup initially:

```bash
zypheron install-deps --all
zypheron tools check
zypheron tools install-all --critical-only --yes
```

## Troubleshooting

If the bootstrap fails:

- verify `go version`
- verify `python3 --version`
- run `zypheron doctor`
- check [HELP.md](HELP.md)

If the release installer fails:

- make sure `curl` or `wget` is installed
- make sure the target install directory is writable or use `sudo`
- rerun with an explicit install directory such as `ZYPHERON_INSTALL_DIR="$HOME/.local/bin"`
