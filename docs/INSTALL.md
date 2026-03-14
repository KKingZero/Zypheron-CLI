# Zypheron Installation Guide

This guide covers the current supported install paths for Zypheron CLI.

## Install Paths

There are two primary ways to install Zypheron:

1. Source bootstrap with [setup-hybrid.sh](../setup-hybrid.sh)
2. Release binary install with [scripts/install.sh](../scripts/install.sh)

## Option 1: Bootstrap From Source

Use this when you want the repository, local build flow, and automated dependency setup.

```bash
git clone https://github.com/KKingZero/Zypheron-CLI.git
cd Zypheron-CLI
bash ./setup-hybrid.sh
```

By default, the bootstrap script:

- builds the CLI to `~/.local/bin/zypheron`
- runs `zypheron install-deps`
- installs shell completion when possible
- optionally installs external tools

Useful options:

```bash
ZYPHERON_INSTALL_DIR="$HOME/.local/bin" bash ./setup-hybrid.sh
ZYPHERON_INSTALL_TOOLS=none bash ./setup-hybrid.sh
ZYPHERON_INSTALL_TOOLS=critical bash ./setup-hybrid.sh
ZYPHERON_INSTALL_TOOLS=all bash ./setup-hybrid.sh
ZYPHERON_DEP_PACKS=core bash ./setup-hybrid.sh
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
- check [../HELP.md](../HELP.md)

If the release installer fails:

- make sure `curl` or `wget` is installed
- make sure the target install directory is writable or use `sudo`
- rerun with an explicit install directory such as `ZYPHERON_INSTALL_DIR="$HOME/.local/bin"`
