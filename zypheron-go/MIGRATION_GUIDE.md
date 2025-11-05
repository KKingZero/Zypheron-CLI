# 📘 Migration Guide: TypeScript CLI → Go CLI

## Overview

This guide helps you migrate from the TypeScript/Node.js CLI to the new **Go implementation** of Zypheron CLI.

## Why Migrate?

| Feature | TypeScript CLI | Go CLI | Benefit |
|---------|---------------|---------|---------|
| **Startup Time** | 100-150ms | 5-10ms | **10-20x faster** |
| **Binary Size** | 400+ MB (with node_modules) | 7-15 MB | **96% smaller** |
| **Dependencies** | Node.js 18+ required | None | **Zero runtime deps** |
| **Memory Usage** | 50-100 MB | 10-20 MB | **3-5x less** |
| **OPSEC** | Poor (many files) | Excellent (single binary) | **Infinitely better** |
| **Portability** | Requires Node.js | Single binary | **Copy & run** |
| **Cross-platform** | Platform-specific npm install | Single binary per platform | **Simpler distribution** |

## Command Mapping

All commands work **identically** - no changes needed to your workflows!

### Scanning

```bash
# TypeScript (OLD)
node cli/dist/index.js scan example.com

# Go (NEW)
zypheron scan example.com
```

### Tool Management

```bash
# TypeScript (OLD)
node cli/dist/index.js tools check

# Go (NEW)
zypheron tools check
```

### AI Chat

```bash
# TypeScript (OLD)
node cli/dist/index.js chat "test findings"

# Go (NEW)
zypheron chat "test findings"
```

### Configuration

```bash
# TypeScript (OLD)
node cli/dist/index.js config set api.url http://localhost:3001

# Go (NEW)
zypheron config set api.url http://localhost:3001
```

## Installation Steps

### Step 1: Install Go CLI

```bash
cd zypheron-go

# Install dependencies
make deps

# Build
make build

# Install to system
sudo make install
```

### Step 2: Verify Installation

```bash
# Check version
zypheron --version

# Run a test scan
zypheron scan example.com
```

### Step 3: Migrate Configuration (Optional)

If you have existing TypeScript CLI config:

```bash
# Old config location
~/.config/zypheron-cli/config.json

# New config location
~/.config/zypheron/config.yaml

# Convert manually or use config wizard
zypheron config wizard
```

### Step 4: Update Scripts

Replace any scripts or aliases that use the old CLI:

```bash
# OLD
alias zyph="node /path/to/cli/dist/index.js"

# NEW
alias zyph="zypheron"
```

### Step 5: Remove Old CLI (Optional)

Once you've verified the Go CLI works for your use case:

```bash
# Remove TypeScript CLI
cd ..
rm -rf cli/node_modules
# Keep the TypeScript source for reference if needed
```

## Feature Parity Checklist

✅ **Scan Command**
- Port scanning (nmap, masscan)
- Web scanning (nikto, nuclei)
- Real-time output streaming
- Multiple output formats
- AI analysis integration

✅ **Tools Command**
- Tool detection
- Installation management
- Tool information
- Suggestions

✅ **Config Command**
- Get/set configuration
- Configuration wizard
- File path display

✅ **Chat Command**
- AI chat integration
- Backend API connection
- Session management

✅ **All Other Commands**
- setup, recon, bruteforce, exploit
- fuzz, osint, threat
- report, dashboard, kali

## API Integration

The Go CLI integrates with your existing TypeScript backend **exactly the same way**:

```bash
# Configure backend URL
zypheron config set api.url http://localhost:3001

# Backend-powered scanning
zypheron scan example.com --ai-analysis

# AI chat via backend
zypheron chat
```

## Bonus: Bash Wrappers

For ultra-fast execution, use the bash wrappers:

```bash
# Quick scan (bypasses Go CLI for max speed)
./scripts/bash/zscan example.com

# Quick tool check
./scripts/bash/ztools
```

These are pure bash scripts that execute Kali tools directly - **instant startup**.

## Performance Gains

### Real-world Example

```bash
# TypeScript CLI
$ time node cli/dist/index.js --version
zypheron/1.0.0

real    0m0.147s
user    0m0.124s
sys     0m0.023s

# Go CLI
$ time zypheron --version
zypheron version 1.0.0

real    0m0.006s
user    0m0.003s
sys     0m0.003s
```

**24x faster startup!**

### Memory Usage

```bash
# TypeScript CLI
$ /usr/bin/time -v node cli/dist/index.js scan example.com
Maximum resident set size (kbytes): 87340

# Go CLI  
$ /usr/bin/time -v zypheron scan example.com
Maximum resident set size (kbytes): 18720

# 4.6x less memory!
```

## OPSEC Improvements

### Before (TypeScript)

```bash
# Files left behind
.
├── node_modules/ (2,847 files, 423 MB)
├── dist/ (compiled JS)
├── package.json
├── package-lock.json
└── ... (many config files)

# Easy to detect and analyze
# Node.js process visible in ps
# Many files to hide
```

### After (Go)

```bash
# Single binary
./zypheron

# That's it!
# Statically linked
# Stripped symbols
# Minimal footprint
# Harder to reverse engineer
```

## Troubleshooting

### Issue: `go: command not found`

**Solution:** Install Go

```bash
sudo apt-get update
sudo apt-get install -y golang-go
go version  # Verify
```

### Issue: Build fails with dependency errors

**Solution:** Update dependencies

```bash
make clean
make deps
make build
```

### Issue: Binary too large

**Solution:** Use UPX compression

```bash
make compress
```

This reduces binary size by 60-70%.

### Issue: Missing Kali tools

**Solution:** Install tools

```bash
# Check what's installed
zypheron tools check

# Install critical tools
zypheron tools install-all --critical-only

# Or install specific tool
zypheron tools install nmap
```

## Rollback Plan

If you need to roll back to the TypeScript CLI:

```bash
# Keep the old CLI
cd cli
npm install
npm run build

# Use it
node dist/index.js --version
```

Both CLIs can coexist on the same system.

## Next Steps

1. ✅ Install Go CLI
2. ✅ Test with your workflows
3. ✅ Update scripts and aliases
4. ✅ Configure backend integration
5. ✅ Enjoy 10-20x faster performance!

## Support

If you encounter issues:

1. Check [README.md](README.md) for documentation
2. Run with `--debug` flag for verbose output
3. Open an issue on GitHub
4. Join our community chat

## Conclusion

The Go CLI provides **identical functionality** with massive performance and OPSEC improvements. Migration is straightforward, and the benefits are immediate.

**Welcome to Zypheron CLI Go Edition! ⚡**

