# Zypheron CLI - Build and Test Guide

This guide covers building, testing, and using the Zypheron CLI with the integrated autonomous attack path engine (Phase 1).

**Quick Help**: For common build and installation issues, see [HELP.md](HELP.md)

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Build Process](#build-process)
- [Testing](#testing)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required

- **Go 1.21+** - For Go CLI compilation
- **Python 3.10+** - For AI/ML features and autonomous orchestrator
- **Make** - Build automation

### Optional (for real tool execution)

- **nmap** - Network scanning
- **sqlmap** - SQL injection testing
- **nikto** - Web vulnerability scanning
- **nuclei** - Template-based vulnerability scanning
- **hydra** - Credential brute-forcing
- **masscan** - Fast port scanning

Install tools on Debian/Ubuntu:
```bash
sudo apt update
sudo apt install nmap nikto -y

# Optional: Install additional tools
sudo apt install hydra masscan sqlmap -y

# For nuclei (Go-based)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

---

## Quick Start

```bash
# 1. Navigate to Go directory
cd zypheron-go

# 2. Build everything (Go binary + Python environment)
make build

# 3. Verify the build succeeded
./build/zypheron --version
./build/zypheron tools check

# 4. (Optional) Install system-wide
sudo make install

# 5. (Optional) Test autonomous pentesting features
./build/zypheron help autopent
```

**Expected output**: You should see the version number and no build errors.

**Having issues?** Check [HELP.md](../HELP.md) for troubleshooting.

---

## Build Process

### Standard Build

```bash
cd zypheron-go
make all
```

This runs two steps:

1. **Go Binary Compilation** (`make build`)
   - Compiles `cmd/zypheron/main.go`
   - Output: `build/zypheron` (~14MB)
   - Includes all Go commands

2. **Python Environment Setup** (`make setup-autopent`)
   - Creates Python virtual environment (`.venv`)
   - Installs Python dependencies from `requirements.txt`
   - Sets up autonomous orchestrator

### Build Targets

```bash
# Individual targets
make build              # Build Go binary only
make setup-autopent     # Setup Python environment only
make deps               # Install Go dependencies
make test               # Run Go tests
make clean              # Clean build artifacts

# Cross-platform builds
make build-all          # Build for all platforms (Linux, macOS, Windows)

# Advanced
make compress           # Compress binary with UPX
make release            # Create release packages with checksums
```

### Manual Build (without Make)

```bash
# Build Go binary
cd zypheron-go
go build -ldflags="-s -w -X main.version=1.0.0" -o build/zypheron cmd/zypheron/main.go

# Setup Python environment
cd ../zypheron-ai
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

---

## Testing

### Test the Build

```bash
cd zypheron-go

# 1. Test binary works
./build/zypheron --version

# 2. Test autopent integration
./build/zypheron help autopent

# 3. Test Python dependencies
cd ../zypheron-ai
.venv/bin/python3 -c "from autopent.autonomous_orchestrator import AutonomousOrchestrator; print('✓ OK')"

# 4. Run the make test target
cd ../zypheron-go
make test-autopent
```

### Test Autonomous Orchestrator

```bash
cd zypheron-go

# Test autopent (simulation mode)
./build/zypheron autopent 127.0.0.1 \
  --objective "test simulation" \
  --save
```

### Test with Real Targets (Authorized Only)

⚠️ **WARNING:** Only test against systems you own or have written authorization to test.

```bash
# Example: Scan your own local network
./build/zypheron autopent 192.168.1.100 \
  --objective "reach database server" \
  --ai-provider claude \
  --save
```

---

## Usage

### Basic Workflow

1. **Configure AI Provider (Optional)**
   ```bash
   ./build/zypheron config set-key claude
   # Or: deepseek, openai, google, etc.
   ```

2. **Run Autonomous Pentest**
   ```bash
   ./build/zypheron autopent <target> \
     --objective "<your objective>" \
     --ai-provider claude
   ```

3. **Session Management**
   ```bash
   # List saved sessions
   ./build/zypheron autopent --list-sessions

   # Resume a session
   ./build/zypheron autopent --resume session_abc123
   ```

### Command Options

```bash
zypheron autopent [target] [flags]

Flags:
  -o, --objective string      Attack objective (required)
                              Examples:
                                - "reach database server"
                                - "obtain domain admin"
                                - "access internal network"

      --ai-provider string    AI provider to use (optional)
                              Priority: claude > deepseek > openai > ollama
                              Default: auto (tries in priority order)

      --save                  Save session on completion
      --session-id string     Custom session ID
      --resume string         Resume saved session by ID
      --list-sessions         List all saved sessions
```

### Interactive Features

During execution, you'll be prompted for:

1. **Approval for High-Risk Actions**
   - `[1]` Approve (this action only)
   - `[2]` Approve for this session
   - `[3]` Deny
   - `[4]` Abort

2. **Credential Usage**
   - Prompts before using any discovered credentials
   - Can approve per-use or for entire session

3. **Error Recovery**
   - Prompts for decision on failures
   - Options: Retry, Try alternative, Skip, Abort

### Examples

#### Example 1: Basic Web Application Test
```bash
./build/zypheron autopent https://example.com \
  --objective "identify vulnerabilities in web app" \
  --ai-provider claude \
  --save
```

#### Example 2: Network Penetration Test
```bash
./build/zypheron autopent 10.0.0.0/24 \
  --objective "reach internal database server" \
  --ai-provider deepseek
```

#### Example 3: Resume Interrupted Session
```bash
# If interrupted (Ctrl+C), session is auto-saved
./build/zypheron autopent --list-sessions

# Resume
./build/zypheron autopent --resume session_abc123
```

---

## Troubleshooting

**Quick Reference**: See [HELP.md](../HELP.md) for solutions to common installation and build issues.

### Issue: "python3 not found"

**Solution:**
```bash
# Install Python 3
sudo apt update
sudo apt install python3 python3-venv python3-pip
```

### Issue: "autonomous orchestrator not found"

**Solution:**
```bash
# Rebuild Python environment
cd zypheron-go
make clean
make setup-autopent
```

### Issue: "externally-managed-environment" (pip error)

This should **not** occur with the current build system as it uses a virtual environment. If you see this:

**Solution:**
```bash
# Manually create venv
cd zypheron-ai
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### Issue: AI provider not working

**Symptoms:**
- "No AI provider available" error
- "API key not configured" warnings

**Solution:**
```bash
# Option 1: Configure cloud provider
./build/zypheron config set-key claude
# Enter your API key

# Option 2: Use local Ollama (no API key needed)
# Install Ollama: https://ollama.ai/
ollama run llama2

# Zypheron will auto-detect and use Ollama
```

### Issue: Tool execution fails

**Symptoms:**
- "nmap not found"
- "sqlmap not found"

**Solution:**
```bash
# Install required tools
sudo apt install nmap sqlmap nikto

# Or the tool will fall back to simulation mode
# Check logs for "using simulation" messages
```

### Issue: Build fails with Go import errors

**Solution:**
```bash
# Update Go dependencies
cd zypheron-go
go mod tidy
go get -u github.com/spf13/cobra@latest
make build
```

### Issue: Permission denied when running tools

**Solution:**
```bash
# Some tools (like nmap) may require sudo for certain scans
# Run with sudo if needed (and authorized)
sudo ./build/zypheron autopent <target> --objective "<goal>"
```

### Debug Mode

Enable debug logging:
```bash
./build/zypheron autopent <target> \
  --objective "<goal>" \
  --debug
```

---

## Architecture Overview

### Components

```
zypheron-go/              ← Go CLI (frontend)
├── cmd/zypheron/
│   └── main.go          ← Entry point
├── internal/commands/
│   ├── autopent.go      ← Autonomous pentest command
│   └── ...              ← Other commands
└── build/
    └── zypheron         ← Compiled binary (14MB)

zypheron-ai/              ← Python AI engine (backend)
├── .venv/               ← Virtual environment (auto-created)
├── autopent/            ← Phase 1 implementation
│   ├── autonomous_orchestrator.py  ← Main orchestrator
│   ├── attack_path_graph.py        ← Graph modeling
│   ├── ai_decision_engine.py       ← AI decision making
│   ├── approval_manager.py         ← User approval system
│   ├── credential_vault.py         ← Credential management
│   ├── interactive_prompt.py       ← Terminal UI
│   ├── session_state.py            ← Save/resume
│   └── tool_executor.py            ← Real tool execution
└── requirements.txt     ← Python dependencies
```

### Communication Flow

```
User → Go CLI → Python Runner → Autonomous Orchestrator
                                      ↓
                    ┌─────────────────┴─────────────────┐
                    │                                   │
              Attack Graph ←→ AI Engine ←→ Tool Executor
                    │                          ↓
              Approval Manager ←───── User Prompts
                    │
              Credential Vault
```

### Automatic Integration

The `make all` target ensures:
1. ✅ Go binary includes autopent command
2. ✅ Python venv is created automatically
3. ✅ All dependencies are installed
4. ✅ Runner script (`run_autopent.py`) is auto-generated
5. ✅ Go binary uses venv Python (not system Python)

No manual steps required! Just run `make all`.

---

## Installation (System-Wide)

```bash
cd zypheron-go

# Install to /usr/local/bin
sudo make install

# Test
zypheron --version
zypheron help autopent

# Uninstall
sudo make uninstall
```

---

## Next Steps

1. ✅ **Build Complete** - You now have a working Zypheron CLI with autonomous pentesting
2. 📚 **Read Documentation** - See [PHASE1_IMPLEMENTATION.md](PHASE1_IMPLEMENTATION.md) for detailed feature docs
3. 🔑 **Configure AI** - Set up your preferred AI provider API keys
4. 🎯 **Start Testing** - Use on authorized targets only
5. 📊 **Review Results** - Check saved sessions and reports

---

## Support

- **Issues:** https://github.com/KKingZero/Cobra-AI/issues
- **Documentation:** See `docs/` directory
---

## License

See [LICENSE](LICENSE) file for details.
