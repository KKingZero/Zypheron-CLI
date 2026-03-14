# Zypheron CLI v1.3.0 - Open Source Edition

**Release Date:** January 2025
**Type:** Feature Release

---

## What's New

### Session Management
Save and resume your scan sessions. Never lose progress on long-running operations.

```bash
zypheron session list              # View saved sessions
zypheron session resume <id>       # Resume where you left off
zypheron session export <id>       # Export to JSON
```

### Scan History
Track all your scans with searchable history and statistics.

```bash
zypheron history                   # List recent scans
zypheron history stats             # View aggregated statistics
zypheron history search <query>    # Search by target, tool, or tags
```

### System Health Check
New `doctor` command to verify your environment is properly configured.

```bash
zypheron doctor                    # Check installed tools
zypheron doctor --verbose          # Show versions and paths
```

### Enhanced Configuration
BYOK (Bring Your Own Key) model with JSON persistence.

```bash
zypheron config show               # View all settings
zypheron config set <key> <value>  # Update configuration
zypheron config reset              # Reset to defaults
```

### AI Providers
- **Ollama** (default) - Local AI, no API key needed
- **DeepSeek** - BYOK via `DEEPSEEK_API_KEY`
- **Anthropic** - BYOK via `ANTHROPIC_API_KEY`
- **OpenAI** - BYOK via `OPENAI_API_KEY`

### Error Recovery
- Automatic retry with exponential backoff
- Circuit breaker for external services
- Graceful degradation in offline mode

### Report Export
Export scan results to JSON format.

```bash
zypheron session export <id> output.json
```

---

## New Commands

| Command | Description |
|---------|-------------|
| `zypheron doctor` | System health check |
| `zypheron session list` | List saved sessions |
| `zypheron session resume <id>` | Resume a session |
| `zypheron session export <id>` | Export session to JSON |
| `zypheron session delete <id>` | Delete a session |
| `zypheron history` | List scan history |
| `zypheron history stats` | Show statistics |
| `zypheron history search <q>` | Search history |
| `zypheron history clear` | Clear all history |
| `zypheron config show` | Display configuration |
| `zypheron config reset` | Reset to defaults |

---

## Installation

### From Source
```bash
git clone https://github.com/KKingZero/Zypheron-CLI.git
cd Zypheron-CLI/zypheron-go
go build -o zypheron ./cmd/zypheron
sudo mv zypheron /usr/local/bin/
```

### Verify
```bash
zypheron --version
zypheron doctor
```

---

## Configuration

Config stored at `~/.zypheron/config.json`

### Local AI (Ollama - Default)
```bash
# No configuration needed, just install Ollama
ollama pull codellama
zypheron scan target.com --ai
```

### Cloud AI (BYOK)
```bash
export DEEPSEEK_API_KEY=sk-your-key
export ZYPHERON_AI_PROVIDER=deepseek
zypheron scan target.com --ai
```

---

## Directory Structure

```
~/.zypheron/
├── config.json      # Configuration
├── sessions/        # Saved sessions
├── history/         # Scan history
├── reports/         # Exported reports
├── cache/           # AI response cache
└── logs/            # Error logs
```

---

## Supported Tools

| Tool | Category | Required |
|------|----------|----------|
| nmap | Scanning | Yes |
| nikto | Web | No |
| nuclei | Web | No |
| masscan | Scanning | No |
| gobuster | Web | No |
| ffuf | Web | No |
| sqlmap | Exploit | No |
| subfinder | Recon | No |
| amass | Recon | No |
| whatweb | Recon | No |
| wpscan | Web | No |
| hydra | Exploit | No |

---

## Requirements

- Go 1.21+ (for building)
- nmap (required)
- Linux/macOS/Windows

---

## What's NOT Included (Pro Only)

- TUI interface
- Post-exploitation modules
- HTML/PDF reports
- Cloud AI (included)
- Priority support

---

## Changelog

### Added
- Session save/resume system
- Scan history with search and statistics
- `doctor` command for system health check
- JSON report export
- BYOK configuration model
- Ollama as default local AI
- Error recovery with retry and circuit breaker
- Offline mode with graceful degradation
- Enhanced `config` commands

### Changed
- Config now persists to `~/.zypheron/config.json`
- Default AI provider changed to Ollama (local)
- Improved CLI help and documentation

### Security Fixes
- **CRITICAL:** Fixed command injection vulnerability in binary path handling (pwn.go)
- **CRITICAL:** Fixed goroutine leak with panic recovery in session auto-save
- **CRITICAL:** Fixed deadlock from spawning goroutine while holding mutex lock
- **CRITICAL:** Fixed resource leak in tool executor (channels now properly closed)
- **HIGH:** Fixed missing mutex in session Complete() function
- **HIGH:** Fixed TOCTOU race condition in circuit breaker half-open state
- **HIGH:** Fixed file descriptor exhaustion from defer in loop (tests.go)
- **MEDIUM:** Enhanced shell metacharacter validation (added quotes, null byte)

### Fixed
- Various stability improvements
- Better error messages
- Improved thread safety throughout codebase

---

## Checksums

```
SHA256 (zypheron-linux-amd64)   = <to be filled>
SHA256 (zypheron-linux-arm64)   = <to be filled>
SHA256 (zypheron-darwin-amd64)  = <to be filled>
SHA256 (zypheron-darwin-arm64)  = <to be filled>
SHA256 (zypheron-windows-amd64) = <to be filled>
```

---

## Links

- **Documentation:** https://github.com/KKingZero/Zypheron-CLI/blob/main/README.md
- **Issues:** https://github.com/KKingZero/Zypheron-CLI/issues
- **Pro Version:** https://github.com/KKingZero/Cobra-AI

---

**Full Changelog:** https://github.com/KKingZero/Zypheron-CLI/compare/v1.2.0...v1.3.0
