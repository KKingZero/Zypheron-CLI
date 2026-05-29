# Zypheron CLI Reference

Practical command reference for the Zypheron CLI. Use `zypheron --help` and `zypheron <command> --help` as the source of truth for your build.

For install: [INSTALL.md](INSTALL.md). For setup: [SETUP_AND_USE.md](SETUP_AND_USE.md).

## Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--debug` | `-d` | Verbose debug output |
| `--no-color` | | Disable colored output |
| `--no-banner` | | Disable ASCII banner |
| `--help` | `-h` | Show help |
| `--version` | `-v` | Show version |

## Core Commands

### TUI and Health

```bash
zypheron              # Launch TUI
zypheron tui          # Launch TUI explicitly
zypheron doctor       # Health check
zypheron install-deps # Install dependencies
```

### Scanning and Recon

```bash
zypheron scan [target] [flags]
zypheron recon [target]
```

**Scan flags:**
- `-t, --tool <name>` -- nmap, nikto, nuclei, masscan
- `-p, --ports <range>` -- port range (default: 1-1000)
- `--web` -- web application scanning
- `--full` -- full pentest suite
- `--fast` -- quick scan
- `--ai-guided` -- AI-guided with ML predictions
- `--ai-analysis` -- AI vulnerability analysis
- `--stream` -- real-time output (default: true)
- `--timeout <sec>` -- timeout (default: 300)
- `-o, --output <file>` -- save output
- `--format <type>` -- text, json, xml
- `-y, --yes` -- non-interactive

**Examples:**
```bash
zypheron scan example.com --tool nmap
zypheron scan https://example.com --web --ai-analysis
zypheron scan example.com -p 1-65535 --yes --no-input
```

### Binary Analysis

```bash
zypheron reverse-eng [binary] [flags]
zypheron pwn [binary] [flags]
zypheron forensics [target] [flags]
```

**Common flags:**
- `-t, --tool <name>` -- file, strings, radare2, gdb, ghidra, checksec, ropper, binwalk, volatility, etc.
- `-c, --chain <name>` -- use a tool chain
- `--timeout <sec>` -- timeout
- `-o, --output <file>` -- save output

**Examples:**
```bash
zypheron reverse-eng binary --tool radare2
zypheron reverse-eng binary --chain reverse_engineering
zypheron pwn binary --tool checksec
zypheron forensics memory.dump --tool volatility
zypheron forensics firmware.bin --tool binwalk
```

### Web and API Security

```bash
zypheron fuzz [target] [flags]       # Directory/file fuzzing (ffuf, gobuster)
zypheron osint [type] [target]       # OSINT (theharvester, subfinder, amass)
zypheron api-pentest [url] [flags]   # API security testing
```

**API pentest flags:**
- `--bola` -- test Broken Object Level Auth
- `--bfla` -- test Broken Function Level Auth
- `--rate-limit` -- test rate limiting
- `-o, --output <file>` -- save results

### AI Features

```bash
zypheron chat [message]              # AI security assistant
zypheron dork [query] [flags]        # AI-powered dorking
zypheron ai start|stop|status        # AI engine management
zypheron ai providers                # List providers
zypheron ai test --provider claude   # Test provider
```

**Dork flags:**
- `--ai-guided` -- AI-enhanced queries
- `-e, --engine <name>` -- google, bing
- `-m, --max-results <n>` -- max results

### Tool Management

```bash
zypheron tools check                           # Check installed tools
zypheron tools list [--installed] [--missing]  # List tools
zypheron tools info <tool>                     # Tool details
zypheron tools suggest <task>                  # Suggest tool for task
zypheron tools install <tool> [-y]             # Install tool
zypheron tools install-all [--critical-only]   # Install all tools
```

Optional C2 frameworks are not installed by the main installer. To opt in:

```bash
sudo bash scripts/install/install-c2.sh
```

### Exploitation and C2

```bash
zypheron exploit [target] [flags]
zypheron exploit --c2 sliver --listener mtls
zypheron exploit --c2 empire
zypheron exploit --c2 empire --listener http
```

**Exploit flags:**
- `--auto` -- automated exploitation mode
- `--manual` -- manual exploitation mode
- `--safe-mode` -- verification-focused mode
- `--c2 <framework>` -- sliver, empire, havoc, metasploit
- `--listener <type>` -- listener type such as mtls, https, or http

Empire uses its REST API instead of CLI arguments. Configure it with:

```bash
export EMPIRE_HOST=https://127.0.0.1:1337
export EMPIRE_USER=<username>
export EMPIRE_PASS=<password>
```

### Configuration

```bash
zypheron config show                    # View config
zypheron config path                    # Config file location
zypheron config get ai.provider         # Get value
zypheron config set ai.provider ollama  # Set value
zypheron config set-key anthropic       # Store API key
zypheron config get-providers           # List configured providers
```

### Workflows and Sessions

```bash
zypheron workflow list          # List workflows
zypheron autopent example.com  # Autonomous pentest
zypheron session list           # List sessions
zypheron history list           # Command history
```

### MCP (Model Context Protocol)

```bash
zypheron mcp config   # Generate MCP config for AI clients
zypheron mcp start    # Start MCP server
zypheron mcp status   # Check MCP status
```

## Additional Commands

The CLI also includes: `ad`, `cloud`, `mitre`, `compliance`, `exploit`, `pwn`, `api-pentest`, `plugin`, `schedule`, `scheduler`, `team`, and others. Some are more mature than others -- check `--help` before scripting.

## Example Workflows

### Full Pentest
```bash
zypheron recon example.com
zypheron scan example.com --full
zypheron scan https://example.com --web --ai-analysis
zypheron api-pentest https://api.example.com
```

### Binary Analysis
```bash
zypheron reverse-eng binary --tool file
zypheron reverse-eng binary --tool strings -o strings.txt
zypheron pwn binary --tool checksec
zypheron reverse-eng binary --chain reverse_engineering
```

---

See also: [TOOL_CHAINS.md](TOOL_CHAINS.md) | [MCP_INTEGRATION.md](MCP_INTEGRATION.md) | [AI_GUIDE.md](AI_GUIDE.md)
