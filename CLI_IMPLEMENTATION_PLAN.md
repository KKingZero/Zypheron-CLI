# 🐍 Zypheron CLI - Kali Linux Integration Plan

## Overview
Transform Zypheron into a full-featured CLI platform combining Kali Linux tool integration with Claude-style AI interactions.

---

## 🎨 Design Philosophy

### **Aesthetic: Kali Terminal + Claude Code**
- **Color Scheme**: Kali's signature cyan/green on dark background
- **Typography**: Monospace with syntax highlighting
- **Interactions**: Claude-style streaming responses with thoughtful pauses
- **Feedback**: Immediate, informative, with professional security researcher tone

### **Terminal Experience**
```
┌─[⚡ zypheron]─[~/projects]
└──╼ $ zypheron scan --target example.com

[*] Initializing Zypheron Security Scanner v1.0.0
[*] Target: example.com (93.184.216.34)
[*] Detected Tools: nmap ✓, nikto ✓, sqlmap ✓, metasploit ✓

┌─────────────────────────────────────────────────────────────┐
│ 🎯 Reconnaissance Phase                            [1/5]    │
└─────────────────────────────────────────────────────────────┘

[+] Running nmap -sV -sC -O example.com
    ├─ Port 80/tcp    open  http    nginx 1.19.0
    ├─ Port 443/tcp   open  https   nginx 1.19.0
    └─ Port 22/tcp    open  ssh     OpenSSH 8.2p1

[+] AI Analysis: Based on the open ports, I've identified...
    ╭─────────────────────────────────────────────────────╮
    │ The target is running nginx 1.19.0 which has a     │
    │ known CVE-2021-23017 vulnerability. OpenSSH 8.2p1  │
    │ is relatively secure but check for weak configs... │
    ╰─────────────────────────────────────────────────────╯
```

---

## 🛠️ Kali Tool Integration Architecture

### **Tool Detection System**
```typescript
// src/cli/core/kali-tools.ts
export interface KaliTool {
  name: string
  command: string
  aliases: string[]
  installed: boolean
  version?: string
  requiredFor: string[]  // Which zypheron commands need this
  installCmd: string     // How to install if missing
}

export class KaliToolManager {
  private tools: Map<string, KaliTool>
  
  // Auto-detect installed Kali tools
  async detectTools(): Promise<KaliTool[]>
  
  // Check if tool is available
  isAvailable(toolName: string): boolean
  
  // Get installation instructions
  getInstallInstructions(toolName: string): string
  
  // Verify tool compatibility
  checkCompatibility(toolName: string): ToolCompatibility
}
```

### **Supported Kali Tools Matrix**

| Tool | Zypheron Command | Integration Type | Priority |
|------|------------------|------------------|----------|
| **nmap** | `scan`, `recon` | Direct execution | Critical |
| **nikto** | `scan --web` | Direct execution | High |
| **sqlmap** | `scan --sql`, `exploit` | Direct execution | High |
| **metasploit** | `exploit`, `post-exploit` | RPC/CLI | Critical |
| **gobuster** | `scan --dirs` | Direct execution | High |
| **wfuzz** | `fuzz` | Direct execution | Medium |
| **hydra** | `bruteforce` | Direct + native | High |
| **john** | `bruteforce hash` | Direct + native | Medium |
| **hashcat** | `bruteforce hash` | Direct + native | High |
| **aircrack-ng** | `wireless` | Direct execution | Medium |
| **wireshark/tshark** | `capture` | Direct execution | Medium |
| **masscan** | `scan --fast` | Direct execution | High |
| **nuclei** | `scan --templates` | Direct execution | High |
| **subfinder** | `recon subdomain` | Direct execution | Medium |
| **amass** | `recon --deep` | Direct execution | Medium |
| **burpsuite** | `proxy`, `scan --web` | Proxy integration | Medium |
| **zaproxy** | `proxy`, `scan --web` | API integration | Medium |
| **ffuf** | `fuzz` | Direct execution | High |
| **recon-ng** | `osint` | Python module | Low |
| **theHarvester** | `osint email` | Direct execution | Medium |
| **maltego** | `osint --visual` | Export format | Low |

### **Tool Execution Framework**

```typescript
// src/cli/core/tool-executor.ts
export class ToolExecutor {
  private toolManager: KaliToolManager
  private outputParser: OutputParser
  
  async execute(options: ExecutionOptions): Promise<ToolResult> {
    // 1. Verify tool availability
    if (!this.toolManager.isAvailable(options.tool)) {
      return this.handleMissingTool(options.tool)
    }
    
    // 2. Build command with security sanitization
    const command = this.buildCommand(options)
    
    // 3. Execute with real-time output streaming
    const process = spawn(command, {
      shell: true,
      stdio: ['pipe', 'pipe', 'pipe']
    })
    
    // 4. Stream output to terminal with syntax highlighting
    process.stdout.on('data', (data) => {
      this.streamOutput(data, options.format)
    })
    
    // 5. Parse structured output
    const result = await this.parseOutput(process)
    
    // 6. AI enhancement (optional)
    if (options.aiAnalysis) {
      result.aiInsights = await this.getAIAnalysis(result)
    }
    
    return result
  }
  
  // Smart output parsing for each tool
  private async parseOutput(process: ChildProcess): Promise<any> {
    // Parse nmap XML, nikto JSON, sqlmap output, etc.
  }
}
```

### **Integration Patterns**

#### **Pattern 1: Direct Execution (nmap, nikto, etc.)**
```typescript
// User runs: zypheron scan --target example.com
//
// Behind the scenes:
// 1. Detect available tools
// 2. Run: nmap -sV -sC -A example.com -oX output.xml
// 3. Parse XML output in real-time
// 4. Display formatted results with Kali-style colors
// 5. Optional: AI analysis of findings
```

#### **Pattern 2: Native + Fallback (hydra, hashcat)**
```typescript
// User runs: zypheron bruteforce ssh --host 192.168.1.1
//
// Behind the scenes:
// 1. Check if hydra is installed
// 2a. If YES: Use hydra for faster execution
//     → hydra -L users.txt -P pass.txt ssh://192.168.1.1
// 2b. If NO: Use native Node.js implementation
//     → backend/services/nativeBruteforce.ts
// 3. Stream progress with success indicators
```

#### **Pattern 3: API Integration (metasploit, burp, zap)**
```typescript
// User runs: zypheron exploit --module exploit/windows/smb/ms17_010
//
// Behind the scenes:
// 1. Connect to msfrpcd (Metasploit RPC daemon)
// 2. Select and configure module
// 3. Execute exploit
// 4. Stream results to terminal
// 5. Offer post-exploitation options
```

#### **Pattern 4: Docker Execution (isolated tools)**
```typescript
// User runs: zypheron scan --tool nikto --isolated
//
// Behind the scenes:
// 1. Check for cobra-ai-kali-pentest Docker image
// 2. Run: docker run --rm cobra-ai-kali-pentest nikto -h example.com
// 3. Stream output from container
// 4. Auto-cleanup
```

---

## 📦 CLI Project Structure

```
zypheron-cli/
├── package.json
├── tsconfig.json
├── .eslintrc.js
│
├── bin/
│   └── zypheron.js                    # Shebang executable
│
├── src/
│   ├── index.ts                       # CLI entry point
│   │
│   ├── cli/
│   │   ├── commands/
│   │   │   ├── index.ts               # Command registry
│   │   │   ├── chat.ts                # AI chat with streaming
│   │   │   ├── scan.ts                # Nmap/Nikto/Nuclei integration
│   │   │   ├── exploit.ts             # Metasploit/SQLMap integration
│   │   │   ├── recon.ts               # Subfinder/Amass/TheHarvester
│   │   │   ├── bruteforce.ts          # Hydra/John/Hashcat
│   │   │   ├── fuzz.ts                # Ffuf/Wfuzz
│   │   │   ├── osint.ts               # Recon-ng/Maltego
│   │   │   ├── wireless.ts            # Aircrack-ng suite
│   │   │   ├── capture.ts             # Tshark/Wireshark
│   │   │   ├── proxy.ts               # Burp/ZAP integration
│   │   │   ├── report.ts              # Report generation
│   │   │   ├── dashboard.ts           # TUI dashboard
│   │   │   ├── tools.ts               # Tool management
│   │   │   └── config.ts              # Configuration
│   │   │
│   │   ├── ui/
│   │   │   ├── themes/
│   │   │   │   ├── kali.ts            # Kali color scheme
│   │   │   │   └── claude.ts          # Claude-inspired theme
│   │   │   ├── components/
│   │   │   │   ├── banner.ts          # ASCII art banners
│   │   │   │   ├── spinner.ts         # Custom spinners
│   │   │   │   ├── progress.ts        # Progress bars
│   │   │   │   ├── table.ts           # Result tables
│   │   │   │   ├── tree.ts            # Directory trees
│   │   │   │   ├── panel.ts           # Info panels
│   │   │   │   ├── stream.ts          # Live output streaming
│   │   │   │   └── prompt.ts          # Interactive prompts
│   │   │   ├── layouts/
│   │   │   │   ├── dashboard.ts       # Blessed dashboard
│   │   │   │   ├── split-pane.ts      # Multi-pane view
│   │   │   │   └── terminal.ts        # Terminal emulator
│   │   │   └── renderer.ts            # Markdown/syntax renderer
│   │   │
│   │   └── core/
│   │       ├── kali-tools.ts          # Kali tool manager
│   │       ├── tool-executor.ts       # Tool execution engine
│   │       ├── output-parser.ts       # Parse tool outputs
│   │       ├── ai-integration.ts      # AI analysis layer
│   │       ├── api-client.ts          # Backend API client
│   │       ├── config-manager.ts      # Configuration system
│   │       ├── session-manager.ts     # Session persistence
│   │       ├── auth-manager.ts        # Authentication
│   │       └── plugin-system.ts       # Plugin loader
│   │
│   ├── utils/
│   │   ├── logger.ts                  # CLI logging
│   │   ├── colors.ts                  # Color utilities
│   │   ├── formatters.ts              # Output formatting
│   │   ├── validators.ts              # Input validation
│   │   ├── sanitizers.ts              # Command sanitization
│   │   ├── exporters.ts               # Export utilities
│   │   └── helpers.ts                 # Helper functions
│   │
│   └── types/
│       ├── commands.ts                # Command types
│       ├── tools.ts                   # Tool types
│       ├── results.ts                 # Result types
│       └── config.ts                  # Config types
│
├── config/
│   ├── default.json                   # Default config
│   ├── kali-tools.json                # Tool definitions
│   └── profiles/                      # User profiles
│
├── completions/
│   ├── zypheron.bash                  # Bash completion
│   └── zypheron.zsh                   # Zsh completion
│
├── templates/
│   ├── reports/                       # Report templates
│   └── banners/                       # ASCII art
│
├── plugins/                           # Plugin directory
│
└── tests/
    ├── unit/
    ├── integration/
    └── e2e/
```

---

## 🎯 Command Implementation Details

### **1. `zypheron scan` - Enhanced with Kali Tools**

```bash
# Auto-detect and use best tools
zypheron scan example.com

# Use specific tool
zypheron scan example.com --tool nmap
zypheron scan example.com --tool nuclei

# Combine tools
zypheron scan example.com --tools nmap,nikto,nuclei

# Custom nmap scan
zypheron scan example.com --nmap-args "-sS -T4 -A"

# Web application focus
zypheron scan example.com --web
# Uses: nikto, nuclei, gobuster, sqlmap

# Full pentest suite
zypheron scan example.com --full
# Uses: nmap, nikto, nuclei, gobuster, sqlmap, wfuzz

# With AI guidance
zypheron scan example.com --ai-guided
# AI suggests tools based on initial findings
```

**Implementation:**
```typescript
export async function scanCommand(options: ScanOptions) {
  const ui = new KaliUI()
  ui.showBanner('Zypheron Security Scanner')
  
  // 1. Tool detection
  const availableTools = await toolManager.detectTools()
  ui.showToolStatus(availableTools)
  
  // 2. Target validation
  const target = await validateTarget(options.target)
  ui.showTarget(target)
  
  // 3. Execute scan phases
  const phases = determineScanPhases(options, availableTools)
  
  for (const phase of phases) {
    ui.startPhase(phase.name)
    
    // Execute tools in parallel where possible
    const results = await executePhase(phase, target)
    
    // Stream results as they come in
    results.on('data', (data) => ui.streamResult(data))
    
    // AI analysis after each phase
    if (options.aiAnalysis) {
      const insights = await aiAnalyze(results)
      ui.showAIInsights(insights)
    }
  }
  
  // 4. Final report
  ui.showSummary(allResults)
  
  // 5. Export options
  await promptExport(allResults)
}
```

### **2. `zypheron chat` - Claude-Style AI Interface**

```bash
# Interactive mode
zypheron chat

# Quick question
zypheron chat "How do I exploit SQL injection in this form?"

# With context from scan
zypheron chat --scan scan-123 "Analyze these results"

# Specific model
zypheron chat --model claude-3-opus "Explain this vulnerability"

# Stream mode (watch files/processes)
zypheron chat --watch nmap-scan.xml
```

**Terminal Interface:**
```
┌─[⚡ zypheron chat]─[gpt-4]──────────────────────────────────┐
│                                                              │
│ You: How can I test for SQL injection in a login form?      │
│                                                              │
│ 🤖 Zypheron: Let me explain SQL injection testing...        │
│                                                              │
│ SQL injection testing involves several approaches:          │
│                                                              │
│ 1. Manual Testing:                                          │
│    ├─ Try basic payloads like ' OR '1'='1                   │
│    ├─ Test with different quote types                       │
│    └─ Look for error messages                               │
│                                                              │
│ 2. Automated Tools:                                         │
│    ┌────────────────────────────────────────────┐          │
│    │ $ zypheron scan --sql http://target/login │          │
│    │ $ sqlmap -u "http://target/login"         │          │
│    └────────────────────────────────────────────┘          │
│                                                              │
│ 3. Would you like me to:                                    │
│    [1] Run sqlmap for you                                   │
│    [2] Show more manual techniques                          │
│    [3] Explain prevention methods                           │
│                                                              │
└──────────────────────────────────────────────────────────────┘
[Ctrl+C to exit | Ctrl+L to clear | ↑↓ for history]
```

### **3. `zypheron dashboard` - Real-Time TUI**

```bash
zypheron dashboard

# Specific view
zypheron dashboard --view scans

# Monitor specific scan
zypheron dashboard --scan scan-123
```

**Dashboard Layout (Blessed TUI):**
```
┌─[⚡ ZYPHERON DASHBOARD]────────────────────────────[14:32:15]─┐
│                                                                │
│ ┌─[Active Scans]──────────────┐  ┌─[Recent Findings]────────┐│
│ │                              │  │                           ││
│ │ ⚡ scan-123: example.com     │  │ 🔴 CRITICAL: SQL Inj     ││
│ │    └─ Phase: Exploitation   │  │ 🟠 HIGH: XSS in /search  ││
│ │    └─ Progress: ████░░ 65%  │  │ 🟡 MEDIUM: Info Discl.   ││
│ │                              │  │ 🔵 LOW: Cookie Settings  ││
│ │ ⚡ scan-124: 192.168.1.0/24  │  │                           ││
│ │    └─ Phase: Reconnaissance  │  │ Total Vulns: 47          ││
│ │    └─ Progress: ██░░░░ 35%  │  │ Scans Today: 12          ││
│ │                              │  │                           ││
│ └──────────────────────────────┘  └───────────────────────────┘│
│                                                                │
│ ┌─[Tool Status]───────────────┐  ┌─[AI Agent Activity]──────┐│
│ │                              │  │                           ││
│ │ nmap      ✓ v7.94           │  │ 🤖 Analyzing findings... ││
│ │ nikto     ✓ v2.1.6          │  │                           ││
│ │ sqlmap    ✓ v1.7            │  │ "Based on port 8080      ││
│ │ metasploit✓ v6.3.5          │  │  being open, I recommend ││
│ │ nuclei    ✓ v3.1.0          │  │  testing for Tomcat      ││
│ │ gobuster  ✓ v3.6            │  │  default credentials..." ││
│ │                              │  │                           ││
│ └──────────────────────────────┘  └───────────────────────────┘│
│                                                                │
│ ┌─[Live Output]──────────────────────────────────────────────┐│
│ │ [+] Starting nmap scan...                                  ││
│ │ [*] Discovered open port 22/tcp on 192.168.1.100         ││
│ │ [*] Discovered open port 80/tcp on 192.168.1.100         ││
│ │ [+] Running service detection...                          ││
│ │ [+] Port 80: nginx 1.19.0                                 ││
│ │ [!] AI Alert: nginx 1.19.0 has CVE-2021-23017           ││
│ └────────────────────────────────────────────────────────────┘│
│                                                                │
└─[F1 Help | F2 Scans | F3 Tools | F4 AI | F5 Logs | Q Quit]───┘
```

---

## 🎨 Kali + Claude Aesthetic Details

### **Color Scheme**
```typescript
// src/cli/ui/themes/kali.ts
export const KaliTheme = {
  primary: '#00FF00',      // Kali green
  secondary: '#00FFFF',    // Cyan
  danger: '#FF0000',       // Red
  warning: '#FFFF00',      // Yellow
  info: '#00BFFF',         // Sky blue
  success: '#00FF00',      // Green
  muted: '#808080',        // Gray
  
  background: '#0A0E14',   // Dark
  foreground: '#B3B1AD',   // Light gray
  
  prompt: '#00FF00',       // Green prompt
  command: '#00FFFF',      // Cyan commands
  output: '#B3B1AD',       // Gray output
  
  // Threat levels
  critical: '#FF0000',     // Red
  high: '#FF6600',         // Orange
  medium: '#FFFF00',       // Yellow
  low: '#00BFFF',          // Blue
  info: '#808080',         // Gray
}
```

### **Typography**
```typescript
// Kali-style prompt
[⚡]─[user@zypheron]─[~/targets]
└──╼ $ _

// Status indicators (like Kali)
[+] Success message
[*] Informational message
[!] Warning message
[-] Error message
[?] Question/prompt
```

### **ASCII Art Banners**
```
╔═══════════════════════════════════════════════════════════╗
║  ███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗║
║  ╚══███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔═══██╗
║    ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝██║   ██║║
║   ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║║
║  ███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║╚██████╔╝║
║  ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ║
║                                                               ║
║           AI-Powered Penetration Testing Platform            ║
║                    v1.0.0 | Kali Edition                     ║
╚═══════════════════════════════════════════════════════════╝
```

---

## 🔧 Shell Integration (Bash & Zsh)

### **Completion Scripts**

**Bash (`completions/zypheron.bash`):**
```bash
#!/bin/bash

_zypheron_completions() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    commands="chat scan threat exploit recon bruteforce fuzz osint report dashboard tools config"
    
    case "${prev}" in
        zypheron)
            COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
            return 0
            ;;
        scan)
            COMPREPLY=( $(compgen -W "--target --tool --tools --web --full --ai-guided --output" -- ${cur}) )
            return 0
            ;;
        --tool|--tools)
            local tools="nmap nikto nuclei sqlmap gobuster metasploit"
            COMPREPLY=( $(compgen -W "${tools}" -- ${cur}) )
            return 0
            ;;
    esac
}

complete -F _zypheron_completions zypheron
```

**Zsh (`completions/zypheron.zsh`):**
```zsh
#compdef zypheron

_zypheron() {
    local -a commands
    commands=(
        'chat:Interactive AI chat interface'
        'scan:Security scanning with Kali tools'
        'threat:Threat intelligence analysis'
        'exploit:Exploitation framework'
        'recon:Reconnaissance operations'
        'bruteforce:Credential attacks'
        'fuzz:Web fuzzing'
        'osint:OSINT operations'
        'report:Report generation'
        'dashboard:Real-time monitoring dashboard'
        'tools:Manage Kali tools'
        'config:Configuration management'
    )
    
    _arguments \
        '1: :->command' \
        '*:: :->args'
    
    case $state in
        command)
            _describe 'command' commands
            ;;
        args)
            case $words[1] in
                scan)
                    _arguments \
                        '--target[Target URL or IP]:target:' \
                        '--tool[Specific tool to use]:tool:(nmap nikto nuclei sqlmap)' \
                        '--web[Web application focus]' \
                        '--full[Full pentest suite]' \
                        '--ai-guided[AI-guided scanning]'
                    ;;
            esac
            ;;
    esac
}

_zypheron "$@"
```

### **Installation Script**
```bash
# Install completion scripts
if [ -n "$BASH_VERSION" ]; then
    cp completions/zypheron.bash /etc/bash_completion.d/zypheron
elif [ -n "$ZSH_VERSION" ]; then
    cp completions/zypheron.zsh /usr/share/zsh/site-functions/_zypheron
fi
```

---

## 📋 Implementation Priority

### **Phase 1: Foundation (Week 1-2)**
- [x] Project structure setup
- [ ] CLI framework (Commander.js)
- [ ] Kali tool detection system
- [ ] Basic UI components (colors, spinners, tables)
- [ ] Configuration system

### **Phase 2: Core Commands (Week 3-4)**
- [ ] `zypheron scan` with nmap integration
- [ ] `zypheron chat` with streaming AI
- [ ] `zypheron tools` for tool management
- [ ] Output parsing system

### **Phase 3: Advanced Tools (Week 5-6)**
- [ ] Nikto, nuclei, sqlmap integration
- [ ] Metasploit RPC integration
- [ ] Hydra/John/Hashcat integration
- [ ] Real-time output streaming

### **Phase 4: TUI & Polish (Week 7-8)**
- [ ] Blessed dashboard
- [ ] Shell completions
- [ ] Plugin system
- [ ] Documentation

---

## 🚀 Quick Start Commands

```bash
# Install
npm install -g @zypheron/cli

# Setup (install completions, detect tools)
zypheron setup

# Check tool availability
zypheron tools check

# Run your first scan
zypheron scan example.com --ai-guided

# Launch dashboard
zypheron dashboard

# Interactive chat
zypheron chat
```

---

## 🔐 Security Considerations

1. **Command Injection Prevention**: All tool arguments sanitized
2. **Isolated Execution**: Docker option for untrusted scans
3. **Audit Logging**: All commands logged for review
4. **Safe Defaults**: Conservative scan settings by default
5. **Permission Checks**: Verify tool permissions before execution

---

This plan creates a professional CLI that feels native to Kali Linux while adding AI-powered intelligence!

