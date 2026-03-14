# Zypheron TUI Implementation Plan

> Terminal User Interface using Bubbletea - Claude Code + Strix inspired design

**Version**: 1.0.0
**Status**: Planning Complete
**Target**: zypheron-go/internal/tui/

---

## Design Overview

### Visual Layout

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  [S]can  [R]econ  [A]I  [T]ools  [H]istory          Zypheron > Scan > nmap   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║                                                                              ║
║                         MAIN CONTENT AREA                                    ║
║                                                                              ║
║              Single pane - switches between views via tabs                   ║
║              Hybrid mode: Raw output <-> Parsed/structured                   ║
║                                                                              ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  AI: Contextual insights appear here based on current view content.          ║
║  Moderate verbosity - paragraph with actionable recommendations.             ║
║  > _                                                          [Enter to ask] ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  [Recon] -> [Scan] -> [Analysis]       :cmd  /search  j/k  ?help  q:quit    ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### Design Decisions Summary

| Aspect | Decision | Notes |
|--------|----------|-------|
| **Layout** | Single pane with tabs | Clean, focused interface |
| **Theme** | Minimal monochrome | Black/white/gray, subtle accents |
| **Borders** | Double-line accent | `╔═╗ ╚═╝` Unicode box drawing |
| **Navigation** | Breadcrumb + quick-launch | `Zypheron > Scan > nmap` |
| **Tabs** | Top bar with shortcuts | `[S]can [R]econ [A]I [T]ools [H]istory` |
| **Keybindings** | Hybrid (vim + arrows) | `j/k` and `↑/↓` both work |
| **Input** | Command palette | `:` or `/` to enter commands |
| **Transitions** | Fade/dissolve | Smooth view switching |
| **AI Chat** | Bottom panel (fixed) | Always visible, resizable |
| **Progress** | Phase-based | `[Recon] → [Scan] → [Analysis]` |
| **Findings** | Hybrid table/tree | Toggle between views |
| **Notifications** | Status line updates | Non-intrusive |
| **Critical alerts** | Highlight in output | Bold/color, no popup |
| **Empty states** | Tips + ASCII art | Helpful onboarding |
| **Help** | Always visible in status | Key hints shown |
| **Mouse** | Scroll only | Wheel scrolling, keyboard nav |
| **Resize** | Responsive | Auto-adapt to terminal size |
| **Persistence** | SQLite database | Full scan history |
| **Min terminal** | 80x24 | Classic terminal support |
| **Entry point** | Default mode | `zypheron` launches TUI, `--no-tui` for classic |
| **Background scans** | Warn and confirm | Dialog on quit if scan running |
| **Splash screen** | Yes (1-2 sec) | ASCII logo fade to dashboard |

---

## Architecture

### Package Structure

```
zypheron-go/internal/tui/
├── app.go                 # Main TUI application entry
├── model.go               # Root model (implements tea.Model)
├── keys.go                # Keybinding definitions
├── messages.go            # Custom message types
│
├── views/
│   ├── dashboard.go       # Dashboard overview view
│   ├── scan.go            # Scan monitor view
│   ├── results.go         # Results browser view
│   ├── history.go         # Scan history view
│   └── recon.go           # Reconnaissance view
│
├── components/
│   ├── header.go          # Top bar (quick-launch + breadcrumb)
│   ├── statusbar.go       # Bottom status bar (keys + progress)
│   ├── aipanel.go         # Fixed AI chat panel
│   ├── table.go           # Results table component
│   ├── tree.go            # Results tree component
│   ├── output.go          # Raw/parsed output viewer
│   ├── progress.go        # Phase-based progress indicator
│   └── input.go           # Command palette input
│
├── styles/
│   └── styles.go          # Lipgloss styling definitions
│
└── store/
    ├── store.go           # SQLite persistence layer
    └── models.go          # Database models
```

### Dependencies

```go
// go.mod additions
require (
    github.com/charmbracelet/bubbletea v1.2.4
    github.com/charmbracelet/bubbles v0.20.0
    github.com/charmbracelet/lipgloss v1.0.0
    github.com/mattn/go-sqlite3 v1.14.22
)
```

---

## Component Specifications

### 1. Header Component

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  [S]can  [R]econ  [A]I  [T]ools  [H]istory          Zypheron > Scan > nmap   ║
╠══════════════════════════════════════════════════════════════════════════════╣
```

**Features:**

- Quick-launch shortcuts (left side)
- Breadcrumb navigation (right side)
- Active tab highlighted
- Double-line border style

**Keybindings:**

- `S` - Switch to Scan view
- `R` - Switch to Recon view
- `A` - Focus AI panel
- `T` - Switch to Tools view
- `H` - Switch to History view

### 2. Main Content Area

**Views:**

| View | Content | Features |
|------|---------|----------|
| **Dashboard** | Overview stats | Recent scans, findings count, system health |
| **Scan** | Live output | Hybrid raw/parsed, phase progress |
| **Results** | Findings browser | Table ↔ Tree toggle, severity filter |
| **History** | Past scans | Search, compare, re-run |
| **Recon** | Recon tools | Subdomain, OSINT, harvesting |

**Hybrid Output Mode:**

- `Tab` or `v` to toggle between Raw and Parsed view
- Raw: Streaming terminal output with ANSI colors
- Parsed: Structured cards/sections (ports, vulns, services)

### 3. AI Panel (Fixed Bottom)

```
╠══════════════════════════════════════════════════════════════════════════════╣
║  AI: Contextual insights appear here based on current view content.          ║
║  Moderate verbosity - paragraph with actionable recommendations.             ║
║  > _                                                          [Enter to ask] ║
╠══════════════════════════════════════════════════════════════════════════════╣
```

**Features:**

- Context-aware insights (analyzes current view content)
- Input line for questions (`> _`)
- Moderate verbosity (1 paragraph)
- Resizable height (`Ctrl+↑/↓`)
- Collapsible (`Ctrl+A` to minimize/expand)

**AI Integration:**

- Uses existing `aibridge` package
- Streams responses in real-time
- Maintains conversation context per session

### 4. Status Bar

```
╠══════════════════════════════════════════════════════════════════════════════╣
║  [Recon] -> [Scan] -> [Analysis]       :cmd  /search  j/k  ?help  q:quit    ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

**Left side:** Phase-based progress indicator
**Right side:** Always-visible key hints

**Progress Phases:**

1. `[Recon]` - Reconnaissance phase
2. `[Scan]` - Active scanning
3. `[Analysis]` - AI analysis & reporting

---

## Keybinding Reference

### Global Keys

| Key | Action |
|-----|--------|
| `q` / `Ctrl+C` | Quit TUI |
| `?` | Show help overlay |
| `:` | Open command palette |
| `/` | Search/filter |
| `Tab` | Toggle view mode (raw/parsed) |
| `Esc` | Close overlay/cancel |

### Navigation

| Key | Action |
|-----|--------|
| `j` / `↓` | Move down |
| `k` / `↑` | Move up |
| `h` / `←` | Move left / collapse |
| `l` / `→` | Move right / expand |
| `g` | Go to top |
| `G` | Go to bottom |
| `Ctrl+d` | Page down |
| `Ctrl+u` | Page up |

### View Switching

| Key | Action |
|-----|--------|
| `S` | Scan view |
| `R` | Recon view |
| `A` | Focus AI panel |
| `T` | Tools view |
| `H` | History view |
| `D` | Dashboard view |

### Actions

| Key | Action |
|-----|--------|
| `Enter` | Select / Execute |
| `Space` | Toggle selection |
| `r` | Refresh / Re-run |
| `e` | Export results |
| `c` | Copy to clipboard |

---

## Color Scheme (Monochrome)

```go
// styles/styles.go
var (
    // Base colors
    ColorFg        = lipgloss.Color("#FFFFFF")  // White text
    ColorBg        = lipgloss.Color("#000000")  // Black background
    ColorMuted     = lipgloss.Color("#666666")  // Gray for secondary
    ColorAccent    = lipgloss.Color("#AAAAAA")  // Light gray accent

    // Semantic colors (subtle)
    ColorCritical  = lipgloss.Color("#FF6B6B")  // Red for critical
    ColorHigh      = lipgloss.Color("#FFA94D")  // Orange for high
    ColorMedium    = lipgloss.Color("#FFE066")  // Yellow for medium
    ColorLow       = lipgloss.Color("#69DB7C")  // Green for low
    ColorInfo      = lipgloss.Color("#74C0FC")  // Blue for info

    // UI elements
    ColorBorder    = lipgloss.Color("#444444")  // Border color
    ColorHighlight = lipgloss.Color("#333333")  // Selection highlight
)
```

---

## Implementation Phases

### Phase 1: Foundation (Core Structure)

- [ ] Set up tui package structure
- [ ] Add bubbletea/lipgloss dependencies
- [ ] Implement root model with view switching
- [ ] Create styles package
- [ ] Implement header component
- [ ] Implement status bar component
- [ ] Basic keyboard navigation

### Phase 2: Views

- [ ] Dashboard view (stats, recent scans)
- [ ] Scan view (output streaming)
- [ ] Results view (table + tree toggle)
- [ ] History view (SQLite integration)
- [ ] Recon view (tool launcher)

### Phase 3: AI Integration

- [ ] AI panel component
- [ ] Aibridge integration
- [ ] Context-aware prompts
- [ ] Response streaming
- [ ] Input handling

### Phase 4: Advanced Features

- [ ] Command palette (`:` commands)
- [ ] Search/filter (`/` pattern)
- [ ] Fade transitions
- [ ] Mouse scroll support
- [ ] Terminal resize handling
- [ ] Help overlay

### Phase 5: Polish

- [ ] Empty states with ASCII art
- [ ] Error handling & recovery
- [ ] Performance optimization
- [ ] Testing & documentation

---

## Command Palette Commands

```
:scan <target>          Start a new scan
:scan --web <target>    Web application scan
:recon <domain>         Run reconnaissance
:history                Show scan history
:export <format>        Export results (json/html/pdf)
:config                 Open configuration
:ai <question>          Ask AI a question
:clear                  Clear current view
:quit                   Exit TUI
```

---

## Database Schema (SQLite)

```sql
-- Scan history
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    findings_count INTEGER DEFAULT 0,
    raw_output TEXT,
    parsed_results TEXT  -- JSON
);

-- Findings
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    cve TEXT,
    cvss REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

-- AI conversations
CREATE TABLE ai_conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    role TEXT NOT NULL,  -- 'user' or 'assistant'
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

---

## Empty States

### Dashboard (No Scans)

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                         ███████╗██╗   ██╗██████╗                             ║
║                         ╚══███╔╝╚██╗ ██╔╝██╔══██╗                            ║
║                           ███╔╝  ╚████╔╝ ██████╔╝                            ║
║                          ███╔╝    ╚██╔╝  ██╔═══╝                             ║
║                         ███████╗   ██║   ██║                                 ║
║                         ╚══════╝   ╚═╝   ╚═╝                                 ║
║                                                                              ║
║                    Welcome to Zypheron TUI                                   ║
║                                                                              ║
║         No scans yet. Here's how to get started:                             ║
║                                                                              ║
║         • Press [S] to start a new scan                                      ║
║         • Press [:] to open command palette                                  ║
║         • Press [?] for help and keybindings                                 ║
║                                                                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## File Manifest

| File | Lines (est.) | Purpose |
|------|--------------|---------|
| `app.go` | 100 | Entry point, initialization |
| `model.go` | 200 | Root model, view routing |
| `keys.go` | 80 | Keybinding definitions |
| `messages.go` | 60 | Custom message types |
| `views/dashboard.go` | 150 | Dashboard view |
| `views/scan.go` | 200 | Scan monitor view |
| `views/results.go` | 250 | Results browser |
| `views/history.go` | 150 | History view |
| `views/recon.go` | 150 | Recon view |
| `components/header.go` | 80 | Header bar |
| `components/statusbar.go` | 100 | Status bar |
| `components/aipanel.go` | 200 | AI chat panel |
| `components/table.go` | 150 | Table component |
| `components/tree.go` | 150 | Tree component |
| `components/output.go` | 180 | Output viewer |
| `components/progress.go` | 60 | Progress indicator |
| `components/input.go` | 120 | Command palette |
| `styles/styles.go` | 100 | Style definitions |
| `store/store.go` | 200 | SQLite layer |
| `store/models.go` | 80 | DB models |
| **Total** | **~2,500** | |

---

## Next Steps

1. **Review this plan** - Confirm design decisions
2. **Set up dependencies** - Add bubbletea to go.mod
3. **Implement Phase 1** - Core structure and navigation
4. **Iterate on views** - Build each view incrementally
5. **Integrate AI** - Connect aibridge to panel
6. **Test & polish** - Responsive design, edge cases

---

## Splash Screen

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║      ███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗ ███╗   ██╗    ║
║      ╚══███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔═══██╗████╗  ██║    ║
║        ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝██║   ██║██╔██╗ ██║    ║
║       ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║██║╚████║     ║
║      ███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚███║     ║
║      ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝     ║
║                                                                              ║
║                   AI-Powered Penetration Testing Platform                    ║
║                              v1.0.0                                          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

- Display for 1-2 seconds
- Fade/dissolve transition to dashboard
- Skip with any keypress

---

## CLI Flags

```bash
zypheron                    # Launch TUI (default)
zypheron --no-tui           # Classic CLI mode
zypheron scan <target>      # Direct command (no TUI)
zypheron tui                # Explicit TUI launch
```

---

**Ready to implement?** Run: `zypheron` (after implementation)
