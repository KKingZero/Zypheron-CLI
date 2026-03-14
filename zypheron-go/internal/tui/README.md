# Zypheron TUI - Terminal User Interface

## Overview

The Zypheron TUI is a full-featured terminal user interface built with Bubble Tea. It provides an interactive, keyboard-driven interface for security testing operations with integrated AI assistance.

## Architecture

### Root Model (`model.go`)

The root model orchestrates the entire TUI application:

- **View Management**: Handles routing between different views (Splash, Dashboard, Scan, Recon, etc.)
- **Component Composition**: Manages persistent components (Header, StatusBar, AIPanel)
- **Global Keybindings**: Processes keyboard shortcuts for navigation and actions
- **Layout Management**: Calculates and renders the complete UI layout
- **Message Routing**: Distributes messages to appropriate views and components

### Entry Point (`app.go`)

Provides clean API for launching the TUI:

- `Run()` - Start TUI with default options
- `RunWithOptions(opts...)` - Start with custom Bubble Tea options
- `RunWithModel(model)` - Start with pre-configured model (testing/debugging)

### Messages (`messages.go`)

Custom message types for inter-component communication:

- **Scan Messages**: `ScanStartMsg`, `ScanOutputMsg`, `ScanCompleteMsg`
- **AI Messages**: `AIRequestMsg`, `AIResponseMsg`
- **Navigation**: `ViewChangeMsg`, `StatusUpdateMsg`
- **Notifications**: `ErrorMsg`, `SuccessMsg`
- **Recon**: `ReconStartMsg`, `ReconResultMsg`
- **History**: `LoadHistoryMsg`, `HistoryLoadedMsg`

### Keybindings (`keys.go`)

Global keyboard shortcuts using Bubble Tea's key package:

**View Switching**:
- `D` - Dashboard
- `S` - Scan view
- `R` - Recon view
- `T` - Tools view
- `H` - History view

**Actions**:
- `A` - Focus AI panel
- `/` - Search mode
- `:` - Command mode
- `?` - Help screen
- `q` or `Ctrl+C` - Quit

**Navigation**:
- `j/k` or `↑/↓` - Up/down in lists

## Views

The TUI supports the following views (enum in `model.go`):

### Implemented
- **ViewSplash** - Animated startup splash screen
- **ViewDashboard** - Main overview (placeholder)
- **ViewScan** - Active scanning interface (placeholder)
- **ViewRecon** - Reconnaissance tools (placeholder)
- **ViewTools** - Security tools (placeholder)
- **ViewHistory** - Scan history (placeholder)
- **ViewResults** - Detailed results viewer (placeholder)

### Placeholder Implementation

Currently, all main views render placeholder content. The infrastructure is in place for:
- Proper height calculation
- Component integration
- Message routing
- Navigation

To implement a view:
1. Create view model in `internal/tui/views/`
2. Add field to root `Model` struct
3. Initialize in `NewModel()`
4. Add case in `Update()` to route messages
5. Replace placeholder in `View()` render switch

## Components

All components live in `internal/tui/components/`:

### Header (`header.go`)
- Quick-launch navigation tabs
- Breadcrumb trail
- Double-line border styling
- Responsive width

### StatusBar (`statusbar.go`)
- Scan phase progress indicator
- Keyboard shortcut hints
- Status messages
- Bottom border

### AIPanel (`aipanel.go`)
- AI-powered contextual assistance
- Text input for queries
- Scrollable response display
- Collapsible/resizable
- Focus-aware styling

### Splash (`splash.go`)
- Animated logo on startup
- Fade-in effect
- Auto-transitions to dashboard
- Keypress to skip

## Layout

The TUI uses a fixed-height layout:

```
╔════════════════════════════════════════╗
║  Header (3 lines)                      ║  <- Tabs + Breadcrumb
╠════════════════════════════════════════╣
║                                        ║
║  Content Area (dynamic height)         ║  <- Active view renders here
║                                        ║
╠════════════════════════════════════════╣
║  AI Panel (7 lines)                    ║  <- Contextual AI assistance
╠════════════════════════════════════════╣
║  Status Bar (3 lines)                  ║  <- Phase + Keybindings
╚════════════════════════════════════════╝
```

Height calculation:
```go
contentHeight = totalHeight - headerHeight(3) - statusHeight(3) - aiHeight(7)
```

## Message Flow

### Scan Workflow
1. User navigates to Scan view (press `S`)
2. View model sends `ScanStartMsg{Target: "192.168.1.1", ScanType: "quick"}`
3. Root model forwards to scan executor
4. Scan executor sends `ScanOutputMsg` for each line of output
5. View updates display in real-time
6. Executor sends `ScanCompleteMsg{Success: true}` when done

### AI Query Workflow
1. User focuses AI panel (press `A`)
2. User types query and presses Enter
3. AI panel sends `AIRequestMsg{Query: "...", Context: "scan"}`
4. Root model forwards to AI service
5. AI service sends `AIResponseMsg{Response: "..."}`
6. AI panel displays response

### View Navigation
1. User presses view shortcut (e.g., `S`)
2. `handleGlobalKeys()` catches keypress
3. Updates `currentView` field
4. Updates header via `updateViewContext()`
5. Next `View()` render shows new view

## Usage

### From Code

```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui"

// Basic usage
if err := tui.Run(); err != nil {
    log.Fatal(err)
}

// With custom options
err := tui.RunWithOptions(
    tea.WithFPS(60),
    tea.WithoutCatchPanics(), // For debugging
)

// With pre-configured model (testing)
model := tui.NewModel()
model.currentView = tui.ViewScan // Skip splash
if err := tui.RunWithModel(model); err != nil {
    log.Fatal(err)
}
```

### From Command Line

```bash
# Build demo
cd cmd/tui-demo
go build

# Run TUI
./tui-demo
```

## Development Guide

### Adding a New View

1. **Create view package**:
```go
// internal/tui/views/myview.go
package views

type MyView struct {
    width  int
    height int
}

func NewMyView() MyView {
    return MyView{}
}

func (v MyView) Update(msg tea.Msg) (MyView, tea.Cmd) {
    // Handle messages
    return v, nil
}

func (v MyView) View() string {
    // Render view
    return "My View Content"
}
```

2. **Add to root model**:
```go
// In model.go Model struct
myView views.MyView

// In NewModel()
myView: views.NewMyView(),
```

3. **Route messages**:
```go
// In Update() else block
case ViewMyView:
    v.myView, cmd = v.myView.Update(msg)
    cmds = append(cmds, cmd)
```

4. **Render view**:
```go
// In View() switch
case ViewMyView:
    content = m.myView.View()
```

### Adding a Custom Message

1. **Define in messages.go**:
```go
type MyCustomMsg struct {
    Data string
}
```

2. **Send from component/view**:
```go
return m, func() tea.Msg {
    return MyCustomMsg{Data: "test"}
}
```

3. **Handle in root Update()**:
```go
case MyCustomMsg:
    // Process message
    // Update state
    // Forward to views if needed
```

### Testing

The TUI can be tested by:

1. **Manual testing**: Run `cmd/tui-demo`
2. **Unit tests**: Test individual components
3. **Integration tests**: Use `RunWithModel()` with test state

Example test:
```go
func TestViewSwitching(t *testing.T) {
    model := NewModel()
    
    // Simulate key press
    model, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'S'}})
    
    if model.currentView != ViewScan {
        t.Errorf("Expected ViewScan, got %v", model.currentView)
    }
}
```

## Styling

All styles are centralized in `internal/tui/styles/`:

- Monochrome base palette (white, black, grays)
- Semantic colors for severity (critical, high, medium, low, info)
- Double-line borders for professional look
- Pre-configured component styles

To use:
```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"

text := styles.CriticalStyle.Render("CRITICAL")
box := styles.HeaderStyle.Render(content)
```

## Next Steps

To complete the TUI:

1. **Implement Views**:
   - Dashboard with stats and recent activity
   - Scan view with target input and real-time output
   - Recon view with enumeration tools
   - Results view with vulnerability list
   - History view with filterable scan list

2. **Integrate Backend**:
   - Connect scan executor for real nmap/masscan
   - Wire up AI service for actual responses
   - Implement database queries for history

3. **Add Features**:
   - Help screen (press `?`)
   - Command mode (press `:`)
   - Search functionality (press `/`)
   - Export results
   - Configuration management

4. **Polish**:
   - Loading indicators
   - Error notifications
   - Success messages
   - Quit confirmation for active scans
   - Keyboard shortcut hints in views

## Files

```
internal/tui/
├── README.md           # This file
├── app.go             # Entry points (Run, RunWithOptions, RunWithModel)
├── keys.go            # Global keybindings
├── messages.go        # Custom message types
├── model.go           # Root model and view orchestration
├── components/        # Reusable UI components
│   ├── aipanel.go
│   ├── header.go
│   ├── splash.go
│   └── statusbar.go
├── styles/            # Centralized styling
│   └── styles.go
└── views/             # View implementations (to be created)
    ├── dashboard.go
    ├── scan.go
    ├── recon.go
    └── ...
```

## Dependencies

- `github.com/charmbracelet/bubbletea` - TUI framework
- `github.com/charmbracelet/bubbles` - Reusable components (textinput, etc.)
- `github.com/charmbracelet/lipgloss` - Terminal styling

## Performance

The TUI is designed for efficiency:

- **Message batching**: Multiple commands batched in `Update()`
- **Lazy rendering**: Only active view is rendered
- **Minimal redraws**: Bubble Tea handles efficient screen updates
- **Component isolation**: Each component manages its own state

Expected performance:
- 60 FPS rendering (configurable)
- Low CPU usage when idle
- Real-time scan output without lag
- Smooth animations and transitions
