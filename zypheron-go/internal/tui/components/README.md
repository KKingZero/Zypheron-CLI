# Zypheron TUI Components

This directory contains reusable UI components for the Zypheron Terminal User Interface, built with [Bubble Tea](https://github.com/charmbracelet/bubbletea).

## Components

### AIPanel (`aipanel.go`)

A fixed-height bottom panel that provides contextual AI insights and accepts user queries.

**Features:**
- **Contextual AI assistance**: Displays AI-generated insights based on current view
- **Interactive input**: Users can ask questions via text input field
- **Scrollable responses**: Long AI responses automatically wrap and scroll
- **Focus-aware styling**: Border changes color (gray → white) when focused
- **Collapsible**: Can minimize to a single line to save screen space
- **Resizable**: Height adjustable between 3-15 lines via Ctrl+Up/Down
- **Double-line borders**: Clean professional look matching Zypheron style

**Default Layout** (5 lines):
```
╠══════════════════════════════════════════════════════════════════════════════╣
║  AI: Contextual insights appear here based on current view content.          ║
║  Moderate verbosity - paragraph with actionable recommendations.             ║
║  > _                                                          [Enter to ask] ║
╠══════════════════════════════════════════════════════════════════════════════╣
```

**Key Bindings** (when focused):
- `Enter`: Submit query
- `Esc`: Unfocus panel
- `Ctrl+Up`: Increase panel height
- `Ctrl+Down`: Decrease panel height

**Public API:**
```go
// Creation
panel := components.NewAIPanel()

// Focus control
panel = panel.Focus()
panel = panel.Blur()
focused := panel.IsFocused()

// Content updates
panel = panel.SetResponse("AI response text here")

// Sizing
panel = panel.SetWidth(terminalWidth)
panel = panel.SetHeight(7)

// Collapse/expand
panel = panel.ToggleCollapse()

// Bubble Tea interface
panel, cmd = panel.Update(msg)
view := panel.View()
```

**Integration Example:**

See `aipanel_example.go` for detailed integration patterns. Quick snippet:

```go
type Model struct {
    aiPanel components.AIPanel
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    switch msg := msg.(type) {
    case tea.KeyMsg:
        if msg.String() == "ctrl+a" {
            if m.aiPanel.IsFocused() {
                m.aiPanel = m.aiPanel.Blur()
            } else {
                m.aiPanel = m.aiPanel.Focus()
            }
        }
    }

    m.aiPanel, cmd = m.aiPanel.Update(msg)
    return m, cmd
}

func (m Model) View() string {
    return lipgloss.JoinVertical(
        lipgloss.Left,
        m.renderHeader(),
        m.renderContent(),
        m.aiPanel.View(),  // AI panel above status bar
        m.renderStatusBar(),
    )
}
```

**Testing:**

```bash
go test ./internal/tui/components/... -v
```

All tests passing, including:
- Component initialization
- Focus/blur behavior
- Setter methods and validation
- Height clamping (3-15 lines)
- Collapse/expand toggling
- Message handling (window resize, keyboard input)
- Text wrapping algorithm

---

## Design Philosophy

All Zypheron TUI components follow these principles:

1. **Monochrome aesthetic**: Minimal color usage, semantic colors only for severity
2. **Double-line borders**: Clean, professional look using Unicode box-drawing (╔═╗)
3. **Focus indication**: Visual feedback via border color changes
4. **Keyboard-driven**: All functionality accessible via keyboard
5. **Responsive**: Adapts to terminal resize events
6. **Composable**: Easy to integrate into larger TUI applications

## Dependencies

- `github.com/charmbracelet/bubbletea` - TUI framework
- `github.com/charmbracelet/bubbles` - Pre-built components (textinput)
- `github.com/charmbracelet/lipgloss` - Styling and layout

All dependencies are already in `go.mod` and automatically managed.
