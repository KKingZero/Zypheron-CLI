package components

// EXAMPLE USAGE:
//
// This file demonstrates how to integrate the AIPanel component into your TUI model.
// The AIPanel is designed to work as a fixed bottom panel in the Zypheron TUI.

/*
// Example integration in your main TUI model:

type Model struct {
    aiPanel    components.AIPanel
    // ... other components
    width      int
    height     int
    focusIndex int // Which component has focus
}

func NewModel() Model {
    return Model{
        aiPanel:    components.NewAIPanel(),
        focusIndex: 0, // Start with main content focused
    }
}

func (m Model) Init() tea.Cmd {
    return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    var cmd tea.Cmd
    var cmds []tea.Cmd

    switch msg := msg.(type) {
    case tea.WindowSizeMsg:
        m.width = msg.Width
        m.height = msg.Height

        // Update AI panel width
        m.aiPanel = m.aiPanel.SetWidth(msg.Width)

    case tea.KeyMsg:
        switch msg.String() {
        case "ctrl+c", "q":
            return m, tea.Quit

        case "ctrl+a":
            // Toggle AI panel focus
            if m.aiPanel.IsFocused() {
                m.aiPanel = m.aiPanel.Blur()
                m.focusIndex = 0 // Return to main content
            } else {
                m.aiPanel = m.aiPanel.Focus()
                m.focusIndex = 1 // Focus AI panel
            }

        case "ctrl+\\": // Toggle collapse
            m.aiPanel = m.aiPanel.ToggleCollapse()
        }

    case AIResponseMsg:
        // Custom message type when AI response arrives
        m.aiPanel = m.aiPanel.SetResponse(msg.Response)
    }

    // Update the appropriate component based on focus
    if m.focusIndex == 1 {
        m.aiPanel, cmd = m.aiPanel.Update(msg)
        cmds = append(cmds, cmd)
    } else {
        // Update other components
    }

    return m, tea.Batch(cmds...)
}

func (m Model) View() string {
    var sections []string

    // Header
    sections = append(sections, m.renderHeader())

    // Main content area
    // Calculate available height: total - header - AI panel - status bar
    contentHeight := m.height - 3 - m.aiPanel.height - 2
    sections = append(sections, m.renderContent(contentHeight))

    // AI Panel (fixed bottom, above status bar)
    sections = append(sections, m.aiPanel.View())

    // Status bar (fixed bottom)
    sections = append(sections, m.renderStatusBar())

    return strings.Join(sections, "\n")
}

// AIResponseMsg is a custom message sent when AI processing completes
type AIResponseMsg struct {
    Response string
}

// Example command to simulate AI processing
func processAIQuery(query string) tea.Cmd {
    return func() tea.Msg {
        // Simulate AI processing (replace with actual AI service call)
        time.Sleep(500 * time.Millisecond)
        return AIResponseMsg{
            Response: "Based on your query about '" + query + "', here are some insights...",
        }
    }
}
*/

// KEY BINDINGS REFERENCE:
//
// When AI Panel is focused:
//   - Enter: Submit query
//   - Esc: Unfocus AI panel
//   - Ctrl+Up: Increase panel height
//   - Ctrl+Down: Decrease panel height
//   - Type normally to enter query
//
// Global bindings (suggested):
//   - Ctrl+A: Toggle AI panel focus
//   - Ctrl+\: Toggle AI panel collapse
//
// LAYOUT STRUCTURE:
//
// ╔══════════════════════════════════════════════════════════════╗
// ║ Header (tabs, breadcrumb)                                    ║
// ╠══════════════════════════════════════════════════════════════╣
// ║                                                              ║
// ║                                                              ║
// ║ Main Content Area (dynamic height)                          ║
// ║                                                              ║
// ║                                                              ║
// ╠══════════════════════════════════════════════════════════════╣
// ║ AI: Response text here...                                   ║
// ║ More response...                                            ║
// ║ > [user input]                          [Enter to ask]      ║
// ╠══════════════════════════════════════════════════════════════╣
// ║ Status Bar: Phase | Stats            [Ctrl+C] Quit          ║
// ╚══════════════════════════════════════════════════════════════╝
//
// The AI panel height is configurable (default 5 lines, min 3, max 15)
// and automatically adjusts the main content area accordingly.
