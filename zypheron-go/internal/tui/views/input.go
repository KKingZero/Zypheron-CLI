package views

import (
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const maxHistory = 100
const maxInputHeight = 8 // Maximum lines the input can expand to

type InputModel struct {
	TextInput  textarea.Model // Changed from textinput to textarea for vertical expansion
	width      int
	height     int      // Current height in lines
	history    []string // Command history
	historyIdx int      // Current position in history (-1 = not browsing)
	tempInput  string   // Stores current input when browsing history
}

func NewInput(width int) InputModel {
	ta := textarea.New()
	ta.Placeholder = "Type a command or query..."
	ta.Focus()
	ta.CharLimit = 1000
	ta.SetWidth(width - 4)
	ta.SetHeight(1) // Start with single line
	ta.ShowLineNumbers = false
	ta.KeyMap.InsertNewline.SetEnabled(false) // Enter submits, not newline

	// Styling - match the previous textinput look
	ta.Prompt = "➜ "
	ta.FocusedStyle.Prompt = lipgloss.NewStyle().Foreground(styles.ColorForestGreen)
	ta.FocusedStyle.Text = lipgloss.NewStyle().Foreground(styles.ColorWhite)
	ta.FocusedStyle.Placeholder = lipgloss.NewStyle().Foreground(styles.ColorGray)
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle() // No highlight on current line
	ta.BlurredStyle = ta.FocusedStyle

	return InputModel{
		TextInput:  ta,
		width:      width,
		height:     1,
		history:    make([]string, 0, maxHistory),
		historyIdx: -1,
		tempInput:  "",
	}
}

func (m InputModel) Init() tea.Cmd {
	return textarea.Blink
}

func (m InputModel) Update(msg tea.Msg) (InputModel, tea.Cmd) {
	// Handle history navigation and special keys
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.Type {
		case tea.KeyUp:
			// Previous command in history
			if len(m.history) > 0 {
				if m.historyIdx == -1 {
					// Starting to browse history - save current input
					m.tempInput = m.TextInput.Value()
					m.historyIdx = len(m.history) - 1
				} else if m.historyIdx > 0 {
					m.historyIdx--
				}
				m.TextInput.SetValue(m.history[m.historyIdx])
			}
			return m, nil

		case tea.KeyDown:
			// Next command in history
			if m.historyIdx >= 0 {
				if m.historyIdx < len(m.history)-1 {
					m.historyIdx++
					m.TextInput.SetValue(m.history[m.historyIdx])
				} else {
					// Reached end - restore original input
					m.historyIdx = -1
					m.TextInput.SetValue(m.tempInput)
				}
			}
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.TextInput, cmd = m.TextInput.Update(msg)

	// Auto-expand height based on content (like Claude Code)
	content := m.TextInput.Value()
	lines := strings.Count(content, "\n") + 1

	// Also account for line wrapping
	if m.width > 4 {
		lineWidth := m.width - 6 // Account for prompt and padding
		for _, line := range strings.Split(content, "\n") {
			if len(line) > lineWidth && lineWidth > 0 {
				lines += len(line) / lineWidth
			}
		}
	}

	// Clamp to max height
	if lines > maxInputHeight {
		lines = maxInputHeight
	}
	if lines < 1 {
		lines = 1
	}

	if lines != m.height {
		m.height = lines
		m.TextInput.SetHeight(lines)
	}

	return m, cmd
}

// AddToHistory adds a command to the history
func (m *InputModel) AddToHistory(cmd string) {
	if cmd == "" {
		return
	}

	// Don't add duplicates of the last command
	if len(m.history) > 0 && m.history[len(m.history)-1] == cmd {
		return
	}

	m.history = append(m.history, cmd)

	// Trim history if it exceeds max size
	if len(m.history) > maxHistory {
		m.history = m.history[1:]
	}

	// Reset history navigation
	m.historyIdx = -1
	m.tempInput = ""
}

// ResetHistoryNavigation resets the history navigation state
func (m *InputModel) ResetHistoryNavigation() {
	m.historyIdx = -1
	m.tempInput = ""
}

// Value returns the current input value
func (m InputModel) Value() string {
	return m.TextInput.Value()
}

// SetValue sets the input value
func (m *InputModel) SetValue(v string) {
	m.TextInput.SetValue(v)
}

// Reset clears the input
func (m *InputModel) Reset() {
	m.TextInput.Reset()
	m.height = 1
	m.TextInput.SetHeight(1)
}

// SetCursor sets cursor position
func (m *InputModel) SetCursor(pos int) {
	// textarea doesn't have SetCursor, but we can work around it
	// by setting the value and letting it position at the end
}

// Height returns the current height
func (m InputModel) Height() int {
	return m.height + 2 // +2 for border and padding
}

func (m InputModel) View() string {
	style := lipgloss.NewStyle().
		Width(m.width).
		Padding(0, 1).
		Border(lipgloss.NormalBorder(), true, false, false, false).
		BorderForeground(styles.ColorDarkGray)

	return style.Render(m.TextInput.View())
}
