package components

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/validation"
)

// Constants define the sizing constraints for the AI panel
// These ensure the panel remains functional at different heights
const (
	DefaultAIPanelHeight = 5  // Default collapsed height - fits response + input
	MinAIPanelHeight     = 3  // Minimum usable height (1 line response + input)
	MaxAIPanelHeight     = 15 // Maximum height to prevent screen domination
)

// AIRequestMsg is sent when the user submits a query in the AI panel
// The parent model handles this message and sends it to the Claude API
type AIRequestMsg struct {
	Query   string // The user's query
	Context string // Optional context (e.g., scan output) for the query
}

// AIPanel represents the AI assistant panel component
// This is a fixed-height bottom panel that provides contextual AI insights
// and accepts user queries via a text input field.
//
// Key features:
// - Displays AI-generated responses based on current view context
// - Scrollable text for long responses
// - Interactive input field for user queries
// - Collapsible to save screen space
// - Focus-aware styling (changes border color when focused)
// - Resizable within min/max constraints
type AIPanel struct {
	input     textinput.Model // User input field for queries
	response  string          // Current AI response text to display
	height    int             // Current panel height in lines
	width     int             // Panel width (should match terminal width)
	focused   bool            // Whether the panel is currently focused
	collapsed bool            // Whether the panel is collapsed to minimal view
	loading   bool            // Whether AI is processing a request
}

// NewAIPanel creates and initializes a new AIPanel component
//
// Returns:
//   - AIPanel configured with default settings and ready to use
//
// The panel starts unfocused with a default welcome message.
// Input field is pre-configured with placeholder text and reasonable limits.
func NewAIPanel() AIPanel {
	// Initialize the text input field with sensible defaults
	ti := textinput.New()
	ti.Placeholder = "Ask AI about the current context..."
	ti.Prompt = "> "
	ti.CharLimit = 500 // Prevent overly long queries

	return AIPanel{
		input:    ti,
		height:   DefaultAIPanelHeight,
		width:    80, // Default width, will be updated by WindowSizeMsg
		focused:  false,
		response: "AI: Ready to analyze. Focus this panel and ask a question.",
	}
}

// Init implements tea.Model interface
// No initialization commands needed for this component
func (a AIPanel) Init() tea.Cmd {
	return nil
}

// Update handles all messages and updates the AIPanel state
//
// Parameters:
//   - msg: tea.Msg - Any Bubble Tea message (keyboard, window resize, etc.)
//
// Returns:
//   - AIPanel: Updated panel state
//   - tea.Cmd: Any command to execute (e.g., from text input)
//
// Handles:
// - Window resizing: Adjusts panel and input width
// - Keyboard input: Enter to submit, Esc to unfocus, Ctrl+Up/Down to resize
// - Text input updates when focused
func (a AIPanel) Update(msg tea.Msg) (AIPanel, tea.Cmd) {
	var cmd tea.Cmd
	var keyHandled bool

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Update panel width to match terminal
		a.width = msg.Width
		// Reserve space for prompt, hint, and padding (minimum width of 10)
		inputWidth := msg.Width - 20
		if inputWidth < 10 {
			inputWidth = 10
		}
		a.input.Width = inputWidth

	case tea.KeyMsg:
		// Only handle keys when panel is focused
		if a.focused {
			switch msg.String() {
			case "enter":
				// Submit query if input is not empty
				if a.input.Value() != "" {
					// Sanitize AI query to prevent injection attacks
					// This removes shell metacharacters and control characters
					query := validation.SanitizeInput(a.input.Value())

					// Set loading state and clear input
					a.loading = true
					a.response = "AI: Processing your query..."
					a.input.SetValue("")

					// Return command to send AI request
					// The parent model will handle this message and call Claude API
					cmd = func() tea.Msg {
						return AIRequestMsg{
							Query:   query,
							Context: "", // Context can be passed from scan output
						}
					}
				}
				keyHandled = true

			case "esc":
				// Unfocus the panel and blur input
				a.focused = false
				a.input.Blur()
				// Reset loading state if stuck
				a.loading = false
				keyHandled = true

			case "ctrl+up":
				// Increase panel height (up to max)
				if a.height < MaxAIPanelHeight {
					a.height++
				}
				keyHandled = true

			case "ctrl+down":
				// Decrease panel height (down to min)
				if a.height > MinAIPanelHeight {
					a.height--
				}
				keyHandled = true
			}
		}
	}

	// Update text input if focused AND key wasn't already handled
	// This prevents double-processing of keys
	if a.focused && !keyHandled {
		a.input, cmd = a.input.Update(msg)
	}

	return a, cmd
}

// Focus sets the panel to focused state and enables input
//
// Returns:
//   - AIPanel: Updated panel with focus enabled
//
// When focused, the panel will:
// - Accept keyboard input
// - Show focused border styling (white border)
// - Allow query submission
func (a AIPanel) Focus() AIPanel {
	a.focused = true
	a.input.Focus()
	return a
}

// Blur removes focus from the panel and disables input
//
// Returns:
//   - AIPanel: Updated panel with focus disabled
//
// When blurred, the panel will:
// - Ignore keyboard input
// - Show default border styling (gray border)
// - Not accept queries
func (a AIPanel) Blur() AIPanel {
	a.focused = false
	a.input.Blur()
	return a
}

// SetResponse updates the AI response text displayed in the panel
//
// Parameters:
//   - resp: string - The new response text to display
//
// Returns:
//   - AIPanel: Updated panel with new response
//
// The response is automatically prefixed with "AI: " and loading state is cleared.
// This method should be called when AI processing completes.
func (a AIPanel) SetResponse(resp string) AIPanel {
	a.response = "AI: " + resp
	a.loading = false
	return a
}

// SetWidth updates the panel width
//
// Parameters:
//   - w: int - New width in characters
//
// Returns:
//   - AIPanel: Updated panel with new width
//
// This should be called when terminal is resized.
// Input field width is automatically adjusted to fit within the panel.
func (a AIPanel) SetWidth(w int) AIPanel {
	if w < 30 {
		w = 30 // Minimum usable panel width
	}
	a.width = w
	// Calculate input width with minimum of 10 characters
	inputWidth := w - 20
	if inputWidth < 10 {
		inputWidth = 10
	}
	a.input.Width = inputWidth
	return a
}

// SetHeight updates the panel height
//
// Parameters:
//   - h: int - New height in lines
//
// Returns:
//   - AIPanel: Updated panel with new height (clamped to min/max)
//
// Height is automatically clamped to valid range (MinAIPanelHeight to MaxAIPanelHeight).
// Values outside the range are clamped to the nearest valid value.
func (a AIPanel) SetHeight(h int) AIPanel {
	if h < MinAIPanelHeight {
		a.height = MinAIPanelHeight
	} else if h > MaxAIPanelHeight {
		a.height = MaxAIPanelHeight
	} else {
		a.height = h
	}
	return a
}

// ToggleCollapse toggles between collapsed and expanded states
//
// Returns:
//   - AIPanel: Updated panel with toggled collapse state
//
// When collapsed, the panel shows only a minimal status line.
// When expanded, it shows the full response and input interface.
func (a AIPanel) ToggleCollapse() AIPanel {
	a.collapsed = !a.collapsed
	return a
}

// IsFocused returns whether the panel is currently focused
//
// Returns:
//   - bool: true if focused, false otherwise
//
// Useful for parent components to determine which panel has focus.
func (a AIPanel) IsFocused() bool {
	return a.focused
}

// GetHeight returns the current panel height including borders
//
// Returns:
//   - int: Total height in lines (content height + 2 for borders)
func (a AIPanel) GetHeight() int {
	return a.height + 2 // +2 for top and bottom borders
}

// View renders the AIPanel to a string
//
// Returns:
//   - string: The rendered panel ready for display
//
// Rendering behavior:
// - Collapsed: Shows single-line minimal view
// - Expanded: Shows response text (word-wrapped and scrollable) + input line
// - Focused: Uses white border instead of gray
// - Automatically wraps long response text
// - Truncates old response lines if content exceeds panel height
func (a AIPanel) View() string {
	if a.collapsed {
		// Show minimal collapsed view - just a hint to expand
		collapsed := styles.MutedStyle.Render("  AI Panel [Press Ctrl+A to expand]")
		return styles.AIPanelStyle.Width(a.width).Render(collapsed)
	}

	// Build response area with word wrapping
	responseLines := a.wrapText(a.response, a.width-6)

	// Calculate how many lines we can show for response
	// Reserve 2 lines: one for input, one for padding
	maxResponseLines := a.height - 2
	if len(responseLines) > maxResponseLines {
		// Show most recent lines (bottom of response)
		// This creates a "scrolling" effect for long responses
		responseLines = responseLines[len(responseLines)-maxResponseLines:]
	}

	// Pad with empty lines if response is shorter than available space
	for len(responseLines) < maxResponseLines {
		responseLines = append(responseLines, "")
	}

	// Build the input line with hint on the right
	inputView := a.input.View()
	hint := styles.MutedStyle.Render("[Enter to ask]")

	// Calculate padding to push hint to the right edge
	inputPadding := a.width - lipgloss.Width(inputView) - lipgloss.Width(hint) - 6
	if inputPadding < 0 {
		inputPadding = 0 // Prevent negative padding
	}
	inputLine := "  " + inputView + strings.Repeat(" ", inputPadding) + hint

	// Combine response lines and input line
	var lines []string
	for _, line := range responseLines {
		lines = append(lines, "  "+line) // Add left padding
	}
	lines = append(lines, inputLine)

	content := strings.Join(lines, "\n")

	// Use different border color when focused
	style := styles.AIPanelStyle
	if a.focused {
		// White border indicates active/focused state
		style = style.BorderForeground(styles.ColorWhite)
	}

	return style.Width(a.width).Render(content)
}

// wrapText wraps text to fit within the specified width
//
// Parameters:
//   - text: string - The text to wrap
//   - width: int - Maximum width in characters
//
// Returns:
//   - []string: Slice of wrapped lines
//
// Word-wrapping algorithm:
// - Splits text on whitespace
// - Builds lines by adding words until width would be exceeded
// - Breaks long words that exceed width
// - Handles edge cases (empty text, zero width, single word)
func (a AIPanel) wrapText(text string, width int) []string {
	// Handle edge case: zero or negative width
	if width <= 0 {
		width = 10 // Minimum width
	}

	// Split text into words
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""} // Empty text
	}

	var lines []string
	currentLine := ""

	for _, word := range words {
		// Handle words longer than width - break them up
		for len(word) > width {
			if currentLine != "" {
				lines = append(lines, currentLine)
				currentLine = ""
			}
			lines = append(lines, word[:width])
			word = word[width:]
		}

		// Check if adding this word would exceed width
		if currentLine == "" {
			currentLine = word
		} else if len(currentLine)+1+len(word) <= width {
			// Add word to current line
			currentLine += " " + word
		} else {
			// Start new line with this word
			lines = append(lines, currentLine)
			currentLine = word
		}
	}

	// Don't forget the last line
	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}
