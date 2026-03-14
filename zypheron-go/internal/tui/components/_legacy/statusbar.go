package components

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
)

// Phase represents the current scan phase in the Zypheron workflow
// This enum tracks the progression through reconnaissance, scanning, and analysis stages
type Phase int

const (
	PhaseIdle     Phase = iota // No active scan
	PhaseRecon                 // Reconnaissance phase - gathering initial information
	PhaseScan                  // Scanning phase - active vulnerability detection
	PhaseAnalysis              // Analysis phase - processing and correlating results
	PhaseComplete              // Scan complete
)

// StatusBar is the bottom status bar component that displays:
// - Current scan phase with progress indicator
// - Keyboard shortcuts and command hints
// - Optional status messages
//
// Design follows the Zypheron minimal aesthetic with double-line borders
// and monochrome color scheme with semantic highlights for active states.
type StatusBar struct {
	phase   Phase  // Current scan phase
	width   int    // Component width (responsive)
	message string // Optional status message (currently unused, reserved for future)
}

// NewStatusBar creates a new status bar component with default settings
//
// Returns:
//   - StatusBar initialized to idle phase with default 80-column width
func NewStatusBar() StatusBar {
	return StatusBar{
		phase: PhaseIdle,
		width: 80,
	}
}

// Init initializes the status bar component
// Required by the Bubble Tea Model interface
//
// Returns:
//   - nil (no initial commands to execute)
func (s StatusBar) Init() tea.Cmd {
	return nil
}

// Update handles Bubble Tea messages and updates the status bar state
// Currently responds to window resize events to maintain responsive layout
//
// Parameters:
//   - msg: Bubble Tea message (typically tea.WindowSizeMsg)
//
// Returns:
//   - Updated StatusBar model
//   - Command to execute (always nil for this component)
func (s StatusBar) Update(msg tea.Msg) (StatusBar, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Update width to match terminal size for responsive layout
		s.width = msg.Width
	}
	return s, nil
}

// SetPhase updates the current scan phase
// This triggers visual updates to the progress indicator
//
// Parameters:
//   - p: New phase to set
//
// Returns:
//   - Updated StatusBar with new phase
func (s StatusBar) SetPhase(p Phase) StatusBar {
	s.phase = p
	return s
}

// SetWidth manually sets the status bar width
// Used for responsive layout when terminal size changes
//
// Parameters:
//   - w: Width in characters
//
// Returns:
//   - Updated StatusBar with new width
func (s StatusBar) SetWidth(w int) StatusBar {
	s.width = w
	return s
}

// SetMessage sets an optional status message
// Reserved for future use (e.g., displaying scan progress details)
//
// Parameters:
//   - msg: Status message to display
//
// Returns:
//   - Updated StatusBar with new message
func (s StatusBar) SetMessage(msg string) StatusBar {
	s.message = msg
	return s
}

// View renders the status bar component to a string
// Implements the Bubble Tea Model interface
//
// Layout:
//   ╠══════════════════════════════════════════════════════════════════════════════╣
//   ║  [Recon] → [Scan] → [Analysis]       :cmd  /search  j/k  ?help  q:quit    ║
//   ╚══════════════════════════════════════════════════════════════════════════════╝
//
// Returns:
//   - Rendered status bar string with borders and styling
func (s StatusBar) View() string {
	// Build progress indicator (left side)
	progressStr := s.renderProgress()

	// Key hints (right side - always visible)
	keyHints := s.renderKeyHints()

	// Calculate spacing between left and right sections
	// lipgloss.Width accounts for ANSI escape codes in styled strings
	progressWidth := lipgloss.Width(progressStr)
	hintsWidth := lipgloss.Width(keyHints)
	padding := s.width - progressWidth - hintsWidth - 6 // -6 for borders and margins
	if padding < 2 {
		padding = 2 // Minimum spacing to prevent overlap
	}

	// Assemble final content with left-right layout
	content := "  " + progressStr + strings.Repeat(" ", padding) + keyHints + "  "

	// Apply status bar style with double-line borders
	return styles.StatusBarStyle.Width(s.width).Render(content)
}

// renderProgress generates the phase progress indicator string
// Shows: [Recon] → [Scan] → [Analysis]
// - Current phase is highlighted (white, bold)
// - Completed phases are dimmed (gray)
// - Future phases are very dim (dark gray)
//
// Returns:
//   - Styled progress indicator string
func (s StatusBar) renderProgress() string {
	// Define the scan phases to display
	phases := []struct {
		phase Phase
		name  string
	}{
		{PhaseRecon, "Recon"},
		{PhaseScan, "Scan"},
		{PhaseAnalysis, "Analysis"},
	}

	var parts []string
	for i, p := range phases {
		var style lipgloss.Style
		var prefix, suffix string

		// Determine styling based on phase state relative to current phase
		if s.phase == p.phase {
			// Current phase - highlighted in white/bold
			style = styles.ActiveTabStyle
			prefix = "["
			suffix = "]"
		} else if s.phase > p.phase {
			// Completed phase - dimmed to show it's done
			style = styles.MutedStyle
			prefix = "["
			suffix = "]"
		} else {
			// Future phase - very dim to show it's upcoming
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#444444"))
			prefix = "["
			suffix = "]"
		}

		// Add styled phase name with brackets
		parts = append(parts, style.Render(prefix+p.name+suffix))

		// Add arrow separator between phases
		if i < len(phases)-1 {
			if s.phase > p.phase {
				// Dimmed arrow for completed transitions
				parts = append(parts, styles.MutedStyle.Render(" → "))
			} else {
				// Very dim arrow for future transitions
				parts = append(parts, lipgloss.NewStyle().Foreground(lipgloss.Color("#444444")).Render(" → "))
			}
		}
	}

	return strings.Join(parts, "")
}

// renderKeyHints generates the keyboard shortcut hints string
// Shows: :cmd  /search  j/k  ?help  q:quit
//
// Format:
// - Key is bold white (e.g., ":")
// - Description is light gray (e.g., ":cmd")
//
// Returns:
//   - Styled keyboard hints string
func (s StatusBar) renderKeyHints() string {
	// Define keyboard shortcuts to display
	hints := []struct {
		key  string
		desc string
	}{
		{":", "cmd"},      // Command mode
		{"/", "search"},   // Search mode
		{"j/k", ""},       // Vim-style navigation (no description needed)
		{"?", "help"},     // Help screen
		{"q", "quit"},     // Quit application
	}

	var parts []string
	for _, h := range hints {
		// Render key in bold white
		keyPart := styles.KeyStyle.Render(h.key)
		// Append description in light gray if present
		if h.desc != "" {
			keyPart += styles.KeyHintStyle.Render(":" + h.desc)
		}
		parts = append(parts, keyPart)
	}

	// Join with spacing between hints
	return strings.Join(parts, "  ")
}
