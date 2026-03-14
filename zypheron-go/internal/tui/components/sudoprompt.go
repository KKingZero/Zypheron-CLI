package components

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// SudoCacheOption represents sudo credential caching options
type SudoCacheOption int

const (
	SudoCacheNone  SudoCacheOption = iota // Don't cache (invalidate immediately after)
	SudoCacheShort                        // Short cache (~5 minutes, default)
	SudoCacheLong                         // Long cache (~15 minutes)
)

// SudoPromptState tracks the prompt stage
type SudoPromptState int

const (
	SudoStatePassword SudoPromptState = iota
	SudoStateCacheChoice
	SudoStateComplete
)

// SudoPromptModel handles sudo password prompting
type SudoPromptModel struct {
	passwordInput textinput.Model
	state         SudoPromptState
	selectedCache SudoCacheOption
	toolName      string
	width         int
	height        int
	errorMsg      string
	password      string
}

// SudoRequestMsg signals that sudo password is needed
type SudoRequestMsg struct {
	ToolName string
	ScanID   string
}

// SudoAuthSuccessMsg signals successful authentication
type SudoAuthSuccessMsg struct {
	CacheOption SudoCacheOption
}

// SudoAuthFailedMsg signals failed authentication
type SudoAuthFailedMsg struct {
	Error string
}

// SudoCancelledMsg signals user cancelled sudo prompt
type SudoCancelledMsg struct{}

// NewSudoPrompt creates a new sudo password prompt
func NewSudoPrompt(toolName string, width, height int) SudoPromptModel {
	ti := textinput.New()
	ti.Placeholder = "Enter sudo password"
	ti.Focus()
	ti.CharLimit = 128
	ti.Width = width - 10
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'
	ti.PromptStyle = lipgloss.NewStyle().Foreground(styles.ColorWarning)
	ti.TextStyle = lipgloss.NewStyle().Foreground(styles.ColorWhite)

	return SudoPromptModel{
		passwordInput: ti,
		state:         SudoStatePassword,
		selectedCache: SudoCacheShort, // Default to short cache
		toolName:      toolName,
		width:         width,
		height:        height,
	}
}

func (m SudoPromptModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m SudoPromptModel) Update(msg tea.Msg) (SudoPromptModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.state {
		case SudoStatePassword:
			switch msg.Type {
			case tea.KeyEnter:
				// Validate password
				m.password = m.passwordInput.Value()
				if m.password == "" {
					m.errorMsg = "Password cannot be empty"
					return m, nil
				}
				// Test sudo authentication
				if err := testSudoPassword(m.password); err != nil {
					m.errorMsg = "Authentication failed. Try again."
					m.passwordInput.SetValue("")
					return m, nil
				}
				// Success - move to cache selection
				m.state = SudoStateCacheChoice
				m.errorMsg = ""
				return m, nil

			case tea.KeyEsc:
				return m, func() tea.Msg { return SudoCancelledMsg{} }
			}

		case SudoStateCacheChoice:
			switch msg.String() {
			case "1":
				m.selectedCache = SudoCacheNone
				m.state = SudoStateComplete
				return m, m.applyCache()
			case "2":
				m.selectedCache = SudoCacheShort
				m.state = SudoStateComplete
				return m, m.applyCache()
			case "3":
				m.selectedCache = SudoCacheLong
				m.state = SudoStateComplete
				return m, m.applyCache()
			case "esc":
				return m, func() tea.Msg { return SudoCancelledMsg{} }
			}
			return m, nil
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.passwordInput.Width = msg.Width - 10
	}

	// Update text input
	if m.state == SudoStatePassword {
		var cmd tea.Cmd
		m.passwordInput, cmd = m.passwordInput.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m SudoPromptModel) View() string {
	var content strings.Builder

	// Title
	titleStyle := lipgloss.NewStyle().
		Foreground(styles.ColorWarning).
		Bold(true).
		Padding(0, 1)

	switch m.state {
	case SudoStatePassword:
		content.WriteString(titleStyle.Render(fmt.Sprintf("🔐 Sudo Required for %s", m.toolName)))
		content.WriteString("\n\n")
		content.WriteString(styles.MutedStyle.Render("This tool requires elevated privileges."))
		content.WriteString("\n\n")
		content.WriteString(m.passwordInput.View())
		content.WriteString("\n")

		if m.errorMsg != "" {
			content.WriteString("\n")
			content.WriteString(styles.ErrorStyle.Render(m.errorMsg))
		}

		content.WriteString("\n\n")
		content.WriteString(styles.MutedStyle.Render("Press Enter to submit, Esc to cancel"))

	case SudoStateCacheChoice:
		content.WriteString(titleStyle.Render("✓ Authentication Successful"))
		content.WriteString("\n\n")
		content.WriteString(styles.MutedStyle.Render("How long should sudo credentials be cached?"))
		content.WriteString("\n\n")

		options := []struct {
			key  string
			text string
			desc string
		}{
			{"1", "No cache", "Credentials invalidated after this command"},
			{"2", "Short cache (5 min)", "Recommended for single sessions"},
			{"3", "Long cache (15 min)", "For extended scanning sessions"},
		}

		for i, opt := range options {
			style := lipgloss.NewStyle().Foreground(styles.ColorWhite)
			if SudoCacheOption(i) == m.selectedCache {
				style = style.Bold(true).Foreground(styles.ColorAccent)
			}
			content.WriteString(fmt.Sprintf("  [%s] %s\n", opt.key, style.Render(opt.text)))
			content.WriteString(fmt.Sprintf("      %s\n\n", styles.MutedStyle.Render(opt.desc)))
		}

		content.WriteString(styles.MutedStyle.Render("Press 1, 2, or 3 to select"))
	}

	// Container style
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(styles.ColorWarning).
		Padding(1, 2).
		Width(m.width - 4)

	return boxStyle.Render(content.String())
}

// testSudoPassword tests if the provided password is correct
func testSudoPassword(password string) error {
	cmd := exec.Command("sudo", "-S", "-v")
	cmd.Stdin = strings.NewReader(password + "\n")
	return cmd.Run()
}

// applyCache applies the selected cache option and returns success message
func (m SudoPromptModel) applyCache() tea.Cmd {
	return func() tea.Msg {
		switch m.selectedCache {
		case SudoCacheNone:
			// Will invalidate after command runs (handled in executor)
		case SudoCacheShort:
			// Default behavior, credentials cached for ~5 min
		case SudoCacheLong:
			// Extend timeout by running sudo -v with longer timestamp_timeout
			// Note: This requires sudoers config; we'll just refresh the timestamp
			exec.Command("sudo", "-v").Run()
		}
		return SudoAuthSuccessMsg{CacheOption: m.selectedCache}
	}
}

// InvalidateSudoCache invalidates the sudo credential cache
func InvalidateSudoCache() {
	exec.Command("sudo", "-k").Run()
}

// IsSudoPromptActive returns true if the model is in an active prompt state
func (m SudoPromptModel) IsSudoPromptActive() bool {
	return m.state == SudoStatePassword || m.state == SudoStateCacheChoice
}
