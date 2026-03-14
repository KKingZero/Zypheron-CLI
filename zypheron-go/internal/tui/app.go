package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

// Start launches the TUI program
func Start() error {
	p := tea.NewProgram(NewModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}
	return nil
}