// +build ignore

package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/components"
)

// This example demonstrates the ToolStatusPanel component

type model struct {
	toolStatus components.ToolStatusPanel
}

func initialModel() model {
	return model{
		toolStatus: components.NewToolStatusPanel(),
	}
}

func (m model) Init() tea.Cmd {
	return m.toolStatus.Init()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.toolStatus = m.toolStatus.SetWidth(msg.Width).SetHeight(msg.Height)
	}

	// Update tool status component
	var cmd tea.Cmd
	m.toolStatus, cmd = m.toolStatus.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m model) View() string {
	header := "Zypheron Tool Status Check\n\n"
	body := m.toolStatus.View()
	footer := "\n\nPress 'q' or 'Esc' to quit"

	return header + body + footer
}

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}
}
