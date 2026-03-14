// +build ignore

package main

import (
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/components"
)

// This example demonstrates the Progress component with simulated scan phases

type model struct {
	progress components.Progress
	phase    components.Phase
	percent  float64
}

func initialModel() model {
	return model{
		progress: components.NewProgress(),
		phase:    components.PhaseRecon,
		percent:  0.0,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		m.progress.Init(),
		m.simulateProgress(),
	)
}

// simulateProgress simulates scan progress advancing
func (m model) simulateProgress() tea.Cmd {
	return tea.Tick(time.Millisecond*200, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

type tickMsg time.Time

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case tickMsg:
		// Advance progress
		m.percent += 0.02

		// When phase completes, move to next
		if m.percent >= 1.0 {
			cmds = append(cmds, func() tea.Msg {
				return components.PhaseCompleteMsg{
					Phase:    m.phase,
					Duration: 5 * time.Second,
				}
			})
			m.phase++
			m.percent = 0.0

			// If all phases done, stop simulation
			if m.phase > components.PhaseAnalysis {
				return m, nil
			}
		}

		// Send progress update
		cmds = append(cmds, func() tea.Msg {
			return components.ProgressUpdateMsg{
				Phase:      m.phase,
				Percent:    m.percent,
				StatusText: fmt.Sprintf("Processing %s at %.0f%%", phaseToString(m.phase), m.percent*100),
			}
		})

		// Add some fake log lines occasionally
		if int(m.percent*100)%10 == 0 {
			logMsg := components.LogLineMsg{
				Line:      fmt.Sprintf("Discovered host 192.168.1.%d", int(m.percent*255)),
				Timestamp: time.Now(),
				Level:     "info",
			}
			cmds = append(cmds, func() tea.Msg { return logMsg })
		}

		// Continue simulation
		cmds = append(cmds, m.simulateProgress())

	case tea.WindowSizeMsg:
		m.progress = m.progress.SetWidth(msg.Width).SetHeight(msg.Height)
	}

	// Update progress component
	var cmd tea.Cmd
	m.progress, cmd = m.progress.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m model) View() string {
	return m.progress.View()
}

func phaseToString(p components.Phase) string {
	switch p {
	case components.PhaseRecon:
		return "Reconnaissance"
	case components.PhaseScan:
		return "Scanning"
	case components.PhaseAnalysis:
		return "Analysis"
	case components.PhaseComplete:
		return "Complete"
	default:
		return "Unknown"
	}
}

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}
}
