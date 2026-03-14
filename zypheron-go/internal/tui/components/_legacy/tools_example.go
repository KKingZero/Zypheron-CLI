package views

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

// ExampleToolsView demonstrates the Tools view in a standalone program.
//
// This example shows:
// - How to create and initialize a ToolsView
// - Navigation with keyboard (j/k, arrow keys, g/G, PgUp/PgDn)
// - Real-time tool status checking
// - Detail panel display for selected tools
//
// Run with:
//   go run internal/tui/views/tools_example.go
func ExampleToolsView() {
	// Create new tools view
	toolsView := NewToolsView()

	// Create Bubble Tea program
	p := tea.NewProgram(
		toolsModel{view: toolsView},
		tea.WithAltScreen(),
	)

	// Run the program
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running tools view: %v\n", err)
		os.Exit(1)
	}
}

// toolsModel wraps ToolsView for use in a standalone program
// This demonstrates how to integrate ToolsView into a Bubble Tea application
type toolsModel struct {
	view ToolsView
}

// Init initializes the tools model
func (m toolsModel) Init() tea.Cmd {
	return m.view.Init()
}

// Update handles messages and updates the model
func (m toolsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Handle quit keys
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		// Update view size
		m.view = m.view.SetSize(msg.Width, msg.Height)
	}

	// Forward all messages to the tools view
	var cmd tea.Cmd
	m.view, cmd = m.view.Update(msg)
	return m, cmd
}

// View renders the model
func (m toolsModel) View() string {
	// Add header
	header := "Zypheron Security Tools - Press 'q' to quit\n\n"

	// Render the tools view
	return header + m.view.View()
}

// Example usage comment for godoc
// This function can be called directly to run the example:
//
//	func main() {
//	    views.ExampleToolsView()
//	}
