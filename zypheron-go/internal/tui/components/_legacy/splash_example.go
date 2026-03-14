package components

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

// ExampleSplashModel demonstrates how to integrate the Splash component into a Bubble Tea app
// This shows the pattern for transitioning from splash screen to main application
type ExampleSplashModel struct {
	splash      Splash
	showingSplash bool
}

// NewExampleSplashModel creates a new example model that demonstrates splash screen usage
func NewExampleSplashModel() ExampleSplashModel {
	return ExampleSplashModel{
		splash:      NewSplash(),
		showingSplash: true,
	}
}

// Init initializes the example model and starts the splash screen
func (m ExampleSplashModel) Init() tea.Cmd {
	return m.splash.Init()
}

// Update handles messages and manages the transition from splash to main content
func (m ExampleSplashModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Handle quit keys
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case SplashDoneMsg:
		// Splash screen is complete - transition to main UI
		m.showingSplash = false
		return m, nil
	}

	// If still showing splash, update it
	if m.showingSplash {
		var cmd tea.Cmd
		m.splash, cmd = m.splash.Update(msg)
		return m, cmd
	}

	return m, nil
}

// View renders either the splash screen or main content
func (m ExampleSplashModel) View() string {
	if m.showingSplash {
		return m.splash.View()
	}

	// After splash, show main content
	// In a real app, this would be replaced with the dashboard or main UI
	return "Main application content goes here\n\nPress 'q' to quit"
}

// RunSplashExample demonstrates the splash screen in a standalone app
// This can be used for testing or as a reference implementation
func RunSplashExample() {
	p := tea.NewProgram(NewExampleSplashModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running splash example: %v\n", err)
		os.Exit(1)
	}
}
