package views

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// ExampleReconView demonstrates how to use the ReconView in a Bubble Tea program.
// This example shows:
//   - Creating and initializing a ReconView
//   - Setting a target for reconnaissance
//   - Handling the full lifecycle (init, update, view)
//   - Integration with the main TUI loop
//
// Usage:
//   Run this example with: go run recon_example.go
//   Or integrate ReconView into your main TUI by following this pattern
func ExampleReconView() {
	// Create a new ReconView instance
	reconView := NewReconView()

	// Set the target domain/IP for reconnaissance
	// This would typically come from user input or a scan configuration
	reconView = reconView.SetTarget("example.com")

	// Set the view dimensions
	// In a real TUI, this would come from tea.WindowSizeMsg
	reconView = reconView.SetSize(120, 40)

	// Initialize and run the Bubble Tea program
	p := tea.NewProgram(reconViewModel{reconView})
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running recon view: %v\n", err)
	}
}

// reconViewModel wraps ReconView to implement the full Bubble Tea Model interface.
// This is needed because ReconView.Update returns (ReconView, tea.Cmd) instead of
// the generic (tea.Model, tea.Cmd) required by Bubble Tea.
//
// In a real application, this wrapping would be handled by your main TUI controller
// which manages multiple views (Dashboard, Recon, Results, etc.)
type reconViewModel struct {
	recon ReconView
}

// Init initializes the wrapped ReconView.
// Part of the Bubble Tea Model interface.
func (m reconViewModel) Init() tea.Cmd {
	return m.recon.Init()
}

// Update handles messages and updates the wrapped ReconView.
// Part of the Bubble Tea Model interface.
//
// This demonstrates the typical pattern for integrating ReconView:
//   1. Handle global quit keys (Ctrl+C, q)
//   2. Delegate all other messages to ReconView.Update
//   3. Wrap the updated ReconView back into the model
func (m reconViewModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Handle global quit keys
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
	}

	// Delegate to ReconView
	var cmd tea.Cmd
	m.recon, cmd = m.recon.Update(msg)
	return m, cmd
}

// View renders the wrapped ReconView.
// Part of the Bubble Tea Model interface.
func (m reconViewModel) View() string {
	return m.recon.View()
}

// ExampleReconViewManualMode demonstrates using ReconView in manual mode.
// Manual mode requires explicit confirmation for every reconnaissance phase.
func ExampleReconViewManualMode() {
	reconView := NewReconView()

	// Force manual mode (can also be toggled with /manual command at runtime)
	reconView.mode = ModeManual

	reconView = reconView.SetTarget("target.com")
	reconView = reconView.SetSize(120, 40)

	p := tea.NewProgram(reconViewModel{reconView})
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running recon view: %v\n", err)
	}
}

// ExampleReconViewWorkflow demonstrates a complete reconnaissance workflow.
// Shows the typical lifecycle and state transitions.
func ExampleReconViewWorkflow() {
	// 1. Create ReconView
	reconView := NewReconView()
	fmt.Printf("Initial state: Phase=%s, Mode=%s\n",
		reconView.currentPhase, reconView.getModeString())

	// 2. Configure target
	reconView = reconView.SetTarget("vulnerable-site.com")

	// 3. In a real program, these updates would be called by Bubble Tea
	// Here we simulate the workflow:

	// User presses 'r' to start reconnaissance
	simulatedMsg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}}
	reconView, _ = reconView.Update(simulatedMsg)
	fmt.Printf("After start: Phase=%s, InProgress=%v\n",
		reconView.currentPhase, reconView.inProgress)

	// Simulate phase completion
	// In production, this would be sent when actual tools finish
	result := ReconResult{
		Phase:    PhaseSubdomain,
		Tool:     "subfinder",
		Output:   "Found 10 subdomains",
		Findings: 10,
	}
	reconView.results = append(reconView.results, result)
	reconView.currentPhase = PhaseDNS
	reconView.inProgress = false

	fmt.Printf("After subdomain phase: Phase=%s, Results=%d\n",
		reconView.currentPhase, len(reconView.results))

	// 4. Render the view
	output := reconView.View()
	fmt.Printf("View rendered: %d characters\n", len(output))
}

// ExampleReconViewCustomTools demonstrates customizing available tools.
// Useful for adapting to different environments or tool installations.
func ExampleReconViewCustomTools() {
	reconView := NewReconView()

	// Customize tools based on what's actually installed
	// In production, you would check with exec.LookPath
	reconView.tools = []ReconTool{
		{Name: "nmap", Description: "Port scanner", Installed: true, Required: true},
		{Name: "masscan", Description: "Fast port scanner", Installed: true, Required: false},
		{Name: "subfinder", Description: "Subdomain enum", Installed: true, Required: false},
		{Name: "amass", Description: "Advanced subdomain discovery", Installed: false, Required: false},
		{Name: "dig", Description: "DNS lookup", Installed: true, Required: true},
		{Name: "whois", Description: "WHOIS client", Installed: true, Required: true},
	}

	// Display tool status
	reconView.showToolStatus()
	fmt.Printf("Custom tools configured: %d tools\n", len(reconView.tools))
}

// ExampleReconViewCommands demonstrates using the command system.
// Shows how to process various commands and mode switches.
func ExampleReconViewCommands() {
	reconView := NewReconView()
	reconView = reconView.SetTarget("example.com")

	// Simulate entering command mode and typing commands
	commands := []string{
		"/help",      // Show help
		"/tools",     // Show tool status
		"/manual",    // Switch to manual mode
		"/auto",      // Switch back to semi-auto
		"/reset",     // Reset session
	}

	for _, cmd := range commands {
		fmt.Printf("Processing command: %s\n", cmd)
		reconView, _ = reconView.processCommand(cmd)
		fmt.Printf("  Mode after: %s, Phase: %s\n",
			reconView.getModeString(), reconView.currentPhase)
	}
}

// ExampleReconViewDenyPrompt demonstrates the Claude Code-style deny prompt.
// Shows how risky operations trigger confirmation dialogs.
func ExampleReconViewDenyPrompt() {
	reconView := NewReconView()
	reconView = reconView.SetTarget("example.com")
	reconView.currentPhase = PhasePort // Port scanning is risky

	// In semi-auto mode, port scanning triggers a deny prompt
	reconView, _ = reconView.startNextPhase()

	if reconView.denyPrompt.Active {
		fmt.Printf("Deny prompt triggered!\n")
		fmt.Printf("  Operation: %s\n", reconView.denyPrompt.Operation)
		fmt.Printf("  Reason: %s\n", reconView.denyPrompt.Reason)
		fmt.Printf("  Redirect: %s\n", reconView.denyPrompt.Redirect)

		// Simulate user confirming with 'y'
		confirmMsg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}}
		reconView, _ = reconView.handleDenyPromptKey(confirmMsg)

		fmt.Printf("After confirmation: DenyPrompt.Active=%v\n", reconView.denyPrompt.Active)
	}
}

// ExampleReconViewVimNavigation demonstrates Vim-style keyboard navigation.
// Shows the various navigation keys supported by ReconView.
func ExampleReconViewVimNavigation() {
	reconView := NewReconView()
	reconView = reconView.SetTarget("example.com")
	reconView.SetSize(80, 24)

	// Add some content to scroll through
	for i := 0; i < 50; i++ {
		reconView.appendOutput(fmt.Sprintf("Line %d\n", i))
	}

	// Simulate Vim navigation keys
	keys := []string{"j", "k", "g", "G", "ctrl+d", "ctrl+u"}

	for _, key := range keys {
		fmt.Printf("Navigation key: %s\n", key)
		// In a real program, these would be tea.KeyMsg events
		// reconView.Update(tea.KeyMsg{...})
	}

	fmt.Printf("Total output lines: %d\n", strings.Count(reconView.streamBuffer.String(), "\n"))
}

// ExampleReconViewIntegration shows how to integrate ReconView into a larger TUI.
// Demonstrates switching between multiple views (Dashboard, Recon, Results, etc.)
func ExampleReconViewIntegration() {
	// In a real TUI, you would have a main model that manages multiple views:
	//
	// type MainModel struct {
	//     currentView string  // "dashboard", "recon", "results", etc.
	//     dashboard   Dashboard
	//     recon       ReconView
	//     results     ResultsView
	//     // ... other views
	// }
	//
	// func (m MainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	//     switch m.currentView {
	//     case "recon":
	//         m.recon, cmd = m.recon.Update(msg)
	//         return m, cmd
	//     case "dashboard":
	//         // ... handle dashboard
	//     }
	// }
	//
	// func (m MainModel) View() string {
	//     switch m.currentView {
	//     case "recon":
	//         return m.recon.View()
	//     case "dashboard":
	//         return m.dashboard.View()
	//     }
	// }

	fmt.Println("See code comments for integration pattern")
}

// ExampleReconViewRealTimeStreaming demonstrates real-time output streaming.
// In production, this would stream live output from running recon tools.
func ExampleReconViewRealTimeStreaming() {
	reconView := NewReconView()
	reconView = reconView.SetTarget("example.com")

	// Simulate streaming output from a running tool
	// In production, this would be done with a goroutine reading from
	// the tool's stdout/stderr and sending updates via tea.Cmd
	outputs := []string{
		"[nmap] Starting Nmap scan...\n",
		"[nmap] Scanning 192.168.1.1...\n",
		"[nmap] Discovered open port 22/tcp\n",
		"[nmap] Discovered open port 80/tcp\n",
		"[nmap] Discovered open port 443/tcp\n",
		"[nmap] Scan complete: 3 ports found\n",
	}

	for _, output := range outputs {
		reconView.appendOutput(output)
		// In real code, each output would trigger a view refresh
	}

	fmt.Printf("Final output buffer size: %d bytes\n", reconView.streamBuffer.Len())
	fmt.Printf("Viewport at bottom: %v\n", reconView.viewport.AtBottom())
}
