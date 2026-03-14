package views

// Example usage of the Dashboard view component.
// This file demonstrates how to integrate the dashboard into a Bubble Tea application.

/*
// Example 1: Empty state (no scans)
func exampleEmptyDashboard() {
	dashboard := NewDashboard()
	dashboard = dashboard.SetSize(80, 24)

	// Render empty state
	view := dashboard.View()
	fmt.Println(view)
}

// Example 2: Dashboard with data
func exampleDashboardWithData() {
	dashboard := NewDashboard()
	dashboard = dashboard.SetSize(80, 24)

	// Set statistics
	dashboard = dashboard.SetStats(DashboardStats{
		TotalScans: 12,
		Critical:   2,
		High:       5,
		Medium:     8,
		Low:        15,
	})

	// Add recent scans with timestamps
	dashboard = dashboard.SetRecent([]RecentScan{
		{Target: "example.com", Status: "Complete", Findings: 3, Timestamp: "2h ago"},
		{Target: "192.168.1.1", Status: "Complete", Findings: 0, Timestamp: "5h ago"},
		{Target: "test.local", Status: "Running", Findings: 0, Timestamp: "just now"},
		{Target: "api.target.io", Status: "Complete", Findings: 7, Timestamp: "Yesterday"},
		{Target: "internal.corp", Status: "Failed", Error: "Connection timeout", Timestamp: "3 days ago"},
	})

	// Set system status
	dashboard = dashboard.SetSystem(SystemStatus{
		AIRunning:   true,
		AIProvider:  "Claude",
		ToolsTotal:  30,
		ToolsAvail:  28,
		DBConnected: true,
	})

	// Render dashboard with data
	view := dashboard.View()
	fmt.Println(view)
}

// Example 3: Integration with Bubble Tea
type AppModel struct {
	dashboard Dashboard
	// ... other fields
}

func (m AppModel) Init() tea.Cmd {
	return nil
}

func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Update dashboard size on terminal resize
		m.dashboard = m.dashboard.SetSize(msg.Width, msg.Height-4) // Reserve space for header/footer

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	}

	// Update dashboard (handles resize events)
	updatedDashboard, cmd := m.dashboard.Update(msg)
	m.dashboard = updatedDashboard

	return m, cmd
}

func (m AppModel) View() string {
	// Render the dashboard
	return m.dashboard.View()
}
*/
