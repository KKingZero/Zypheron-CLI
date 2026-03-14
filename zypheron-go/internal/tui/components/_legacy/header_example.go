package components

// Example usage of the Header component in a Bubble Tea application.
//
// This file demonstrates how to integrate the Header component into your TUI views.
// It is not meant to be compiled as part of the main application, but serves as
// reference documentation for developers.

/*

// Basic integration in a Bubble Tea model:

type Model struct {
    header Header
    // ... other fields
}

func NewModel() Model {
    return Model{
        header: NewHeader(),
    }
}

func (m Model) Init() tea.Cmd {
    return m.header.Init()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    var cmd tea.Cmd

    // Update header with messages (handles WindowSizeMsg automatically)
    m.header, cmd = m.header.Update(msg)

    // Handle view changes
    switch msg := msg.(type) {
    case tea.KeyMsg:
        switch msg.String() {
        case "s":
            // Navigate to scan view
            m.header = m.header.SetActiveTab("scan")
            m.header = m.header.SetBreadcrumb([]string{"Zypheron", "Scan"})
        case "r":
            // Navigate to recon view
            m.header = m.header.SetActiveTab("recon")
            m.header = m.header.SetBreadcrumb([]string{"Zypheron", "Recon"})
        case "a":
            // Navigate to AI view
            m.header = m.header.SetActiveTab("ai")
            m.header = m.header.SetBreadcrumb([]string{"Zypheron", "AI Assistant"})
        // ... handle other tab shortcuts
        }
    }

    return m, cmd
}

func (m Model) View() string {
    return m.header.View() + "\n" + m.renderContent()
}

// Example: Updating breadcrumb when navigating deeper into a view
func (m Model) navigateToNmapScan(target string) {
    m.header = m.header.SetBreadcrumb([]string{"Zypheron", "Scan", "nmap", target})
}

// Example: Dynamic breadcrumb based on application state
func (m Model) updateBreadcrumb() {
    crumbs := []string{"Zypheron"}

    switch m.currentView {
    case "scan":
        crumbs = append(crumbs, "Scan")
        if m.selectedTool != "" {
            crumbs = append(crumbs, m.selectedTool)
        }
        if m.scanTarget != "" {
            crumbs = append(crumbs, m.scanTarget)
        }
    case "recon":
        crumbs = append(crumbs, "Recon")
        // Add recon-specific breadcrumb elements
    // ... other views
    }

    m.header = m.header.SetBreadcrumb(crumbs)
}

*/
