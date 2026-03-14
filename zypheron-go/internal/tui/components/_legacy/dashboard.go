package views

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
)

// DashboardStats holds aggregate statistics for scans and findings.
// Used to populate the stats overview panel on the dashboard.
type DashboardStats struct {
	TotalScans int // Total number of scans performed
	Critical   int // Number of critical severity findings
	High       int // Number of high severity findings
	Medium     int // Number of medium severity findings
	Low        int // Number of low severity findings
}

// RecentScan represents a single scan entry in the recent scans list.
// Contains the minimal information needed to display scan status at a glance.
type RecentScan struct {
	Target    string // Target hostname or IP address
	Status    string // Scan status: "Complete", "Running", "Failed"
	Findings  int    // Number of findings discovered (ignored for Running/Failed)
	Error     string // Error message if status is "Failed"
	Timestamp string // Time when scan was performed (e.g., "2h ago", "Yesterday")
}

// SystemStatus represents the current state of the Zypheron system.
// Displays connectivity and availability of critical components.
type SystemStatus struct {
	AIRunning  bool   // Whether the AI engine is currently running
	AIProvider string // Name of the AI provider (e.g., "Claude", "OpenAI")
	ToolsTotal int    // Total number of security tools in the system
	ToolsAvail int    // Number of tools currently available
	DBConnected bool  // Whether the database connection is active
}

// Dashboard is the main landing view for the Zypheron TUI.
// Shows an empty state when no scans exist, or displays stats, recent scans,
// and system status when data is available.
type Dashboard struct {
	width  int          // Current terminal width
	height int          // Current terminal height
	stats  DashboardStats // Aggregate scan statistics
	recent []RecentScan // List of recent scans (max 5)
	system SystemStatus // Current system status
	empty  bool         // Whether to show empty state (no scans yet)
}

// NewDashboard creates a new Dashboard with default values.
// Initializes in empty state with reasonable defaults for system status.
//
// Returns:
//   - Dashboard instance ready to be integrated into a Bubble Tea program
func NewDashboard() Dashboard {
	return Dashboard{
		width:  80,
		height: 20,
		empty:  true, // Start in empty state (no scans)
		system: SystemStatus{
			AIRunning:   false,
			AIProvider:  "",
			ToolsTotal:  30,
			ToolsAvail:  28,
			DBConnected: false,
		},
	}
}

// Init initializes the Dashboard component.
// Required by the Bubble Tea Model interface.
//
// Returns:
//   - nil (no initial commands to run)
func (d Dashboard) Init() tea.Cmd {
	return nil
}

// Update handles terminal resize messages to adjust dashboard layout.
// Part of the Bubble Tea Model interface.
//
// Parameters:
//   - msg: Bubble Tea message (typically tea.WindowSizeMsg)
//
// Returns:
//   - Updated Dashboard model
//   - Command to run (always nil for dashboard)
func (d Dashboard) Update(msg tea.Msg) (Dashboard, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Adjust layout when terminal is resized
		d.width = msg.Width
		d.height = msg.Height
	}
	return d, nil
}

// SetStats updates the dashboard statistics and exits empty state if scans exist.
//
// Parameters:
//   - s: DashboardStats with current scan statistics
//
// Returns:
//   - Updated Dashboard instance
func (d Dashboard) SetStats(s DashboardStats) Dashboard {
	d.stats = s
	// Exit empty state if we have scans
	d.empty = s.TotalScans == 0
	return d
}

// SetRecent updates the list of recent scans shown on the dashboard.
// Typically limited to the 5 most recent scans.
//
// Parameters:
//   - scans: Slice of RecentScan entries
//
// Returns:
//   - Updated Dashboard instance
func (d Dashboard) SetRecent(scans []RecentScan) Dashboard {
	d.recent = scans
	return d
}

// SetSystem updates the system status indicators.
//
// Parameters:
//   - s: SystemStatus with current system state
//
// Returns:
//   - Updated Dashboard instance
func (d Dashboard) SetSystem(s SystemStatus) Dashboard {
	d.system = s
	return d
}

// SetSize manually sets the dashboard dimensions.
// Useful when the dashboard is embedded in a larger layout.
//
// Parameters:
//   - w: Width in characters
//   - h: Height in lines
//
// Returns:
//   - Updated Dashboard instance
func (d Dashboard) SetSize(w, h int) Dashboard {
	d.width = w
	d.height = h
	return d
}

// View renders the dashboard to a string.
// Part of the Bubble Tea Model interface.
// Displays either the empty state or the full dashboard with data.
//
// Returns:
//   - Rendered dashboard as a string
func (d Dashboard) View() string {
	if d.empty {
		return d.renderEmpty()
	}
	return d.renderWithData()
}

// renderEmpty renders the welcome/empty state with ASCII art and getting started tips.
// Shown when the user has not performed any scans yet.
//
// Returns:
//   - Formatted empty state view
func (d Dashboard) renderEmpty() string {
	// ASCII art logo using Unicode box-drawing characters
	logo := `
                         ███████╗██╗   ██╗██████╗
                         ╚══███╔╝╚██╗ ██╔╝██╔══██╗
                           ███╔╝  ╚████╔╝ ██████╔╝
                          ███╔╝    ╚██╔╝  ██╔═══╝
                         ███████╗   ██║   ██║
                         ╚══════╝   ╚═╝   ╚═╝
`

	welcome := "Welcome to Zypheron TUI"

	// Getting started tips with keyboard shortcuts
	tips := `
         No scans yet. Here's how to get started:

         • Press [S] to start a new scan
         • Press [:] to open command palette
         • Press [?] for help and keybindings
`

	// Style the different sections
	logoStyle := lipgloss.NewStyle().Foreground(styles.ColorWhite).Bold(true)
	welcomeStyle := lipgloss.NewStyle().Foreground(styles.ColorLightGray).Bold(true)
	tipsStyle := lipgloss.NewStyle().Foreground(styles.ColorGray)

	// Combine all sections
	content := logoStyle.Render(logo) + "\n" +
		welcomeStyle.Render(welcome) + "\n" +
		tipsStyle.Render(tips)

	// Center everything in the available space
	return lipgloss.NewStyle().
		Width(d.width).
		Height(d.height).
		Align(lipgloss.Center, lipgloss.Center).
		Render(content)
}

// renderWithData renders the full dashboard with stats, recent scans, and system status.
// Uses rounded borders (╭─╮╰─╯) for inner boxes to differentiate from main double-line border.
//
// Returns:
//   - Formatted dashboard view with all data panels
func (d Dashboard) renderWithData() string {
	// Rounded border style for inner boxes (different from main double-line border)
	roundedBorder := lipgloss.Border{
		Top:         "─",
		Bottom:      "─",
		Left:        "│",
		Right:       "│",
		TopLeft:     "╭",
		TopRight:    "╮",
		BottomLeft:  "╰",
		BottomRight: "╯",
	}

	// === STATS BOX ===
	// Display total scans and findings broken down by severity
	statsContent := fmt.Sprintf(
		"Total Scans:    %d\n"+
			"%s:       %d\n"+
			"%s:           %d\n"+
			"%s:        %d\n"+
			"%s:            %d",
		d.stats.TotalScans,
		styles.CriticalStyle.Render("Critical"), d.stats.Critical,
		styles.HighStyle.Render("High"), d.stats.High,
		styles.MediumStyle.Render("Medium"), d.stats.Medium,
		styles.LowStyle.Render("Low"), d.stats.Low,
	)

	// Create stats box with title
	statsBoxWithTitle := lipgloss.NewStyle().
		BorderStyle(roundedBorder).
		BorderForeground(styles.ColorGray).
		Padding(0, 1).
		Width(25).
		Render(fmt.Sprintf("%s\n%s",
			styles.MutedStyle.Render("─ Stats ─"),
			statsContent))

	// === RECENT SCANS BOX ===
	// Display the last 5 scans with status, findings count, and timestamp
	var recentLines []string
	for _, scan := range d.recent {
		status := d.formatStatus(scan.Status)
		findings := fmt.Sprintf("%d findings", scan.Findings)

		// Special handling for Running and Failed states
		if scan.Status == "Running" {
			findings = "--"
		} else if scan.Status == "Failed" {
			findings = "Error"
		}

		// Format timestamp with muted style
		timestamp := styles.MutedStyle.Render(scan.Timestamp)

		// Format: • target [status] findings - timestamp
		line := fmt.Sprintf("• %-18s %s  %-12s %s", scan.Target, status, findings, timestamp)
		recentLines = append(recentLines, line)
	}
	recentContent := strings.Join(recentLines, "\n")

	// Create recent scans box with title
	recentBoxWithTitle := lipgloss.NewStyle().
		BorderStyle(roundedBorder).
		BorderForeground(styles.ColorGray).
		Padding(0, 1).
		Width(60).
		Render(fmt.Sprintf("%s\n%s",
			styles.MutedStyle.Render("─ Recent Scans ─"),
			recentContent))

	// === TOP ROW: STATS + RECENT SCANS ===
	// Place boxes side by side with spacing
	topRow := lipgloss.JoinHorizontal(lipgloss.Top, statsBoxWithTitle, "  ", recentBoxWithTitle)

	// === SYSTEM STATUS BOX ===
	// Display AI engine, tools, and database status
	aiStatus := "○ Stopped"
	if d.system.AIRunning {
		aiStatus = fmt.Sprintf("● Running (%s)", d.system.AIProvider)
	}

	dbStatus := "Disconnected"
	if d.system.DBConnected {
		dbStatus = "Connected"
	}

	systemContent := fmt.Sprintf(
		"AI Engine: %s    Tools: %d/%d available    DB: %s",
		aiStatus, d.system.ToolsAvail, d.system.ToolsTotal, dbStatus,
	)

	// Create system status box spanning full width
	systemBoxWithTitle := lipgloss.NewStyle().
		BorderStyle(roundedBorder).
		BorderForeground(styles.ColorGray).
		Padding(0, 1).
		Width(d.width - 4). // Leave some margin
		Render(fmt.Sprintf("%s\n%s",
			styles.MutedStyle.Render("─ System Status ─"),
			systemContent))

	// === QUICK ACTIONS BOX ===
	// Display keyboard shortcuts for common actions
	quickActionsContent := fmt.Sprintf(
		"%s Start new scan    %s View results    %s History    %s Command palette    %s Help",
		styles.KeyStyle.Render("[S]"),
		styles.KeyStyle.Render("[R]"),
		styles.KeyStyle.Render("[H]"),
		styles.KeyStyle.Render("[:]"),
		styles.KeyStyle.Render("[?]"),
	)

	quickActionsBox := lipgloss.NewStyle().
		BorderStyle(roundedBorder).
		BorderForeground(styles.ColorGray).
		Padding(0, 1).
		Width(d.width - 4).
		Render(fmt.Sprintf("%s\n%s",
			styles.MutedStyle.Render("─ Quick Actions ─"),
			quickActionsContent))

	// === COMBINE ALL PANELS ===
	// Vertical layout: top row + blank line + system status + blank line + quick actions
	return lipgloss.JoinVertical(lipgloss.Left, topRow, "", systemBoxWithTitle, "", quickActionsBox)
}

// formatStatus returns a styled status indicator for scan status.
// Maps status strings to appropriate color-coded labels.
//
// Parameters:
//   - status: Raw status string ("Complete", "Running", "Failed", etc.)
//
// Returns:
//   - Styled status string with color and brackets
func (d Dashboard) formatStatus(status string) string {
	switch status {
	case "Complete":
		// Green for successful completion
		return styles.LowStyle.Render("[Complete]")
	case "Running":
		// Blue for in-progress scans
		return styles.InfoStyle.Render("[Running]")
	case "Failed":
		// Red for failed scans
		return styles.CriticalStyle.Render("[Failed]")
	default:
		// Gray for unknown/custom statuses
		return styles.MutedStyle.Render("[" + status + "]")
	}
}
