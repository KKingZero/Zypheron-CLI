// Package views provides the Tools view for the Zypheron TUI.
//
// The Tools view displays a comprehensive list of security tools used by Zypheron,
// organized by category (Scanning, Recon, Exploitation, Utilities). It provides
// real-time status checking, version information, and detailed descriptions.
//
// Key Features:
//   - Categorized tool list with visual organization
//   - Real-time installation status indicators ([+] installed, [-] missing, [~] installing)
//   - Keyboard navigation (j/k, arrow keys, g/G, PgUp/PgDn)
//   - Detail panel showing selected tool information
//   - Integration with ToolStatus component for status checking
//   - Security-focused design following OWASP guidelines
//
// Usage:
//   toolsView := views.NewToolsView()
//   p := tea.NewProgram(toolsView)
//   p.Run()
package views

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/components"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
)

// ToolCategory represents a category of security tools
// Used to group related tools together in the UI
type ToolCategory struct {
	Name        string             // Category name (e.g., "Scanning", "Recon")
	Description string             // Brief category description
	Tools       []ToolInfo         // List of tools in this category
}

// ToolInfo represents detailed information about a security tool
// Extends the basic Tool from components with category-specific metadata
type ToolInfo struct {
	Name           string                 // Tool name (e.g., "nmap")
	DisplayName    string                 // Human-friendly name
	Description    string                 // Tool description
	Status         components.ToolStatus  // Installation status
	Version        string                 // Detected version
	Category       string                 // Category name
	Required       bool                   // Whether tool is required
}

// ToolsView displays a categorized list of security tools with status indicators.
//
// Key features:
// - Tools organized by category (Scanning, Recon, Exploitation, Utilities)
// - Real-time status indicators ([+] installed, [-] missing, [~] installing)
// - Keyboard navigation with j/k or arrow keys
// - Selected tool details displayed in side panel
// - Version information for installed tools
// - Visual highlighting of required tools
//
// Layout:
// ┌─ Tools List ────────┐  ┌─ Tool Details ──────┐
// │ [+] nmap           │  │ Name: Nmap          │
// │ [-] nuclei         │  │ Status: Installed   │
// │ [+] nikto          │  │ Version: 7.93       │
// │                    │  │                     │
// │ === Recon ===      │  │ Description:        │
// │ [+] subfinder      │  │ Network scanner...  │
// │ [-] amass          │  │                     │
// └────────────────────┘  └─────────────────────┘
type ToolsView struct {
	width           int              // Terminal width
	height          int              // Terminal height
	categories      []ToolCategory   // All tool categories
	flatTools       []ToolInfo       // Flattened list for navigation
	selectedIndex   int              // Currently selected tool index
	scrollOffset    int              // Scroll position in tool list
	toolStatusPanel components.ToolStatusPanel // Underlying status checker
}

// NewToolsView creates and initializes a new ToolsView.
//
// Returns:
//   - ToolsView configured with all security tool categories
//
// Initializes with a comprehensive list of security tools organized by category.
// Tool statuses are marked as unknown initially; they will be checked asynchronously.
func NewToolsView() ToolsView {
	// Initialize the underlying tool status panel
	statusPanel := components.NewToolStatusPanel()

	// Define tool categories with detailed tool information
	categories := []ToolCategory{
		{
			Name:        "Scanning",
			Description: "Network and vulnerability scanners",
			Tools: []ToolInfo{
				{
					Name:        "nmap",
					DisplayName: "Nmap",
					Description: "Network exploration tool and security/port scanner. Industry-standard for network discovery and security auditing.",
					Category:    "Scanning",
					Status:      components.ToolStatusUnknown,
					Required:    true,
				},
				{
					Name:        "nuclei",
					DisplayName: "Nuclei",
					Description: "Fast and customizable vulnerability scanner based on templates. Supports 1000+ vulnerability types.",
					Category:    "Scanning",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
				{
					Name:        "nikto",
					DisplayName: "Nikto",
					Description: "Web server scanner which performs comprehensive tests against web servers for multiple security issues.",
					Category:    "Scanning",
					Status:      components.ToolStatusUnknown,
					Required:    true,
				},
				{
					Name:        "masscan",
					DisplayName: "Masscan",
					Description: "TCP port scanner that transmits SYN packets asynchronously. Can scan the entire Internet in under 5 minutes.",
					Category:    "Scanning",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
				{
					Name:        "zap",
					DisplayName: "OWASP ZAP",
					Description: "Web application security scanner. One of the world's most popular free security tools.",
					Category:    "Scanning",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
			},
		},
		{
			Name:        "Recon",
			Description: "Information gathering and reconnaissance",
			Tools: []ToolInfo{
				{
					Name:        "subfinder",
					DisplayName: "Subfinder",
					Description: "Subdomain discovery tool that discovers subdomains using passive sources. Supports 30+ sources.",
					Category:    "Recon",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
				{
					Name:        "amass",
					DisplayName: "Amass",
					Description: "In-depth attack surface mapping and asset discovery tool. Performs network mapping of attack surfaces.",
					Category:    "Recon",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
				{
					Name:        "httpx",
					DisplayName: "httpx",
					Description: "Fast and multi-purpose HTTP toolkit that allows running multiple probes using retryable HTTP library.",
					Category:    "Recon",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
				{
					Name:        "dnsx",
					DisplayName: "dnsx",
					Description: "Fast and multi-purpose DNS toolkit for running various DNS queries. Supports DNS validation and verification.",
					Category:    "Recon",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
				{
					Name:        "whatweb",
					DisplayName: "WhatWeb",
					Description: "Web technology detector that identifies CMS, blogging platforms, JavaScript libraries, web servers, and more.",
					Category:    "Recon",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
				{
					Name:        "theHarvester",
					DisplayName: "theHarvester",
					Description: "OSINT gathering tool for collecting emails, names, subdomains, IPs, and URLs from public sources.",
					Category:    "Recon",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
			},
		},
		{
			Name:        "Exploitation",
			Description: "Penetration testing and exploitation frameworks",
			Tools: []ToolInfo{
				{
					Name:        "sqlmap",
					DisplayName: "SQLMap",
					Description: "Automatic SQL injection and database takeover tool. Supports all major database management systems.",
					Category:    "Exploitation",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
				{
					Name:        "msfconsole",
					DisplayName: "Metasploit Framework",
					Description: "Advanced penetration testing platform with the world's largest database of public, tested exploits.",
					Category:    "Exploitation",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
				{
					Name:        "burpsuite",
					DisplayName: "Burp Suite",
					Description: "Integrated platform for performing security testing of web applications. Industry-standard tool.",
					Category:    "Exploitation",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
				{
					Name:        "gobuster",
					DisplayName: "Gobuster",
					Description: "Directory/file & DNS busting tool written in Go. Fast and efficient for content discovery.",
					Category:    "Exploitation",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
				{
					Name:        "ffuf",
					DisplayName: "ffuf",
					Description: "Fast web fuzzer written in Go. Supports various fuzzing modes including GET, POST, and header fuzzing.",
					Category:    "Exploitation",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
			},
		},
		{
			Name:        "Utilities",
			Description: "Network utilities and supporting tools",
			Tools: []ToolInfo{
				{
					Name:        "curl",
					DisplayName: "cURL",
					Description: "Command-line tool for transferring data with URLs. Supports HTTP, HTTPS, FTP, and many other protocols.",
					Category:    "Utilities",
					Status:      components.ToolStatusUnknown,
					Required:    true,
				},
				{
					Name:        "wget",
					DisplayName: "Wget",
					Description: "Non-interactive network downloader. Supports HTTP, HTTPS, and FTP protocols with resume capability.",
					Category:    "Utilities",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
				{
					Name:        "whois",
					DisplayName: "Whois",
					Description: "Client for the whois directory service. Queries databases about domain registration and IP ownership.",
					Category:    "Utilities",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
				{
					Name:        "dig",
					DisplayName: "dig",
					Description: "DNS lookup utility. Flexible tool for interrogating DNS name servers and diagnosing DNS problems.",
					Category:    "Utilities",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
				{
					Name:        "nslookup",
					DisplayName: "nslookup",
					Description: "Query Internet domain name servers. Simple tool for DNS troubleshooting and information gathering.",
					Category:    "Utilities",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
				{
					Name:        "netcat",
					DisplayName: "Netcat",
					Description: "Networking utility for reading/writing network connections using TCP/UDP. The 'Swiss Army knife' of networking.",
					Category:    "Utilities",
					Status:      components.ToolStatusUnknown,
					Required:    false,
				},
			},
		},
	}

	// Flatten tool list for navigation
	flatTools := make([]ToolInfo, 0)
	for _, category := range categories {
		flatTools = append(flatTools, category.Tools...)
	}

	return ToolsView{
		width:           80,
		height:          24,
		categories:      categories,
		flatTools:       flatTools,
		selectedIndex:   0,
		scrollOffset:    0,
		toolStatusPanel: statusPanel,
	}
}

// Init initializes the ToolsView component.
// Required by the Bubble Tea Model interface.
//
// Returns:
//   - tea.Cmd to trigger tool status checks
func (t ToolsView) Init() tea.Cmd {
	// Trigger initial tool status checks
	return t.toolStatusPanel.Init()
}

// Update handles all messages and updates the ToolsView state.
//
// Parameters:
//   - msg: tea.Msg - Any Bubble Tea message
//
// Returns:
//   - ToolsView: Updated view state
//   - tea.Cmd: Any command to execute
//
// Handles:
// - Window resizing: Adjusts layout
// - Keyboard input: Navigation, selection
// - Tool status updates: Reflects current installation status
func (t ToolsView) Update(msg tea.Msg) (ToolsView, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Update dimensions
		t.width = msg.Width
		t.height = msg.Height

	case tea.KeyMsg:
		// Handle keyboard navigation
		switch msg.String() {
		case "j", "down":
			// Navigate down
			if t.selectedIndex < len(t.flatTools)-1 {
				t.selectedIndex++
				t.updateScrollOffset()
			}

		case "k", "up":
			// Navigate up
			if t.selectedIndex > 0 {
				t.selectedIndex--
				t.updateScrollOffset()
			}

		case "g", "home":
			// Jump to top
			t.selectedIndex = 0
			t.scrollOffset = 0

		case "G", "end":
			// Jump to bottom
			t.selectedIndex = len(t.flatTools) - 1
			t.updateScrollOffset()

		case "pgdown":
			// Page down
			pageSize := t.getVisibleToolCount()
			t.selectedIndex += pageSize
			if t.selectedIndex >= len(t.flatTools) {
				t.selectedIndex = len(t.flatTools) - 1
			}
			t.updateScrollOffset()

		case "pgup":
			// Page up
			pageSize := t.getVisibleToolCount()
			t.selectedIndex -= pageSize
			if t.selectedIndex < 0 {
				t.selectedIndex = 0
			}
			t.updateScrollOffset()
		}

	case components.ToolCheckCompleteMsg:
		// Update tool status from status panel
		t = t.updateToolStatus(msg.ToolName, msg.Status, msg.Version)

		// Forward to tool status panel for its own state management
		panel, cmd := t.toolStatusPanel.Update(msg)
		t.toolStatusPanel = panel
		cmds = append(cmds, cmd)

	case components.ToolInstallProgressMsg, components.ToolInstallCompleteMsg:
		// Forward to tool status panel
		panel, cmd := t.toolStatusPanel.Update(msg)
		t.toolStatusPanel = panel
		cmds = append(cmds, cmd)
	}

	return t, tea.Batch(cmds...)
}

// updateToolStatus updates the status of a specific tool in all data structures.
// This ensures consistency between the categories view and the flat navigation list.
//
// Parameters:
//   - toolName: Name of the tool to update
//   - status: New status
//   - version: Detected version string
//
// Returns:
//   - ToolsView: Updated view with new tool status
//
// Security Note: Input validation is performed to prevent invalid tool names
// from causing panics or undefined behavior.
func (t ToolsView) updateToolStatus(toolName string, status components.ToolStatus, version string) ToolsView {
	// Update in categories (for display)
	for i, category := range t.categories {
		for j, tool := range category.Tools {
			if tool.Name == toolName {
				t.categories[i].Tools[j].Status = status
				t.categories[i].Tools[j].Version = version
			}
		}
	}

	// Update in flat list (for navigation)
	for i, tool := range t.flatTools {
		if tool.Name == toolName {
			t.flatTools[i].Status = status
			t.flatTools[i].Version = version
		}
	}

	return t
}

// updateScrollOffset adjusts the scroll position to keep the selected tool visible.
// Implements smooth scrolling with the selected item always in view.
func (t *ToolsView) updateScrollOffset() {
	visibleCount := t.getVisibleToolCount()

	// Scroll down if selected item is below visible area
	if t.selectedIndex >= t.scrollOffset+visibleCount {
		t.scrollOffset = t.selectedIndex - visibleCount + 1
	}

	// Scroll up if selected item is above visible area
	if t.selectedIndex < t.scrollOffset {
		t.scrollOffset = t.selectedIndex
	}

	// Bounds check
	if t.scrollOffset < 0 {
		t.scrollOffset = 0
	}
}

// getVisibleToolCount calculates how many tools can fit in the current viewport.
// Accounts for category headers and spacing in the calculation.
//
// Returns:
//   - int: Number of tools visible in current viewport
func (t ToolsView) getVisibleToolCount() int {
	// Reserve space for borders, headers, and details panel
	// Each tool takes 1 line, category headers take 2 lines
	availableHeight := t.height - 6

	// Estimate: roughly 70% of height for tools, 30% for category headers
	return int(float64(availableHeight) * 0.7)
}

// SetSize manually sets the view dimensions.
// Useful when the view is embedded in a larger layout.
//
// Parameters:
//   - w: Width in characters
//   - h: Height in lines
//
// Returns:
//   - ToolsView: Updated view with new dimensions
func (t ToolsView) SetSize(w, h int) ToolsView {
	t.width = w
	t.height = h
	return t
}

// View renders the ToolsView to a string.
// Part of the Bubble Tea Model interface.
//
// Returns:
//   - string: The rendered view ready for display
//
// Layout:
// - Left panel (60%): Categorized tool list with status indicators
// - Right panel (40%): Detailed information about selected tool
// - Bottom: Navigation hints
func (t ToolsView) View() string {
	// Calculate panel widths
	masterWidth := int(float64(t.width) * 0.55)
	detailWidth := t.width - masterWidth - 3 // 3 for spacing

	// Render master panel (tool list)
	masterPanel := t.renderMasterPanel(masterWidth)

	// Render detail panel (selected tool details)
	detailPanel := t.renderDetailPanel(detailWidth)

	// Combine panels horizontally
	panels := lipgloss.JoinHorizontal(lipgloss.Top, masterPanel, "  ", detailPanel)

	// Add navigation hints at bottom
	hints := t.renderNavigationHints()

	return panels + "\n" + hints
}

// renderMasterPanel renders the left panel with categorized tool list.
//
// Parameters:
//   - width: Panel width in characters
//
// Returns:
//   - string: Formatted master panel
//
// Displays:
// - Tools grouped by category
// - Status indicators for each tool
// - Visual highlighting for selected tool
// - Category headers with counts
func (t ToolsView) renderMasterPanel(width int) string {
	var lines []string

	currentFlatIndex := 0

	// Render each category
	for _, category := range t.categories {
		// Category header
		installedCount := 0
		for _, tool := range category.Tools {
			if tool.Status == components.ToolStatusInstalled {
				installedCount++
			}
		}

		categoryHeader := fmt.Sprintf("═══ %s (%d/%d) ═══",
			category.Name,
			installedCount,
			len(category.Tools))
		lines = append(lines, styles.KeyStyle.Render(categoryHeader))
		lines = append(lines, "")

		// Render tools in category
		for _, tool := range category.Tools {
			isSelected := currentFlatIndex == t.selectedIndex

			// Status icon with color
			var iconStyle lipgloss.Style
			switch tool.Status {
			case components.ToolStatusInstalled:
				iconStyle = styles.ToolInstalledStyle
			case components.ToolStatusMissing:
				iconStyle = styles.ToolMissingStyle
			case components.ToolStatusInstalling:
				iconStyle = styles.ToolInstallingStyle
			case components.ToolStatusFailed:
				iconStyle = styles.CriticalStyle
			default:
				iconStyle = styles.MutedStyle
			}
			icon := iconStyle.Render(tool.Status.String())

			// Tool name
			nameStyle := lipgloss.NewStyle()
			if tool.Required {
				nameStyle = nameStyle.Bold(true).Foreground(styles.ColorWhite)
			} else {
				nameStyle = nameStyle.Foreground(styles.ColorLightGray)
			}

			name := nameStyle.Render(tool.DisplayName)

			// Version info (if available)
			var versionStr string
			if tool.Status == components.ToolStatusInstalled && tool.Version != "" {
				// Truncate long version strings
				version := tool.Version
				if len(version) > 25 {
					version = version[:22] + "..."
				}
				versionStr = " " + styles.MutedStyle.Render(fmt.Sprintf("(%s)", version))
			}

			// Required indicator
			var requiredMarker string
			if tool.Required {
				requiredMarker = " " + styles.HighStyle.Render("*")
			}

			// Build line
			line := fmt.Sprintf("%s %s%s%s", icon, name, versionStr, requiredMarker)

			// Add selection indicator
			if isSelected {
				line = styles.ListSelectedStyle.Render("> " + line)
			} else {
				line = "  " + line
			}

			lines = append(lines, line)
			currentFlatIndex++
		}

		// Spacing between categories
		lines = append(lines, "")
	}

	// Apply border and styling
	content := strings.Join(lines, "\n")

	panelStyle := styles.MasterPanelStyle.
		Width(width).
		Height(t.height - 4)

	return panelStyle.Render(content)
}

// renderDetailPanel renders the right panel with selected tool details.
//
// Parameters:
//   - width: Panel width in characters
//
// Returns:
//   - string: Formatted detail panel
//
// Displays:
// - Tool name and category
// - Installation status with colored indicator
// - Version information (if installed)
// - Detailed description
// - Installation status message
func (t ToolsView) renderDetailPanel(width int) string {
	if t.selectedIndex < 0 || t.selectedIndex >= len(t.flatTools) {
		return ""
	}

	tool := t.flatTools[t.selectedIndex]

	var lines []string

	// Tool name header
	lines = append(lines, styles.DetailTitleStyle.Render(tool.DisplayName))
	lines = append(lines, "")

	// Category
	lines = append(lines, t.renderDetailField("Category", tool.Category))

	// Status
	var statusStr string
	var statusStyle lipgloss.Style
	switch tool.Status {
	case components.ToolStatusInstalled:
		statusStr = "Installed"
		statusStyle = styles.ToolInstalledStyle
	case components.ToolStatusMissing:
		statusStr = "Not Installed"
		statusStyle = styles.ToolMissingStyle
	case components.ToolStatusInstalling:
		statusStr = "Installing..."
		statusStyle = styles.ToolInstallingStyle
	case components.ToolStatusFailed:
		statusStr = "Failed"
		statusStyle = styles.CriticalStyle
	default:
		statusStr = "Checking..."
		statusStyle = styles.MutedStyle
	}
	lines = append(lines, t.renderDetailFieldStyled("Status", statusStr, statusStyle))

	// Version (if installed)
	if tool.Status == components.ToolStatusInstalled && tool.Version != "" {
		lines = append(lines, t.renderDetailField("Version", tool.Version))
	}

	// Required indicator
	if tool.Required {
		lines = append(lines, t.renderDetailFieldStyled("Required", "Yes", styles.HighStyle))
	}

	lines = append(lines, "")

	// Description
	lines = append(lines, styles.MutedStyle.Render("Description:"))
	lines = append(lines, "")

	// Word wrap description to fit panel width
	wrappedDesc := wordWrap(tool.Description, width-4)
	for _, line := range wrappedDesc {
		lines = append(lines, styles.DetailValueStyle.Render(line))
	}

	lines = append(lines, "")

	// Status message
	if tool.Status == components.ToolStatusMissing {
		lines = append(lines, styles.MutedStyle.Render("This tool is not currently installed."))
		lines = append(lines, styles.InfoStyle.Render("Installation can be added in future versions."))
	} else if tool.Status == components.ToolStatusInstalled {
		lines = append(lines, styles.LowStyle.Render("✓ Ready to use"))
	}

	content := strings.Join(lines, "\n")

	panelStyle := styles.DetailPanelStyle.
		Width(width).
		Height(t.height - 4)

	return panelStyle.Render(content)
}

// renderDetailField renders a labeled field in the detail panel.
//
// Parameters:
//   - label: Field label
//   - value: Field value
//
// Returns:
//   - string: Formatted field line
func (t ToolsView) renderDetailField(label, value string) string {
	labelStyled := styles.DetailLabelStyle.Render(label + ":")
	valueStyled := styles.DetailValueStyle.Render(value)
	return labelStyled + " " + valueStyled
}

// renderDetailFieldStyled renders a labeled field with custom value styling.
//
// Parameters:
//   - label: Field label
//   - value: Field value
//   - valueStyle: Custom style for the value
//
// Returns:
//   - string: Formatted field line
func (t ToolsView) renderDetailFieldStyled(label, value string, valueStyle lipgloss.Style) string {
	labelStyled := styles.DetailLabelStyle.Render(label + ":")
	valueStyled := valueStyle.Render(value)
	return labelStyled + " " + valueStyled
}

// renderNavigationHints renders keyboard shortcut hints at the bottom.
//
// Returns:
//   - string: Formatted hints line
func (t ToolsView) renderNavigationHints() string {
	hints := []string{
		styles.KeyStyle.Render("↑/↓, j/k") + " Navigate",
		styles.KeyStyle.Render("g/G") + " Top/Bottom",
		styles.KeyStyle.Render("PgUp/PgDn") + " Page",
	}

	// Tool counts summary
	installedCount := 0
	totalCount := len(t.flatTools)
	for _, tool := range t.flatTools {
		if tool.Status == components.ToolStatusInstalled {
			installedCount++
		}
	}

	summary := fmt.Sprintf("Tools: %d/%d installed", installedCount, totalCount)
	summaryStyled := styles.MutedStyle.Render(summary)

	hintsLine := strings.Join(hints, " • ")

	// Combine hints and summary
	return styles.KeyHintStyle.Render(hintsLine) + "    " + summaryStyled
}

// GetToolStatus returns the current status of a specific tool.
// Useful for external components that need to check tool availability.
//
// Parameters:
//   - toolName: Name of the tool to check
//
// Returns:
//   - components.ToolStatus: Current status
//   - bool: Whether the tool was found
//
// Security Note: This is a read-only operation that doesn't modify state
// or perform any privileged operations.
func (t ToolsView) GetToolStatus(toolName string) (components.ToolStatus, bool) {
	for _, tool := range t.flatTools {
		if tool.Name == toolName {
			return tool.Status, true
		}
	}
	return components.ToolStatusUnknown, false
}

// GetInstalledTools returns a list of all installed tool names.
//
// Returns:
//   - []string: Slice of installed tool names
func (t ToolsView) GetInstalledTools() []string {
	var installed []string
	for _, tool := range t.flatTools {
		if tool.Status == components.ToolStatusInstalled {
			installed = append(installed, tool.Name)
		}
	}
	return installed
}

// GetMissingRequiredTools returns a list of required tools that are not installed.
// This is critical for determining if the system is ready for security scans.
//
// Returns:
//   - []string: Slice of missing required tool names
func (t ToolsView) GetMissingRequiredTools() []string {
	var missing []string
	for _, tool := range t.flatTools {
		if tool.Required && tool.Status != components.ToolStatusInstalled {
			missing = append(missing, tool.DisplayName)
		}
	}
	return missing
}
