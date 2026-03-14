package views

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"
)

// Severity levels for vulnerability classification
type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
	SeverityInfo
)

// String representation of severity levels
func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	case SeverityInfo:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

// Color returns the appropriate style color for each severity level
// Monochrome Pro palette with severity pops
func (s Severity) Color() lipgloss.Color {
	switch s {
	case SeverityCritical:
		return lipgloss.Color("#FF3B30") // Vibrant red
	case SeverityHigh:
		return lipgloss.Color("#FF9500") // Orange
	case SeverityMedium:
		return lipgloss.Color("#FFCC00") // Yellow
	case SeverityLow:
		return lipgloss.Color("#34C759") // Green
	case SeverityInfo:
		return lipgloss.Color("#007AFF") // Blue
	default:
		return lipgloss.Color("#8E8E93") // Gray
	}
}

// Vulnerability represents a single security finding
type Vulnerability struct {
	ID           string   // Unique identifier (CVE, CWE, custom ID)
	Title        string   // Brief description
	Severity     Severity // Severity level
	CVSS         float64  // CVSS score (0.0-10.0)
	CVSSVector   string   // CVSS vector string
	Description  string   // Detailed description
	Evidence     string   // Code snippet or proof of concept
	Location     string   // File path or endpoint
	LineNumber   int      // Line number in file (if applicable)
	Remediation  string   // Fix recommendations
	References   []string // External references (CVE, CWE, etc.)
	Confidence   string   // Detection confidence (High, Medium, Low)
	Category     string   // Vulnerability category (Injection, XSS, etc.)
	Timestamp    string   // Discovery timestamp
}

// SortMode defines how the vulnerability list should be sorted
type SortMode int

const (
	SortBySeverity SortMode = iota
	SortByTitle
	SortByCVSS
	SortByLocation
)

// FilterMode defines which severities to show
type FilterMode struct {
	ShowCritical bool
	ShowHigh     bool
	ShowMedium   bool
	ShowLow      bool
	ShowInfo     bool
}

// ResultsView implements the master-detail results interface
type ResultsView struct {
	// Core state
	width  int
	height int
	ready  bool

	// Data
	allVulnerabilities      []Vulnerability // Complete unfiltered list
	filteredVulnerabilities []Vulnerability // After filtering/search
	selectedIndex           int             // Current selection in filtered list

	// UI Components
	searchInput    textinput.Model // Search bar for filtering results
	detailViewport viewport.Model  // Scrollable detail pane
	searchActive   bool            // Whether search mode is active

	// Filtering and sorting
	sortMode   SortMode   // Current sort order
	filterMode FilterMode // Active severity filters
	searchTerm string     // Current search query

	// Layout dimensions
	masterWidth int // Left panel width
	detailWidth int // Right panel width
	listHeight  int // Usable height for list

	// Styles
	listItemStyle         lipgloss.Style
	listItemSelectedStyle lipgloss.Style
	severityStyle         map[Severity]lipgloss.Style
	panelBorderStyle      lipgloss.Style
	headerStyle           lipgloss.Style
	detailTitleStyle      lipgloss.Style
	detailSectionStyle    lipgloss.Style
	detailTextStyle       lipgloss.Style
}

// NewResultsView creates and initializes a new ResultsView
func NewResultsView(vulnerabilities []Vulnerability) *ResultsView {
	// Initialize search input
	ti := textinput.New()
	ti.Placeholder = "Search vulnerabilities..."
	ti.CharLimit = 100
	ti.Width = 40

	// Initialize detail viewport (sized later)
	vp := viewport.New(0, 0)

	// All filters enabled by default
	filterMode := FilterMode{
		ShowCritical: true,
		ShowHigh:     true,
		ShowMedium:   true,
		ShowLow:      true,
		ShowInfo:     true,
	}

	// Create severity-specific styles (bold + color, no icons)
	severityStyles := make(map[Severity]lipgloss.Style)
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		severityStyles[sev] = lipgloss.NewStyle().
			Bold(true).
			Foreground(sev.Color())
	}

	rv := &ResultsView{
		allVulnerabilities:      vulnerabilities,
		filteredVulnerabilities: make([]Vulnerability, len(vulnerabilities)),
		selectedIndex:           0,
		searchInput:             ti,
		detailViewport:          vp,
		searchActive:            false,
		sortMode:                SortBySeverity,
		filterMode:              filterMode,
		searchTerm:              "",

		// Styles - Monochrome Pro palette
		listItemStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#D1D1D6")).
			PaddingLeft(2),

		listItemSelectedStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#3A3A3C")).
			Bold(true).
			PaddingLeft(1),

		severityStyle: severityStyles,

		panelBorderStyle: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#48484A")).
			Foreground(lipgloss.Color("#D1D1D6")),

		headerStyle: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#1C1C1E")).
			Padding(0, 1),

		detailTitleStyle: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Underline(true).
			MarginBottom(1),

		detailSectionStyle: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#8E8E93")).
			MarginTop(1).
			MarginBottom(0),

		detailTextStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#D1D1D6")),
	}

	// Initial filter and sort
	copy(rv.filteredVulnerabilities, vulnerabilities)
	rv.applyFiltersAndSort()

	return rv
}

// Init initializes the ResultsView (Bubble Tea interface)
func (r *ResultsView) Init() tea.Cmd {
	return nil
}

// Update handles messages and user input (Bubble Tea interface)
func (r *ResultsView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		r.width = msg.Width
		r.height = msg.Height
		r.updateLayout()
		r.ready = true
		return r, nil

	case tea.KeyMsg:
		// Handle search mode separately
		if r.searchActive {
			return r.handleSearchInput(msg)
		}

		// Normal navigation mode
		switch msg.String() {
		// Search activation
		case "/":
			r.searchActive = true
			r.searchInput.Focus()
			return r, textinput.Blink

		// Vim-style navigation - move down
		case "j", "down":
			if r.selectedIndex < len(r.filteredVulnerabilities)-1 {
				r.selectedIndex++
				r.updateDetailPane()
			}

		// Vim-style navigation - move up
		case "k", "up":
			if r.selectedIndex > 0 {
				r.selectedIndex--
				r.updateDetailPane()
			}

		// Vim-style - jump to top
		case "g":
			if len(r.filteredVulnerabilities) > 0 {
				r.selectedIndex = 0
				r.updateDetailPane()
			}

		// Vim-style - jump to bottom
		case "G":
			if len(r.filteredVulnerabilities) > 0 {
				r.selectedIndex = len(r.filteredVulnerabilities) - 1
				r.updateDetailPane()
			}

		// Page down in detail pane
		case "d", "ctrl+d":
			r.detailViewport.ViewDown()

		// Page up in detail pane
		case "u", "ctrl+u":
			r.detailViewport.ViewUp()

		// Scroll detail pane down
		case "J":
			r.detailViewport.LineDown(3)

		// Scroll detail pane up
		case "K":
			r.detailViewport.LineUp(3)

		// Sorting modes
		case "s":
			r.cycleSortMode()
			r.applyFiltersAndSort()
			r.updateDetailPane()

		// Toggle severity filters
		case "1":
			r.filterMode.ShowCritical = !r.filterMode.ShowCritical
			r.applyFiltersAndSort()
			r.updateDetailPane()

		case "2":
			r.filterMode.ShowHigh = !r.filterMode.ShowHigh
			r.applyFiltersAndSort()
			r.updateDetailPane()

		case "3":
			r.filterMode.ShowMedium = !r.filterMode.ShowMedium
			r.applyFiltersAndSort()
			r.updateDetailPane()

		case "4":
			r.filterMode.ShowLow = !r.filterMode.ShowLow
			r.applyFiltersAndSort()
			r.updateDetailPane()

		case "5":
			r.filterMode.ShowInfo = !r.filterMode.ShowInfo
			r.applyFiltersAndSort()
			r.updateDetailPane()

		// Export placeholder (integration point)
		case "e":
			// TODO: Trigger export dialog/action
			// This is where export functionality would be invoked
			return r, nil

		// Quit
		case "q", "ctrl+c":
			return r, tea.Quit
		}
	}

	return r, tea.Batch(cmds...)
}

// handleSearchInput processes input when search mode is active
func (r *ResultsView) handleSearchInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg.String() {
	case "enter":
		// Apply search
		r.searchTerm = r.searchInput.Value()
		r.searchActive = false
		r.searchInput.Blur()
		r.applyFiltersAndSort()
		r.selectedIndex = 0 // Reset to top of filtered results
		r.updateDetailPane()
		return r, nil

	case "esc":
		// Cancel search
		r.searchActive = false
		r.searchInput.Blur()
		r.searchInput.SetValue(r.searchTerm) // Restore previous search
		return r, nil

	default:
		// Update search input
		r.searchInput, cmd = r.searchInput.Update(msg)
		return r, cmd
	}
}

// View renders the ResultsView (Bubble Tea interface)
func (r *ResultsView) View() string {
	if !r.ready {
		return "Loading results..."
	}

	if len(r.filteredVulnerabilities) == 0 {
		return r.renderEmptyState()
	}

	// Build master-detail layout
	masterPanel := r.renderMasterPanel()
	detailPanel := r.renderDetailPanel()

	// Side-by-side layout
	layout := lipgloss.JoinHorizontal(
		lipgloss.Top,
		masterPanel,
		detailPanel,
	)

	// Add header and footer
	header := r.renderHeader()
	footer := r.renderFooter()

	return lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		layout,
		footer,
	)
}

// renderHeader creates the top header bar with summary stats
func (r *ResultsView) renderHeader() string {
	// Count by severity
	counts := make(map[Severity]int)
	for _, vuln := range r.allVulnerabilities {
		counts[vuln.Severity]++
	}

	// Build summary with severity colors
	summary := fmt.Sprintf("Total: %d | ", len(r.allVulnerabilities))

	critStyle := r.severityStyle[SeverityCritical]
	highStyle := r.severityStyle[SeverityHigh]
	medStyle := r.severityStyle[SeverityMedium]
	lowStyle := r.severityStyle[SeverityLow]
	infoStyle := r.severityStyle[SeverityInfo]

	summary += critStyle.Render(fmt.Sprintf("CRITICAL: %d", counts[SeverityCritical])) + " | "
	summary += highStyle.Render(fmt.Sprintf("HIGH: %d", counts[SeverityHigh])) + " | "
	summary += medStyle.Render(fmt.Sprintf("MEDIUM: %d", counts[SeverityMedium])) + " | "
	summary += lowStyle.Render(fmt.Sprintf("LOW: %d", counts[SeverityLow])) + " | "
	summary += infoStyle.Render(fmt.Sprintf("INFO: %d", counts[SeverityInfo]))

	if r.searchTerm != "" {
		summary += fmt.Sprintf(" | Filtered: %d", len(r.filteredVulnerabilities))
	}

	return r.headerStyle.Width(r.width).Render(summary)
}

// renderFooter creates the bottom help bar
func (r *ResultsView) renderFooter() string {
	if r.searchActive {
		return r.headerStyle.Width(r.width).Render("Search: [enter] apply | [esc] cancel")
	}

	help := "j/k: navigate | g/G: top/bottom | J/K: scroll detail | d/u: page detail | "
	help += "s: sort | 1-5: filter severity | /: search | e: export | q: quit"

	// Show active sort mode
	sortModeStr := ""
	switch r.sortMode {
	case SortBySeverity:
		sortModeStr = "Severity"
	case SortByTitle:
		sortModeStr = "Title"
	case SortByCVSS:
		sortModeStr = "CVSS"
	case SortByLocation:
		sortModeStr = "Location"
	}
	help += fmt.Sprintf(" | Sort: %s", sortModeStr)

	return r.headerStyle.Width(r.width).Render(help)
}

// renderMasterPanel creates the left vulnerability list panel
func (r *ResultsView) renderMasterPanel() string {
	var listItems []string

	// Add search bar if active
	if r.searchActive {
		listItems = append(listItems, r.searchInput.View())
		listItems = append(listItems, strings.Repeat("-", r.masterWidth-4))
	} else if r.searchTerm != "" {
		searchDisplay := fmt.Sprintf("Search: %s", r.searchTerm)
		listItems = append(listItems, r.detailTextStyle.Render(searchDisplay))
		listItems = append(listItems, strings.Repeat("-", r.masterWidth-4))
	}

	// Calculate visible window for list items
	visibleStart := 0
	visibleEnd := len(r.filteredVulnerabilities)

	// Adjust for viewport scrolling (keep selection in view)
	maxVisible := r.listHeight - 3 // Account for search bar and separators
	if r.searchActive || r.searchTerm != "" {
		maxVisible -= 2
	}

	if len(r.filteredVulnerabilities) > maxVisible {
		if r.selectedIndex >= maxVisible/2 {
			visibleStart = r.selectedIndex - maxVisible/2
			visibleEnd = visibleStart + maxVisible
			if visibleEnd > len(r.filteredVulnerabilities) {
				visibleEnd = len(r.filteredVulnerabilities)
				visibleStart = visibleEnd - maxVisible
			}
		} else {
			visibleEnd = maxVisible
		}
	}

	// Render visible vulnerability items
	for i := visibleStart; i < visibleEnd; i++ {
		vuln := r.filteredVulnerabilities[i]
		listItems = append(listItems, r.formatListItem(vuln, i == r.selectedIndex))
	}

	// Scroll indicator if needed
	if len(r.filteredVulnerabilities) > maxVisible {
		scrollInfo := fmt.Sprintf("[%d-%d of %d]", visibleStart+1, visibleEnd, len(r.filteredVulnerabilities))
		listItems = append(listItems, r.detailTextStyle.Render(scrollInfo))
	}

	content := strings.Join(listItems, "\n")

	// Wrap in bordered panel
	return r.panelBorderStyle.
		Width(r.masterWidth).
		Height(r.listHeight).
		Render(content)
}

// formatListItem renders a single vulnerability in the list
func (r *ResultsView) formatListItem(vuln Vulnerability, selected bool) string {
	// Severity badge with color
	sevStyle := r.severityStyle[vuln.Severity]
	sevBadge := sevStyle.Render(fmt.Sprintf("[%s]", vuln.Severity.String()))

	// CVSS score
	cvssStr := fmt.Sprintf("%.1f", vuln.CVSS)

	// Truncate title to fit
	maxTitleLen := r.masterWidth - 25 // Account for severity, CVSS, padding
	title := vuln.Title
	if len(title) > maxTitleLen {
		title = title[:maxTitleLen-3] + "..."
	}

	// Format: [SEVERITY] CVSS Title
	item := fmt.Sprintf("%s %4s %s", sevBadge, cvssStr, title)

	// Apply selection style
	if selected {
		return r.listItemSelectedStyle.Width(r.masterWidth - 4).Render("> " + item)
	}
	return r.listItemStyle.Width(r.masterWidth - 4).Render("  " + item)
}

// renderDetailPanel creates the right detail view panel
func (r *ResultsView) renderDetailPanel() string {
	if len(r.filteredVulnerabilities) == 0 {
		content := r.detailTextStyle.Render("No vulnerabilities to display")
		return r.panelBorderStyle.
			Width(r.detailWidth).
			Height(r.listHeight).
			Render(content)
	}

	// Detail pane is rendered through viewport (updated elsewhere)
	return r.panelBorderStyle.
		Width(r.detailWidth).
		Height(r.listHeight).
		Render(r.detailViewport.View())
}

// renderEmptyState shows message when no results match filters
func (r *ResultsView) renderEmptyState() string {
	msg := "No vulnerabilities found matching current filters.\n\n"
	msg += "Try adjusting severity filters (1-5) or search term (/)."

	return r.panelBorderStyle.
		Width(r.width - 4).
		Height(r.height - 6).
		Render(r.detailTextStyle.Render(msg))
}

// updateLayout recalculates panel dimensions based on terminal size
func (r *ResultsView) updateLayout() {
	// Header and footer take 2 lines each
	r.listHeight = r.height - 4

	// Master-detail split: 40% master, 60% detail
	r.masterWidth = r.width * 40 / 100
	r.detailWidth = r.width - r.masterWidth

	// Update detail viewport size
	r.detailViewport.Width = r.detailWidth - 4   // Account for borders/padding
	r.detailViewport.Height = r.listHeight - 2   // Account for borders

	// Refresh detail content with new dimensions
	r.updateDetailPane()
}

// updateDetailPane renders the currently selected vulnerability's details
func (r *ResultsView) updateDetailPane() {
	if len(r.filteredVulnerabilities) == 0 {
		r.detailViewport.SetContent("")
		return
	}

	// Ensure selected index is valid
	if r.selectedIndex >= len(r.filteredVulnerabilities) {
		r.selectedIndex = len(r.filteredVulnerabilities) - 1
	}
	if r.selectedIndex < 0 {
		r.selectedIndex = 0
	}

	vuln := r.filteredVulnerabilities[r.selectedIndex]

	var details strings.Builder

	// Title with severity color
	titleStyle := r.severityStyle[vuln.Severity]
	details.WriteString(titleStyle.Render(vuln.Title))
	details.WriteString("\n\n")

	// ID and basic info
	details.WriteString(r.detailSectionStyle.Render("IDENTIFIER"))
	details.WriteString("\n")
	details.WriteString(r.detailTextStyle.Render(vuln.ID))
	details.WriteString("\n")

	// Severity and CVSS
	details.WriteString(r.detailSectionStyle.Render("SEVERITY"))
	details.WriteString("\n")
	sevStyle := r.severityStyle[vuln.Severity]
	details.WriteString(sevStyle.Render(fmt.Sprintf("%s (CVSS %.1f)", vuln.Severity.String(), vuln.CVSS)))
	details.WriteString("\n")

	if vuln.CVSSVector != "" {
		details.WriteString(r.detailTextStyle.Render(fmt.Sprintf("Vector: %s", vuln.CVSSVector)))
		details.WriteString("\n")
	}

	// Category and confidence
	if vuln.Category != "" || vuln.Confidence != "" {
		details.WriteString(r.detailSectionStyle.Render("CLASSIFICATION"))
		details.WriteString("\n")
		if vuln.Category != "" {
			details.WriteString(r.detailTextStyle.Render(fmt.Sprintf("Category: %s", vuln.Category)))
			details.WriteString("\n")
		}
		if vuln.Confidence != "" {
			details.WriteString(r.detailTextStyle.Render(fmt.Sprintf("Confidence: %s", vuln.Confidence)))
			details.WriteString("\n")
		}
	}

	// Location
	details.WriteString(r.detailSectionStyle.Render("LOCATION"))
	details.WriteString("\n")
	if vuln.LineNumber > 0 {
		details.WriteString(r.detailTextStyle.Render(fmt.Sprintf("%s:%d", vuln.Location, vuln.LineNumber)))
	} else {
		details.WriteString(r.detailTextStyle.Render(vuln.Location))
	}
	details.WriteString("\n")

	// Description
	details.WriteString(r.detailSectionStyle.Render("DESCRIPTION"))
	details.WriteString("\n")
	details.WriteString(r.wrapText(vuln.Description, r.detailViewport.Width))
	details.WriteString("\n")

	// Evidence (code snippet)
	if vuln.Evidence != "" {
		details.WriteString(r.detailSectionStyle.Render("EVIDENCE"))
		details.WriteString("\n")
		evidenceStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00D4FF")).
			Background(lipgloss.Color("#1C1C1E")).
			Padding(1)
		details.WriteString(evidenceStyle.Render(vuln.Evidence))
		details.WriteString("\n")
	}

	// Remediation
	if vuln.Remediation != "" {
		details.WriteString(r.detailSectionStyle.Render("REMEDIATION"))
		details.WriteString("\n")
		details.WriteString(r.wrapText(vuln.Remediation, r.detailViewport.Width))
		details.WriteString("\n")
	}

	// References
	if len(vuln.References) > 0 {
		details.WriteString(r.detailSectionStyle.Render("REFERENCES"))
		details.WriteString("\n")
		for _, ref := range vuln.References {
			details.WriteString(r.detailTextStyle.Render(fmt.Sprintf("  - %s", ref)))
			details.WriteString("\n")
		}
	}

	// Timestamp
	if vuln.Timestamp != "" {
		details.WriteString(r.detailSectionStyle.Render("DISCOVERED"))
		details.WriteString("\n")
		details.WriteString(r.detailTextStyle.Render(vuln.Timestamp))
		details.WriteString("\n")
	}

	r.detailViewport.SetContent(details.String())
	r.detailViewport.GotoTop()
}

// wrapText wraps text to specified width, preserving words
func (r *ResultsView) wrapText(text string, width int) string {
	if width <= 0 {
		return text
	}

	words := strings.Fields(text)
	if len(words) == 0 {
		return text
	}

	var lines []string
	var currentLine strings.Builder

	for _, word := range words {
		// Check if adding this word would exceed width
		if currentLine.Len() > 0 && currentLine.Len()+len(word)+1 > width {
			lines = append(lines, r.detailTextStyle.Render(currentLine.String()))
			currentLine.Reset()
		}

		if currentLine.Len() > 0 {
			currentLine.WriteString(" ")
		}
		currentLine.WriteString(word)
	}

	if currentLine.Len() > 0 {
		lines = append(lines, r.detailTextStyle.Render(currentLine.String()))
	}

	return strings.Join(lines, "\n")
}

// applyFiltersAndSort filters vulnerabilities by severity/search and applies sort
func (r *ResultsView) applyFiltersAndSort() {
	// Start with all vulnerabilities
	filtered := make([]Vulnerability, 0, len(r.allVulnerabilities))

	for _, vuln := range r.allVulnerabilities {
		// Apply severity filter
		include := false
		switch vuln.Severity {
		case SeverityCritical:
			include = r.filterMode.ShowCritical
		case SeverityHigh:
			include = r.filterMode.ShowHigh
		case SeverityMedium:
			include = r.filterMode.ShowMedium
		case SeverityLow:
			include = r.filterMode.ShowLow
		case SeverityInfo:
			include = r.filterMode.ShowInfo
		}

		if !include {
			continue
		}

		// Apply search filter (if active)
		if r.searchTerm != "" {
			searchLower := strings.ToLower(r.searchTerm)
			matchFound := strings.Contains(strings.ToLower(vuln.Title), searchLower) ||
				strings.Contains(strings.ToLower(vuln.Description), searchLower) ||
				strings.Contains(strings.ToLower(vuln.ID), searchLower) ||
				strings.Contains(strings.ToLower(vuln.Location), searchLower) ||
				strings.Contains(strings.ToLower(vuln.Category), searchLower)

			if !matchFound {
				continue
			}
		}

		filtered = append(filtered, vuln)
	}

	// Apply sort
	switch r.sortMode {
	case SortBySeverity:
		sort.Slice(filtered, func(i, j int) bool {
			// Sort by severity first (critical first), then by CVSS within same severity
			if filtered[i].Severity != filtered[j].Severity {
				return filtered[i].Severity < filtered[j].Severity
			}
			return filtered[i].CVSS > filtered[j].CVSS
		})

	case SortByTitle:
		sort.Slice(filtered, func(i, j int) bool {
			return strings.ToLower(filtered[i].Title) < strings.ToLower(filtered[j].Title)
		})

	case SortByCVSS:
		sort.Slice(filtered, func(i, j int) bool {
			return filtered[i].CVSS > filtered[j].CVSS // High to low
		})

	case SortByLocation:
		sort.Slice(filtered, func(i, j int) bool {
			return filtered[i].Location < filtered[j].Location
		})
	}

	r.filteredVulnerabilities = filtered

	// Ensure selection is valid
	if r.selectedIndex >= len(r.filteredVulnerabilities) {
		r.selectedIndex = len(r.filteredVulnerabilities) - 1
	}
	if r.selectedIndex < 0 && len(r.filteredVulnerabilities) > 0 {
		r.selectedIndex = 0
	}
}

// cycleSortMode rotates through available sort modes
func (r *ResultsView) cycleSortMode() {
	switch r.sortMode {
	case SortBySeverity:
		r.sortMode = SortByTitle
	case SortByTitle:
		r.sortMode = SortByCVSS
	case SortByCVSS:
		r.sortMode = SortByLocation
	case SortByLocation:
		r.sortMode = SortBySeverity
	}
}

// Export integration points for future implementation

// ExportToJSON prepares vulnerability data for JSON export
func (r *ResultsView) ExportToJSON() []Vulnerability {
	return r.filteredVulnerabilities
}

// ExportToHTML prepares vulnerability data for HTML report export
func (r *ResultsView) ExportToHTML() []Vulnerability {
	return r.filteredVulnerabilities
}

// ExportToMarkdown prepares vulnerability data for Markdown report export
func (r *ResultsView) ExportToMarkdown() []Vulnerability {
	return r.filteredVulnerabilities
}

// GetSelectedVulnerability returns the currently selected vulnerability
func (r *ResultsView) GetSelectedVulnerability() *Vulnerability {
	if len(r.filteredVulnerabilities) == 0 || r.selectedIndex < 0 || r.selectedIndex >= len(r.filteredVulnerabilities) {
		return nil
	}
	return &r.filteredVulnerabilities[r.selectedIndex]
}

// GetFilteredCount returns the number of visible vulnerabilities after filtering
func (r *ResultsView) GetFilteredCount() int {
	return len(r.filteredVulnerabilities)
}

// GetTotalCount returns the total number of vulnerabilities
func (r *ResultsView) GetTotalCount() int {
	return len(r.allVulnerabilities)
}
