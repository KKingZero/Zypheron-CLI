package views

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/storage"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	"github.com/KKingZero/Cobra-AI/zypheron-go/pkg/types"
)

// ViewMode defines the current navigation state of the history view
// This enables drill-down navigation from list view to detailed scan view
type ViewMode int

const (
	// ListMode displays the table of scan summaries with search/filter
	ListMode ViewMode = iota
	// DetailMode shows the full details of a selected scan
	DetailMode
	// ConfirmDeleteMode prompts for deletion confirmation
	ConfirmDeleteMode
)

// FilterType defines the type of filter being applied to the scan list
type FilterType int

const (
	// FilterNone means no filter is active - show all scans
	FilterNone FilterType = iota
	// FilterTarget filters scans by target hostname/IP
	FilterTarget
	// FilterStatus filters scans by success/failure status
	FilterStatus
	// FilterDate filters scans by date range
	FilterDate
)

// HistoryView manages the history/audit log view of past scans
// Provides drill-down navigation, search/filter, and scan management capabilities
type HistoryView struct {
	// Core state
	storage      *storage.ScanStorage  // Persistent storage for scan results
	scans        []types.ScanSummary   // All scans loaded from storage
	filteredIDs  []string              // IDs of scans matching current filter
	selectedScan *types.ScanResult     // Currently selected scan (in detail view)

	// UI components
	table       table.Model    // Bubble tea table for scan list display
	searchInput textinput.Model // Text input for search/filter queries

	// Navigation state
	mode         ViewMode    // Current view mode (list/detail/confirm)
	cursor       int         // Current cursor position in list view
	scrollOffset int         // Vertical scroll offset for detail view

	// Filter state
	filterType   FilterType  // Type of active filter
	filterQuery  string      // Current filter query string
	searchActive bool        // Whether search input is focused

	// Deletion state
	pendingDeleteID string   // ID of scan pending deletion (in confirm mode)

	// Display dimensions
	width  int // Terminal width
	height int // Terminal height

	// Error state
	errorMsg string // Error message to display
}

// NewHistoryView creates and initializes a new History view
// Sets up the table, search input, and loads scan history from storage
//
// Returns:
//   - Initialized HistoryView ready for rendering
func NewHistoryView() HistoryView {
	// Initialize storage backend
	// This connects to ~/.zypheron/scans for persistent scan storage
	store, err := storage.NewScanStorage()
	if err != nil {
		// If storage fails, create a view with error state
		// User can still navigate but won't see scan data
		return HistoryView{
			mode:     ListMode,
			errorMsg: fmt.Sprintf("Failed to initialize storage: %v", err),
		}
	}

	// Create search input with monochrome styling
	// Used for filtering scans by target, status, etc.
	ti := textinput.New()
	ti.Placeholder = "Search by target... (Press / to search)"
	ti.CharLimit = 100
	ti.Width = 50
	// Apply monochrome theme colors
	ti.PromptStyle = lipgloss.NewStyle().Foreground(styles.ColorLightGray)
	ti.TextStyle = lipgloss.NewStyle().Foreground(styles.ColorWhite)
	ti.PlaceholderStyle = lipgloss.NewStyle().Foreground(styles.ColorGray)

	// Initialize table columns for scan list view
	// Columns: ID (short), Target, Date, Status, Findings count
	columns := []table.Column{
		{Title: "ID", Width: 20},
		{Title: "Target", Width: 30},
		{Title: "Date", Width: 19},
		{Title: "Status", Width: 10},
		{Title: "Findings", Width: 10},
	}

	// Create table with monochrome styling
	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(10),
	)

	// Apply Monochrome Pro theme to table
	// Selected row: dark gray background with white text
	// Header: light gray text with gray border
	tableStyle := table.DefaultStyles()
	tableStyle.Header = tableStyle.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(styles.ColorGray).
		BorderBottom(true).
		Bold(true).
		Foreground(styles.ColorLightGray)
	tableStyle.Selected = tableStyle.Selected.
		Foreground(styles.ColorWhite).
		Background(styles.ColorDarkGray).
		Bold(false)
	t.SetStyles(tableStyle)

	hv := HistoryView{
		storage:      store,
		table:        t,
		searchInput:  ti,
		mode:         ListMode,
		filterType:   FilterNone,
		searchActive: false,
	}

	// Load initial scan data from storage
	hv.loadScans()

	return hv
}

// Init implements tea.Model interface
// Returns nil as we don't need any initial commands
func (h HistoryView) Init() tea.Cmd {
	return nil
}

// Update handles messages and updates the view state
// Implements tea.Model interface for Bubble Tea event loop
//
// Parameters:
//   - msg: Incoming message (keyboard input, window resize, etc.)
//
// Returns:
//   - Updated model and optional command to execute
func (h HistoryView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Handle terminal resize - update dimensions and table size
		h.width = msg.Width
		h.height = msg.Height
		h.table.SetHeight(h.height - 12) // Reserve space for header/footer/search
		h.updateTableData()

	case tea.KeyMsg:
		// Handle keyboard input based on current mode
		switch h.mode {
		case ListMode:
			cmd = h.handleListModeKeys(msg)
		case DetailMode:
			cmd = h.handleDetailModeKeys(msg)
		case ConfirmDeleteMode:
			cmd = h.handleConfirmDeleteKeys(msg)
		}
		cmds = append(cmds, cmd)
	}

	// Update search input if active
	// This handles character input, cursor movement, etc.
	if h.searchActive {
		h.searchInput, cmd = h.searchInput.Update(msg)
		cmds = append(cmds, cmd)

		// Apply filter as user types
		if h.searchInput.Value() != h.filterQuery {
			h.filterQuery = h.searchInput.Value()
			h.applyFilter()
		}
	}

	// Update table component (handles its own key events when focused)
	if h.mode == ListMode && !h.searchActive {
		h.table, cmd = h.table.Update(msg)
		cmds = append(cmds, cmd)
	}

	return h, tea.Batch(cmds...)
}

// View renders the current view based on mode
// Implements tea.Model interface for Bubble Tea rendering
//
// Returns:
//   - Rendered string for display in terminal
func (h HistoryView) View() string {
	if h.errorMsg != "" {
		// Display error state with helpful message
		return h.renderError()
	}

	// Route to appropriate render function based on mode
	switch h.mode {
	case ListMode:
		return h.renderListView()
	case DetailMode:
		return h.renderDetailView()
	case ConfirmDeleteMode:
		return h.renderConfirmDelete()
	default:
		return "Unknown view mode"
	}
}

// loadScans loads all scans from storage and populates the scans slice
// Called on initialization and after any scan modifications (delete, etc.)
func (h *HistoryView) loadScans() {
	summaries, err := h.storage.ListScans()
	if err != nil {
		h.errorMsg = fmt.Sprintf("Failed to load scans: %v", err)
		return
	}

	h.scans = summaries
	h.applyFilter() // Reapply current filter to new data
}

// applyFilter filters the scan list based on current filter type and query
// Updates filteredIDs with matching scan IDs and refreshes table display
func (h *HistoryView) applyFilter() {
	h.filteredIDs = []string{}

	// If no filter, show all scans
	if h.filterType == FilterNone || h.filterQuery == "" {
		for _, scan := range h.scans {
			h.filteredIDs = append(h.filteredIDs, scan.ID)
		}
		h.updateTableData()
		return
	}

	// Apply filter based on type
	query := strings.ToLower(h.filterQuery)
	for _, scan := range h.scans {
		match := false

		switch h.filterType {
		case FilterTarget:
			// Case-insensitive substring match on target
			if strings.Contains(strings.ToLower(scan.Target), query) {
				match = true
			}
		case FilterStatus:
			// Match success/failure status
			status := "failed"
			if scan.Success {
				status = "success"
			}
			if strings.Contains(status, query) {
				match = true
			}
		case FilterDate:
			// Match date string (YYYY-MM-DD format)
			dateStr := scan.Timestamp.Format("2006-01-02")
			if strings.Contains(dateStr, query) {
				match = true
			}
		}

		if match {
			h.filteredIDs = append(h.filteredIDs, scan.ID)
		}
	}

	h.updateTableData()
}

// updateTableData updates the table with filtered scan data
// Converts scan summaries to table rows with appropriate formatting
func (h *HistoryView) updateTableData() {
	rows := []table.Row{}

	for _, scanID := range h.filteredIDs {
		// Find scan by ID in our loaded scans
		var scan *types.ScanSummary
		for i := range h.scans {
			if h.scans[i].ID == scanID {
				scan = &h.scans[i]
				break
			}
		}

		if scan == nil {
			continue
		}

		// Format data for table display
		// Truncate ID to first 18 chars for readability
		shortID := scan.ID
		if len(shortID) > 18 {
			shortID = shortID[:18]
		}

		// Format timestamp as human-readable date/time
		dateStr := scan.Timestamp.Format("2006-01-02 15:04:05")

		// Status: Success or Failed
		status := "Success"
		if !scan.Success {
			status = "Failed"
		}

		// Findings count with severity breakdown
		findings := fmt.Sprintf("%d (%d C, %d H)",
			scan.VulnCount,
			scan.CriticalCount,
			scan.HighCount,
		)

		rows = append(rows, table.Row{
			shortID,
			scan.Target,
			dateStr,
			status,
			findings,
		})
	}

	h.table.SetRows(rows)
}

// handleListModeKeys handles keyboard input in list view mode
// Supports Vim-style navigation (j/k), search, drill-down, and actions
//
// Parameters:
//   - msg: Key message from Bubble Tea
//
// Returns:
//   - Optional command to execute (e.g., quit)
func (h *HistoryView) handleListModeKeys(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "q", "ctrl+c":
		// Quit application
		return tea.Quit

	case "/":
		// Activate search input
		h.searchActive = true
		h.filterType = FilterTarget // Default to target search
		h.searchInput.Focus()
		h.searchInput.SetValue("")
		return textinput.Blink

	case "esc":
		// Clear search/filter
		if h.searchActive || h.filterQuery != "" {
			h.searchActive = false
			h.searchInput.Blur()
			h.filterType = FilterNone
			h.filterQuery = ""
			h.searchInput.SetValue("")
			h.applyFilter()
		}

	case "enter":
		// Drill down into selected scan details
		if h.searchActive {
			// Commit search and exit search mode
			h.searchActive = false
			h.searchInput.Blur()
		} else {
			h.enterDetailView()
		}

	case "d":
		// Delete selected scan (with confirmation)
		if !h.searchActive {
			h.enterDeleteConfirmation()
		}

	case "r":
		// Re-run selected scan
		if !h.searchActive {
			h.rerunScan()
		}

	case "c":
		// Compare scans (stub - to be implemented)
		if !h.searchActive {
			h.errorMsg = "Compare feature coming soon..."
		}

	case "t":
		// Toggle filter type (target -> status -> date -> none)
		if !h.searchActive {
			h.cycleFilterType()
		}

	case "R":
		// Refresh scan list from storage
		if !h.searchActive {
			h.loadScans()
		}
	}

	return nil
}

// handleDetailModeKeys handles keyboard input in detail view mode
// Supports scrolling and navigation back to list
//
// Parameters:
//   - msg: Key message from Bubble Tea
//
// Returns:
//   - Optional command to execute
func (h *HistoryView) handleDetailModeKeys(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "q", "esc", "backspace":
		// Return to list view
		h.mode = ListMode
		h.selectedScan = nil
		h.scrollOffset = 0

	case "j", "down":
		// Scroll down (Vim-style)
		h.scrollOffset++

	case "k", "up":
		// Scroll up (Vim-style)
		if h.scrollOffset > 0 {
			h.scrollOffset--
		}

	case "g":
		// Go to top (Vim-style gg)
		h.scrollOffset = 0

	case "G":
		// Go to bottom (Vim-style G)
		h.scrollOffset = 9999 // Will be clamped in render

	case "d":
		// Delete this scan
		h.pendingDeleteID = h.selectedScan.ID
		h.mode = ConfirmDeleteMode

	case "r":
		// Re-run this scan
		h.rerunScan()
		h.mode = ListMode
		h.selectedScan = nil

	case "ctrl+c":
		return tea.Quit
	}

	return nil
}

// handleConfirmDeleteKeys handles keyboard input in delete confirmation mode
//
// Parameters:
//   - msg: Key message from Bubble Tea
//
// Returns:
//   - Optional command to execute
func (h *HistoryView) handleConfirmDeleteKeys(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "y", "Y":
		// Confirm deletion
		err := h.storage.DeleteScan(h.pendingDeleteID)
		if err != nil {
			h.errorMsg = fmt.Sprintf("Delete failed: %v", err)
		} else {
			h.loadScans() // Reload scan list
		}
		h.mode = ListMode
		h.pendingDeleteID = ""
		h.selectedScan = nil

	case "n", "N", "esc", "q":
		// Cancel deletion
		h.mode = ListMode
		h.pendingDeleteID = ""
	}

	return nil
}

// enterDetailView loads and displays the full details of the selected scan
// Transitions from list view to detail view
func (h *HistoryView) enterDetailView() {
	// Get selected row index from table
	cursor := h.table.Cursor()
	if cursor < 0 || cursor >= len(h.filteredIDs) {
		return
	}

	// Load full scan data from storage
	scanID := h.filteredIDs[cursor]
	scan, err := h.storage.LoadScan(scanID)
	if err != nil {
		h.errorMsg = fmt.Sprintf("Failed to load scan details: %v", err)
		return
	}

	h.selectedScan = scan
	h.mode = DetailMode
	h.scrollOffset = 0
}

// enterDeleteConfirmation enters the delete confirmation mode
// Prepares to delete the currently selected scan
func (h *HistoryView) enterDeleteConfirmation() {
	cursor := h.table.Cursor()
	if cursor < 0 || cursor >= len(h.filteredIDs) {
		return
	}

	h.pendingDeleteID = h.filteredIDs[cursor]
	h.mode = ConfirmDeleteMode
}

// rerunScan re-runs the currently selected scan
// TODO: Implement actual scan execution - this is a stub for now
func (h *HistoryView) rerunScan() {
	cursor := h.table.Cursor()
	if cursor < 0 || cursor >= len(h.filteredIDs) {
		return
	}

	scanID := h.filteredIDs[cursor]
	scan, err := h.storage.LoadScan(scanID)
	if err != nil {
		h.errorMsg = fmt.Sprintf("Failed to load scan: %v", err)
		return
	}

	// TODO: Implement actual scan re-run
	// For now, just show a message
	h.errorMsg = fmt.Sprintf("Re-running scan on %s with %s (feature coming soon)", scan.Target, scan.Tool)
}

// cycleFilterType cycles through filter types: None -> Target -> Status -> Date -> None
// Updates search input placeholder to reflect current filter type
func (h *HistoryView) cycleFilterType() {
	switch h.filterType {
	case FilterNone:
		h.filterType = FilterTarget
		h.searchInput.Placeholder = "Filter by target..."
	case FilterTarget:
		h.filterType = FilterStatus
		h.searchInput.Placeholder = "Filter by status (success/failed)..."
	case FilterStatus:
		h.filterType = FilterDate
		h.searchInput.Placeholder = "Filter by date (YYYY-MM-DD)..."
	case FilterDate:
		h.filterType = FilterNone
		h.searchInput.Placeholder = "Search by target... (Press / to search)"
		h.filterQuery = ""
		h.searchInput.SetValue("")
		h.applyFilter()
	}

	// If we have an active query, reapply filter with new type
	if h.filterQuery != "" {
		h.applyFilter()
	}
}

// renderError renders the error state view
//
// Returns:
//   - Rendered error message with styling
func (h *HistoryView) renderError() string {
	errorStyle := lipgloss.NewStyle().
		Foreground(styles.ColorCritical).
		Bold(true).
		Padding(2)

	return errorStyle.Render(fmt.Sprintf("ERROR: %s\n\nPress 'q' to quit", h.errorMsg))
}

// renderListView renders the list view with scan table and search
//
// Returns:
//   - Rendered list view string
func (h *HistoryView) renderListView() string {
	var b strings.Builder

	// Header with breadcrumb navigation
	breadcrumb := styles.BreadcrumbStyle.Render("History > Scan List")
	b.WriteString(breadcrumb)
	b.WriteString("\n\n")

	// Show filter status if active
	if h.filterType != FilterNone && h.filterQuery != "" {
		filterLabel := ""
		switch h.filterType {
		case FilterTarget:
			filterLabel = "Target"
		case FilterStatus:
			filterLabel = "Status"
		case FilterDate:
			filterLabel = "Date"
		}
		filterInfo := styles.MutedStyle.Render(
			fmt.Sprintf("Filter: %s = \"%s\" (%d results)",
				filterLabel,
				h.filterQuery,
				len(h.filteredIDs),
			),
		)
		b.WriteString(filterInfo)
		b.WriteString("\n\n")
	}

	// Search input (if active)
	if h.searchActive {
		b.WriteString(styles.KeyHintStyle.Render("Search: "))
		b.WriteString(h.searchInput.View())
		b.WriteString("\n\n")
	}

	// Scan table
	if len(h.filteredIDs) == 0 {
		emptyMsg := styles.MutedStyle.Render("No scans found. Press '/' to search or 'R' to refresh.")
		b.WriteString(emptyMsg)
	} else {
		b.WriteString(h.table.View())
	}

	b.WriteString("\n\n")

	// Status bar with keyboard hints
	b.WriteString(h.renderStatusBar())

	// Show temporary error message if present
	if h.errorMsg != "" {
		b.WriteString("\n")
		errStyle := lipgloss.NewStyle().Foreground(styles.ColorHigh)
		b.WriteString(errStyle.Render(h.errorMsg))
		// Clear error after displaying (will disappear on next render)
		h.errorMsg = ""
	}

	return b.String()
}

// renderDetailView renders the detailed view of a selected scan
// Shows full scan metadata, vulnerabilities, and AI analysis
//
// Returns:
//   - Rendered detail view string with scrolling support
func (h *HistoryView) renderDetailView() string {
	if h.selectedScan == nil {
		return "No scan selected"
	}

	var b strings.Builder

	// Breadcrumb navigation
	breadcrumb := styles.BreadcrumbStyle.Render(
		fmt.Sprintf("History > Scan List > %s", h.selectedScan.Target),
	)
	b.WriteString(breadcrumb)
	b.WriteString("\n\n")

	// Scan metadata section
	metaStyle := lipgloss.NewStyle().Bold(true).Foreground(styles.ColorWhite)
	b.WriteString(metaStyle.Render("SCAN DETAILS"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 80))
	b.WriteString("\n\n")

	// Format scan metadata
	b.WriteString(fmt.Sprintf("  %s: %s\n",
		styles.MutedStyle.Render("ID"),
		h.selectedScan.ID,
	))
	b.WriteString(fmt.Sprintf("  %s: %s\n",
		styles.MutedStyle.Render("Target"),
		h.selectedScan.Target,
	))
	b.WriteString(fmt.Sprintf("  %s: %s\n",
		styles.MutedStyle.Render("Tool"),
		h.selectedScan.Tool,
	))
	b.WriteString(fmt.Sprintf("  %s: %s\n",
		styles.MutedStyle.Render("Timestamp"),
		h.selectedScan.Timestamp.Format(time.RFC1123),
	))
	b.WriteString(fmt.Sprintf("  %s: %.2f seconds\n",
		styles.MutedStyle.Render("Duration"),
		h.selectedScan.Duration,
	))

	// Status with color coding
	statusStr := "Success"
	statusStyle := styles.LowStyle
	if !h.selectedScan.Success {
		statusStr = "Failed"
		statusStyle = styles.CriticalStyle
	}
	b.WriteString(fmt.Sprintf("  %s: %s\n",
		styles.MutedStyle.Render("Status"),
		statusStyle.Render(statusStr),
	))

	if h.selectedScan.ErrorMessage != "" {
		b.WriteString(fmt.Sprintf("  %s: %s\n",
			styles.MutedStyle.Render("Error"),
			styles.CriticalStyle.Render(h.selectedScan.ErrorMessage),
		))
	}

	b.WriteString("\n")

	// Vulnerabilities section
	vulnCount := len(h.selectedScan.Vulnerabilities)
	b.WriteString(metaStyle.Render(fmt.Sprintf("VULNERABILITIES (%d)", vulnCount)))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 80))
	b.WriteString("\n\n")

	if vulnCount == 0 {
		b.WriteString(styles.MutedStyle.Render("  No vulnerabilities detected."))
		b.WriteString("\n")
	} else {
		// Group vulnerabilities by severity for display
		criticals := []types.Vulnerability{}
		highs := []types.Vulnerability{}
		mediums := []types.Vulnerability{}
		lows := []types.Vulnerability{}
		infos := []types.Vulnerability{}

		for _, v := range h.selectedScan.Vulnerabilities {
			switch v.Severity {
			case "critical":
				criticals = append(criticals, v)
			case "high":
				highs = append(highs, v)
			case "medium":
				mediums = append(mediums, v)
			case "low":
				lows = append(lows, v)
			default:
				infos = append(infos, v)
			}
		}

		// Render vulnerability groups in severity order
		h.renderVulnGroup(&b, "CRITICAL", criticals, styles.CriticalStyle)
		h.renderVulnGroup(&b, "HIGH", highs, styles.HighStyle)
		h.renderVulnGroup(&b, "MEDIUM", mediums, styles.MediumStyle)
		h.renderVulnGroup(&b, "LOW", lows, styles.LowStyle)
		h.renderVulnGroup(&b, "INFO", infos, styles.InfoStyle)
	}

	b.WriteString("\n")

	// AI Analysis section
	if h.selectedScan.AIAnalysis != "" {
		b.WriteString(metaStyle.Render("AI ANALYSIS"))
		b.WriteString("\n")
		b.WriteString(strings.Repeat("─", 80))
		b.WriteString("\n\n")

		// Wrap AI analysis text to 78 chars for readability
		wrapped := wordWrap(h.selectedScan.AIAnalysis, 78)
		for _, line := range wrapped {
			b.WriteString("  " + line + "\n")
		}
		b.WriteString("\n")
	}

	// Status bar for detail view
	b.WriteString("\n")
	b.WriteString(h.renderDetailStatusBar())

	// Apply scrolling offset
	// TODO: Implement proper viewport scrolling
	// For now, just render everything
	return b.String()
}

// renderVulnGroup renders a group of vulnerabilities with the same severity
// Helper function for renderDetailView
//
// Parameters:
//   - b: String builder to append to
//   - severity: Severity label (e.g., "CRITICAL", "HIGH")
//   - vulns: Slice of vulnerabilities to render
//   - style: Lipgloss style for severity color
func (h *HistoryView) renderVulnGroup(b *strings.Builder, severity string, vulns []types.Vulnerability, style lipgloss.Style) {
	if len(vulns) == 0 {
		return
	}

	// Severity header
	b.WriteString(fmt.Sprintf("  %s (%d):\n", style.Render(severity), len(vulns)))

	// Sort vulnerabilities by title for consistent display
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].Title < vulns[j].Title
	})

	for i, v := range vulns {
		// Vulnerability title with index
		b.WriteString(fmt.Sprintf("    [%d] %s\n", i+1, v.Title))

		// Description (truncated if too long)
		desc := v.Description
		if len(desc) > 200 {
			desc = desc[:197] + "..."
		}
		wrapped := wordWrap(desc, 70)
		for _, line := range wrapped {
			b.WriteString(fmt.Sprintf("        %s\n", styles.MutedStyle.Render(line)))
		}

		// CVE ID if available
		if v.CVEID != nil {
			b.WriteString(fmt.Sprintf("        CVE: %s\n", *v.CVEID))
		}

		// CVSS score if available
		if v.CVSSScore != nil {
			b.WriteString(fmt.Sprintf("        CVSS: %.1f\n", *v.CVSSScore))
		}

		// Port/Host if available
		if v.Port != nil {
			b.WriteString(fmt.Sprintf("        Port: %d\n", *v.Port))
		}
		if v.Host != nil {
			b.WriteString(fmt.Sprintf("        Host: %s\n", *v.Host))
		}

		b.WriteString("\n")
	}
}

// renderConfirmDelete renders the delete confirmation dialog
//
// Returns:
//   - Rendered confirmation dialog
func (h *HistoryView) renderConfirmDelete() string {
	var b strings.Builder

	// Find scan info for display
	var target string
	for _, scan := range h.scans {
		if scan.ID == h.pendingDeleteID {
			target = scan.Target
			break
		}
	}

	// Confirmation dialog box
	dialogStyle := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(styles.ColorGray).
		Padding(1, 2).
		Width(60)

	warningStyle := lipgloss.NewStyle().
		Foreground(styles.ColorHigh).
		Bold(true)

	content := fmt.Sprintf(
		"%s\n\n"+
			"Target: %s\n"+
			"ID: %s\n\n"+
			"This action cannot be undone.\n\n"+
			"Delete this scan? [y/N]",
		warningStyle.Render("WARNING: Delete Scan"),
		target,
		h.pendingDeleteID,
	)

	b.WriteString(dialogStyle.Render(content))

	return b.String()
}

// renderStatusBar renders the status bar with keyboard shortcuts for list view
//
// Returns:
//   - Rendered status bar string
func (h *HistoryView) renderStatusBar() string {
	hints := []string{
		fmt.Sprintf("%s Enter", styles.KeyStyle.Render("View")),
		fmt.Sprintf("%s d", styles.KeyStyle.Render("Delete")),
		fmt.Sprintf("%s r", styles.KeyStyle.Render("Re-run")),
		fmt.Sprintf("%s /", styles.KeyStyle.Render("Search")),
		fmt.Sprintf("%s t", styles.KeyStyle.Render("Filter")),
		fmt.Sprintf("%s R", styles.KeyStyle.Render("Refresh")),
		fmt.Sprintf("%s c", styles.KeyStyle.Render("Compare")),
		fmt.Sprintf("%s q", styles.KeyStyle.Render("Quit")),
	}

	return styles.StatusBarStyle.Render(strings.Join(hints, " | "))
}

// renderDetailStatusBar renders the status bar for detail view
//
// Returns:
//   - Rendered status bar string
func (h *HistoryView) renderDetailStatusBar() string {
	hints := []string{
		fmt.Sprintf("%s j/k", styles.KeyStyle.Render("Scroll")),
		fmt.Sprintf("%s g/G", styles.KeyStyle.Render("Top/Bottom")),
		fmt.Sprintf("%s r", styles.KeyStyle.Render("Re-run")),
		fmt.Sprintf("%s d", styles.KeyStyle.Render("Delete")),
		fmt.Sprintf("%s Esc", styles.KeyStyle.Render("Back")),
		fmt.Sprintf("%s q", styles.KeyStyle.Render("Quit")),
	}

	return styles.StatusBarStyle.Render(strings.Join(hints, " | "))
}

// wordWrap wraps text to specified width while preserving words
// Helper function for rendering long text content
//
// Parameters:
//   - text: Text to wrap
//   - width: Maximum line width
//
// Returns:
//   - Slice of wrapped lines
func wordWrap(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{}
	}

	var lines []string
	var currentLine string

	for _, word := range words {
		// If adding this word would exceed width, start a new line
		if len(currentLine)+len(word)+1 > width {
			if currentLine != "" {
				lines = append(lines, currentLine)
				currentLine = word
			} else {
				// Word itself is longer than width, just add it
				lines = append(lines, word)
			}
		} else {
			if currentLine == "" {
				currentLine = word
			} else {
				currentLine += " " + word
			}
		}
	}

	// Add last line
	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}
