package components

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
)

// ScanState represents the current state of a scan
type ScanState int

const (
	ScanIdle ScanState = iota
	ScanRunning
	ScanPaused
	ScanCompleted
	ScanFailed
)

// Finding represents a discovered item during scanning
type Finding struct {
	Type      string // "port", "vuln", "dir", "subdomain", "cred"
	Value     string // e.g., "80/tcp http", "/admin (200)", "CVE-2021-1234"
	Severity  string // "critical", "high", "medium", "low", "info"
	Timestamp time.Time
}

// ScanProgressModel is a Bubbletea component for displaying scan progress in the TUI
type ScanProgressModel struct {
	// Display components
	spinner  spinner.Model
	progress progress.Model

	// Scan info
	scanID    string
	target    string
	tool      string
	state     ScanState
	startTime time.Time

	// Progress tracking
	percent    float64
	statusText string

	// Findings
	findings     []Finding
	findingCount int
	maxDisplay   int // max findings to show in view

	// Output buffer (for raw output display)
	outputLines []string
	maxLines    int

	// Dimensions
	width  int
	height int
}

// Messages for scan progress updates
type (
	// ScanStartMsg indicates a scan has started
	ScanStartMsg struct {
		ScanID string
		Target string
		Tool   string
	}

	// ScanProgressMsg updates scan progress
	ScanProgressMsg struct {
		ScanID  string
		Percent float64
		Status  string
	}

	// ScanFindingMsg reports a new finding
	ScanFindingMsg struct {
		ScanID  string
		Finding Finding
	}

	// ScanOutputMsg appends raw output
	ScanOutputMsg struct {
		ScanID string
		Line   string
	}

	// ScanCompleteMsg indicates scan finished
	ScanCompleteMsg struct {
		ScanID   string
		Success  bool
		Duration time.Duration
		Error    string
	}

	// TickMsg for animations
	TickMsg time.Time
)

// NewScanProgress creates a new scan progress component
func NewScanProgress(width, height int) ScanProgressModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(styles.ColorAccent)

	p := progress.New(
		progress.WithDefaultGradient(),
		progress.WithWidth(40),
		progress.WithoutPercentage(),
	)

	return ScanProgressModel{
		spinner:    s,
		progress:   p,
		state:      ScanIdle,
		findings:   make([]Finding, 0),
		maxDisplay: 8,
		outputLines: make([]string, 0),
		maxLines:   50,
		width:      width,
		height:     height,
	}
}

// Init implements tea.Model
func (m ScanProgressModel) Init() tea.Cmd {
	// Don't tick spinner until scan actually starts - saves CPU when idle
	return nil
}

// Update implements tea.Model
func (m ScanProgressModel) Update(msg tea.Msg) (ScanProgressModel, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.progress.Width = msg.Width - 30

	case ScanStartMsg:
		m.scanID = msg.ScanID
		m.target = msg.Target
		m.tool = msg.Tool
		m.state = ScanRunning
		m.startTime = time.Now()
		m.percent = 0
		m.statusText = "Starting..."
		m.findings = make([]Finding, 0)
		m.findingCount = 0
		m.outputLines = make([]string, 0)
		cmds = append(cmds, m.spinner.Tick)

	case ScanProgressMsg:
		if msg.ScanID == m.scanID {
			m.percent = msg.Percent
			if msg.Status != "" {
				m.statusText = msg.Status
			}
		}

	case ScanFindingMsg:
		if msg.ScanID == m.scanID {
			m.findingCount++
			// Keep only last N findings for display
			if len(m.findings) >= m.maxDisplay {
				m.findings = m.findings[1:]
			}
			m.findings = append(m.findings, msg.Finding)
		}

	case ScanOutputMsg:
		if msg.ScanID == m.scanID {
			// Keep only last N lines
			if len(m.outputLines) >= m.maxLines {
				m.outputLines = m.outputLines[1:]
			}
			m.outputLines = append(m.outputLines, msg.Line)
		}

	case ScanCompleteMsg:
		if msg.ScanID == m.scanID {
			if msg.Success {
				m.state = ScanCompleted
				m.statusText = fmt.Sprintf("Completed in %s", msg.Duration.Round(time.Second))
				m.percent = 100
			} else {
				m.state = ScanFailed
				m.statusText = fmt.Sprintf("Failed: %s", msg.Error)
			}
		}

	case spinner.TickMsg:
		if m.state == ScanRunning {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			cmds = append(cmds, cmd)
		}

	case progress.FrameMsg:
		progressModel, cmd := m.progress.Update(msg)
		m.progress = progressModel.(progress.Model)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// View implements tea.Model
func (m ScanProgressModel) View() string {
	if m.state == ScanIdle {
		return m.renderIdleView()
	}

	return m.renderActiveView()
}

// renderIdleView shows the waiting state
func (m ScanProgressModel) renderIdleView() string {
	style := lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Align(lipgloss.Center, lipgloss.Center).
		Foreground(styles.ColorMuted)

	return style.Render("Waiting for command...")
}

// renderActiveView shows active scan progress
func (m ScanProgressModel) renderActiveView() string {
	var b strings.Builder

	// Header with tool and target
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(styles.ColorAccent)

	b.WriteString(headerStyle.Render(fmt.Sprintf("  %s", strings.ToUpper(m.tool))))
	b.WriteString(styles.MutedStyle.Render(fmt.Sprintf(" scanning %s", m.target)))
	b.WriteString("\n\n")

	// Progress section
	b.WriteString(m.renderProgressBar())
	b.WriteString("\n\n")

	// Findings section
	b.WriteString(m.renderFindings())
	b.WriteString("\n")

	// Output section (last few lines)
	b.WriteString(m.renderOutput())

	// Wrap in container
	containerStyle := lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Padding(1, 2)

	return containerStyle.Render(b.String())
}

// renderProgressBar renders the progress bar with status
func (m ScanProgressModel) renderProgressBar() string {
	var b strings.Builder

	// Spinner and status
	if m.state == ScanRunning {
		b.WriteString(m.spinner.View())
		b.WriteString(" ")
	} else if m.state == ScanCompleted {
		b.WriteString(styles.SuccessStyle.Render("[+] "))
	} else if m.state == ScanFailed {
		b.WriteString(styles.CriticalStyle.Render("[-] "))
	}

	b.WriteString(m.statusText)
	b.WriteString("\n")

	// Progress bar
	progressBar := m.progress.ViewAs(m.percent / 100)
	b.WriteString("  ")
	b.WriteString(progressBar)
	b.WriteString(" ")
	b.WriteString(styles.MutedStyle.Render(fmt.Sprintf("%.0f%%", m.percent)))

	// Elapsed time and findings count
	if m.state == ScanRunning {
		elapsed := time.Since(m.startTime).Round(time.Second)
		b.WriteString(styles.MutedStyle.Render(fmt.Sprintf(" | %s", elapsed)))
	}
	if m.findingCount > 0 {
		b.WriteString(styles.SuccessStyle.Render(fmt.Sprintf(" | %d found", m.findingCount)))
	}

	return b.String()
}

// renderFindings renders the findings list
func (m ScanProgressModel) renderFindings() string {
	if len(m.findings) == 0 {
		return styles.MutedStyle.Render("  No findings yet...")
	}

	var b strings.Builder
	b.WriteString(styles.KeyStyle.Render("  Findings:\n"))

	for i, f := range m.findings {
		prefix := "├─"
		if i == len(m.findings)-1 {
			prefix = "└─"
		}

		// Color by severity
		var valueStyle lipgloss.Style
		switch f.Severity {
		case "critical":
			valueStyle = styles.CriticalStyle
		case "high":
			valueStyle = styles.HighStyle
		case "medium":
			valueStyle = styles.MediumStyle
		default:
			valueStyle = styles.MutedStyle
		}

		b.WriteString(fmt.Sprintf("  %s %s\n",
			styles.MutedStyle.Render(prefix),
			valueStyle.Render(f.Value)))
	}

	if m.findingCount > len(m.findings) {
		b.WriteString(styles.MutedStyle.Render(
			fmt.Sprintf("     ... and %d more\n", m.findingCount-len(m.findings))))
	}

	return b.String()
}

// renderOutput renders the last few output lines
func (m ScanProgressModel) renderOutput() string {
	if len(m.outputLines) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString(styles.MutedStyle.Render("  ─── Output ───\n"))

	// Dynamic output lines based on height (more lines for taller terminals)
	outputLineCount := m.height / 6
	if outputLineCount < 3 {
		outputLineCount = 3
	}
	if outputLineCount > 15 {
		outputLineCount = 15
	}

	start := len(m.outputLines) - outputLineCount
	if start < 0 {
		start = 0
	}

	for _, line := range m.outputLines[start:] {
		// Truncate long lines
		if len(line) > m.width-6 {
			line = line[:m.width-9] + "..."
		}
		b.WriteString(styles.MutedStyle.Render(fmt.Sprintf("  %s\n", line)))
	}

	return b.String()
}

// SetSize updates dimensions
func (m *ScanProgressModel) SetSize(width, height int) {
	m.width = width
	m.height = height
	m.progress.Width = width - 30
}

// IsActive returns true if a scan is currently active
func (m ScanProgressModel) IsActive() bool {
	return m.state == ScanRunning || m.state == ScanPaused
}

// GetState returns the current scan state
func (m ScanProgressModel) GetState() ScanState {
	return m.state
}

// GetFindings returns the list of findings
func (m ScanProgressModel) GetFindings() []Finding {
	return m.findings
}

// GetFindingCount returns the total number of findings discovered
func (m ScanProgressModel) GetFindingCount() int {
	return m.findingCount
}

// Reset clears the progress state
func (m *ScanProgressModel) Reset() {
	m.state = ScanIdle
	m.scanID = ""
	m.target = ""
	m.tool = ""
	m.percent = 0
	m.statusText = ""
	m.findings = make([]Finding, 0)
	m.findingCount = 0
	m.outputLines = make([]string, 0)
}

// ============================================================================
// MultiScanProgressModel - Shows multiple concurrent scans stacked vertically
// ============================================================================

// SingleScan holds state for one concurrent scan
type SingleScan struct {
	ScanID       string
	Target       string
	Tool         string
	State        ScanState
	StartTime    time.Time
	Percent      float64
	StatusText   string
	Findings     []Finding
	FindingCount int
	Progress     progress.Model
	Spinner      spinner.Model
	// Raw output storage for Ctrl+O toggle
	RawOutput    []string
	MaxRawLines  int
}

// MultiScanProgressModel manages multiple concurrent scan displays
type MultiScanProgressModel struct {
	scans      map[string]*SingleScan // Active scans by ID
	scanOrder  []string               // Order of scans for display
	maxDisplay int                    // Max scans to show
	width      int
	height     int
}

// NewMultiScanProgress creates a new multi-scan progress component
func NewMultiScanProgress(width, height int) MultiScanProgressModel {
	// Calculate maxDisplay dynamically based on terminal height
	// Each scan takes ~6 lines (header + status + progress + finding + padding)
	linesPerScan := 6
	maxDisplay := (height - 4) / linesPerScan
	if maxDisplay < 1 {
		maxDisplay = 1
	}
	if maxDisplay > 10 {
		maxDisplay = 10 // Cap at 10 for sanity
	}

	return MultiScanProgressModel{
		scans:      make(map[string]*SingleScan),
		scanOrder:  make([]string, 0),
		maxDisplay: maxDisplay, // Dynamic based on terminal height
		width:      width,
		height:     height,
	}
}

// Init implements tea.Model
func (m MultiScanProgressModel) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model
func (m MultiScanProgressModel) Update(msg tea.Msg) (MultiScanProgressModel, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// Update all scan progress bar widths
		for _, scan := range m.scans {
			scan.Progress.Width = msg.Width - 30
		}

	case ScanStartMsg:
		// Create new scan entry
		s := spinner.New()
		s.Spinner = spinner.Dot
		s.Style = lipgloss.NewStyle().Foreground(styles.ColorAccent)

		p := progress.New(
			progress.WithDefaultGradient(),
			progress.WithWidth(m.width - 30),
			progress.WithoutPercentage(),
		)

		scan := &SingleScan{
			ScanID:      msg.ScanID,
			Target:      msg.Target,
			Tool:        msg.Tool,
			State:       ScanRunning,
			StartTime:   time.Now(),
			Percent:     0,
			StatusText:  "Starting...",
			Findings:    make([]Finding, 0),
			Progress:    p,
			Spinner:     s,
			RawOutput:   make([]string, 0),
			MaxRawLines: 1000, // Store up to 1000 lines of raw output
		}
		m.scans[msg.ScanID] = scan
		m.scanOrder = append(m.scanOrder, msg.ScanID)
		cmds = append(cmds, scan.Spinner.Tick)

	case ScanProgressMsg:
		if scan, ok := m.scans[msg.ScanID]; ok {
			scan.Percent = msg.Percent
			if msg.Status != "" {
				scan.StatusText = msg.Status
			}
		}

	case ScanFindingMsg:
		if scan, ok := m.scans[msg.ScanID]; ok {
			scan.FindingCount++
			// Keep only last 4 findings per scan for display
			if len(scan.Findings) >= 4 {
				scan.Findings = scan.Findings[1:]
			}
			scan.Findings = append(scan.Findings, msg.Finding)
		}

	case ScanOutputMsg:
		if scan, ok := m.scans[msg.ScanID]; ok {
			// Store raw output (up to MaxRawLines)
			if len(scan.RawOutput) >= scan.MaxRawLines {
				// Remove oldest line
				scan.RawOutput = scan.RawOutput[1:]
			}
			scan.RawOutput = append(scan.RawOutput, msg.Line)
		}

	case ScanCompleteMsg:
		if scan, ok := m.scans[msg.ScanID]; ok {
			if msg.Success {
				scan.State = ScanCompleted
				scan.StatusText = fmt.Sprintf("Completed in %s", msg.Duration.Round(time.Second))
				scan.Percent = 100
			} else {
				scan.State = ScanFailed
				scan.StatusText = fmt.Sprintf("Failed: %s", msg.Error)
			}
			// Remove from active after a short delay (keep showing completion)
			// Auto-cleanup handled by checking state in View
		}

	case spinner.TickMsg:
		// Update all running spinners
		for _, scan := range m.scans {
			if scan.State == ScanRunning {
				var cmd tea.Cmd
				scan.Spinner, cmd = scan.Spinner.Update(msg)
				cmds = append(cmds, cmd)
			}
		}

	case progress.FrameMsg:
		// Update all progress bars
		for _, scan := range m.scans {
			progressModel, cmd := scan.Progress.Update(msg)
			scan.Progress = progressModel.(progress.Model)
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

// View implements tea.Model - renders all active scans stacked
func (m MultiScanProgressModel) View() string {
	// Clean up completed scans older than 5 seconds
	m.cleanupOldScans()

	if len(m.scans) == 0 {
		return m.renderIdleView()
	}

	var sections []string

	// Render each active scan (up to maxDisplay)
	displayed := 0
	for _, scanID := range m.scanOrder {
		if displayed >= m.maxDisplay {
			break
		}
		scan, ok := m.scans[scanID]
		if !ok {
			continue
		}

		sections = append(sections, m.renderSingleScan(scan))
		displayed++
	}

	// Show count of additional scans if any
	remaining := len(m.scans) - displayed
	if remaining > 0 {
		sections = append(sections, styles.MutedStyle.Render(
			fmt.Sprintf("  + %d more scans running...", remaining)))
	}

	// Join all sections with dividers
	result := lipgloss.JoinVertical(lipgloss.Left, sections...)

	containerStyle := lipgloss.NewStyle().
		Width(m.width).
		Padding(1, 2)

	return containerStyle.Render(result)
}

// renderSingleScan renders one scan's progress
func (m MultiScanProgressModel) renderSingleScan(scan *SingleScan) string {
	var b strings.Builder

	// Header with tool and target
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(styles.ColorAccent)

	b.WriteString(headerStyle.Render(fmt.Sprintf("  %s", strings.ToUpper(scan.Tool))))
	b.WriteString(styles.MutedStyle.Render(fmt.Sprintf(" scanning %s", scan.Target)))
	b.WriteString("\n")

	// Progress bar line
	if scan.State == ScanRunning {
		b.WriteString(scan.Spinner.View())
		b.WriteString(" ")
	} else if scan.State == ScanCompleted {
		b.WriteString(styles.SuccessStyle.Render("[+] "))
	} else if scan.State == ScanFailed {
		b.WriteString(styles.CriticalStyle.Render("[-] "))
	}
	b.WriteString(scan.StatusText)
	b.WriteString("\n")

	// Progress bar
	progressBar := scan.Progress.ViewAs(scan.Percent / 100)
	b.WriteString("  ")
	b.WriteString(progressBar)
	b.WriteString(" ")
	b.WriteString(styles.MutedStyle.Render(fmt.Sprintf("%.0f%%", scan.Percent)))

	// Elapsed time
	if scan.State == ScanRunning {
		elapsed := time.Since(scan.StartTime).Round(time.Second)
		b.WriteString(styles.MutedStyle.Render(fmt.Sprintf(" | %s", elapsed)))
	}
	if scan.FindingCount > 0 {
		b.WriteString(styles.SuccessStyle.Render(fmt.Sprintf(" | %d found", scan.FindingCount)))
	}
	b.WriteString("\n")

	// Show last 2-3 findings per scan (more vertical space)
	if len(scan.Findings) > 0 {
		maxFindings := 3
		startIdx := len(scan.Findings) - maxFindings
		if startIdx < 0 {
			startIdx = 0
		}

		displayFindings := scan.Findings[startIdx:]
		for i, finding := range displayFindings {
			var findingStyle lipgloss.Style
			switch finding.Severity {
			case "critical":
				findingStyle = styles.CriticalStyle
			case "high":
				findingStyle = styles.HighStyle
			case "medium":
				findingStyle = styles.MediumStyle
			default:
				findingStyle = styles.MutedStyle
			}

			prefix := "  ├─ "
			if i == len(displayFindings)-1 {
				prefix = "  └─ "
			}
			b.WriteString(prefix)
			b.WriteString(findingStyle.Render(truncateString(finding.Value, 60)))
			b.WriteString("\n")
		}
	}

	return b.String()
}

// renderIdleView shows waiting state
func (m MultiScanProgressModel) renderIdleView() string {
	style := lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Align(lipgloss.Center, lipgloss.Center).
		Foreground(styles.ColorMuted)

	return style.Render("Waiting for command...")
}

// cleanupOldScans removes completed scans older than 5 seconds
func (m *MultiScanProgressModel) cleanupOldScans() {
	var newOrder []string
	for _, scanID := range m.scanOrder {
		scan, ok := m.scans[scanID]
		if !ok {
			continue
		}
		// Keep running scans and recently completed ones
		if scan.State == ScanRunning ||
			(scan.State == ScanCompleted && time.Since(scan.StartTime) < 30*time.Second) ||
			(scan.State == ScanFailed && time.Since(scan.StartTime) < 30*time.Second) {
			newOrder = append(newOrder, scanID)
		} else {
			delete(m.scans, scanID)
		}
	}
	m.scanOrder = newOrder
}

// SetSize updates dimensions and recalculates maxDisplay
func (m *MultiScanProgressModel) SetSize(width, height int) {
	m.width = width
	m.height = height

	// Recalculate maxDisplay based on new height
	linesPerScan := 6
	maxDisplay := (height - 4) / linesPerScan
	if maxDisplay < 1 {
		maxDisplay = 1
	}
	if maxDisplay > 10 {
		maxDisplay = 10
	}
	m.maxDisplay = maxDisplay

	// Update progress bar widths
	for _, scan := range m.scans {
		scan.Progress.Width = width - 30
	}
}

// IsActive returns true if any scan is running
func (m MultiScanProgressModel) IsActive() bool {
	for _, scan := range m.scans {
		if scan.State == ScanRunning {
			return true
		}
	}
	return false
}

// GetAllFindings returns findings from all scans
func (m MultiScanProgressModel) GetAllFindings() []Finding {
	var all []Finding
	for _, scan := range m.scans {
		all = append(all, scan.Findings...)
	}
	return all
}

// GetTotalFindingCount returns total findings across all scans
func (m MultiScanProgressModel) GetTotalFindingCount() int {
	total := 0
	for _, scan := range m.scans {
		total += scan.FindingCount
	}
	return total
}

// Reset clears all scans
func (m *MultiScanProgressModel) Reset() {
	m.scans = make(map[string]*SingleScan)
	m.scanOrder = make([]string, 0)
}

// ActiveCount returns number of running scans
func (m MultiScanProgressModel) ActiveCount() int {
	count := 0
	for _, scan := range m.scans {
		if scan.State == ScanRunning {
			count++
		}
	}
	return count
}

// truncateString truncates a string to max length
func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// GetRawOutput returns raw output for a specific scan
func (m MultiScanProgressModel) GetRawOutput(scanID string) []string {
	if scan, ok := m.scans[scanID]; ok {
		return scan.RawOutput
	}
	return nil
}

// GetAllRawOutput returns combined raw output from all scans
func (m MultiScanProgressModel) GetAllRawOutput() []string {
	var all []string
	for _, scanID := range m.scanOrder {
		if scan, ok := m.scans[scanID]; ok {
			// Add header for each scan
			header := fmt.Sprintf("─── %s → %s ───", strings.ToUpper(scan.Tool), scan.Target)
			all = append(all, header)
			all = append(all, scan.RawOutput...)
			all = append(all, "") // Empty line between scans
		}
	}
	return all
}

// GetActiveScanIDs returns IDs of running scans
func (m MultiScanProgressModel) GetActiveScanIDs() []string {
	var active []string
	for _, scanID := range m.scanOrder {
		if scan, ok := m.scans[scanID]; ok && scan.State == ScanRunning {
			active = append(active, scanID)
		}
	}
	return active
}

// RenderRawOutputView renders raw output view for Ctrl+O toggle
func (m MultiScanProgressModel) RenderRawOutputView() string {
	var b strings.Builder

	// Header
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(styles.ColorWarning)
	b.WriteString(headerStyle.Render("RAW OUTPUT VIEW"))
	b.WriteString(styles.MutedStyle.Render(" (Ctrl+O to toggle back)"))
	b.WriteString("\n")
	b.WriteString(styles.MutedStyle.Render(strings.Repeat("─", m.width-4)))
	b.WriteString("\n\n")

	if len(m.scans) == 0 {
		b.WriteString(styles.MutedStyle.Render("No scans running..."))
		return b.String()
	}

	// Show output from all scans
	linesRemaining := m.height - 6 // Reserve space for header and footer

	for _, scanID := range m.scanOrder {
		scan, ok := m.scans[scanID]
		if !ok || linesRemaining <= 0 {
			continue
		}

		// Scan header
		stateIcon := "●"
		stateStyle := styles.SuccessStyle
		if scan.State == ScanRunning {
			stateIcon = "◐"
			stateStyle = styles.WarningStyle
		} else if scan.State == ScanFailed {
			stateIcon = "✗"
			stateStyle = styles.CriticalStyle
		}

		b.WriteString(stateStyle.Render(fmt.Sprintf("%s %s", stateIcon, strings.ToUpper(scan.Tool))))
		b.WriteString(styles.MutedStyle.Render(fmt.Sprintf(" → %s (%.0f%%)", scan.Target, scan.Percent)))
		b.WriteString("\n")
		linesRemaining--

		// Show last N lines of output
		outputLines := scan.RawOutput
		maxLines := linesRemaining - 2 // Leave room for next scan
		if maxLines < 5 {
			maxLines = 5
		}
		if maxLines > 20 {
			maxLines = 20
		}

		startIdx := len(outputLines) - maxLines
		if startIdx < 0 {
			startIdx = 0
		}

		for _, line := range outputLines[startIdx:] {
			if linesRemaining <= 0 {
				break
			}
			// Truncate long lines
			if len(line) > m.width-4 {
				line = line[:m.width-7] + "..."
			}
			b.WriteString(styles.MutedStyle.Render("  " + line))
			b.WriteString("\n")
			linesRemaining--
		}

		b.WriteString("\n")
		linesRemaining--
	}

	containerStyle := lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Padding(1, 2)

	return containerStyle.Render(b.String())
}
