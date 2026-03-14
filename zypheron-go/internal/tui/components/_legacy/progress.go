package components

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
)

// phaseToString returns the display name for a scan phase
// Uses the Phase type defined in statusbar.go
func phaseToString(p Phase) string {
	switch p {
	case PhaseRecon:
		return "Reconnaissance"
	case PhaseScan:
		return "Scanning"
	case PhaseAnalysis:
		return "Analysis"
	case PhaseComplete:
		return "Complete"
	default:
		return "Unknown"
	}
}

// ProgressTickMsg is sent periodically to update animation frames
// This drives the animated progress bar and spinner visuals
type ProgressTickMsg time.Time

// ProgressUpdateMsg updates the progress percentage for the current phase
type ProgressUpdateMsg struct {
	Phase      Phase   // Which phase this update applies to
	Percent    float64 // Progress as 0.0 to 1.0
	StatusText string  // Optional status text to display (e.g., "Scanning port 80/443")
}

// LogLineMsg adds a new line to the streaming output log
type LogLineMsg struct {
	Line      string    // The log line content
	Timestamp time.Time // When the log was generated
	Level     string    // Log level: "info", "warn", "error", "success"
}

// PhaseCompleteMsg signals that a phase has finished
type PhaseCompleteMsg struct {
	Phase    Phase // Which phase just completed
	Duration time.Duration
}

// Constants for progress component configuration
const (
	DefaultProgressWidth    = 40   // Width of the progress bar in characters
	MaxLogLines             = 100  // Maximum number of log lines to retain
	ProgressBarUpdateRate   = 100  // Milliseconds between progress bar animation frames
	ETACalculationMinSample = 5    // Minimum samples needed before showing ETA
)

// Progress represents a multi-phase progress tracking component
// with integrated log streaming and real-time status display.
//
// Key features:
// - Multi-phase progress visualization (Recon -> Scan -> Analysis)
// - Animated progress bar with percentage display
// - Streaming log output with automatic scrolling
// - Time elapsed and ETA calculation
// - Graceful cancellation support
// - ASCII-only visuals (no emoji icons)
type Progress struct {
	// Phase tracking
	currentPhase Phase     // Current active phase
	phaseStart   time.Time // When current phase started
	scanStart    time.Time // When entire scan started
	phaseHistory []time.Duration

	// Progress tracking
	progressBar  progress.Model // Charmbracelet progress bar model
	percent      float64        // Current phase progress (0.0 to 1.0)
	statusText   string         // Current status message
	width        int            // Component width
	height       int            // Component height (for log scrolling)

	// Log streaming
	logLines    []LogLineMsg // Circular buffer of log lines
	logOffset   int          // Scroll offset for log viewing
	autoScroll  bool         // Whether to auto-scroll to newest logs

	// State
	cancelled bool // Whether the scan was cancelled
	paused    bool // Whether the scan is paused
}

// NewProgress creates and initializes a new Progress component
//
// Returns:
//   - Progress configured with default settings and ready to track a scan
//
// The component starts in PhaseRecon with 0% progress.
// Timer starts automatically on first Init() call.
func NewProgress() Progress {
	// Initialize the progress bar with monochrome styling
	prog := progress.New(
		progress.WithDefaultGradient(),
		progress.WithWidth(DefaultProgressWidth),
		progress.WithoutPercentage(), // We'll render percentage ourselves
	)

	return Progress{
		currentPhase: PhaseRecon,
		scanStart:    time.Now(),
		phaseStart:   time.Now(),
		progressBar:  prog,
		percent:      0.0,
		width:        80,
		height:       10,
		logLines:     make([]LogLineMsg, 0, MaxLogLines),
		autoScroll:   true,
		phaseHistory: make([]time.Duration, 0, 3),
	}
}

// Init implements tea.Model interface
// Starts the progress animation ticker
func (p Progress) Init() tea.Cmd {
	return tea.Batch(
		// Start progress bar animation
		p.tickCmd(),
	)
}

// tickCmd returns a command that sends ProgressTickMsg at regular intervals
// This drives the progress bar animation
func (p Progress) tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*ProgressBarUpdateRate, func(t time.Time) tea.Msg {
		return ProgressTickMsg(t)
	})
}

// Update handles all messages and updates the Progress state
//
// Parameters:
//   - msg: tea.Msg - Any Bubble Tea message
//
// Returns:
//   - Progress: Updated progress state
//   - tea.Cmd: Any command to execute (e.g., tick for animation)
//
// Handles:
// - ProgressUpdateMsg: Updates progress percentage
// - LogLineMsg: Adds new log lines
// - PhaseCompleteMsg: Advances to next phase
// - ProgressTickMsg: Updates progress bar animation
// - tea.KeyMsg: Handles user input (scroll, cancel, pause)
func (p Progress) Update(msg tea.Msg) (Progress, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case ProgressUpdateMsg:
		// Update progress for the specified phase
		if msg.Phase == p.currentPhase {
			p.percent = msg.Percent
			if msg.StatusText != "" {
				p.statusText = msg.StatusText
			}
		}

	case LogLineMsg:
		// Add new log line to buffer
		p.addLogLine(msg)

	case PhaseCompleteMsg:
		// Record phase duration and advance to next phase
		if msg.Phase == p.currentPhase {
			duration := time.Since(p.phaseStart)
			p.phaseHistory = append(p.phaseHistory, duration)

			// Advance to next phase
			if p.currentPhase < PhaseComplete {
				p.currentPhase++
				p.phaseStart = time.Now()
				p.percent = 0.0
				p.statusText = fmt.Sprintf("Starting %s phase...", phaseToString(p.currentPhase))
			}
		}

	case ProgressTickMsg:
		// Update progress bar animation
		var cmd tea.Cmd
		progressModel, progressCmd := p.progressBar.Update(msg)
		p.progressBar = progressModel.(progress.Model)
		cmd = progressCmd
		cmds = append(cmds, cmd)
		// Schedule next tick
		cmds = append(cmds, p.tickCmd())

	case tea.WindowSizeMsg:
		// Update component dimensions
		p.width = msg.Width
		p.height = msg.Height
		// Update progress bar width to fit
		barWidth := msg.Width - 30 // Reserve space for labels and percentage
		if barWidth < 10 {
			barWidth = 10
		}
		p.progressBar.Width = barWidth

	case tea.KeyMsg:
		// Handle keyboard controls
		switch msg.String() {
		case "up", "k":
			// Scroll log up
			if p.logOffset > 0 {
				p.logOffset--
				p.autoScroll = false
			}

		case "down", "j":
			// Scroll log down
			maxOffset := len(p.logLines) - p.getLogVisibleLines()
			if maxOffset < 0 {
				maxOffset = 0
			}
			if p.logOffset < maxOffset {
				p.logOffset++
			} else {
				// At bottom - re-enable auto-scroll
				p.autoScroll = true
			}

		case "home", "g":
			// Jump to top of log
			p.logOffset = 0
			p.autoScroll = false

		case "end", "G":
			// Jump to bottom of log
			p.logOffset = len(p.logLines) - p.getLogVisibleLines()
			if p.logOffset < 0 {
				p.logOffset = 0
			}
			p.autoScroll = true

		case "ctrl+c":
			// Cancel the scan
			p.cancelled = true
			p.statusText = "Cancelling scan..."
			// Parent should handle actual cancellation

		case "space":
			// Pause/resume scan
			p.paused = !p.paused
			if p.paused {
				p.statusText = "Scan paused"
			} else {
				p.statusText = fmt.Sprintf("Resuming %s...", phaseToString(p.currentPhase))
			}
		}
	}

	return p, tea.Batch(cmds...)
}

// View renders the Progress component to a string
//
// Returns:
//   - string: The rendered progress display
//
// Layout (top to bottom):
// 1. Phase indicators (ASCII art pipeline: Recon -> Scan -> Analysis)
// 2. Progress bar with percentage
// 3. Status text and elapsed time
// 4. ETA (if calculable)
// 5. Streaming log output (scrollable)
// 6. Control hints
func (p Progress) View() string {
	var b strings.Builder

	// Calculate elapsed time
	elapsed := time.Since(p.scanStart)

	// 1. PHASE INDICATORS
	// ASCII art showing progression through phases
	phaseView := p.renderPhaseIndicators()
	b.WriteString(phaseView)
	b.WriteString("\n\n")

	// 2. PROGRESS BAR
	// Render current phase progress with percentage
	progressView := p.progressBar.ViewAs(p.percent)
	percentStr := fmt.Sprintf("%.0f%%", p.percent*100)

	phaseLabel := fmt.Sprintf(" %s ", phaseToString(p.currentPhase))
	progressLine := lipgloss.JoinHorizontal(
		lipgloss.Left,
		styles.KeyStyle.Render(phaseLabel),
		progressView,
		"  ",
		styles.MutedStyle.Render(percentStr),
	)
	b.WriteString(progressLine)
	b.WriteString("\n\n")

	// 3. STATUS TEXT AND ELAPSED TIME
	statusLine := lipgloss.JoinHorizontal(
		lipgloss.Left,
		styles.InfoStyle.Render("Status: "),
		p.statusText,
		strings.Repeat(" ", 3),
		styles.MutedStyle.Render(fmt.Sprintf("Elapsed: %s", p.formatDuration(elapsed))),
	)
	b.WriteString(statusLine)
	b.WriteString("\n")

	// 4. ETA (if we have enough data to estimate)
	eta := p.calculateETA()
	if eta > 0 {
		etaLine := styles.MutedStyle.Render(fmt.Sprintf("ETA: %s", p.formatDuration(eta)))
		b.WriteString(etaLine)
		b.WriteString("\n")
	}

	b.WriteString("\n")

	// 5. STREAMING LOG OUTPUT
	logSection := p.renderLogs()
	b.WriteString(styles.ContentStyle.Render(logSection))
	b.WriteString("\n")

	// 6. CONTROL HINTS
	hints := p.renderControlHints()
	b.WriteString(styles.MutedStyle.Render(hints))

	return b.String()
}

// renderPhaseIndicators creates ASCII art showing scan phase progression
//
// Example output:
//   [+] Recon -> [~] Scan -> [-] Analysis
//
// Legend:
//   [+] = completed
//   [~] = in progress (animated)
//   [-] = pending
func (p Progress) renderPhaseIndicators() string {
	phases := []Phase{PhaseRecon, PhaseScan, PhaseAnalysis}
	var indicators []string

	for i, phase := range phases {
		var icon, label string
		var style lipgloss.Style

		if phase < p.currentPhase {
			// Completed phase
			icon = "[+]"
			style = styles.InfoStyle
		} else if phase == p.currentPhase {
			// Current phase (animated)
			icon = "[~]"
			style = styles.KeyStyle.Bold(true)
		} else {
			// Pending phase
			icon = "[-]"
			style = styles.MutedStyle
		}

		label = phaseToString(phase)
		indicator := style.Render(icon + " " + label)
		indicators = append(indicators, indicator)

		// Add arrow between phases
		if i < len(phases)-1 {
			arrow := styles.MutedStyle.Render(" -> ")
			indicators = append(indicators, arrow)
		}
	}

	return lipgloss.JoinHorizontal(lipgloss.Left, indicators...)
}

// renderLogs renders the scrollable log section
func (p Progress) renderLogs() string {
	if len(p.logLines) == 0 {
		return styles.MutedStyle.Render("No logs yet...")
	}

	visibleLines := p.getLogVisibleLines()
	start := p.logOffset
	end := start + visibleLines

	// Clamp to actual log size
	if start >= len(p.logLines) {
		start = len(p.logLines) - visibleLines
		if start < 0 {
			start = 0
		}
	}
	if end > len(p.logLines) {
		end = len(p.logLines)
	}

	var logView strings.Builder
	for i := start; i < end; i++ {
		logLine := p.logLines[i]
		// Format: [HH:MM:SS] LEVEL: message
		timestamp := logLine.Timestamp.Format("15:04:05")
		prefix := fmt.Sprintf("[%s] ", timestamp)

		// Style based on log level
		var lineStyle lipgloss.Style
		switch logLine.Level {
		case "error":
			lineStyle = styles.CriticalStyle
		case "warn":
			lineStyle = styles.HighStyle
		case "success":
			lineStyle = styles.LowStyle
		default:
			lineStyle = styles.MutedStyle
		}

		line := prefix + logLine.Line
		logView.WriteString(lineStyle.Render(line))
		logView.WriteString("\n")
	}

	return logView.String()
}

// renderControlHints renders keyboard control hints
func (p Progress) renderControlHints() string {
	hints := []string{
		"[↑/↓] Scroll",
		"[Space] Pause",
		"[Ctrl+C] Cancel",
		"[Home/End] Jump",
	}

	if !p.autoScroll {
		hints = append(hints, "[Auto-scroll: OFF]")
	}

	return strings.Join(hints, "  ")
}

// addLogLine adds a log line to the buffer (circular buffer with MaxLogLines capacity)
func (p *Progress) addLogLine(msg LogLineMsg) {
	// Add timestamp if not set
	if msg.Timestamp.IsZero() {
		msg.Timestamp = time.Now()
	}

	// Add to buffer
	p.logLines = append(p.logLines, msg)

	// Trim if exceeded max
	if len(p.logLines) > MaxLogLines {
		p.logLines = p.logLines[len(p.logLines)-MaxLogLines:]
	}

	// Auto-scroll to newest if enabled
	if p.autoScroll {
		p.logOffset = len(p.logLines) - p.getLogVisibleLines()
		if p.logOffset < 0 {
			p.logOffset = 0
		}
	}
}

// getLogVisibleLines calculates how many log lines can fit in the visible area
func (p Progress) getLogVisibleLines() int {
	// Reserve space for:
	// - Phase indicators (3 lines)
	// - Progress bar (3 lines)
	// - Status/ETA (3 lines)
	// - Control hints (1 line)
	// Total: ~10 lines of overhead
	reserved := 10
	available := p.height - reserved
	if available < 5 {
		available = 5 // Minimum log view size
	}
	return available
}

// calculateETA estimates time remaining based on progress and phase history
//
// Returns:
//   - time.Duration: Estimated time to completion (0 if not calculable)
//
// ETA calculation strategy:
// - Use historical phase durations if available
// - Otherwise, extrapolate from current phase progress
// - Requires minimum sample size to avoid wild estimates
func (p Progress) calculateETA() time.Duration {
	// Can't calculate ETA if we're done or just started
	if p.currentPhase == PhaseComplete || p.percent < 0.05 {
		return 0
	}

	// Calculate remaining time in current phase based on progress
	currentPhaseElapsed := time.Since(p.phaseStart)
	if p.percent > 0 {
		estimatedPhaseTotal := time.Duration(float64(currentPhaseElapsed) / p.percent)
		currentPhaseRemaining := estimatedPhaseTotal - currentPhaseElapsed

		// Estimate remaining phases using historical average (if available)
		var futurePhases time.Duration
		if len(p.phaseHistory) >= ETACalculationMinSample {
			// Use average of completed phases as estimate for future phases
			var total time.Duration
			for _, d := range p.phaseHistory {
				total += d
			}
			avgPhaseDuration := total / time.Duration(len(p.phaseHistory))

			// Count remaining phases after current
			remainingPhaseCount := int(PhaseComplete - p.currentPhase - 1)
			if remainingPhaseCount > 0 {
				futurePhases = avgPhaseDuration * time.Duration(remainingPhaseCount)
			}
		}

		return currentPhaseRemaining + futurePhases
	}

	return 0
}

// formatDuration formats a duration into human-readable format
// Examples: "1m 23s", "45s", "2h 15m"
func (p Progress) formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute
	d -= minutes * time.Minute
	seconds := d / time.Second

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// SetWidth updates the component width
func (p Progress) SetWidth(w int) Progress {
	p.width = w
	// Update progress bar width
	barWidth := w - 30
	if barWidth < 10 {
		barWidth = 10
	}
	p.progressBar.Width = barWidth
	return p
}

// SetHeight updates the component height
func (p Progress) SetHeight(h int) Progress {
	p.height = h
	return p
}

// IsCancelled returns whether the scan was cancelled by user
func (p Progress) IsCancelled() bool {
	return p.cancelled
}

// IsPaused returns whether the scan is currently paused
func (p Progress) IsPaused() bool {
	return p.paused
}

// GetCurrentPhase returns the current scan phase
func (p Progress) GetCurrentPhase() Phase {
	return p.currentPhase
}

// GetProgress returns the current progress percentage (0.0 to 1.0)
func (p Progress) GetProgress() float64 {
	return p.percent
}
