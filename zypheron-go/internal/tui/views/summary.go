package views

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Conversational AI-style idle messages
var idleMessages = []string{
	"How can I help you today?",
	"Ready to assist with your security assessment.",
	"What would you like to explore?",
	"I'm here to help. Just type your request.",
	"Need help? Press ? for command reference.",
	"What target shall we analyze today?",
	"Ready for your next task.",
	"Awaiting your instructions.",
}

type SummaryModel struct {
	spinner      spinner.Model
	status       string
	details      string
	phase        string
	isLoading    bool
	width        int
	height       int
	idleIndex    int
	lastIdleSwap time.Time

	// Session stats
	SessionStart time.Time
	ScanCount    int
	FindingCount int
	ModelName    string
}

const (
	HUDHeight = 3 // Top border plus status and detail rows.
)

func NewSummary(width int) SummaryModel {
	s := spinner.New()
	s.Spinner = spinner.Line
	s.Style = lipgloss.NewStyle().Foreground(styles.ColorAccent) // Cyan spinner

	return SummaryModel{
		spinner:      s,
		status:       "Ready",
		details:      idleMessages[0],
		phase:        "IDLE",
		isLoading:    false,
		width:        width,
		height:       HUDHeight,
		idleIndex:    0,
		lastIdleSwap: time.Now(),
		SessionStart: time.Now(),
		ScanCount:    0,
		FindingCount: 0,
		ModelName:    "deepseek",
	}
}

func (m SummaryModel) Init() tea.Cmd {
	// Don't start spinner tick on init - only tick when actively loading
	// This saves CPU cycles when idle
	return nil
}

func (m SummaryModel) Update(msg tea.Msg) (SummaryModel, tea.Cmd) {
	var cmd tea.Cmd

	// Always update spinner so it's ready when needed
	m.spinner, cmd = m.spinner.Update(msg)

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	}

	// Rotate idle messages every 10 seconds when in idle state
	if m.phase == "IDLE" && !m.isLoading {
		if time.Since(m.lastIdleSwap) > 10*time.Second {
			m.idleIndex = rand.Intn(len(idleMessages))
			m.details = idleMessages[m.idleIndex]
			m.lastIdleSwap = time.Now()
		}
	}

	// Only return tick command if loading (saves CPU when idle)
	if m.isLoading {
		return m, cmd
	}
	return m, nil
}

func (m SummaryModel) View() string {
	// HUD Container Style with cyan border
	containerStyle := lipgloss.NewStyle().
		Width(m.width).
		Height(HUDHeight).
		Border(lipgloss.NormalBorder(), true, false, false, false).
		BorderForeground(styles.ColorBorder).
		Padding(0, 1)

	// Status Line (e.g. "Scanning 192.168.1.1...")
	statusIcon := "●"
	statusColor := styles.ColorMuted
	if m.isLoading {
		statusIcon = m.spinner.View()
		statusColor = styles.ColorAccent // Cyan when active
	} else if m.phase == "IDLE" {
		statusColor = styles.ColorSuccess // Green when ready
	}

	statusLine := fmt.Sprintf("%s %s", statusIcon, lipgloss.NewStyle().Foreground(statusColor).Render(m.status))

	// Phase Badge with color based on state
	badgeBg := styles.ColorDarkGray
	badgeFg := styles.ColorWhite
	switch m.phase {
	case "IDLE":
		badgeBg = styles.ColorSubtle
		badgeFg = styles.ColorSuccess
	case "SCAN", "RECON":
		badgeBg = styles.ColorAccent
		badgeFg = styles.ColorBg
	case "THINKING":
		badgeBg = styles.ColorAIThinking
		badgeFg = styles.ColorWhite
	case "ERROR":
		badgeBg = styles.ColorCritical
		badgeFg = styles.ColorWhite
	}

	phaseBadge := lipgloss.NewStyle().
		Background(badgeBg).
		Foreground(badgeFg).
		Bold(true).
		Padding(0, 1).
		Render(m.phase)

	// Layout - simplified without stats (stats moved to bottom bar)
	content := lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.JoinHorizontal(lipgloss.Center, phaseBadge, " ", statusLine),
		styles.MutedStyle.Render(m.details),
	)

	return containerStyle.Render(content)
}

func (m SummaryModel) Height() int {
	return HUDHeight
}

// SetStatus updates the status display and returns a command to start the spinner if loading
func (m *SummaryModel) SetStatus(status, details, phase string, loading bool) tea.Cmd {
	m.status = status
	m.details = details
	m.phase = phase
	m.isLoading = loading

	// Start spinner animation when loading begins
	if loading {
		return m.spinner.Tick
	}
	return nil
}

// SetModelName updates the displayed AI model name
func (m *SummaryModel) SetModelName(name string) {
	m.ModelName = name
}

// IncrementScanCount increments the scan counter
func (m *SummaryModel) IncrementScanCount() {
	m.ScanCount++
}

// AddFindings adds to the finding count
func (m *SummaryModel) AddFindings(count int) {
	m.FindingCount += count
}

// ResetToIdle resets status to idle with a random conversational message
func (m *SummaryModel) ResetToIdle() {
	m.status = "Ready"
	m.phase = "IDLE"
	m.isLoading = false
	m.idleIndex = rand.Intn(len(idleMessages))
	m.details = idleMessages[m.idleIndex]
	m.lastIdleSwap = time.Now()
}
