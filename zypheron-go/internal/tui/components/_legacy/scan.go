package views

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/validation"
)

// ScanMode defines the current display mode of the scan view
type ScanMode int

const (
	ModeRaw    ScanMode = iota // Raw terminal output
	ModeParsed                 // Parsed/Structured results
)

// Available tools for scanning
var availableTools = []string{
	"nmap",
	"nikto",
	"dirb",
	"gobuster",
	"whatweb",
	"wpscan",
	"sqlmap",
}

// ScanModel is the main model for the Scan View
// It persists state (output, scroll position, input) even when switching tabs.
type ScanModel struct {
	// Components
	viewport viewport.Model
	input    textinput.Model

	// State
	mode         ScanMode
	width        int
	height       int
	ready        bool
	scanning     bool
	target       string
	selectedTool int             // Index into availableTools
	output       strings.Builder // Buffer for raw output
	lines        []string        // Cache of lines for viewport
	cmdHistory   []string
}

// NewScanModel creates a new ScanModel with default settings
func NewScanModel() ScanModel {
	// Initialize text input
	ti := textinput.New()
	ti.Placeholder = "Enter target (e.g., 10.10.10.5) or command..."
	ti.Focus()
	ti.CharLimit = 100
	ti.Width = 30

	return ScanModel{
		input:        ti,
		mode:         ModeRaw,
		selectedTool: 0, // Default to nmap
		output:       strings.Builder{},
		lines:        []string{},
		scanning:     false,
	}
}

// Init initializes the model
func (m ScanModel) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles messages for the Scan View
func (m ScanModel) Update(msg tea.Msg) (ScanModel, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		// Calculate viewport height
		// Height = Total - Header(3) - Status(3) - AI(5-15) - Input(3)
		// We approximate the available space passed from the parent model
		// For now, we rely on SetSize being called by the parent
		if !m.ready {
			// Initialize viewport on first resize
			// Parent will call SetSize with correct dimensions
			m.ready = true
		} else {
			m.viewport.Width = msg.Width
			// Height is managed by SetSize from parent
		}

	case tea.KeyMsg:
		// View-specific keybindings
		switch msg.String() {
		case "tab":
			// Toggle between Raw and Parsed modes
			if m.mode == ModeRaw {
				m.mode = ModeParsed
			} else {
				m.mode = ModeRaw
			}
			return m, nil

		case "enter":
			if m.input.Focused() {
				// Start scan / Execute command
				cmd = m.executeCommand(m.input.Value())
				m.input.SetValue("") // Clear input
				return m, cmd
			}
		}
	}

	// Update components
	m.input, cmd = m.input.Update(msg)
	cmds = append(cmds, cmd)

	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

// SetSize updates the dimensions of the view and its viewport
// This allows the parent model to strictly control layout
func (m *ScanModel) SetSize(width, height int) {
	m.width = width
	m.height = height

	// Input takes ~3 lines, Viewport takes the rest
	inputHeight := 3
	viewportHeight := height - inputHeight

	if viewportHeight < 0 {
		viewportHeight = 0
	}

	m.viewport.Width = width
	m.viewport.Height = viewportHeight
}

// AddOutput appends new streaming output to the viewport
// Call this when receiving data from a running scan command
func (m *ScanModel) AddOutput(text string) {
	m.output.WriteString(text)
	// Simple split for now, robust implementations handle partial lines
	newLines := strings.Split(text, "\n")
	m.lines = append(m.lines, newLines...)
	
	// Update viewport content
	m.viewport.SetContent(m.output.String())
	
	// Auto-scroll to bottom if already at bottom
	if m.viewport.AtBottom() {
		m.viewport.GotoBottom()
	}
}

// View renders the Scan View
func (m ScanModel) View() string {
	if !m.ready {
		return "Initializing scan engine..."
	}

	// 1. Render Input Area
	inputStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(styles.ColorInfo).
		Padding(0, 1).
		Width(m.width - 2) // Account for borders

	inputView := inputStyle.Render(m.input.View())

	// 2. Render Viewport (Content)
	var content string
	if m.mode == ModeRaw {
		content = m.viewport.View()
	} else {
		content = m.renderParsedView()
	}

	// 3. Combine
	return lipgloss.JoinVertical(lipgloss.Left, inputView, content)
}

// renderParsedView renders the structured/tree view of findings
func (m ScanModel) renderParsedView() string {
	// Placeholder for Phase 2 Parsed View
	return lipgloss.NewStyle().
		Width(m.viewport.Width).
		Height(m.viewport.Height).
		Align(lipgloss.Center, lipgloss.Center).
		Render(fmt.Sprintf("\n%s\n\n%s", 
			styles.ActiveTabStyle.Render("PARSED FINDINGS VIEW"),
			styles.MutedStyle.Render("(Switch to Raw view with Tab for live output)")))
}

// EnqueueScanMsg requests a new scan to be added to the queue
// This is defined here to avoid import cycles with the tui package
type EnqueueScanMsg struct {
	ID     string
	Target string
	Tool   string
	Phase  string
}

// generateScanID creates a unique scan ID
func generateScanID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("scan-%s-%s", time.Now().Format("20060102-150405"), hex.EncodeToString(b))
}

// GetSelectedTool returns the currently selected tool name
func (m ScanModel) GetSelectedTool() string {
	if m.selectedTool >= 0 && m.selectedTool < len(availableTools) {
		return availableTools[m.selectedTool]
	}
	return "nmap" // Default fallback
}

// SetSelectedTool sets the selected tool by index
func (m ScanModel) SetSelectedTool(index int) ScanModel {
	if index >= 0 && index < len(availableTools) {
		m.selectedTool = index
	}
	return m
}

// NextTool cycles to the next available tool
func (m ScanModel) NextTool() ScanModel {
	m.selectedTool = (m.selectedTool + 1) % len(availableTools)
	return m
}

// PrevTool cycles to the previous available tool
func (m ScanModel) PrevTool() ScanModel {
	m.selectedTool--
	if m.selectedTool < 0 {
		m.selectedTool = len(availableTools) - 1
	}
	return m
}

// executeCommand starts a scan after validating input
// Validates target format before execution to prevent command injection
// and ensure valid scan targets.
func (m *ScanModel) executeCommand(cmdStr string) tea.Cmd {
	if cmdStr == "" {
		return nil
	}

	// Sanitize input first to remove dangerous characters
	sanitizedCmd := validation.SanitizeInput(cmdStr)

	// Validate target format (IP, domain, CIDR, or URL)
	if err := validation.ValidateTarget(sanitizedCmd); err != nil {
		// Display validation error in output
		errorMsg := fmt.Sprintf("\n%s %s\n",
			styles.CriticalStyle.Render("[VALIDATION ERROR]"),
			styles.MutedStyle.Render(err.Error()),
		)
		m.AddOutput(errorMsg)
		return nil
	}

	m.scanning = true
	m.target = sanitizedCmd

	// Generate unique scan ID
	scanID := generateScanID()
	tool := m.GetSelectedTool()

	// Show queuing message in output
	header := fmt.Sprintf("\n%s Queuing scan on target: %s using %s\n%s\n",
		styles.InfoStyle.Render(">>>"),
		styles.KeyStyle.Render(sanitizedCmd),
		styles.ActiveTabStyle.Render(tool),
		strings.Repeat("─", m.width),
	)
	m.AddOutput(header)

	// Return command to enqueue the scan
	return func() tea.Msg {
		return EnqueueScanMsg{
			ID:     scanID,
			Target: sanitizedCmd,
			Tool:   tool,
		}
	}
}