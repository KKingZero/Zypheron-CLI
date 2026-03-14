package views

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/validation"
)

// ReconPhase represents a distinct stage in the reconnaissance workflow.
// Each phase has specific tools and objectives for information gathering.
type ReconPhase string

const (
	PhaseSubdomain ReconPhase = "subdomain"  // Subdomain enumeration (amass, subfinder, etc.)
	PhaseDNS       ReconPhase = "dns"        // DNS lookups and zone transfers
	PhaseWHOIS     ReconPhase = "whois"      // WHOIS queries and registrar info
	PhasePort      ReconPhase = "port"       // Port discovery and service detection
	PhaseOSINT     ReconPhase = "osint"      // Open-source intelligence gathering
	PhaseComplete  ReconPhase = "complete"   // All phases finished
)

// ReconMode determines the level of automation in the recon workflow.
type ReconMode int

const (
	// ModeSemiAuto runs most operations automatically but prompts for risky actions.
	// This is the default mode providing a balance of efficiency and control.
	ModeSemiAuto ReconMode = iota

	// ModeManual requires explicit confirmation for every recon phase.
	// Provides maximum control and understanding of each step.
	ModeManual
)

// ReconTool represents a single reconnaissance tool with installation status.
type ReconTool struct {
	Name        string // Tool name (e.g., "nmap", "subfinder")
	Description string // Brief description of tool purpose
	Installed   bool   // Whether tool is currently available
	Required    bool   // Whether tool is required (vs optional)
}

// ReconResult holds the output from a completed reconnaissance phase.
type ReconResult struct {
	Phase     ReconPhase // Which phase produced this result
	Tool      string     // Which tool was used
	Output    string     // Raw tool output
	Findings  int        // Number of items discovered (subdomains, ports, etc.)
	Duration  time.Duration // How long the operation took
	Error     string     // Error message if operation failed
	Timestamp time.Time  // When this result was generated
}

// DenyPrompt represents a Claude Code-style safety prompt for risky operations.
// This prevents accidental execution of dangerous or noisy reconnaissance actions.
type DenyPrompt struct {
	Active      bool   // Whether a prompt is currently being shown
	Operation   string // What operation is being blocked (e.g., "aggressive port scan")
	Reason      string // Why this operation requires confirmation
	Redirect    string // Suggested safer alternative
	Callback    func(bool) tea.Cmd // Function to call with user's decision
}

// ReconView is the main reconnaissance interface for Zypheron TUI.
// Provides semi-automated or manual reconnaissance workflows with real-time output.
//
// Features:
//   - Multi-phase recon workflow (subdomains → DNS → WHOIS → ports → OSINT)
//   - Claude Code-style deny/redirect prompts for risky operations
//   - Manual mode toggle for explicit control
//   - Real-time streaming output with scrollable viewport
//   - Tool availability checking and status display
//   - Vim-style navigation (j/k for scrolling)
type ReconView struct {
	// Dimensions
	width  int
	height int

	// Target configuration
	target string    // Target domain/IP being scanned
	mode   ReconMode // Current automation mode (semi-auto or manual)

	// Workflow state
	currentPhase ReconPhase    // Current phase of reconnaissance
	results      []ReconResult // All completed recon results
	inProgress   bool          // Whether a recon operation is currently running
	completed    bool          // Whether entire workflow is finished

	// Tools
	tools []ReconTool // Available reconnaissance tools

	// UI components
	viewport  viewport.Model  // Scrollable output area
	input     textinput.Model // Command input for /manual and other commands
	inputMode bool            // Whether input field is focused

	// Safety features
	denyPrompt DenyPrompt // Current deny/redirect prompt if active

	// Output streaming
	streamBuffer strings.Builder // Buffer for accumulating streaming output
	lastUpdate   time.Time       // Last time output was updated
}

// NewReconView creates a new ReconView initialized with default settings.
// Starts in semi-auto mode with no target set.
//
// Returns:
//   - ReconView instance ready to be integrated into a Bubble Tea program
func NewReconView() ReconView {
	// Initialize text input for commands
	ti := textinput.New()
	ti.Placeholder = "Type /manual to toggle mode, or :help for commands"
	ti.CharLimit = 256
	ti.Width = 80

	// Initialize viewport for output
	vp := viewport.New(80, 20)
	vp.Style = lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(styles.ColorGray).
		Padding(0, 1)

	// Define available reconnaissance tools with installation status
	// In production, this would be dynamically checked via exec.LookPath
	tools := []ReconTool{
		{Name: "nmap", Description: "Port scanner", Installed: true, Required: true},
		{Name: "subfinder", Description: "Subdomain enumeration", Installed: true, Required: false},
		{Name: "amass", Description: "Advanced subdomain discovery", Installed: false, Required: false},
		{Name: "dig", Description: "DNS lookup utility", Installed: true, Required: true},
		{Name: "whois", Description: "WHOIS client", Installed: true, Required: true},
		{Name: "theHarvester", Description: "OSINT framework", Installed: false, Required: false},
		{Name: "dnsenum", Description: "DNS enumeration", Installed: true, Required: false},
		{Name: "masscan", Description: "Fast port scanner", Installed: false, Required: false},
	}

	return ReconView{
		width:        80,
		height:       24,
		mode:         ModeSemiAuto, // Default to semi-auto mode
		currentPhase: PhaseSubdomain,
		results:      make([]ReconResult, 0),
		tools:        tools,
		viewport:     vp,
		input:        ti,
		inputMode:    false,
		lastUpdate:   time.Now(),
	}
}

// Init initializes the ReconView component.
// Required by the Bubble Tea Model interface.
//
// Returns:
//   - Command to start initial setup (currently nil)
func (r ReconView) Init() tea.Cmd {
	return nil
}

// Update handles messages and updates the ReconView state.
// Part of the Bubble Tea Model interface.
//
// Handles:
//   - Window resize events
//   - Keyboard input (navigation, commands, prompts)
//   - Streaming output updates
//   - Phase transitions
//
// Parameters:
//   - msg: Bubble Tea message
//
// Returns:
//   - Updated ReconView model
//   - Command to run (if any)
func (r ReconView) Update(msg tea.Msg) (ReconView, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Adjust layout when terminal is resized
		r.width = msg.Width
		r.height = msg.Height

		// Update viewport dimensions (leave room for header, status bar, input)
		viewportHeight := r.height - 10
		if viewportHeight < 5 {
			viewportHeight = 5
		}
		r.viewport.Width = r.width - 4
		r.viewport.Height = viewportHeight
		r.input.Width = r.width - 4

	case tea.KeyMsg:
		// Handle deny prompt responses first (highest priority)
		if r.denyPrompt.Active {
			return r.handleDenyPromptKey(msg)
		}

		// Handle input mode (command entry)
		if r.inputMode {
			return r.handleInputKey(msg)
		}

		// Handle normal mode (navigation and shortcuts)
		return r.handleNormalKey(msg)
	}

	// Update viewport for scrolling
	r.viewport, cmd = r.viewport.Update(msg)
	if cmd != nil {
		cmds = append(cmds, cmd)
	}

	return r, tea.Batch(cmds...)
}

// handleDenyPromptKey processes keyboard input when a deny prompt is active.
// Allows user to confirm (y) or cancel (n/Esc) the risky operation.
//
// Parameters:
//   - msg: Keyboard message
//
// Returns:
//   - Updated ReconView model
//   - Command from the prompt callback
func (r ReconView) handleDenyPromptKey(msg tea.KeyMsg) (ReconView, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		// User confirmed the risky operation
		callback := r.denyPrompt.Callback
		r.denyPrompt.Active = false
		if callback != nil {
			return r, callback(true)
		}
		return r, nil

	case "n", "N", "esc":
		// User declined the operation
		callback := r.denyPrompt.Callback
		r.denyPrompt.Active = false
		r.appendOutput(fmt.Sprintf("[CANCELLED] %s\n", r.denyPrompt.Operation))
		if callback != nil {
			return r, callback(false)
		}
		return r, nil
	}

	return r, nil
}

// handleInputKey processes keyboard input when the command input is focused.
// Handles command submission, escape, and text input.
//
// Parameters:
//   - msg: Keyboard message
//
// Returns:
//   - Updated ReconView model
//   - Command to execute (if any)
func (r ReconView) handleInputKey(msg tea.KeyMsg) (ReconView, tea.Cmd) {
	var cmd tea.Cmd

	switch msg.String() {
	case "enter":
		// Process the entered command
		command := strings.TrimSpace(r.input.Value())
		r.input.SetValue("")
		r.inputMode = false
		return r.processCommand(command)

	case "esc":
		// Cancel input mode
		r.input.SetValue("")
		r.inputMode = false
		return r, nil

	default:
		// Update the text input
		r.input, cmd = r.input.Update(msg)
		return r, cmd
	}
}

// handleNormalKey processes keyboard input in normal (navigation) mode.
// Supports Vim-style navigation and command palette activation.
//
// Parameters:
//   - msg: Keyboard message
//
// Returns:
//   - Updated ReconView model
//   - Command to execute (if any)
func (r ReconView) handleNormalKey(msg tea.KeyMsg) (ReconView, tea.Cmd) {
	switch msg.String() {
	// Vim-style scrolling
	case "j", "down":
		r.viewport.LineDown(1)
	case "k", "up":
		r.viewport.LineUp(1)
	case "d", "ctrl+d":
		r.viewport.HalfViewDown()
	case "u", "ctrl+u":
		r.viewport.HalfViewUp()
	case "g":
		r.viewport.GotoTop()
	case "G", "shift+g":
		r.viewport.GotoBottom()

	// Command mode activation
	case ":":
		r.inputMode = true
		r.input.Focus()
		return r, nil

	// Quick command: toggle manual mode
	case "m":
		return r.toggleMode()

	// Quick command: start/resume recon
	case "r":
		if !r.inProgress {
			return r.startNextPhase()
		}
	}

	return r, nil
}

// processCommand parses and executes a command entered in input mode.
// Supports commands like /manual, /auto, /reset, /help.
//
// Parameters:
//   - command: The command string to process
//
// Returns:
//   - Updated ReconView model
//   - Command to execute (if any)
func (r ReconView) processCommand(command string) (ReconView, tea.Cmd) {
	// Ignore empty commands
	if command == "" {
		return r, nil
	}

	// Split command and arguments
	parts := strings.Fields(command)
	cmd := parts[0]

	switch cmd {
	case "/manual":
		// Switch to manual mode
		r.mode = ModeManual
		r.appendOutput("[MODE] Switched to Manual mode. Each phase requires confirmation.\n")
		return r, nil

	case "/auto", "/semi-auto":
		// Switch to semi-auto mode
		r.mode = ModeSemiAuto
		r.appendOutput("[MODE] Switched to Semi-Auto mode. Risky operations require confirmation.\n")
		return r, nil

	case "/reset":
		// Reset the reconnaissance session
		r.results = make([]ReconResult, 0)
		r.currentPhase = PhaseSubdomain
		r.completed = false
		r.streamBuffer.Reset()
		r.viewport.SetContent("")
		r.appendOutput("[RESET] Reconnaissance session reset.\n")
		return r, nil

	case "/help":
		// Show help text
		r.showHelp()
		return r, nil

	case "/tools":
		// Show tool status
		r.showToolStatus()
		return r, nil

	default:
		r.appendOutput(fmt.Sprintf("[ERROR] Unknown command: %s\n", command))
		return r, nil
	}
}

// toggleMode switches between semi-auto and manual modes.
//
// Returns:
//   - Updated ReconView model
//   - nil command
func (r ReconView) toggleMode() (ReconView, tea.Cmd) {
	if r.mode == ModeSemiAuto {
		r.mode = ModeManual
		r.appendOutput("[MODE] Switched to Manual mode.\n")
	} else {
		r.mode = ModeSemiAuto
		r.appendOutput("[MODE] Switched to Semi-Auto mode.\n")
	}
	return r, nil
}

// startNextPhase begins the next phase of reconnaissance workflow.
// May trigger a deny prompt for risky operations or manual mode confirmations.
//
// Returns:
//   - Updated ReconView model
//   - Command to execute the phase (if approved)
func (r ReconView) startNextPhase() (ReconView, tea.Cmd) {
	// Check if already in progress
	if r.inProgress {
		return r, nil
	}

	// Check if workflow is complete
	if r.completed {
		r.appendOutput("[INFO] Reconnaissance workflow already complete. Use /reset to start over.\n")
		return r, nil
	}

	// Manual mode requires explicit confirmation for each phase
	if r.mode == ModeManual {
		return r.promptForPhase(r.currentPhase)
	}

	// Semi-auto mode: check if current phase is risky
	if r.isRiskyPhase(r.currentPhase) {
		return r.promptForRiskyPhase(r.currentPhase)
	}

	// Safe to proceed automatically
	return r.executePhase(r.currentPhase)
}

// isRiskyPhase determines if a phase requires a deny prompt in semi-auto mode.
// Risky phases are those that might be noisy or aggressive.
//
// Parameters:
//   - phase: The recon phase to check
//
// Returns:
//   - true if phase is considered risky
func (r ReconView) isRiskyPhase(phase ReconPhase) bool {
	switch phase {
	case PhasePort:
		// Port scanning can be noisy and may trigger IDS/IPS
		return true
	case PhaseOSINT:
		// OSINT can leave traces and may query third-party services
		return true
	default:
		return false
	}
}

// promptForPhase shows a manual mode confirmation for the given phase.
//
// Parameters:
//   - phase: The phase to prompt for
//
// Returns:
//   - Updated ReconView model with active deny prompt
//   - nil command (waiting for user response)
func (r ReconView) promptForPhase(phase ReconPhase) (ReconView, tea.Cmd) {
	r.denyPrompt = DenyPrompt{
		Active:    true,
		Operation: fmt.Sprintf("Start %s phase", r.phaseDisplayName(phase)),
		Reason:    "Manual mode enabled - explicit confirmation required",
		Redirect:  "Switch to semi-auto mode with /auto for automatic execution",
		Callback: func(confirmed bool) tea.Cmd {
			if confirmed {
				r.inProgress = true
				// In production, this would trigger actual tool execution
				return r.mockPhaseExecution(phase)
			}
			return nil
		},
	}
	return r, nil
}

// promptForRiskyPhase shows a Claude Code-style deny prompt for risky operations.
//
// Parameters:
//   - phase: The risky phase to prompt for
//
// Returns:
//   - Updated ReconView model with active deny prompt
//   - nil command (waiting for user response)
func (r ReconView) promptForRiskyPhase(phase ReconPhase) (ReconView, tea.Cmd) {
	var operation, reason, redirect string

	switch phase {
	case PhasePort:
		operation = "Aggressive port scanning"
		reason = "Full port scans can be noisy and may trigger IDS/IPS systems"
		redirect = "Consider using stealth scan (-sS) or limiting port range"

	case PhaseOSINT:
		operation = "OSINT collection"
		reason = "Querying third-party services may leave attribution trails"
		redirect = "Use VPN/proxy or limit sources to passive collections"
	}

	r.denyPrompt = DenyPrompt{
		Active:    true,
		Operation: operation,
		Reason:    reason,
		Redirect:  redirect,
		Callback: func(confirmed bool) tea.Cmd {
			if confirmed {
				r.inProgress = true
				return r.mockPhaseExecution(phase)
			}
			return nil
		},
	}
	return r, nil
}

// executePhase runs the given reconnaissance phase without prompting.
// Used when operation is approved or not risky.
//
// Parameters:
//   - phase: The phase to execute
//
// Returns:
//   - Updated ReconView model
//   - Command to execute the phase
func (r ReconView) executePhase(phase ReconPhase) (ReconView, tea.Cmd) {
	r.inProgress = true
	r.appendOutput(fmt.Sprintf("\n[STARTING] %s phase...\n", r.phaseDisplayName(phase)))
	return r, r.mockPhaseExecution(phase)
}

// mockPhaseExecution simulates a reconnaissance phase execution.
// In production, this would call actual recon tools and stream output.
//
// Parameters:
//   - phase: The phase to execute
//
// Returns:
//   - Command that simulates tool execution
func (r *ReconView) mockPhaseExecution(phase ReconPhase) tea.Cmd {
	// This is a mock implementation for demonstration
	// In production, this would:
	// 1. Execute actual tools (nmap, subfinder, etc.)
	// 2. Stream output in real-time to viewport
	// 3. Parse results and populate ReconResult
	// 4. Advance to next phase on completion

	return func() tea.Msg {
		// Simulate tool execution delay
		time.Sleep(2 * time.Second)

		// Create mock result
		result := ReconResult{
			Phase:     phase,
			Tool:      r.getToolForPhase(phase),
			Output:    r.generateMockOutput(phase),
			Findings:  r.generateMockFindings(phase),
			Duration:  2 * time.Second,
			Timestamp: time.Now(),
		}

		return phaseCompleteMsg{result: result}
	}
}

// phaseCompleteMsg is sent when a reconnaissance phase completes.
type phaseCompleteMsg struct {
	result ReconResult
}

// getToolForPhase returns the primary tool used for a given phase.
//
// Parameters:
//   - phase: The reconnaissance phase
//
// Returns:
//   - Tool name string
func (r ReconView) getToolForPhase(phase ReconPhase) string {
	switch phase {
	case PhaseSubdomain:
		return "subfinder"
	case PhaseDNS:
		return "dig"
	case PhaseWHOIS:
		return "whois"
	case PhasePort:
		return "nmap"
	case PhaseOSINT:
		return "theHarvester"
	default:
		return "unknown"
	}
}

// generateMockOutput creates realistic-looking tool output for demonstration.
//
// Parameters:
//   - phase: The reconnaissance phase
//
// Returns:
//   - Mock tool output string
func (r ReconView) generateMockOutput(phase ReconPhase) string {
	switch phase {
	case PhaseSubdomain:
		return `[subfinder] Enumerating subdomains for target.com
www.target.com
mail.target.com
ftp.target.com
admin.target.com
api.target.com
[subfinder] Found 5 subdomains`

	case PhaseDNS:
		return `[dig] Querying DNS records for target.com
target.com.  300  IN  A  192.168.1.100
target.com.  300  IN  MX  10 mail.target.com
target.com.  300  IN  NS  ns1.target.com`

	case PhaseWHOIS:
		return `[whois] Querying WHOIS for target.com
Domain Name: TARGET.COM
Registrar: Example Registrar
Creation Date: 2020-01-01
Expiration Date: 2025-01-01
Name Server: ns1.target.com
Name Server: ns2.target.com`

	case PhasePort:
		return `[nmap] Scanning ports on 192.168.1.100
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
3306/tcp open  mysql
[nmap] Scan complete: 4 ports open`

	case PhaseOSINT:
		return `[theHarvester] Gathering OSINT for target.com
[+] Emails found: 3
admin@target.com
info@target.com
support@target.com
[+] Subdomains found: 2
blog.target.com
dev.target.com`

	default:
		return "[unknown] No output"
	}
}

// generateMockFindings returns the number of findings for mock output.
//
// Parameters:
//   - phase: The reconnaissance phase
//
// Returns:
//   - Number of findings
func (r ReconView) generateMockFindings(phase ReconPhase) int {
	switch phase {
	case PhaseSubdomain:
		return 5
	case PhaseDNS:
		return 3
	case PhaseWHOIS:
		return 1
	case PhasePort:
		return 4
	case PhaseOSINT:
		return 5
	default:
		return 0
	}
}

// phaseDisplayName returns a human-readable name for a phase.
//
// Parameters:
//   - phase: The reconnaissance phase
//
// Returns:
//   - Display name string
func (r ReconView) phaseDisplayName(phase ReconPhase) string {
	switch phase {
	case PhaseSubdomain:
		return "Subdomain Enumeration"
	case PhaseDNS:
		return "DNS Lookup"
	case PhaseWHOIS:
		return "WHOIS Query"
	case PhasePort:
		return "Port Scanning"
	case PhaseOSINT:
		return "OSINT Collection"
	case PhaseComplete:
		return "Complete"
	default:
		return "Unknown"
	}
}

// appendOutput adds text to the output buffer and updates the viewport.
//
// Parameters:
//   - text: Text to append
func (r *ReconView) appendOutput(text string) {
	r.streamBuffer.WriteString(text)
	r.viewport.SetContent(r.streamBuffer.String())
	r.viewport.GotoBottom() // Auto-scroll to bottom
	r.lastUpdate = time.Now()
}

// showHelp displays help text in the viewport.
func (r *ReconView) showHelp() {
	helpText := `
=== RECON VIEW HELP ===

Navigation:
  j/Down      Scroll down
  k/Up        Scroll up
  Ctrl+d      Scroll half page down
  Ctrl+u      Scroll half page up
  g           Jump to top
  G           Jump to bottom

Commands:
  :           Enter command mode
  /manual     Switch to manual mode
  /auto       Switch to semi-auto mode
  /reset      Reset reconnaissance session
  /tools      Show tool availability
  /help       Show this help

Quick Actions:
  m           Toggle manual/semi-auto mode
  r           Start/resume reconnaissance

Modes:
  Semi-Auto   Automatic execution, prompts for risky operations (default)
  Manual      Explicit confirmation required for each phase
`
	r.appendOutput(helpText)
}

// showToolStatus displays the status of all reconnaissance tools.
func (r *ReconView) showToolStatus() {
	r.appendOutput("\n=== TOOL STATUS ===\n\n")

	for _, tool := range r.tools {
		status := "[X]"
		statusStyle := styles.CriticalStyle
		if tool.Installed {
			status = "[✓]"
			statusStyle = styles.LowStyle
		}

		required := ""
		if tool.Required {
			required = "(required)"
		}

		line := fmt.Sprintf("%s %-15s - %s %s\n",
			statusStyle.Render(status),
			tool.Name,
			tool.Description,
			styles.MutedStyle.Render(required))

		r.appendOutput(line)
	}

	// Show summary
	installed := 0
	for _, tool := range r.tools {
		if tool.Installed {
			installed++
		}
	}
	r.appendOutput(fmt.Sprintf("\nTotal: %d/%d tools available\n", installed, len(r.tools)))
}

// SetTarget sets the target domain/IP for reconnaissance.
//
// Parameters:
//   - target: Target domain or IP address
//
// Returns:
//   - Updated ReconView instance
//
// Security: Validates target format before accepting to prevent command injection
// and ensure only valid reconnaissance targets are processed.
func (r ReconView) SetTarget(target string) ReconView {
	// Sanitize input first to remove dangerous characters
	sanitizedTarget := validation.SanitizeInput(target)

	// Validate target format (IP, domain, CIDR, or URL)
	if err := validation.ValidateTarget(sanitizedTarget); err != nil {
		// Display validation error in output
		r.appendOutput(fmt.Sprintf("[ERROR] Invalid target: %s\n", err.Error()))
		r.appendOutput("[HINT] Valid formats: domain (example.com), IP (192.168.1.1), CIDR (10.0.0.0/24), URL (https://example.com)\n")
		return r
	}

	r.target = sanitizedTarget
	r.appendOutput(fmt.Sprintf("[TARGET] Set to: %s\n", sanitizedTarget))
	r.appendOutput(fmt.Sprintf("[MODE] Running in %s mode\n", r.getModeString()))
	r.appendOutput("\nPress [r] to start reconnaissance, or [:] for commands\n")
	return r
}

// SetSize manually sets the view dimensions.
//
// Parameters:
//   - w: Width in characters
//   - h: Height in lines
//
// Returns:
//   - Updated ReconView instance
func (r ReconView) SetSize(w, h int) ReconView {
	r.width = w
	r.height = h

	// Update component dimensions
	viewportHeight := h - 10
	if viewportHeight < 5 {
		viewportHeight = 5
	}
	r.viewport.Width = w - 4
	r.viewport.Height = viewportHeight
	r.input.Width = w - 4

	return r
}

// getModeString returns a string representation of the current mode.
//
// Returns:
//   - "Semi-Auto" or "Manual"
func (r ReconView) getModeString() string {
	if r.mode == ModeSemiAuto {
		return "Semi-Auto"
	}
	return "Manual"
}

// View renders the ReconView to a string.
// Part of the Bubble Tea Model interface.
//
// Returns:
//   - Rendered view as a string
func (r ReconView) View() string {
	// If deny prompt is active, render it over the normal view
	if r.denyPrompt.Active {
		return r.renderWithDenyPrompt()
	}

	// Render normal view
	var sections []string

	// === HEADER ===
	sections = append(sections, r.renderHeader())

	// === OUTPUT VIEWPORT ===
	sections = append(sections, r.viewport.View())

	// === INPUT (if active) ===
	if r.inputMode {
		inputBox := lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(styles.ColorInfo).
			Padding(0, 1).
			Width(r.width - 4).
			Render(r.input.View())
		sections = append(sections, inputBox)
	}

	// === STATUS BAR ===
	sections = append(sections, r.renderStatusBar())

	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

// renderHeader renders the top header with target and phase info.
//
// Returns:
//   - Rendered header string
func (r ReconView) renderHeader() string {
	title := styles.ActiveTabStyle.Render("RECONNAISSANCE")

	targetInfo := ""
	if r.target != "" {
		targetInfo = fmt.Sprintf("Target: %s", styles.InfoStyle.Render(r.target))
	} else {
		targetInfo = styles.MutedStyle.Render("No target set")
	}

	phaseInfo := fmt.Sprintf("Phase: %s", r.phaseDisplayName(r.currentPhase))
	if r.completed {
		phaseInfo = styles.LowStyle.Render("Phase: Complete")
	} else if r.inProgress {
		phaseInfo = styles.HighStyle.Render(fmt.Sprintf("Phase: %s (running...)", r.phaseDisplayName(r.currentPhase)))
	}

	modeInfo := fmt.Sprintf("Mode: %s", r.getModeString())

	headerContent := lipgloss.JoinHorizontal(lipgloss.Left,
		title,
		"  |  ",
		targetInfo,
		"  |  ",
		phaseInfo,
		"  |  ",
		modeInfo,
	)

	return styles.HeaderStyle.Width(r.width - 2).Render(headerContent)
}

// renderStatusBar renders the bottom status bar with keybindings.
//
// Returns:
//   - Rendered status bar string
func (r ReconView) renderStatusBar() string {
	hints := []string{
		styles.KeyStyle.Render("r") + styles.KeyHintStyle.Render("=start"),
		styles.KeyStyle.Render("m") + styles.KeyHintStyle.Render("=mode"),
		styles.KeyStyle.Render(":") + styles.KeyHintStyle.Render("=cmd"),
		styles.KeyStyle.Render("j/k") + styles.KeyHintStyle.Render("=scroll"),
		styles.KeyStyle.Render("?") + styles.KeyHintStyle.Render("=help"),
	}

	statusContent := strings.Join(hints, "  ")
	return styles.StatusBarStyle.Width(r.width - 2).Render(statusContent)
}

// renderWithDenyPrompt renders the view with a deny prompt overlay.
// Uses Claude Code-style visual treatment for safety prompts.
//
// Returns:
//   - Rendered view with deny prompt
func (r ReconView) renderWithDenyPrompt() string {
	// Create deny prompt box
	promptTitle := styles.HighStyle.Bold(true).Render("⚠ CONFIRMATION REQUIRED")

	operation := fmt.Sprintf("Operation: %s", styles.KeyStyle.Render(r.denyPrompt.Operation))
	reason := fmt.Sprintf("Reason: %s", r.denyPrompt.Reason)
	redirect := fmt.Sprintf("Alternative: %s", styles.InfoStyle.Render(r.denyPrompt.Redirect))

	question := "\nProceed with this operation?"
	options := styles.LowStyle.Render("[Y]") + " Yes  " +
		styles.CriticalStyle.Render("[N]") + " No  " +
		styles.MutedStyle.Render("[Esc]") + " Cancel"

	promptContent := lipgloss.JoinVertical(lipgloss.Left,
		promptTitle,
		"",
		operation,
		reason,
		redirect,
		question,
		options,
	)

	// Style the prompt box with prominent border
	promptBox := lipgloss.NewStyle().
		BorderStyle(lipgloss.DoubleBorder()).
		BorderForeground(styles.ColorHigh).
		Padding(1, 2).
		Width(r.width - 20).
		Align(lipgloss.Left).
		Render(promptContent)

	// Center the prompt box
	centered := lipgloss.Place(
		r.width,
		r.height,
		lipgloss.Center,
		lipgloss.Center,
		promptBox,
		lipgloss.WithWhitespaceChars(" "),
		lipgloss.WithWhitespaceForeground(styles.ColorDarkGray),
	)

	return centered
}
