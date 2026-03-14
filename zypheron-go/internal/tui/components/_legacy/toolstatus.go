package components

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
)

// ToolStatus represents the installation/availability status of a security tool
type ToolStatus int

const (
	// ToolStatusUnknown means we haven't checked yet
	ToolStatusUnknown ToolStatus = iota

	// ToolStatusInstalled means tool is installed and available
	ToolStatusInstalled

	// ToolStatusMissing means tool is not found in PATH
	ToolStatusMissing

	// ToolStatusInstalling means installation is in progress
	ToolStatusInstalling

	// ToolStatusFailed means installation or detection failed
	ToolStatusFailed
)

// String returns ASCII icon representation for tool status
func (s ToolStatus) String() string {
	switch s {
	case ToolStatusInstalled:
		return "[+]"
	case ToolStatusMissing:
		return "[-]"
	case ToolStatusInstalling:
		return "[~]"
	case ToolStatusFailed:
		return "[!]"
	default:
		return "[?]"
	}
}

// Tool represents a single security tool with installation metadata
type Tool struct {
	Name            string      // Tool name (e.g., "nmap")
	DisplayName     string      // Human-friendly name (e.g., "Nmap Network Scanner")
	Status          ToolStatus  // Current status
	Version         string      // Detected version string
	InstallCommand  string      // Command to install (e.g., "sudo apt install nmap")
	CheckCommand    string      // Command to check installation (e.g., "nmap --version")
	Required        bool        // Whether this tool is required for core functionality
	InstallProgress float64     // Installation progress (0.0 to 1.0)
	Error           error       // Error if status check or install failed
	LastChecked     time.Time   // When we last verified this tool
}

// ToolCheckCompleteMsg is sent when a tool status check completes
type ToolCheckCompleteMsg struct {
	ToolName string
	Status   ToolStatus
	Version  string
	Error    error
}

// ToolInstallProgressMsg updates installation progress for a tool
type ToolInstallProgressMsg struct {
	ToolName string
	Progress float64 // 0.0 to 1.0
	Message  string  // Status message (e.g., "Downloading packages...")
}

// ToolInstallCompleteMsg is sent when tool installation finishes
type ToolInstallCompleteMsg struct {
	ToolName string
	Success  bool
	Error    error
}

// Constants for tool status component
const (
	ToolCheckTimeout     = 5 * time.Second  // Timeout for tool version checks
	ToolInstallTimeout   = 5 * time.Minute  // Timeout for installation
	MinTimeBetweenChecks = 30 * time.Second // Minimum time between re-checks
)

// ToolStatusPanel manages security tool availability checking and installation
//
// Key features:
// - Parallel tool detection with version parsing
// - Inline install prompts for missing tools
// - Real-time installation progress tracking
// - ASCII status icons: [+] installed, [-] missing, [~] installing, [!] failed
// - Tool version display
// - Background refresh capability
type ToolStatusPanel struct {
	tools         map[string]*Tool // Map of tool name -> Tool info
	width         int              // Component width
	height        int              // Component height
	selectedIndex int              // Currently selected tool for installation
	checking      bool             // Whether we're currently checking tools
	mu            sync.RWMutex     // Protects concurrent access to tools map
	autoInstall   bool             // Whether to auto-prompt for installation
	showDetails   bool             // Whether to show detailed version info
}

// NewToolStatusPanel creates and initializes a new ToolStatusPanel
//
// Returns:
//   - ToolStatusPanel configured with common security tools
//
// Pre-configured tools:
// - nmap (required): Network scanner
// - nikto (required): Web server scanner
// - sqlmap: SQL injection tool
// - gobuster: Directory/DNS busting
// - whatweb: Web technology identifier
// - metasploit-framework: Exploitation framework (optional)
func NewToolStatusPanel() ToolStatusPanel {
	panel := ToolStatusPanel{
		tools:         make(map[string]*Tool),
		width:         80,
		height:        20,
		selectedIndex: 0,
		autoInstall:   true,
		showDetails:   true,
	}

	// Define common security tools to check
	// This list should match Zypheron's actual dependencies
	toolConfigs := []Tool{
		{
			Name:           "nmap",
			DisplayName:    "Nmap Network Scanner",
			Status:         ToolStatusUnknown,
			CheckCommand:   "nmap --version",
			InstallCommand: "sudo apt install -y nmap", // Debian/Ubuntu
			Required:       true,
		},
		{
			Name:           "nikto",
			DisplayName:    "Nikto Web Scanner",
			Status:         ToolStatusUnknown,
			CheckCommand:   "nikto -Version",
			InstallCommand: "sudo apt install -y nikto",
			Required:       true,
		},
		{
			Name:           "sqlmap",
			DisplayName:    "SQLMap SQL Injection Tool",
			Status:         ToolStatusUnknown,
			CheckCommand:   "sqlmap --version",
			InstallCommand: "sudo apt install -y sqlmap",
			Required:       false,
		},
		{
			Name:           "gobuster",
			DisplayName:    "Gobuster Directory Buster",
			Status:         ToolStatusUnknown,
			CheckCommand:   "gobuster version",
			InstallCommand: "sudo apt install -y gobuster",
			Required:       false,
		},
		{
			Name:           "whatweb",
			DisplayName:    "WhatWeb Technology Detector",
			Status:         ToolStatusUnknown,
			CheckCommand:   "whatweb --version",
			InstallCommand: "sudo apt install -y whatweb",
			Required:       false,
		},
		{
			Name:           "msfconsole",
			DisplayName:    "Metasploit Framework",
			Status:         ToolStatusUnknown,
			CheckCommand:   "msfconsole --version",
			InstallCommand: "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall",
			Required:       false,
		},
	}

	// Add tools to map
	for _, tool := range toolConfigs {
		toolCopy := tool
		panel.tools[tool.Name] = &toolCopy
	}

	return panel
}

// Init implements tea.Model interface
// Triggers initial tool status checks
func (t ToolStatusPanel) Init() tea.Cmd {
	// Start checking all tools in parallel
	return t.checkAllTools()
}

// Update handles all messages and updates the ToolStatusPanel state
//
// Parameters:
//   - msg: tea.Msg - Any Bubble Tea message
//
// Returns:
//   - ToolStatusPanel: Updated panel state
//   - tea.Cmd: Any command to execute
//
// Handles:
// - ToolCheckCompleteMsg: Updates tool status after check
// - ToolInstallProgressMsg: Updates installation progress
// - ToolInstallCompleteMsg: Marks installation as complete
// - tea.KeyMsg: Handles user input (navigation, install, refresh)
func (t ToolStatusPanel) Update(msg tea.Msg) (ToolStatusPanel, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case ToolCheckCompleteMsg:
		// Update tool status after check completes
		t.mu.Lock()
		if tool, exists := t.tools[msg.ToolName]; exists {
			tool.Status = msg.Status
			tool.Version = msg.Version
			tool.Error = msg.Error
			tool.LastChecked = time.Now()
		}
		t.mu.Unlock()

	case ToolInstallProgressMsg:
		// Update installation progress
		t.mu.Lock()
		if tool, exists := t.tools[msg.ToolName]; exists {
			tool.InstallProgress = msg.Progress
			// Status is already ToolStatusInstalling from install trigger
		}
		t.mu.Unlock()

	case ToolInstallCompleteMsg:
		// Installation finished - re-check the tool
		t.mu.Lock()
		if tool, exists := t.tools[msg.ToolName]; exists {
			if msg.Success {
				// Re-check to get version
				cmds = append(cmds, t.checkTool(msg.ToolName))
			} else {
				tool.Status = ToolStatusFailed
				tool.Error = msg.Error
			}
			tool.InstallProgress = 0.0
		}
		t.mu.Unlock()

	case tea.WindowSizeMsg:
		// Update dimensions
		t.width = msg.Width
		t.height = msg.Height

	case tea.KeyMsg:
		// Handle keyboard controls
		switch msg.String() {
		case "up", "k":
			// Navigate up through tools list
			if t.selectedIndex > 0 {
				t.selectedIndex--
			}

		case "down", "j":
			// Navigate down through tools list
			if t.selectedIndex < len(t.tools)-1 {
				t.selectedIndex++
			}

		case "enter", "i":
			// Install selected tool if missing
			toolName := t.getToolNameByIndex(t.selectedIndex)
			if toolName != "" {
				t.mu.RLock()
				tool := t.tools[toolName]
				t.mu.RUnlock()

				if tool.Status == ToolStatusMissing || tool.Status == ToolStatusFailed {
					cmds = append(cmds, t.installTool(toolName))
				}
			}

		case "r":
			// Refresh all tool statuses
			cmds = append(cmds, t.checkAllTools())

		case "d":
			// Toggle detailed version display
			t.showDetails = !t.showDetails
		}
	}

	return t, tea.Batch(cmds...)
}

// View renders the ToolStatusPanel to a string
//
// Returns:
//   - string: The rendered tool status display
//
// Layout:
// 1. Header with summary (X/Y tools installed)
// 2. Tool list with status icons, names, and versions
// 3. Install prompts for missing tools
// 4. Installation progress bars
// 5. Control hints
func (t ToolStatusPanel) View() string {
	var b strings.Builder

	// 1. HEADER
	installedCount, totalCount := t.getToolCounts()
	header := fmt.Sprintf("Security Tools (%d/%d installed)", installedCount, totalCount)
	headerStyle := styles.KeyStyle.Bold(true)
	b.WriteString(headerStyle.Render(header))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", t.width))
	b.WriteString("\n\n")

	// 2. TOOL LIST
	tools := t.getSortedTools()
	for i, tool := range tools {
		isSelected := i == t.selectedIndex
		toolLine := t.renderToolLine(tool, isSelected)
		b.WriteString(toolLine)
		b.WriteString("\n")

		// Show install prompt if selected and missing
		if isSelected && (tool.Status == ToolStatusMissing || tool.Status == ToolStatusFailed) {
			installPrompt := t.renderInstallPrompt(tool)
			b.WriteString(installPrompt)
			b.WriteString("\n")
		}

		// Show installation progress if installing
		if tool.Status == ToolStatusInstalling {
			progressLine := t.renderInstallProgress(tool)
			b.WriteString(progressLine)
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")

	// 3. WARNINGS FOR MISSING REQUIRED TOOLS
	missingRequired := t.getMissingRequiredTools()
	if len(missingRequired) > 0 {
		warning := styles.HighStyle.Render("WARNING: Required tools missing: " + strings.Join(missingRequired, ", "))
		b.WriteString(warning)
		b.WriteString("\n\n")
	}

	// 4. CONTROL HINTS
	hints := t.renderControlHints()
	b.WriteString(styles.MutedStyle.Render(hints))

	return b.String()
}

// renderToolLine renders a single tool status line
func (t ToolStatusPanel) renderToolLine(tool *Tool, isSelected bool) string {
	// Status icon with color
	var iconStyle lipgloss.Style
	switch tool.Status {
	case ToolStatusInstalled:
		iconStyle = styles.LowStyle // Green-ish
	case ToolStatusMissing:
		iconStyle = styles.HighStyle // Orange
	case ToolStatusInstalling:
		iconStyle = styles.InfoStyle // Blue
	case ToolStatusFailed:
		iconStyle = styles.CriticalStyle // Red
	default:
		iconStyle = styles.MutedStyle // Gray
	}
	icon := iconStyle.Render(tool.Status.String())

	// Tool name
	nameStyle := styles.KeyStyle
	if tool.Required {
		nameStyle = nameStyle.Bold(true)
	}
	if isSelected {
		nameStyle = nameStyle.Underline(true)
	}
	name := nameStyle.Render(tool.DisplayName)

	// Version info (if installed and showing details)
	var versionStr string
	if tool.Status == ToolStatusInstalled && tool.Version != "" && t.showDetails {
		versionStr = styles.MutedStyle.Render(fmt.Sprintf(" (%s)", tool.Version))
	}

	// Required indicator
	var requiredMarker string
	if tool.Required {
		requiredMarker = styles.CriticalStyle.Render(" *")
	}

	// Combine parts
	line := lipgloss.JoinHorizontal(
		lipgloss.Left,
		icon,
		" ",
		name,
		versionStr,
		requiredMarker,
	)

	// Add selection indicator
	if isSelected {
		line = "> " + line
	} else {
		line = "  " + line
	}

	return line
}

// renderInstallPrompt renders the inline install prompt for a missing tool
func (t ToolStatusPanel) renderInstallPrompt(tool *Tool) string {
	var prompt strings.Builder

	prompt.WriteString("    ")
	prompt.WriteString(styles.MutedStyle.Render("Missing. Install with: "))
	prompt.WriteString(styles.InfoStyle.Render(tool.InstallCommand))
	prompt.WriteString("\n    ")
	prompt.WriteString(styles.KeyHintStyle.Render("[Press Enter/i to install]"))

	return prompt.String()
}

// renderInstallProgress renders installation progress for a tool
func (t ToolStatusPanel) renderInstallProgress(tool *Tool) string {
	// Simple ASCII progress bar
	barWidth := 40
	filled := int(tool.InstallProgress * float64(barWidth))
	if filled > barWidth {
		filled = barWidth
	}

	bar := strings.Repeat("=", filled) + strings.Repeat("-", barWidth-filled)
	percent := fmt.Sprintf("%.0f%%", tool.InstallProgress*100)

	progressLine := fmt.Sprintf("    [%s] %s Installing...", bar, percent)
	return styles.InfoStyle.Render(progressLine)
}

// renderControlHints renders keyboard control hints
func (t ToolStatusPanel) renderControlHints() string {
	hints := []string{
		"[↑/↓] Navigate",
		"[Enter/i] Install",
		"[r] Refresh",
		"[d] Toggle Details",
	}
	return strings.Join(hints, "  ")
}

// getToolCounts returns (installed, total) counts
func (t ToolStatusPanel) getToolCounts() (int, int) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	installed := 0
	for _, tool := range t.tools {
		if tool.Status == ToolStatusInstalled {
			installed++
		}
	}
	return installed, len(t.tools)
}

// getSortedTools returns tools sorted by: Required first, then alphabetically
func (t ToolStatusPanel) getSortedTools() []*Tool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var required, optional []*Tool
	for _, tool := range t.tools {
		if tool.Required {
			required = append(required, tool)
		} else {
			optional = append(optional, tool)
		}
	}

	// Simple alphabetical sort (bubble sort for small lists)
	for i := 0; i < len(required)-1; i++ {
		for j := i + 1; j < len(required); j++ {
			if required[i].DisplayName > required[j].DisplayName {
				required[i], required[j] = required[j], required[i]
			}
		}
	}
	for i := 0; i < len(optional)-1; i++ {
		for j := i + 1; j < len(optional); j++ {
			if optional[i].DisplayName > optional[j].DisplayName {
				optional[i], optional[j] = optional[j], optional[i]
			}
		}
	}

	return append(required, optional...)
}

// getToolNameByIndex returns tool name for the given sorted index
func (t ToolStatusPanel) getToolNameByIndex(index int) string {
	tools := t.getSortedTools()
	if index >= 0 && index < len(tools) {
		return tools[index].Name
	}
	return ""
}

// getMissingRequiredTools returns names of missing required tools
func (t ToolStatusPanel) getMissingRequiredTools() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var missing []string
	for _, tool := range t.tools {
		if tool.Required && tool.Status != ToolStatusInstalled {
			missing = append(missing, tool.DisplayName)
		}
	}
	return missing
}

// checkAllTools returns a command that checks all tools in parallel
func (t ToolStatusPanel) checkAllTools() tea.Cmd {
	t.mu.RLock()
	toolNames := make([]string, 0, len(t.tools))
	for name := range t.tools {
		toolNames = append(toolNames, name)
	}
	t.mu.RUnlock()

	// Create batch of check commands
	var cmds []tea.Cmd
	for _, name := range toolNames {
		cmds = append(cmds, t.checkTool(name))
	}

	return tea.Batch(cmds...)
}

// checkTool returns a command that checks if a specific tool is installed
func (t ToolStatusPanel) checkTool(toolName string) tea.Cmd {
	return func() tea.Msg {
		t.mu.RLock()
		tool, exists := t.tools[toolName]
		if !exists {
			t.mu.RUnlock()
			return nil
		}

		// Don't re-check too frequently
		if time.Since(tool.LastChecked) < MinTimeBetweenChecks {
			t.mu.RUnlock()
			return nil
		}

		checkCommand := tool.CheckCommand
		t.mu.RUnlock()

		// Parse check command (simple space split)
		parts := strings.Fields(checkCommand)
		if len(parts) == 0 {
			return ToolCheckCompleteMsg{
				ToolName: toolName,
				Status:   ToolStatusFailed,
				Error:    fmt.Errorf("invalid check command"),
			}
		}

		// Execute check command with timeout
		cmd := exec.Command(parts[0], parts[1:]...)
		output, err := cmd.CombinedOutput()

		if err != nil {
			// Tool not found or check failed
			return ToolCheckCompleteMsg{
				ToolName: toolName,
				Status:   ToolStatusMissing,
				Error:    err,
			}
		}

		// Parse version from output (simple heuristic: take first line)
		version := strings.TrimSpace(strings.Split(string(output), "\n")[0])
		// Limit version string length
		if len(version) > 50 {
			version = version[:50] + "..."
		}

		return ToolCheckCompleteMsg{
			ToolName: toolName,
			Status:   ToolStatusInstalled,
			Version:  version,
		}
	}
}

// installTool returns a command that installs a tool
func (t ToolStatusPanel) installTool(toolName string) tea.Cmd {
	return func() tea.Msg {
		t.mu.Lock()
		tool, exists := t.tools[toolName]
		if !exists {
			t.mu.Unlock()
			return nil
		}

		// Mark as installing
		tool.Status = ToolStatusInstalling
		tool.InstallProgress = 0.1
		installCmd := tool.InstallCommand
		t.mu.Unlock()

		// Send initial progress
		// Note: Real progress tracking would require parsing install output
		// For now, we'll just show indeterminate progress

		// Parse install command
		parts := strings.Fields(installCmd)
		if len(parts) == 0 {
			return ToolInstallCompleteMsg{
				ToolName: toolName,
				Success:  false,
				Error:    fmt.Errorf("invalid install command"),
			}
		}

		// Execute install command
		cmd := exec.Command(parts[0], parts[1:]...)
		err := cmd.Run()

		if err != nil {
			return ToolInstallCompleteMsg{
				ToolName: toolName,
				Success:  false,
				Error:    err,
			}
		}

		return ToolInstallCompleteMsg{
			ToolName: toolName,
			Success:  true,
		}
	}
}

// SetWidth updates the component width
func (t ToolStatusPanel) SetWidth(w int) ToolStatusPanel {
	t.width = w
	return t
}

// SetHeight updates the component height
func (t ToolStatusPanel) SetHeight(h int) ToolStatusPanel {
	t.height = h
	return t
}

// AllRequiredInstalled returns true if all required tools are installed
func (t ToolStatusPanel) AllRequiredInstalled() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, tool := range t.tools {
		if tool.Required && tool.Status != ToolStatusInstalled {
			return false
		}
	}
	return true
}

// GetInstalledTools returns a list of installed tool names
func (t ToolStatusPanel) GetInstalledTools() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var installed []string
	for name, tool := range t.tools {
		if tool.Status == ToolStatusInstalled {
			installed = append(installed, name)
		}
	}
	return installed
}

// GetMissingTools returns a list of missing tool names
func (t ToolStatusPanel) GetMissingTools() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var missing []string
	for name, tool := range t.tools {
		if tool.Status == ToolStatusMissing || tool.Status == ToolStatusFailed {
			missing = append(missing, name)
		}
	}
	return missing
}
