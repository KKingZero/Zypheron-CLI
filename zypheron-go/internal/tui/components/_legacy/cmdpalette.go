package components

import (
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
)

// Command represents a command in the palette
type Command struct {
	ID          string   // Unique identifier
	Name        string   // Display name
	Description string   // Brief description
	Category    string   // Category for grouping (e.g., "Scan", "Navigation")
	Shortcut    string   // Keyboard shortcut hint
	Keywords    []string // Additional search keywords
}

// CommandPalette implements a VSCode-style fuzzy command search
// Features:
// - Fuzzy text matching
// - Category grouping
// - Keyboard navigation
// - Real-time filtering
// - Shortcut hints
type CommandPalette struct {
	input         textinput.Model
	commands      []Command
	filtered      []Command
	selectedIndex int
	visible       bool
	width         int
	height        int
	maxVisible    int
}

// CommandExecuteMsg is sent when a command is selected
type CommandExecuteMsg struct {
	ID string
}

// CommandPaletteCloseMsg is sent when the palette is closed
type CommandPaletteCloseMsg struct{}

// Default commands for Zypheron
var DefaultCommands = []Command{
	// Navigation
	{ID: "nav.dashboard", Name: "Go to Dashboard", Description: "View system overview", Category: "Navigation", Shortcut: "D", Keywords: []string{"home", "main"}},
	{ID: "nav.scan", Name: "Go to Scan", Description: "Start or monitor scans", Category: "Navigation", Shortcut: "S", Keywords: []string{"target", "attack"}},
	{ID: "nav.recon", Name: "Go to Recon", Description: "Reconnaissance tools", Category: "Navigation", Shortcut: "R", Keywords: []string{"discovery", "enum"}},
	{ID: "nav.results", Name: "Go to Results", Description: "View scan results", Category: "Navigation", Shortcut: "V", Keywords: []string{"findings", "vulns"}},
	{ID: "nav.history", Name: "Go to History", Description: "Browse past scans", Category: "Navigation", Shortcut: "H", Keywords: []string{"previous", "old"}},
	{ID: "nav.tools", Name: "Go to Tools", Description: "Utility tools", Category: "Navigation", Shortcut: "T", Keywords: []string{"utils", "helpers"}},

	// Scan commands
	{ID: "scan.new", Name: "New Scan", Description: "Start a new scan", Category: "Scan", Keywords: []string{"start", "begin", "target"}},
	{ID: "scan.quick", Name: "Quick Scan", Description: "Fast port scan", Category: "Scan", Keywords: []string{"fast", "nmap"}},
	{ID: "scan.full", Name: "Full Scan", Description: "Comprehensive scan", Category: "Scan", Keywords: []string{"complete", "thorough"}},
	{ID: "scan.web", Name: "Web Scan", Description: "Web application scan", Category: "Scan", Keywords: []string{"http", "webapp", "owasp"}},
	{ID: "scan.stop", Name: "Stop Scan", Description: "Stop running scan", Category: "Scan", Keywords: []string{"cancel", "abort"}},

	// Recon commands
	{ID: "recon.subdomain", Name: "Subdomain Enum", Description: "Enumerate subdomains", Category: "Recon", Keywords: []string{"dns", "domain"}},
	{ID: "recon.dns", Name: "DNS Lookup", Description: "Query DNS records", Category: "Recon", Keywords: []string{"records", "mx", "a"}},
	{ID: "recon.whois", Name: "WHOIS Lookup", Description: "Query WHOIS data", Category: "Recon", Keywords: []string{"registrar", "owner"}},
	{ID: "recon.ports", Name: "Port Discovery", Description: "Discover open ports", Category: "Recon", Keywords: []string{"services", "tcp", "udp"}},

	// Export commands
	{ID: "export.json", Name: "Export JSON", Description: "Export results as JSON", Category: "Export", Keywords: []string{"save", "download"}},
	{ID: "export.html", Name: "Export HTML", Description: "Export results as HTML", Category: "Export", Keywords: []string{"report", "web"}},
	{ID: "export.pdf", Name: "Export PDF", Description: "Export results as PDF", Category: "Export", Keywords: []string{"report", "document"}},

	// Settings
	{ID: "settings.config", Name: "Configuration", Description: "Edit settings", Category: "Settings", Keywords: []string{"options", "preferences"}},
	{ID: "settings.tools", Name: "Manage Tools", Description: "Install/update tools", Category: "Settings", Keywords: []string{"install", "deps"}},
	{ID: "settings.ai", Name: "AI Settings", Description: "Configure AI behavior", Category: "Settings", Keywords: []string{"llm", "assistant"}},

	// Help
	{ID: "help.keybindings", Name: "Keyboard Shortcuts", Description: "Show all shortcuts", Category: "Help", Shortcut: "?", Keywords: []string{"keys", "bindings"}},
	{ID: "help.docs", Name: "Documentation", Description: "Open docs", Category: "Help", Keywords: []string{"manual", "guide"}},
	{ID: "help.about", Name: "About Zypheron", Description: "Version info", Category: "Help", Keywords: []string{"version", "info"}},
}

// NewCommandPalette creates a new command palette
func NewCommandPalette() CommandPalette {
	ti := textinput.New()
	ti.Placeholder = "Type to search commands..."
	ti.CharLimit = 50
	ti.Width = 60
	ti.Prompt = "> "
	ti.PromptStyle = lipgloss.NewStyle().Foreground(styles.ColorWhite).Bold(true)
	ti.TextStyle = lipgloss.NewStyle().Foreground(styles.ColorWhite)
	ti.PlaceholderStyle = lipgloss.NewStyle().Foreground(styles.ColorGray)

	cp := CommandPalette{
		input:         ti,
		commands:      DefaultCommands,
		filtered:      DefaultCommands,
		selectedIndex: 0,
		visible:       false,
		width:         70,
		height:        20,
		maxVisible:    10,
	}
	return cp
}

// Init initializes the command palette
func (cp CommandPalette) Init() tea.Cmd {
	return nil
}

// Update handles messages for the command palette
func (cp CommandPalette) Update(msg tea.Msg) (CommandPalette, tea.Cmd) {
	if !cp.visible {
		return cp, nil
	}

	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			cp.visible = false
			cp.input.SetValue("")
			cp.filtered = cp.commands
			cp.selectedIndex = 0
			return cp, func() tea.Msg { return CommandPaletteCloseMsg{} }

		case "enter":
			if len(cp.filtered) > 0 && cp.selectedIndex < len(cp.filtered) {
				selected := cp.filtered[cp.selectedIndex]
				cp.visible = false
				cp.input.SetValue("")
				cp.filtered = cp.commands
				cp.selectedIndex = 0
				return cp, func() tea.Msg { return CommandExecuteMsg{ID: selected.ID} }
			}

		case "up", "ctrl+k":
			cp.selectedIndex--
			if cp.selectedIndex < 0 {
				cp.selectedIndex = 0
			}
			return cp, nil

		case "down", "ctrl+j":
			cp.selectedIndex++
			if cp.selectedIndex >= len(cp.filtered) {
				cp.selectedIndex = len(cp.filtered) - 1
			}
			if cp.selectedIndex < 0 {
				cp.selectedIndex = 0
			}
			return cp, nil

		case "ctrl+n":
			// Next item (vim style)
			cp.selectedIndex++
			if cp.selectedIndex >= len(cp.filtered) {
				cp.selectedIndex = len(cp.filtered) - 1
			}
			return cp, nil

		case "ctrl+p":
			// Previous item (vim style) - but only when palette is already open
			cp.selectedIndex--
			if cp.selectedIndex < 0 {
				cp.selectedIndex = 0
			}
			return cp, nil
		}
	}

	// Update text input
	cp.input, cmd = cp.input.Update(msg)

	// Filter commands based on input
	query := cp.input.Value()
	cp.filtered = cp.fuzzyFilter(query)

	// Reset selection if it's out of bounds
	if cp.selectedIndex >= len(cp.filtered) {
		cp.selectedIndex = 0
	}

	return cp, cmd
}

// fuzzyFilter filters commands based on fuzzy matching
func (cp CommandPalette) fuzzyFilter(query string) []Command {
	if query == "" {
		return cp.commands
	}

	query = strings.ToLower(query)
	type scored struct {
		cmd   Command
		score int
	}

	var matches []scored

	for _, cmd := range cp.commands {
		score := 0
		name := strings.ToLower(cmd.Name)
		desc := strings.ToLower(cmd.Description)
		cat := strings.ToLower(cmd.Category)

		// Exact prefix match (highest score)
		if strings.HasPrefix(name, query) {
			score += 100
		}

		// Contains match
		if strings.Contains(name, query) {
			score += 50
		}
		if strings.Contains(desc, query) {
			score += 30
		}
		if strings.Contains(cat, query) {
			score += 20
		}

		// Keyword match
		for _, kw := range cmd.Keywords {
			if strings.Contains(strings.ToLower(kw), query) {
				score += 25
			}
		}

		// Fuzzy character match
		if cp.fuzzyMatch(name, query) {
			score += 10
		}

		if score > 0 {
			matches = append(matches, scored{cmd, score})
		}
	}

	// Sort by score descending
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].score > matches[j].score
	})

	result := make([]Command, len(matches))
	for i, m := range matches {
		result[i] = m.cmd
	}

	return result
}

// fuzzyMatch checks if all characters in pattern appear in str in order
func (cp CommandPalette) fuzzyMatch(str, pattern string) bool {
	pi := 0
	for i := 0; i < len(str) && pi < len(pattern); i++ {
		if str[i] == pattern[pi] {
			pi++
		}
	}
	return pi == len(pattern)
}

// View renders the command palette
func (cp CommandPalette) View() string {
	if !cp.visible {
		return ""
	}

	// Container style
	containerStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(styles.ColorGray).
		Padding(0, 1).
		Width(cp.width)

	// Header
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(styles.ColorWhite).
		Width(cp.width - 4).
		Align(lipgloss.Center)

	// Build content
	var sb strings.Builder

	// Title
	sb.WriteString(headerStyle.Render("Command Palette"))
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", cp.width-4))
	sb.WriteString("\n\n")

	// Input field
	sb.WriteString(cp.input.View())
	sb.WriteString("\n\n")

	// Results
	if len(cp.filtered) == 0 {
		noResults := lipgloss.NewStyle().
			Foreground(styles.ColorGray).
			Italic(true).
			Render("No matching commands")
		sb.WriteString(noResults)
	} else {
		// Calculate visible range
		start := 0
		end := len(cp.filtered)
		if end > cp.maxVisible {
			// Scroll to keep selection visible
			if cp.selectedIndex >= cp.maxVisible {
				start = cp.selectedIndex - cp.maxVisible + 1
			}
			end = start + cp.maxVisible
			if end > len(cp.filtered) {
				end = len(cp.filtered)
				start = end - cp.maxVisible
				if start < 0 {
					start = 0
				}
			}
		}

		// Category grouping
		currentCategory := ""
		for i := start; i < end; i++ {
			cmd := cp.filtered[i]

			// Category header
			if cmd.Category != currentCategory {
				currentCategory = cmd.Category
				catStyle := lipgloss.NewStyle().
					Foreground(styles.ColorGray).
					Bold(true)
				sb.WriteString(catStyle.Render(currentCategory))
				sb.WriteString("\n")
			}

			// Command item
			prefix := "  "
			if i == cp.selectedIndex {
				prefix = "> "
			}

			nameStyle := lipgloss.NewStyle().Foreground(styles.ColorWhite)
			descStyle := lipgloss.NewStyle().Foreground(styles.ColorGray)
			shortcutStyle := lipgloss.NewStyle().Foreground(styles.ColorLightGray).Bold(true)

			if i == cp.selectedIndex {
				nameStyle = nameStyle.Background(styles.ColorDarkGray).Bold(true)
				descStyle = descStyle.Background(styles.ColorDarkGray)
			}

			line := prefix + nameStyle.Render(cmd.Name)
			if cmd.Description != "" {
				line += " " + descStyle.Render("- "+cmd.Description)
			}
			if cmd.Shortcut != "" {
				// Right align shortcut
				remaining := cp.width - 6 - len(cmd.Name) - len(cmd.Description) - 3
				if remaining > 0 {
					line += strings.Repeat(" ", remaining)
				}
				line += shortcutStyle.Render("[" + cmd.Shortcut + "]")
			}

			sb.WriteString(line)
			sb.WriteString("\n")
		}

		// Scroll indicator
		if len(cp.filtered) > cp.maxVisible {
			indicator := lipgloss.NewStyle().
				Foreground(styles.ColorGray).
				Italic(true).
				Render("   ... and more (scroll with j/k)")
			sb.WriteString("\n")
			sb.WriteString(indicator)
		}
	}

	// Footer hints
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", cp.width-4))
	hintStyle := lipgloss.NewStyle().Foreground(styles.ColorGray)
	sb.WriteString("\n")
	sb.WriteString(hintStyle.Render("Enter: select  |  Esc: close  |  j/k: navigate"))

	return containerStyle.Render(sb.String())
}

// Show opens the command palette
func (cp CommandPalette) Show() CommandPalette {
	cp.visible = true
	cp.input.Focus()
	cp.input.SetValue("")
	cp.filtered = cp.commands
	cp.selectedIndex = 0
	return cp
}

// Hide closes the command palette
func (cp CommandPalette) Hide() CommandPalette {
	cp.visible = false
	cp.input.Blur()
	cp.input.SetValue("")
	cp.filtered = cp.commands
	cp.selectedIndex = 0
	return cp
}

// IsVisible returns whether the palette is visible
func (cp CommandPalette) IsVisible() bool {
	return cp.visible
}

// SetWidth sets the palette width
func (cp CommandPalette) SetWidth(width int) CommandPalette {
	cp.width = width
	cp.input.Width = width - 10
	return cp
}

// SetHeight sets the palette height
func (cp CommandPalette) SetHeight(height int) CommandPalette {
	cp.height = height
	cp.maxVisible = height - 8
	if cp.maxVisible < 5 {
		cp.maxVisible = 5
	}
	return cp
}

// AddCommand adds a custom command to the palette
func (cp CommandPalette) AddCommand(cmd Command) CommandPalette {
	cp.commands = append(cp.commands, cmd)
	cp.filtered = cp.commands
	return cp
}

// SetCommands replaces all commands in the palette
func (cp CommandPalette) SetCommands(commands []Command) CommandPalette {
	cp.commands = commands
	cp.filtered = commands
	cp.selectedIndex = 0
	return cp
}
