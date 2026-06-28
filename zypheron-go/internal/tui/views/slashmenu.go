package views

import (
	"fmt"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// SlashMenuItem represents a menu item
type SlashMenuItem struct {
	Command     string
	Description string
	Usage       string
	Icon        string
	Category    string
	NeedsArgs   bool
}

// SlashMenu displays available slash commands
type SlashMenu struct {
	items    []SlashMenuItem
	filtered []SlashMenuItem
	selected int
	isOpen   bool
	filter   string
	width    int
}

// SlashMenuItems defines all available slash commands
var SlashMenuItems = []SlashMenuItem{
	// Scanning
	{Command: "/scan", Description: "Start a security scan", Usage: "/scan <target> [--tool <tool>]", Icon: "", Category: "Scanning", NeedsArgs: true},
	{Command: "/recon", Description: "Set recon target/status context", Usage: "/recon <domain>", Icon: "", Category: "Scanning", NeedsArgs: true},
	{Command: "/autopent", Description: "Autonomous pentest", Usage: "/autopent <target>", Icon: "", Category: "Scanning", NeedsArgs: true},

	// AI
	{Command: "/ai", Description: "Direct AI query", Usage: "/ai <question>", Icon: "", Category: "AI", NeedsArgs: true},
	{Command: "/auth", Description: "Manage authenticated testing session", Usage: "/auth use <session-id> | /auth status | /auth clear | /auth test <url>", Icon: "", Category: "AI", NeedsArgs: true},
	{Command: "/auth use", Description: "Set authenticated runtime session", Usage: "/auth use <session-id>", Icon: "", Category: "AI", NeedsArgs: true},
	{Command: "/auth status", Description: "Show active auth session", Usage: "/auth status", Icon: "", Category: "AI"},
	{Command: "/auth clear", Description: "Clear active auth session", Usage: "/auth clear", Icon: "", Category: "AI"},
	{Command: "/auth test", Description: "Run authenticated runtime checks", Usage: "/auth test <url> [idor|sqli|authz] [key=value ...]", Icon: "", Category: "AI", NeedsArgs: true},
	{Command: "/agent", Description: "Create custom AI agent", Usage: "/agent <description>", Icon: "", Category: "AI", NeedsArgs: true},
	{Command: "/agents", Description: "List/manage saved agents", Usage: "/agents", Icon: "", Category: "AI"},
	{Command: "/agents use", Description: "Run a saved agent", Usage: "/agents use <agent-id> <target>", Icon: "", Category: "AI", NeedsArgs: true},
	{Command: "/agents edit", Description: "Edit a saved agent", Usage: "/agents edit <agent-id>", Icon: "", Category: "AI", NeedsArgs: true},
	{Command: "/agents delete", Description: "Delete a saved agent", Usage: "/agents delete <agent-id>", Icon: "", Category: "AI", NeedsArgs: true},
	{Command: "/dork", Description: "AI-enhanced dorking", Usage: "/dork <query>", Icon: "", Category: "AI", NeedsArgs: true},

	// Settings & Config
	{Command: "/apis", Description: "Configure API keys", Usage: "/apis", Icon: "", Category: "Settings"},
	{Command: "/settings", Description: "General settings", Usage: "/settings", Icon: "", Category: "Settings"},
	{Command: "/providers", Description: "AI provider settings", Usage: "/providers", Icon: "", Category: "Settings"},

	// Account
	{Command: "/account", Description: "Account management", Usage: "/account", Icon: "", Category: "Account"},
	{Command: "/plan", Description: "View subscription plan", Usage: "/plan", Icon: "", Category: "Account"},
	{Command: "/upgrade", Description: "Upgrade account", Usage: "/upgrade", Icon: "", Category: "Account"},
	{Command: "/usage", Description: "View token usage", Usage: "/usage", Icon: "", Category: "Account"},

	// Tools
	{Command: "/tools", Description: "Available security tools", Usage: "/tools", Icon: "", Category: "Tools"},
	{Command: "/history", Description: "Scan history", Usage: "/history", Icon: "", Category: "Tools"},
	{Command: "/export", Description: "Export results", Usage: "/export <format> [filename]", Icon: "", Category: "Tools", NeedsArgs: true},

	// Context & Session
	{Command: "/context", Description: "View pentest context", Usage: "/context", Icon: "", Category: "Context"},
	{Command: "/context full", Description: "Full context details", Usage: "/context full", Icon: "", Category: "Context"},
	{Command: "/reset", Description: "Reset for new engagement", Usage: "/reset", Icon: "", Category: "Context"},

	// System
	{Command: "/doctor", Description: "System health check", Usage: "/doctor", Icon: "", Category: "System"},
	{Command: "/help", Description: "Show help", Usage: "/help", Icon: "?", Category: "System"},
	{Command: "/clear", Description: "Clear console", Usage: "/clear", Icon: "", Category: "System"},
	{Command: "/quit", Description: "Exit Zypheron", Usage: "/quit", Icon: "", Category: "System"},
}

func SlashMenuItemByCommand(command string) (SlashMenuItem, bool) {
	for _, item := range SlashMenuItems {
		if item.Command == command {
			return item, true
		}
	}
	return SlashMenuItem{}, false
}

func NewSlashMenu(width int) SlashMenu {
	return SlashMenu{
		items:    SlashMenuItems,
		filtered: SlashMenuItems,
		selected: 0,
		isOpen:   false,
		filter:   "",
		width:    width,
	}
}

func (m SlashMenu) Init() tea.Cmd {
	return nil
}

func (m SlashMenu) Update(msg tea.Msg) (SlashMenu, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if !m.isOpen {
			return m, nil
		}

		switch msg.Type {
		case tea.KeyUp:
			if m.selected > 0 {
				m.selected--
			}
		case tea.KeyDown:
			if m.selected < len(m.filtered)-1 {
				m.selected++
			}
		case tea.KeyEsc:
			m.isOpen = false
			m.filter = ""
			m.filtered = m.items
			m.selected = 0
		case tea.KeyEnter:
			// Selection handled by parent
		case tea.KeyBackspace:
			if len(m.filter) > 1 {
				m.filter = m.filter[:len(m.filter)-1]
				m.applyFilter()
			} else if len(m.filter) == 1 {
				m.isOpen = false
				m.filter = ""
				m.filtered = m.items
			}
		default:
			if msg.Type == tea.KeyRunes {
				m.filter += string(msg.Runes)
				m.applyFilter()
			}
		}
	}
	return m, nil
}

func (m *SlashMenu) applyFilter() {
	if m.filter == "/" || m.filter == "" {
		m.filtered = m.items
		m.selected = 0
		return
	}

	query := strings.ToLower(m.filter)
	var filtered []SlashMenuItem

	for _, item := range m.items {
		if strings.Contains(strings.ToLower(item.Command), query) ||
			strings.Contains(strings.ToLower(item.Description), query) {
			filtered = append(filtered, item)
		}
	}

	m.filtered = filtered
	if m.selected >= len(m.filtered) {
		m.selected = 0
	}
}

func (m SlashMenu) View() string {
	if !m.isOpen || len(m.filtered) == 0 {
		return ""
	}

	// Build menu items (show max 8)
	maxItems := 8
	if len(m.filtered) < maxItems {
		maxItems = len(m.filtered)
	}

	// Calculate start index for scrolling
	startIdx := 0
	if m.selected >= maxItems {
		startIdx = m.selected - maxItems + 1
	}

	var lines []string
	currentCategory := ""

	for i := startIdx; i < startIdx+maxItems && i < len(m.filtered); i++ {
		item := m.filtered[i]

		// Category header (only show if different from previous)
		if item.Category != currentCategory {
			currentCategory = item.Category
			categoryLine := styles.MutedStyle.Render("  " + currentCategory)
			lines = append(lines, categoryLine)
		}

		// Item
		icon := item.Icon
		if icon == "" {
			icon = " "
		}

		cmd := item.Command
		desc := item.Description

		var line string
		if i == m.selected {
			// Selected item
			line = lipgloss.NewStyle().
				Background(styles.ColorAccent).
				Foreground(styles.ColorBg).
				Bold(true).
				Padding(0, 1).
				Render(icon + " " + cmd + "  " + desc)
		} else {
			// Normal item
			cmdStyled := styles.KeyStyle.Render(cmd)
			descStyled := styles.MutedStyle.Render(desc)
			line = "  " + icon + " " + cmdStyled + "  " + descStyled
		}

		lines = append(lines, line)
	}

	// Add scroll indicator if needed
	if len(m.filtered) > maxItems {
		indicator := styles.MutedStyle.Render(fmt.Sprintf("  ... %d more", len(m.filtered)-maxItems))
		lines = append(lines, indicator)
	}

	content := strings.Join(lines, "\n")

	// Menu container
	menuStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(styles.ColorBorder).
		Padding(0, 1).
		Width(50)

	return menuStyle.Render(content)
}

// Open opens the menu with initial filter
func (m *SlashMenu) Open(filter string) {
	m.isOpen = true
	m.filter = filter
	m.selected = 0
	m.applyFilter()
}

// Close closes the menu
func (m *SlashMenu) Close() {
	m.isOpen = false
	m.filter = ""
	m.filtered = m.items
	m.selected = 0
}

// IsOpen returns whether menu is open
func (m SlashMenu) IsOpen() bool {
	return m.isOpen
}

// SelectedCommand returns the currently selected command
func (m SlashMenu) SelectedCommand() string {
	if m.selected < len(m.filtered) {
		return m.filtered[m.selected].Command
	}
	return ""
}

// SetFilter updates the filter
func (m *SlashMenu) SetFilter(filter string) {
	m.filter = filter
	m.applyFilter()
}

// Filter returns current filter
func (m SlashMenu) Filter() string {
	return m.filter
}
