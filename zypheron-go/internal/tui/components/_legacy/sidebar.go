package components

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
)

// SidebarItem represents a navigation item in the sidebar
type SidebarItem struct {
	ID       string // Unique identifier (e.g., "scan", "recon")
	Label    string // Display label
	Shortcut string // Keyboard shortcut (e.g., "S")
	Icon     string // ASCII icon
}

// Sidebar implements a VSCode-style vertical navigation sidebar
// Features:
// - Collapsible (icons only vs icons + labels)
// - Keyboard navigation with vim bindings
// - Active item highlighting
// - Subtle hover/focus effects
// - Pure ASCII icons
type Sidebar struct {
	items        []SidebarItem
	activeIndex  int
	activeID     string
	focused      bool
	collapsed    bool
	width        int
	height       int
	expandedWidth int
	collapsedWidth int
}

// Default sidebar items for Zypheron TUI
var DefaultSidebarItems = []SidebarItem{
	{ID: "dashboard", Label: "Dashboard", Shortcut: "D", Icon: "[=]"},
	{ID: "scan", Label: "Scan", Shortcut: "S", Icon: "[>]"},
	{ID: "recon", Label: "Recon", Shortcut: "R", Icon: "[~]"},
	{ID: "results", Label: "Results", Shortcut: "V", Icon: "[!]"},
	{ID: "history", Label: "History", Shortcut: "H", Icon: "[#]"},
	{ID: "tools", Label: "Tools", Shortcut: "T", Icon: "[*]"},
}

// NewSidebar creates a new sidebar with default configuration
func NewSidebar() Sidebar {
	return Sidebar{
		items:         DefaultSidebarItems,
		activeIndex:   0,
		activeID:      "dashboard",
		focused:       false,
		collapsed:     false,
		width:         20,
		height:        24,
		expandedWidth: 20,
		collapsedWidth: 6,
	}
}

// Init initializes the sidebar (satisfies tea.Model-like interface)
func (s Sidebar) Init() tea.Cmd {
	return nil
}

// Update handles messages for the sidebar
func (s Sidebar) Update(msg tea.Msg) (Sidebar, tea.Cmd) {
	if !s.focused {
		return s, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "j", "down":
			s.activeIndex++
			if s.activeIndex >= len(s.items) {
				s.activeIndex = len(s.items) - 1
			}
			s.activeID = s.items[s.activeIndex].ID
		case "k", "up":
			s.activeIndex--
			if s.activeIndex < 0 {
				s.activeIndex = 0
			}
			s.activeID = s.items[s.activeIndex].ID
		case "enter", "l", "right":
			// Return command to switch view
			return s, func() tea.Msg {
				return SidebarSelectMsg{ID: s.activeID}
			}
		case "tab":
			// Toggle collapsed state
			s.collapsed = !s.collapsed
			if s.collapsed {
				s.width = s.collapsedWidth
			} else {
				s.width = s.expandedWidth
			}
		}
	}
	return s, nil
}

// SidebarSelectMsg is sent when a sidebar item is selected
type SidebarSelectMsg struct {
	ID string
}

// View renders the sidebar
func (s Sidebar) View() string {
	var sb strings.Builder

	// Sidebar styles
	borderStyle := lipgloss.NewStyle().
		BorderStyle(styles.DoubleBorder).
		BorderForeground(styles.ColorGray).
		BorderRight(true).
		Width(s.width - 1).
		Height(s.height)

	itemStyle := lipgloss.NewStyle().
		Padding(0, 1).
		Width(s.width - 3)

	activeItemStyle := lipgloss.NewStyle().
		Padding(0, 1).
		Width(s.width - 3).
		Background(styles.ColorDarkGray).
		Foreground(styles.ColorWhite).
		Bold(true)

	focusedActiveStyle := lipgloss.NewStyle().
		Padding(0, 1).
		Width(s.width - 3).
		Background(lipgloss.Color("#333333")).
		Foreground(styles.ColorWhite).
		Bold(true)

	shortcutStyle := lipgloss.NewStyle().
		Foreground(styles.ColorGray)

	// Header
	if !s.collapsed {
		header := lipgloss.NewStyle().
			Bold(true).
			Foreground(styles.ColorWhite).
			Padding(0, 1).
			Width(s.width - 3).
			Render("ZYPHERON")
		sb.WriteString(header)
		sb.WriteString("\n")
		sb.WriteString(strings.Repeat("─", s.width-3))
		sb.WriteString("\n")
	} else {
		sb.WriteString("\n\n")
	}

	// Render each item
	for i, item := range s.items {
		var line string
		if s.collapsed {
			// Collapsed: icon only
			line = item.Icon
		} else {
			// Expanded: icon + label + shortcut
			line = item.Icon + " " + item.Label
			// Right-align shortcut
			padding := s.width - 5 - len(item.Icon) - len(item.Label) - len(item.Shortcut)
			if padding > 0 {
				line += strings.Repeat(" ", padding)
			}
			line += shortcutStyle.Render(item.Shortcut)
		}

		// Apply appropriate style
		var styledLine string
		if i == s.activeIndex {
			if s.focused {
				styledLine = focusedActiveStyle.Render(line)
			} else {
				styledLine = activeItemStyle.Render(line)
			}
		} else {
			styledLine = itemStyle.Render(line)
		}
		sb.WriteString(styledLine)
		sb.WriteString("\n")
	}

	// Fill remaining height
	usedLines := 2 + len(s.items) // header + separator + items
	remaining := s.height - usedLines - 2 // -2 for border
	if remaining > 0 {
		sb.WriteString(strings.Repeat("\n", remaining))
	}

	// Bottom hint
	if !s.collapsed {
		hint := lipgloss.NewStyle().
			Foreground(styles.ColorGray).
			Italic(true).
			Padding(0, 1).
			Width(s.width - 3).
			Render("Tab: toggle")
		sb.WriteString(hint)
	}

	return borderStyle.Render(sb.String())
}

// SetActive sets the active sidebar item by ID
func (s Sidebar) SetActive(id string) Sidebar {
	for i, item := range s.items {
		if item.ID == id {
			s.activeIndex = i
			s.activeID = id
			break
		}
	}
	return s
}

// SetHeight sets the sidebar height
func (s Sidebar) SetHeight(height int) Sidebar {
	s.height = height
	return s
}

// SetWidth sets the sidebar width
func (s Sidebar) SetWidth(width int) Sidebar {
	s.width = width
	s.expandedWidth = width
	return s
}

// GetWidth returns the current sidebar width
func (s Sidebar) GetWidth() int {
	return s.width
}

// Focus sets the sidebar to focused state
func (s Sidebar) Focus() Sidebar {
	s.focused = true
	return s
}

// Blur removes focus from the sidebar
func (s Sidebar) Blur() Sidebar {
	s.focused = false
	return s
}

// IsFocused returns whether the sidebar is focused
func (s Sidebar) IsFocused() bool {
	return s.focused
}

// IsCollapsed returns whether the sidebar is collapsed
func (s Sidebar) IsCollapsed() bool {
	return s.collapsed
}

// Toggle toggles the collapsed state
func (s Sidebar) Toggle() Sidebar {
	s.collapsed = !s.collapsed
	if s.collapsed {
		s.width = s.collapsedWidth
	} else {
		s.width = s.expandedWidth
	}
	return s
}

// GetActiveID returns the currently active item ID
func (s Sidebar) GetActiveID() string {
	return s.activeID
}
