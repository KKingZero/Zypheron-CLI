package views

import (
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type ConsoleModel struct {
	viewport viewport.Model
	lines    []string // Use slice instead of strings.Builder to avoid copy issues
	width    int
	height   int
}

func NewConsole(width, height int) ConsoleModel {
	vp := viewport.New(width, height)
	vp.Style = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, false). // No border for cleaner look
		Padding(0, 1)

	return ConsoleModel{
		viewport: vp,
		lines:    make([]string, 0),
		width:    width,
		height:   height,
	}
}

func (m ConsoleModel) Init() tea.Cmd {
	return nil
}

func (m ConsoleModel) Update(msg tea.Msg) (ConsoleModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height // Will be calculated by parent
		m.viewport.Width = m.width
		m.viewport.Height = m.height

	case string: // Should define proper types for log messages
		m.lines = append(m.lines, msg)
		m.viewport.SetContent(strings.Join(m.lines, "\n"))
		m.viewport.GotoBottom()
	}

	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

func (m ConsoleModel) View() string {
	if len(m.lines) == 0 {
		return m.renderWelcome()
	}
	return m.viewport.View()
}

// renderWelcome shows AI-first quick start content when console is empty
func (m ConsoleModel) renderWelcome() string {
	logo := renderWelcomeLogo()
	logoWidth := lipgloss.Width(logo)

	metaLine := lipgloss.NewStyle().
		Foreground(styles.ColorMuted).
		Width(logoWidth).
		Align(lipgloss.Center).
		Render(ui.BannerVersionLine(ui.StartupBannerVersion, ui.StartupBannerByline))

	divider := lipgloss.NewStyle().
		Foreground(styles.ColorBorder).
		Width(logoWidth).
		Align(lipgloss.Center).
		Render(ui.BannerDivider(72))

	tagline := lipgloss.NewStyle().
		Foreground(styles.ColorAqua).
		Bold(true).
		Width(logoWidth).
		Align(lipgloss.Center).
		Render(ui.BannerTagline())

	quickStart := renderQuickStartCard(m.width)

	idea := styles.WarningStyle.Render("TIP")
	tips := lipgloss.JoinVertical(
		lipgloss.Left,
		lipgloss.JoinHorizontal(
			lipgloss.Left,
			idea,
			styles.MutedStyle.Render("  Just type naturally - the AI understands security tasks."),
		),
		styles.SubtleStyle.Render(`     Try: "scan example.com for vulnerabilities"`),
	)

	content := lipgloss.JoinVertical(lipgloss.Center,
		logo,
		divider,
		metaLine,
		"",
		tagline,
		"",
		quickStart,
		"",
		tips,
	)

	return lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Align(lipgloss.Center, lipgloss.Center).
		Render(content)
}

func renderWelcomeLogo() string {
	lines := ui.BannerLines()
	brandStyle := lipgloss.NewStyle().Foreground(styles.ColorAccent).Bold(true)

	for i, line := range lines {
		lines[i] = brandStyle.Render(line)
	}

	return strings.Join(lines, "\n")
}

func renderQuickStartCard(width int) string {
	type quickStartItem struct {
		command     string
		description string
	}

	items := []quickStartItem{
		{command: "ai <question>", description: "Ask the AI assistant anything"},
		{command: "autopent <target>", description: "Autonomous pentest"},
		{command: "dork <query>", description: "AI-enhanced search dorking"},
		{command: "/scan <target>", description: "Start a security scan"},
		{command: "?", description: "Show all commands and help"},
	}

	maxWidth := 82
	if width > 0 && width-12 < maxWidth {
		maxWidth = width - 12
	}
	if maxWidth < 42 {
		maxWidth = 42
	}

	labelStyle := lipgloss.NewStyle().
		Foreground(styles.ColorAccent).
		Bold(true)
	bodyStyle := lipgloss.NewStyle().
		Foreground(styles.ColorSlateBlue)

	commandWidth := 0
	for _, item := range items {
		if w := lipgloss.Width(item.command); w > commandWidth {
			commandWidth = w
		}
	}

	var rows []string
	compact := maxWidth < 58
	for _, item := range items {
		if compact {
			rows = append(rows,
				labelStyle.Render(item.command),
				"  "+bodyStyle.Render(item.description),
			)
			continue
		}

		padding := commandWidth - lipgloss.Width(item.command)
		row := labelStyle.Render(item.command) +
			strings.Repeat(" ", padding+2) +
			bodyStyle.Render(item.description)
		rows = append(rows, row)
	}

	sectionLabel := lipgloss.NewStyle().
		Foreground(styles.ColorWhite).
		Bold(true).
		Render("Quick Start")

	helper := lipgloss.NewStyle().
		Foreground(styles.ColorMuted).
		Render("Type a command or ask naturally")

	cardBody := lipgloss.JoinVertical(
		lipgloss.Left,
		lipgloss.JoinHorizontal(lipgloss.Left, sectionLabel, "  ", helper),
		"",
		lipgloss.JoinVertical(lipgloss.Left, rows...),
	)
	card := lipgloss.NewStyle().
		Width(maxWidth).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(styles.ColorBorder).
		Padding(1, 2).
		Render(cardBody)

	return card
}

// AppendLog adds a line to the console
func (m *ConsoleModel) AppendLog(text string) {
	m.lines = append(m.lines, text)
	m.viewport.SetContent(strings.Join(m.lines, "\n"))
	m.viewport.GotoBottom()
}
