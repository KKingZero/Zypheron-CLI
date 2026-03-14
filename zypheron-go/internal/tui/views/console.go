package views

import (
	"fmt"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
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
	// ASCII logo (smaller, fits better)
	logo := styles.LogoStyle.Render(`
    ███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗ ███╗   ██╗
    ╚══███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔═══██╗████╗  ██║
      ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝██║   ██║██╔██╗ ██║
     ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║██║╚██╗██║
    ███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚████║
    ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝`)

	tagline := styles.MutedStyle.Render("    AI-Powered Penetration Testing Platform")

	// Quick start section with AI-first focus
	quickStart := lipgloss.JoinVertical(lipgloss.Left,
		"",
		styles.AIStyle.Render("  ┌─ Quick Start ─────────────────────────────────────────┐"),
		"  │                                                        │",
		fmt.Sprintf("  │  %s  %s     │",
			styles.KeyStyle.Render("ai <question>"),
			styles.MutedStyle.Render("Ask the AI assistant anything")),
		fmt.Sprintf("  │  %s  %s       │",
			styles.KeyStyle.Render("autopent <target>"),
			styles.MutedStyle.Render("Autonomous pentest")),
		fmt.Sprintf("  │  %s  %s    │",
			styles.KeyStyle.Render("dork <query>"),
			styles.MutedStyle.Render("AI-enhanced search dorking")),
		fmt.Sprintf("  │  %s  %s          │",
			styles.KeyStyle.Render("/scan <target>"),
			styles.MutedStyle.Render("Start a security scan")),
		"  │                                                        │",
		fmt.Sprintf("  │  %s  %s           │",
			styles.KeyStyle.Render("?"),
			styles.MutedStyle.Render("Show all commands and help")),
		styles.AIStyle.Render("  └────────────────────────────────────────────────────────┘"),
	)

	// Helpful tips
	tips := styles.MutedStyle.Render("\n  💡 Just type naturally - the AI understands security tasks!\n     Try: \"scan example.com for vulnerabilities\"")

	content := lipgloss.JoinVertical(lipgloss.Center,
		logo,
		tagline,
		quickStart,
		tips,
	)

	return lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Align(lipgloss.Center, lipgloss.Center).
		Render(content)
}

// AppendLog adds a line to the console
func (m *ConsoleModel) AppendLog(text string) {
	m.lines = append(m.lines, text)
	m.viewport.SetContent(strings.Join(m.lines, "\n"))
	m.viewport.GotoBottom()
}
