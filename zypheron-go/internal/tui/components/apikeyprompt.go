package components

import (
	"fmt"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type APIKeySubmittedMsg struct {
	Provider string
	APIKey   string
}

type APIKeyCancelledMsg struct{}

type APIKeyPromptModel struct {
	input         textinput.Model
	provider      string
	providerLabel string
	modelName     string
	width         int
	height        int
	errorMsg      string
}

func NewAPIKeyPrompt(provider, providerLabel, modelName string, width, height int) APIKeyPromptModel {
	ti := textinput.New()
	ti.Placeholder = fmt.Sprintf("Enter %s API key", providerLabel)
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = promptMax(width-10, 36)
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'
	ti.PromptStyle = lipgloss.NewStyle().Foreground(styles.ColorAccent)
	ti.TextStyle = lipgloss.NewStyle()

	return APIKeyPromptModel{
		input:         ti,
		provider:      provider,
		providerLabel: providerLabel,
		modelName:     modelName,
		width:         width,
		height:        height,
	}
}

func (m APIKeyPromptModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m APIKeyPromptModel) Update(msg tea.Msg) (APIKeyPromptModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEnter:
			key := strings.TrimSpace(m.input.Value())
			if key == "" {
				m.errorMsg = "API key cannot be empty"
				return m, nil
			}
			return m, func() tea.Msg {
				return APIKeySubmittedMsg{Provider: m.provider, APIKey: key}
			}
		case tea.KeyEsc:
			return m, func() tea.Msg { return APIKeyCancelledMsg{} }
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.input.Width = promptMax(msg.Width-10, 36)
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m APIKeyPromptModel) View() string {
	var body strings.Builder

	body.WriteString(lipgloss.NewStyle().Bold(true).Render(fmt.Sprintf("%s API Key Required", m.providerLabel)))
	body.WriteString("\n\n")
	body.WriteString(fmt.Sprintf("Selected model: %s\n", lipgloss.NewStyle().Bold(true).Render(m.modelName)))
	body.WriteString(styles.MutedStyle.Render("This provider is not configured yet. Enter a key to continue."))
	body.WriteString("\n\n")
	body.WriteString(m.input.View())

	if m.errorMsg != "" {
		body.WriteString("\n\n")
		body.WriteString(styles.ErrorStyle.Render(m.errorMsg))
	}

	body.WriteString("\n\n")
	body.WriteString(styles.MutedStyle.Render("Press Enter to save securely, Esc to cancel"))

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(styles.ColorAccent).
		Padding(1, 2).
		Width(promptMax(m.width-4, 48)).
		Render(body.String())
}

func promptMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}
