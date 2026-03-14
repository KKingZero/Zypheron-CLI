package views

import (
	"fmt"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type ModelSelector struct {
	availableModels []string
	selectedIdx     int
	isOpen          bool
	width           int
}

func NewModelSelector(width int) ModelSelector {
	return ModelSelector{
		availableModels: []string{
			"claude-opus-4-6",
			"claude-sonnet-4-6",
			"gpt-5.4",
			"gemini-3.1-pro-preview",
			"gemini-3-flash-preview",
			"deepseek-r1",
			"kimi-k2",
			"ollama-qwen3-coder",
			"ollama-llama3.2:3b",
		},
		selectedIdx: 0, // Default to Claude Opus
		isOpen:      false,
		width:       width,
	}
}

func (m ModelSelector) Init() tea.Cmd {
	return nil
}

func (m ModelSelector) Update(msg tea.Msg) (ModelSelector, tea.Cmd) {
	// Only handle inputs if open/focused? Or global key?
	// The prompt implies we can "arrow down to it".
	// Implementation: In parent model, if Down arrow pressed from Input, verify focus logic.

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if !m.isOpen {
			return m, nil
		}

		switch msg.String() {
		case "down", "j":
			if m.selectedIdx < len(m.availableModels)-1 {
				m.selectedIdx++
			}
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
		case "enter":
			m.isOpen = false // Selection confirmed
		case "esc":
			m.isOpen = false
		}
	}

	return m, nil
}

func (m ModelSelector) View() string {
	if !m.isOpen {
		// Minimized view (Just Show Selected)
		// Minimized view (Just Show Selected)
		// "Model: [ Claude 4.5 Sonnet ▼ ]"
		return styles.MutedStyle.Render(fmt.Sprintf("Model: [%s ▼] (Tab to change)", m.availableModels[m.selectedIdx]))
	}

	// Expanded Dropdown View
	var list strings.Builder

	for i, md := range m.availableModels {
		cursor := " "
		style := styles.MutedStyle

		if i == m.selectedIdx {
			cursor = "➜"
			style = styles.PromptStyle // Accent color
		}

		list.WriteString(fmt.Sprintf("%s %s\n", cursor, style.Render(md)))
	}

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(styles.ColorAccent).
		Padding(0, 1).
		Render(list.String())
}

// Helper methods for parent
func (m *ModelSelector) Toggle() {
	m.isOpen = !m.isOpen
}

func (m *ModelSelector) SetIndex(i int) {
	m.selectedIdx = i
}

func (m ModelSelector) SelectedIndex() int {
	return m.selectedIdx
}

func (m ModelSelector) SelectedModel() string {
	if len(m.availableModels) == 0 {
		return ""
	}
	return m.availableModels[m.selectedIdx]
}

func (m *ModelSelector) Open() {
	m.isOpen = true
}

func (m *ModelSelector) Close() {
	m.isOpen = false
}

func (m ModelSelector) IsOpen() bool {
	return m.isOpen
}

// SelectedProvider returns the provider name for the AI engine (e.g., "gemini" not "gemini-3-flash")
func (m ModelSelector) SelectedProvider() string {
	model := m.SelectedModel()
	return ModelToProvider(model)
}

// ModelToProvider maps display model names to AI engine provider names
func ModelToProvider(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return ""
	}

	if strings.HasPrefix(model, "ollama-") {
		return "ollama"
	}
	if strings.HasPrefix(model, "claude-") {
		return "claude"
	}
	if strings.HasPrefix(model, "gpt-") {
		return "openai"
	}
	if strings.HasPrefix(model, "gemini-") {
		return "gemini"
	}
	if strings.HasPrefix(model, "kimi-") {
		return "kimi"
	}
	if strings.HasPrefix(model, "deepseek-") {
		return "deepseek"
	}

	// Fallback: use model name as provider (for custom models)
	return model
}

func ModelRequiresAPIKey(model string) bool {
	return ModelToCredentialProvider(model) != ""
}

func ModelToCredentialProvider(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return ""
	}

	switch {
	case strings.HasPrefix(model, "ollama-"):
		return ""
	case strings.HasPrefix(model, "claude-"):
		return "anthropic"
	case strings.HasPrefix(model, "gpt-"):
		return "openai"
	case strings.HasPrefix(model, "gemini-"):
		return "google"
	case strings.HasPrefix(model, "kimi-"):
		return "kimi"
	case strings.HasPrefix(model, "deepseek-"):
		return "deepseek"
	case strings.HasPrefix(model, "grok-"):
		return "grok"
	default:
		return ""
	}
}

func CredentialProviderEnvVar(provider string) string {
	switch strings.TrimSpace(strings.ToLower(provider)) {
	case "anthropic":
		return "ANTHROPIC_API_KEY"
	case "openai":
		return "OPENAI_API_KEY"
	case "google":
		return "GOOGLE_API_KEY"
	case "kimi":
		return "KIMI_API_KEY"
	case "deepseek":
		return "DEEPSEEK_API_KEY"
	case "grok":
		return "GROK_API_KEY"
	default:
		return ""
	}
}

func CredentialProviderLabel(provider string) string {
	switch strings.TrimSpace(strings.ToLower(provider)) {
	case "anthropic":
		return "Claude"
	case "openai":
		return "OpenAI"
	case "google":
		return "Gemini"
	case "kimi":
		return "Kimi"
	case "deepseek":
		return "DeepSeek"
	case "grok":
		return "Grok"
	default:
		return strings.TrimSpace(provider)
	}
}

func FindModelIndex(models []string, target string) int {
	target = strings.TrimSpace(target)
	for i, model := range models {
		if model == target {
			return i
		}
	}
	return -1
}

// ModelToEngineModel maps display model names to engine model overrides.
// For cloud providers we keep empty to use server defaults. For Ollama we pass the exact model.
func ModelToEngineModel(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return ""
	}
	if strings.HasPrefix(model, "ollama-") {
		return strings.TrimPrefix(model, "ollama-")
	}
	return ""
}
