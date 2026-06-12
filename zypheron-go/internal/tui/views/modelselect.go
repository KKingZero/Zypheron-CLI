package views

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	ClaudeModelLabel  = "Claude"
	GeminiModelLabel  = "Gemini"
	ChatGPTModelLabel = "ChatGPT"
	KimiModelLabel    = "Kimi"
	LocalAIModelLabel = "local ai"
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
			ClaudeModelLabel,
			GeminiModelLabel,
			ChatGPTModelLabel,
			KimiModelLabel,
			LocalAIModelLabel,
		},
		selectedIdx: 0,
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

func (m ModelSelector) Height() int {
	return lipgloss.Height(m.View())
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

	if strings.EqualFold(model, ClaudeModelLabel) {
		return "claude"
	}
	if strings.EqualFold(model, GeminiModelLabel) {
		return "gemini"
	}
	if strings.EqualFold(model, ChatGPTModelLabel) {
		return "openai"
	}
	if strings.EqualFold(model, KimiModelLabel) {
		return "kimi"
	}
	if strings.HasPrefix(model, "ollama-") {
		return "ollama"
	}
	if strings.EqualFold(model, LocalAIModelLabel) {
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
	case strings.EqualFold(model, LocalAIModelLabel):
		return ""
	case strings.HasPrefix(model, "ollama-"):
		return ""
	case strings.EqualFold(model, ClaudeModelLabel), strings.HasPrefix(model, "claude-"):
		return "anthropic"
	case strings.EqualFold(model, ChatGPTModelLabel), strings.HasPrefix(model, "gpt-"):
		return "openai"
	case strings.EqualFold(model, GeminiModelLabel), strings.HasPrefix(model, "gemini-"):
		return "google"
	case strings.EqualFold(model, KimiModelLabel), strings.HasPrefix(model, "kimi-"):
		return "kimi"
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
		return "ChatGPT"
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
	if strings.EqualFold(model, LocalAIModelLabel) {
		return ResolveLargestOllamaModel()
	}
	return ""
}

func ResolveLargestOllamaModel() string {
	baseURL := strings.TrimSpace(os.Getenv("OLLAMA_URL"))
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}

	client := http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Get(strings.TrimRight(baseURL, "/") + "/api/tags")
	if err != nil {
		return fallbackOllamaModel()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fallbackOllamaModel()
	}

	var payload struct {
		Models []struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fallbackOllamaModel()
	}

	var selectedName string
	var selectedSize int64
	for _, model := range payload.Models {
		name := strings.TrimSpace(model.Name)
		if name == "" {
			continue
		}
		if model.Size > selectedSize || selectedName == "" {
			selectedName = name
			selectedSize = model.Size
		}
	}
	if selectedName == "" {
		return fallbackOllamaModel()
	}

	return selectedName
}

func fallbackOllamaModel() string {
	if model := strings.TrimSpace(os.Getenv("OLLAMA_MODEL")); model != "" {
		return model
	}
	return "codellama"
}
