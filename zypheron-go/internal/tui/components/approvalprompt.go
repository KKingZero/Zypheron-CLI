package components

import (
	"fmt"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type ApprovalPromptModel struct {
	ToolName     string
	Reason       string
	RiskCategory string
	RequestID    string
	TaskID       string
	width        int
	height       int
	selected     int
}

type ApprovalSubmittedMsg struct {
	TaskID    string
	RequestID string
	Decision  string
}

type ApprovalCancelledMsg struct{}

func NewApprovalPrompt(toolName, reason, riskCategory, requestID, taskID string, width, height int) ApprovalPromptModel {
	return ApprovalPromptModel{
		ToolName:     strings.TrimSpace(toolName),
		Reason:       strings.TrimSpace(reason),
		RiskCategory: strings.TrimSpace(riskCategory),
		RequestID:    strings.TrimSpace(requestID),
		TaskID:       strings.TrimSpace(taskID),
		width:        width,
		height:       height,
		selected:     0,
	}
}

func (m ApprovalPromptModel) Init() tea.Cmd {
	return nil
}

func (m ApprovalPromptModel) Update(msg tea.Msg) (ApprovalPromptModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "left", "h":
			if m.selected > 0 {
				m.selected--
			}
			return m, nil
		case "right", "l":
			if m.selected < 2 {
				m.selected++
			}
			return m, nil
		case "1", "a", "A":
			return m, func() tea.Msg {
				return ApprovalSubmittedMsg{TaskID: m.TaskID, RequestID: m.RequestID, Decision: "approve_once"}
			}
		case "2", "s", "S":
			return m, func() tea.Msg {
				return ApprovalSubmittedMsg{TaskID: m.TaskID, RequestID: m.RequestID, Decision: "approve_session"}
			}
		case "3", "d", "D":
			return m, func() tea.Msg {
				return ApprovalSubmittedMsg{TaskID: m.TaskID, RequestID: m.RequestID, Decision: "deny"}
			}
		case "enter":
			decisions := []string{"approve_once", "approve_session", "deny"}
			return m, func() tea.Msg {
				return ApprovalSubmittedMsg{TaskID: m.TaskID, RequestID: m.RequestID, Decision: decisions[m.selected]}
			}
		case "esc":
			return m, func() tea.Msg { return ApprovalCancelledMsg{} }
		}
	}
	return m, nil
}

func (m ApprovalPromptModel) View() string {
	title := styles.HighStyle.Bold(true).Render("CONFIRMATION REQUIRED")
	operation := fmt.Sprintf("Tool: %s", styles.KeyStyle.Render(m.ToolName))
	risk := fmt.Sprintf("Risk: %s", renderRisk(m.RiskCategory))
	reason := fmt.Sprintf("Reason: %s", m.Reason)

	options := []struct {
		label string
		hint  string
	}{
		{"[1] Approve once", "Run this action only once"},
		{"[2] Allow for session", "Auto-approve this tool for this session"},
		{"[3] Deny", "Do not run the action"},
	}

	renderedOptions := make([]string, 0, len(options))
	for i, option := range options {
		style := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(styles.ColorBorder).
			Padding(0, 1)
		if m.selected == i {
			style = style.BorderForeground(styles.ColorAccent).Bold(true)
		}
		renderedOptions = append(renderedOptions, style.Render(option.label+"\n"+styles.MutedStyle.Render(option.hint)))
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		title,
		"",
		operation,
		risk,
		reason,
		"",
		lipgloss.JoinHorizontal(lipgloss.Top, renderedOptions...),
		"",
		styles.MutedStyle.Render("Use Left/Right or 1/2/3. Enter confirms. Esc cancels."),
	)

	box := lipgloss.NewStyle().
		BorderStyle(lipgloss.DoubleBorder()).
		BorderForeground(styles.ColorWarning).
		Padding(1, 2).
		Width(maxPromptWidth(m.width-12, 72)).
		Render(content)

	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		box,
		lipgloss.WithWhitespaceChars(" "),
		lipgloss.WithWhitespaceForeground(styles.ColorDarkGray),
	)
}

func renderRisk(risk string) string {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "critical":
		return styles.CriticalStyle.Render(strings.ToUpper(risk))
	case "high":
		return styles.HighStyle.Render(strings.ToUpper(risk))
	case "medium":
		return styles.WarningStyle.Render(strings.ToUpper(risk))
	default:
		return styles.LowStyle.Render(strings.ToUpper(risk))
	}
}

func maxPromptWidth(a, b int) int {
	if a < b {
		return a
	}
	return b
}
