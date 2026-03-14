package components

import (
	"fmt"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	"github.com/charmbracelet/lipgloss"
)

type Header struct {
	ActiveTab string
	Width     int
}

func NewHeader() Header {
	return Header{
		ActiveTab: "scan",
	}
}

func (h Header) Update(activeTab string) Header {
	h.ActiveTab = activeTab
	return h
}

func (h Header) View() string {
	// Tab order: Recon -> Scan -> AI -> Tools -> History (matches pentest methodology)
	tabs := []struct {
		key   string
		label string
		id    string
	}{
		{"R", "Recon", "recon"},
		{"S", "Scan", "scan"},
		{"A", "AI", "ai"},
		{"T", "Tools", "tools"},
		{"H", "History", "history"},
	}

	var renderedTabs []string

	for _, tab := range tabs {
		isActive := strings.ToLower(h.ActiveTab) == tab.id ||
			(len(h.ActiveTab) > 0 && strings.ToLower(string(h.ActiveTab[0])) == strings.ToLower(tab.key))

		// Style active vs inactive tabs with new cyan accent
		var rendered string
		if isActive {
			// Active tab: cyan background with white text
			rendered = styles.ActiveTabStyle.Render(fmt.Sprintf("[%s]%s", tab.key, tab.label[1:]))
		} else {
			// Inactive tab: muted with cyan key
			keyPart := styles.KeyStyle.Render("[" + tab.key + "]")
			labelPart := styles.InactiveTabStyle.Render(tab.label[1:])
			rendered = keyPart + labelPart
		}

		renderedTabs = append(renderedTabs, rendered)
	}

	leftSide := strings.Join(renderedTabs, " ")

	// Breadcrumb with cyan accent
	breadcrumb := styles.Accent("Zypheron") + styles.MutedStyle.Render(" > "+strings.Title(h.ActiveTab))

	return lipgloss.JoinHorizontal(lipgloss.Center,
		leftSide,
		"   ",
		breadcrumb,
	)
}
