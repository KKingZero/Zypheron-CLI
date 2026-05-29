package components

import (
	"math/rand"
	"strings"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type SplashModel struct {
	width  int
	height int
	frame  int
}

func NewSplash() SplashModel {
	return SplashModel{}
}

// SplashCompleteMsg signals splash screen is done
type SplashCompleteMsg struct{}
type splashFrameMsg struct{}

var splashFrameIntensities = []float64{0.18, 0.10, 0.05, 0.02}

func (m SplashModel) Init() tea.Cmd {
	return tea.Tick(80*time.Millisecond, func(t time.Time) tea.Msg {
		return splashFrameMsg{}
	})
}

func (m SplashModel) Update(msg tea.Msg) (SplashModel, tea.Cmd) {
	switch msg.(type) {
	case splashFrameMsg:
		if m.frame < len(splashFrameIntensities)-1 {
			m.frame++
			return m, tea.Tick(80*time.Millisecond, func(t time.Time) tea.Msg {
				return splashFrameMsg{}
			})
		}
		return m, tea.Tick(900*time.Millisecond, func(t time.Time) tea.Msg {
			return SplashCompleteMsg{}
		})
	}

	return m, nil
}

func (m SplashModel) View() string {
	var lines []string
	if m.frame < len(splashFrameIntensities) {
		lines = ui.GlitchBannerLines(splashFrameIntensities[m.frame], rand.New(rand.NewSource(int64(7331+m.frame))))
	} else {
		lines = ui.BannerLines()
	}

	content := lipgloss.JoinVertical(
		lipgloss.Center,
		renderSplashBanner(lines),
		"",
		styles.SubtleStyle.Render(ui.BannerDivider(72)),
		styles.MutedStyle.Render(ui.BannerVersionLine(ui.StartupBannerVersion, ui.StartupBannerByline)),
		"",
		lipgloss.NewStyle().Foreground(styles.ColorAqua).Bold(true).Render(ui.BannerTagline()),
	)

	return content // Parent model should handle screen centering
}

func renderSplashBanner(lines []string) string {
	var rendered []string
	glitchStyle := lipgloss.NewStyle().Foreground(styles.ColorWhite).Bold(true)

	for _, line := range lines {
		var row strings.Builder
		for _, r := range line {
			switch {
			case r == ' ':
				row.WriteRune(r)
			case ui.IsGlitchRune(r):
				row.WriteString(glitchStyle.Render(string(r)))
			default:
				row.WriteString(styles.LogoStyle.Render(string(r)))
			}
		}
		rendered = append(rendered, row.String())
	}

	return strings.Join(rendered, "\n")
}
