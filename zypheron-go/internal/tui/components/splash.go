package components

import (
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type SplashModel struct {
	width  int
	height int
}

func NewSplash() SplashModel {
	return SplashModel{}
}

// SplashCompleteMsg signals splash screen is done
type SplashCompleteMsg struct{}

func (m SplashModel) Init() tea.Cmd {
	// Auto-dismiss after 1.5 seconds
	return tea.Tick(1500*time.Millisecond, func(t time.Time) tea.Msg {
		return SplashCompleteMsg{}
	})
}

func (m SplashModel) Update(msg tea.Msg) (SplashModel, tea.Cmd) {
	return m, nil
}

func (m SplashModel) View() string {
	logo := `
███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗ ███╗   ██╗
╚══███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔═══██╗████╗  ██║
  ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝██║   ██║██╔██╗ ██║
 ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║██║╚████║
███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚███║
╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝
    `

	snake := `
             /^\\/^\\
           _|__|  O|
  \\/     /~     \\_/ \\
   \\____|__________/  \\
          \\_______      \\
                   \     \\                 \\
                    |     |                  \\
                   /      /                    \\
                  /     /                       \\\\
                /      /                         \\ \\
               /     /                            \\  \\
             /     /             _----_            \\   \\
            /     /           _-~      ~-_         |   |
           (      (        _-~    _--_    ~-_     _/   |
            \\      ~-____-~    _-~    ~-_    ~-_-~    /
              ~-_           _-~          ~-_       _-~   
                 ~--______-~                ~-___-~
`

	version := styles.MutedStyle.Render("v2.0.0 | Elite Cyber Security Suite")

	// Center the logo
	content := lipgloss.JoinVertical(lipgloss.Center,
		styles.LogoStyle.Render(logo),
		styles.LogoStyle.Render(snake),
		"\n",
		version,
	)

	return content // Parent model should handle screen centering
}
