package styles

import (
	"github.com/charmbracelet/lipgloss"
)

// Elite Color Palette (Teal/Green-Blue Mix)
var (
	// Base colors
	ColorFg     = lipgloss.Color("#EEEEEE") // Primary text (Off-white)
	ColorBg     = lipgloss.Color("#0D0D0D") // Background (Deep black)
	ColorMuted  = lipgloss.Color("#6B7280") // Muted text (Gray)
	ColorSubtle = lipgloss.Color("#1E2A2A") // Subtle borders/lines (Dark teal-gray)

	// Primary Accent - Teal (Green-Blue mix)
	ColorAccent    = lipgloss.Color("#2DD4BF") // Teal (Primary brand)
	ColorTeal      = ColorAccent               // Alias
	ColorSeaGreen  = lipgloss.Color("#3EB489") // Sea Green (secondary)
	ColorAqua      = lipgloss.Color("#5EEAD4") // Light Aqua
	ColorSlateBlue = lipgloss.Color("#8FA7C2") // Grey-blue for AI responses

	// Success - Emerald Green
	ColorSuccess     = lipgloss.Color("#34D399") // Emerald Green
	ColorForestGreen = lipgloss.Color("#10B981") // Forest Teal

	// Status colors
	ColorWarning  = lipgloss.Color("#FBBF24") // Amber
	ColorCritical = lipgloss.Color("#EF4444") // Red
	ColorInfo     = lipgloss.Color("#8B5CF6") // Purple

	// UI Elements
	ColorGray     = ColorMuted
	ColorWhite    = ColorFg
	ColorDarkGray = ColorSubtle

	// UI Elements
	ColorBorder    = lipgloss.Color("#2D3D3D") // Teal-tinted border
	ColorHighlight = lipgloss.Color("#1A2E2E") // Row highlight (teal tint)

	// AI-specific colors
	ColorAI         = ColorAccent               // AI elements use teal
	ColorAIThinking = lipgloss.Color("#14B8A6") // Darker teal for thinking
)

// Text Styles
var (
	// Base text
	TextStyle   = lipgloss.NewStyle().Foreground(ColorFg).Bold(true)
	MutedStyle  = lipgloss.NewStyle().Foreground(ColorMuted)
	SubtleStyle = lipgloss.NewStyle().Foreground(ColorSubtle)
	InfoStyle   = lipgloss.NewStyle().Foreground(ColorInfo)

	// Brand/Header - Cyan accent
	LogoStyle = lipgloss.NewStyle().
			Foreground(ColorAccent).
			Bold(true)

	HeaderStyle = lipgloss.NewStyle().
			Foreground(ColorFg).
			Background(ColorSubtle).
			Bold(true).
			Padding(0, 1)

	// Status indicators
	SuccessStyle  = lipgloss.NewStyle().Foreground(ColorSuccess) // Matrix green for success
	WarningStyle  = lipgloss.NewStyle().Foreground(ColorWarning)
	CriticalStyle = lipgloss.NewStyle().Foreground(ColorCritical)
	ErrorStyle    = CriticalStyle // Alias for error messages

	// Severity styles for findings
	HighStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6600")) // Orange-red for high severity
	MediumStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFCC00")) // Yellow for medium severity
	LowStyle    = lipgloss.NewStyle().Foreground(ColorMuted)                // Gray for low severity

	// Navigation - Cyan accent
	PromptStyle = lipgloss.NewStyle().Foreground(ColorAccent).Bold(true)

	// User input style - uses terminal default for best compatibility
	UserStyle = lipgloss.NewStyle()

	// Keyboard shortcuts
	KeyStyle = lipgloss.NewStyle().
			Foreground(ColorAccent).
			Bold(true)

	DescStyle = lipgloss.NewStyle().
			Foreground(ColorMuted)

	// AI-specific styles use the terminal default foreground so the UI respects
	// the user's theme instead of forcing a fixed brand color.
	AIStyle = lipgloss.NewStyle().
		Bold(true)

	AIThinkingStyle = lipgloss.NewStyle().
			Foreground(ColorAIThinking)

	AIResponseStyle = lipgloss.NewStyle()

	// Containers
	BorderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder)

	FocusedBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(ColorAccent)

	// Active tab style - cyan highlight
	ActiveTabStyle = lipgloss.NewStyle().
			Foreground(ColorFg).
			Background(ColorAccent).
			Bold(true).
			Padding(0, 1)

	// Inactive tab style
	InactiveTabStyle = lipgloss.NewStyle().
				Foreground(ColorMuted).
				Padding(0, 1)
)

// Helper methods
func Bold(s string) string {
	return lipgloss.NewStyle().Bold(true).Render(s)
}

func Accent(s string) string {
	return lipgloss.NewStyle().Foreground(ColorAccent).Render(s)
}

func Muted(s string) string {
	return lipgloss.NewStyle().Foreground(ColorMuted).Render(s)
}

func Success(s string) string {
	return lipgloss.NewStyle().Foreground(ColorSuccess).Render(s)
}

func Cyan(s string) string {
	return lipgloss.NewStyle().Foreground(ColorTeal).Render(s)
}

func User(s string) string {
	return s // Use terminal default color
}

func AI(s string) string {
	return AIStyle.Render(s)
}

func Warning(s string) string {
	return WarningStyle.Render(s)
}

func Critical(s string) string {
	return CriticalStyle.Render(s)
}
