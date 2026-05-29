package ui

import (
	"fmt"
	"io"
	"math/rand"
	"strings"
	"time"

	"github.com/fatih/color"
)

const (
	StartupBannerVersion = "v2.0.0"
	StartupBannerByline  = "by Zero/Harrison"
	StartupTagline       = "[ BREACH. OPERATE. DOMINATE. — AI stays in your hands. ]"
)

var (
	startupBannerLines = []string{
		" ███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗ ███╗   ██╗",
		"    ███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔═══██╗████╗  ██║",
		"   ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝██║   ██║██╔██╗ ██║",
		"  ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║██║╚██╗██║",
		" ███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚████║ ",
		" ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝",
	}
	glitchChars = []rune{'░', '▒', '▓', '█', '▄', '▀', '▌', '▐'}
	glitchSet   = map[rune]struct{}{
		'░': {}, '▒': {}, '▓': {}, '█': {}, '▄': {}, '▀': {}, '▌': {}, '▐': {},
	}
)

type StartupBannerOptions struct {
	Version  string
	Byline   string
	Animated bool
	Color    bool
}

func BannerLines() []string {
	lines := make([]string, len(startupBannerLines))
	copy(lines, startupBannerLines)
	return lines
}

func BannerDivider(width int) string {
	if width <= 0 {
		width = 72
	}
	return strings.Repeat("─", width)
}

func BannerVersionLine(version, byline string) string {
	if version == "" {
		version = StartupBannerVersion
	}
	if byline == "" {
		byline = StartupBannerByline
	}
	return fmt.Sprintf("%s  |  AI-Powered Penetration Testing Platform  |  %s", version, byline)
}

func BannerTagline() string {
	return StartupTagline
}

func IsGlitchRune(r rune) bool {
	_, ok := glitchSet[r]
	return ok
}

func GlitchBannerLines(intensity float64, rnd *rand.Rand) []string {
	if rnd == nil {
		rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
	}

	lines := BannerLines()
	for i, line := range lines {
		runes := []rune(line)
		for j, r := range runes {
			if r == ' ' || rnd.Float64() >= intensity {
				continue
			}
			runes[j] = glitchChars[rnd.Intn(len(glitchChars))]
		}
		lines[i] = string(runes)
	}
	return lines
}

func Banner() string {
	return renderStartupBanner(StartupBannerOptions{
		Version: StartupBannerVersion,
		Byline:  StartupBannerByline,
		Color:   !color.NoColor,
	})
}

func PlayStartupBanner(w io.Writer, opts StartupBannerOptions) error {
	if w == nil {
		return nil
	}

	if opts.Version == "" {
		opts.Version = StartupBannerVersion
	}
	if opts.Byline == "" {
		opts.Byline = StartupBannerByline
	}

	if !opts.Animated {
		_, err := io.WriteString(w, renderStartupBanner(opts))
		return err
	}

	frames := []float64{0.18, 0.10, 0.05, 0.02}
	frameHeight := len(startupBannerLines)
	for i, intensity := range frames {
		if i > 0 {
			if _, err := io.WriteString(w, fmt.Sprintf("\033[%dA", frameHeight)); err != nil {
				return err
			}
		}
		lines := GlitchBannerLines(intensity, rand.New(rand.NewSource(int64(1337+i))))
		if _, err := io.WriteString(w, colorizeBannerFrame(lines, opts.Color)); err != nil {
			return err
		}
		time.Sleep(70 * time.Millisecond)
	}

	_, err := io.WriteString(w, renderBannerFooter(opts))
	return err
}

func renderStartupBanner(opts StartupBannerOptions) string {
	if opts.Version == "" {
		opts.Version = StartupBannerVersion
	}
	if opts.Byline == "" {
		opts.Byline = StartupBannerByline
	}

	var b strings.Builder
	b.WriteString(colorizeBannerFrame(BannerLines(), opts.Color))
	b.WriteString(renderBannerFooter(opts))
	return b.String()
}

func renderBannerFooter(opts StartupBannerOptions) string {
	var b strings.Builder
	b.WriteByte('\n')
	b.WriteString(colorizeMuted(BannerDivider(72), opts.Color))
	b.WriteByte('\n')
	b.WriteString(colorizeMuted(BannerVersionLine(opts.Version, opts.Byline), opts.Color))
	b.WriteString("\n\n")
	b.WriteString(colorizeAccent(BannerTagline(), opts.Color))
	b.WriteString("\n\n")
	return b.String()
}

func colorizeBannerFrame(lines []string, withColor bool) string {
	var b strings.Builder
	for _, line := range lines {
		for _, r := range line {
			switch {
			case r == ' ':
				b.WriteRune(r)
			case IsGlitchRune(r):
				b.WriteString(colorizeString(string(r), withColor, color.FgWhite, color.Bold))
			default:
				b.WriteString(colorizeString(string(r), withColor, color.FgHiGreen, color.Bold))
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func colorizeMuted(text string, withColor bool) string {
	return colorizeString(text, withColor, color.FgHiBlack)
}

func colorizeAccent(text string, withColor bool) string {
	return colorizeString(text, withColor, color.FgHiGreen, color.Bold)
}

func colorizeString(text string, withColor bool, attrs ...color.Attribute) string {
	if !withColor {
		return text
	}
	return color.New(attrs...).Sprint(text)
}
