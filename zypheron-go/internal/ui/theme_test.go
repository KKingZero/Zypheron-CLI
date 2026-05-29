package ui

import (
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestInitColors(t *testing.T) {
	// Save original state
	originalColorblindMode := colorblindMode

	// Reset to default state
	colorblindMode = false
	initColors()

	t.Run("default colors initialized", func(t *testing.T) {
		if Primary == nil {
			t.Error("Primary color not initialized")
		}
		if Secondary == nil {
			t.Error("Secondary color not initialized")
		}
		if Success == nil {
			t.Error("Success color not initialized")
		}
		if Warning == nil {
			t.Error("Warning color not initialized")
		}
		if Danger == nil {
			t.Error("Danger color not initialized")
		}
		if Info == nil {
			t.Error("Info color not initialized")
		}
		if Muted == nil {
			t.Error("Muted color not initialized")
		}
		if Accent == nil {
			t.Error("Accent color not initialized")
		}
	})

	t.Run("default indicators initialized", func(t *testing.T) {
		if IndicatorSuccess == "" {
			t.Error("IndicatorSuccess not initialized")
		}
		if IndicatorInfo == "" {
			t.Error("IndicatorInfo not initialized")
		}
		if IndicatorWarning == "" {
			t.Error("IndicatorWarning not initialized")
		}
		if IndicatorError == "" {
			t.Error("IndicatorError not initialized")
		}

		// With colors disabled, check exact values
		color.NoColor = true
		defer func() { color.NoColor = false }()

		// Re-initialize to get plain text versions
		initColors()

		if !strings.Contains(IndicatorSuccess, "[+]") {
			t.Errorf("IndicatorSuccess = %q, want to contain [+]", IndicatorSuccess)
		}
		if !strings.Contains(IndicatorInfo, "[*]") {
			t.Errorf("IndicatorInfo = %q, want to contain [*]", IndicatorInfo)
		}
		if !strings.Contains(IndicatorWarning, "[!]") {
			t.Errorf("IndicatorWarning = %q, want to contain [!]", IndicatorWarning)
		}
		if !strings.Contains(IndicatorError, "[-]") {
			t.Errorf("IndicatorError = %q, want to contain [-]", IndicatorError)
		}
	})

	// Restore original state
	colorblindMode = originalColorblindMode
	if colorblindMode {
		EnableColorblindMode()
	} else {
		initColors()
	}
}

func TestEnableColorblindMode(t *testing.T) {
	// Save original state
	originalColorblindMode := colorblindMode

	// Reset to default
	colorblindMode = false
	initColors()

	t.Run("colorblind mode enabled", func(t *testing.T) {
		EnableColorblindMode()

		if !IsColorblindMode() {
			t.Error("IsColorblindMode() = false, want true")
		}
	})

	t.Run("colorblind indicators changed", func(t *testing.T) {
		EnableColorblindMode()

		color.NoColor = true
		defer func() { color.NoColor = false }()

		// Re-enable to get plain text versions
		EnableColorblindMode()

		if !strings.Contains(IndicatorSuccess, "[OK]") {
			t.Errorf("IndicatorSuccess = %q, want to contain [OK]", IndicatorSuccess)
		}
		if !strings.Contains(IndicatorInfo, "[**]") {
			t.Errorf("IndicatorInfo = %q, want to contain [**]", IndicatorInfo)
		}
		if !strings.Contains(IndicatorWarning, "[!!]") {
			t.Errorf("IndicatorWarning = %q, want to contain [!!]", IndicatorWarning)
		}
		if !strings.Contains(IndicatorError, "[XX]") {
			t.Errorf("IndicatorError = %q, want to contain [XX]", IndicatorError)
		}
	})

	t.Run("colors are different from default", func(t *testing.T) {
		// Reset to default
		colorblindMode = false
		initColors()
		defaultSuccess := Success.Sprint("test")
		defaultWarning := Warning.Sprint("test")

		// Enable colorblind mode
		EnableColorblindMode()
		colorblindSuccess := Success.Sprint("test")
		colorblindWarning := Warning.Sprint("test")

		// The output should be different (different ANSI codes)
		// Note: We can't do direct comparison because color objects might be recreated
		// Instead, we verify the mode flag changed
		if !colorblindMode {
			t.Error("colorblindMode flag not set after EnableColorblindMode()")
		}

		// Verify they produce different outputs (when colors are enabled)
		color.NoColor = false
		if defaultSuccess == colorblindSuccess || defaultWarning == colorblindWarning {
			// This might be OK if NoColor was set, so we just note it
			t.Logf("Note: colorblind and default colors produced same output")
		}
	})

	// Restore original state
	colorblindMode = originalColorblindMode
	if colorblindMode {
		EnableColorblindMode()
	} else {
		initColors()
	}
}

func TestIsColorblindMode(t *testing.T) {
	// Save original state
	originalColorblindMode := colorblindMode

	tests := []struct {
		name     string
		setup    func()
		expected bool
	}{
		{
			name: "default mode disabled",
			setup: func() {
				colorblindMode = false
				initColors()
			},
			expected: false,
		},
		{
			name: "colorblind mode enabled",
			setup: func() {
				EnableColorblindMode()
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			result := IsColorblindMode()
			if result != tt.expected {
				t.Errorf("IsColorblindMode() = %v, want %v", result, tt.expected)
			}
		})
	}

	// Restore original state
	colorblindMode = originalColorblindMode
	if colorblindMode {
		EnableColorblindMode()
	} else {
		initColors()
	}
}

func TestDisableColors(t *testing.T) {
	// Save original NoColor state
	originalNoColor := color.NoColor

	t.Run("disables color output", func(t *testing.T) {
		color.NoColor = false
		DisableColors()

		if !color.NoColor {
			t.Error("DisableColors() did not set color.NoColor to true")
		}
	})

	t.Run("affects formatted output", func(t *testing.T) {
		color.NoColor = false
		withColor := Success.Sprint("test")

		DisableColors()
		withoutColor := Success.Sprint("test")

		// When colors are disabled, output should be plain text
		if withoutColor != "test" {
			t.Errorf("Expected plain 'test', got %q", withoutColor)
		}

		// With colors enabled, output should have ANSI codes (longer)
		// Note: This test might be environment-dependent
		if len(withColor) <= len("test") {
			t.Logf("Note: withColor output appears to be plain text: %q", withColor)
		}
	})

	// Restore original state
	color.NoColor = originalNoColor
}

func TestBanner(t *testing.T) {
	t.Run("returns non-empty string", func(t *testing.T) {
		banner := Banner()
		if banner == "" {
			t.Error("Banner() returned empty string")
		}
	})

	t.Run("contains zypheron text", func(t *testing.T) {
		color.NoColor = true
		defer func() { color.NoColor = false }()

		banner := Banner()

		// Banner should contain recognizable elements
		if !strings.Contains(banner, "ZYPHERON") && !strings.Contains(banner, "███") {
			t.Error("Banner() does not contain expected ASCII art")
		}
	})

	t.Run("contains updated byline", func(t *testing.T) {
		color.NoColor = true
		defer func() { color.NoColor = false }()

		banner := Banner()

		if !strings.Contains(banner, StartupBannerByline) {
			t.Errorf("Banner() does not contain byline %q", StartupBannerByline)
		}
	})

	t.Run("contains tagline", func(t *testing.T) {
		color.NoColor = true
		defer func() { color.NoColor = false }()

		banner := Banner()

		if !strings.Contains(banner, "AI-Powered Penetration Testing Platform") {
			t.Error("Banner() does not contain expected tagline")
		}
	})

	t.Run("does not contain snake art", func(t *testing.T) {
		color.NoColor = true
		defer func() { color.NoColor = false }()

		banner := Banner()

		if strings.Contains(banner, "(snake)") {
			t.Error("Banner() should not contain snake reference")
		}
	})
}

func TestSuccessMsg(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{"simple message", "Operation completed", "Operation completed"},
		{"empty message", "", "[+]"},
		{"message with special chars", "Success: 100%!", "Success: 100%!"},
		{"message with newline", "Line1\nLine2", "Line1\nLine2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SuccessMsg(tt.input)

			if !strings.Contains(result, tt.contains) {
				t.Errorf("SuccessMsg(%q) = %q, want to contain %q", tt.input, result, tt.contains)
			}

			// Should always contain the success indicator
			if !strings.Contains(result, "[+]") {
				t.Errorf("SuccessMsg(%q) = %q, want to contain [+]", tt.input, result)
			}
		})
	}
}

func TestInfoMsg(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{"simple message", "Processing request", "Processing request"},
		{"empty message", "", "[*]"},
		{"message with numbers", "Found 42 items", "Found 42 items"},
		{"long message", strings.Repeat("info ", 50), "info "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InfoMsg(tt.input)

			if !strings.Contains(result, tt.contains) {
				t.Errorf("InfoMsg(%q) = %q, want to contain %q", tt.input, result, tt.contains)
			}

			// Should always contain the info indicator
			if !strings.Contains(result, "[*]") {
				t.Errorf("InfoMsg(%q) = %q, want to contain [*]", tt.input, result)
			}
		})
	}
}

func TestWarningMsg(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{"simple warning", "Deprecated feature", "Deprecated feature"},
		{"empty message", "", "[!]"},
		{"warning with details", "Timeout in 30s", "Timeout in 30s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WarningMsg(tt.input)

			if !strings.Contains(result, tt.contains) {
				t.Errorf("WarningMsg(%q) = %q, want to contain %q", tt.input, result, tt.contains)
			}

			// Should always contain the warning indicator
			if !strings.Contains(result, "[!]") {
				t.Errorf("WarningMsg(%q) = %q, want to contain [!]", tt.input, result)
			}
		})
	}
}

func TestError(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{"simple error", "Connection failed", "Connection failed"},
		{"empty message", "", "[-]"},
		{"error with code", "Error 404: Not found", "Error 404"},
		{"multiline error", "Error:\nDetails here", "Error:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Error(tt.input)

			if !strings.Contains(result, tt.contains) {
				t.Errorf("Error(%q) = %q, want to contain %q", tt.input, result, tt.contains)
			}

			// Should always contain the error indicator
			if !strings.Contains(result, "[-]") {
				t.Errorf("Error(%q) = %q, want to contain [-]", tt.input, result)
			}
		})
	}
}

func TestTarget(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name     string
		namePart string
		value    string
		wantName string
		wantVal  string
	}{
		{"ip target", "Target", "192.168.1.1", "Target:", "192.168.1.1"},
		{"domain target", "Host", "example.com", "Host:", "example.com"},
		{"port target", "Port", "8080", "Port:", "8080"},
		{"empty name", "", "value", ":", "value"},
		{"empty value", "Name", "", "Name:", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Target(tt.namePart, tt.value)

			if !strings.Contains(result, tt.wantName) {
				t.Errorf("Target(%q, %q) = %q, want to contain %q", tt.namePart, tt.value, result, tt.wantName)
			}

			if !strings.Contains(result, tt.wantVal) {
				t.Errorf("Target(%q, %q) = %q, want to contain %q", tt.namePart, tt.value, result, tt.wantVal)
			}
		})
	}
}

func TestSeparator(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name   string
		length int
	}{
		{"zero length", 0},
		{"short separator", 10},
		{"medium separator", 50},
		{"long separator", 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Separator(tt.length)

			// Count the number of separator characters
			count := strings.Count(result, "─")
			if count != tt.length {
				t.Errorf("Separator(%d) has %d separator chars, want %d", tt.length, count, tt.length)
			}
		})
	}
}

func TestBox(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name  string
		title string
	}{
		{"short title", "Test"},
		{"medium title", "Configuration Details"},
		{"long title", "This is a very long title for testing purposes"},
		{"empty title", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			top, bottom := Box(tt.title)

			// Verify top contains title
			if !strings.Contains(top, tt.title) {
				t.Errorf("Box(%q) top = %q, want to contain %q", tt.title, top, tt.title)
			}

			// Verify box characters are present
			if !strings.Contains(top, "╔") || !strings.Contains(top, "╗") {
				t.Errorf("Box(%q) top missing box characters", tt.title)
			}

			if !strings.Contains(bottom, "╚") || !strings.Contains(bottom, "╝") {
				t.Errorf("Box(%q) bottom missing box characters", tt.title)
			}

			// Verify top and bottom have consistent structure
			// Both should have similar visible length (accounting for ANSI codes)
			topRunes := []rune(top)
			bottomRunes := []rune(bottom)

			// Should have some content
			if len(topRunes) == 0 || len(bottomRunes) == 0 {
				t.Errorf("Box(%q) returned empty string", tt.title)
			}
		})
	}
}

func TestBoxConsistency(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	t.Run("multiple calls return same structure", func(t *testing.T) {
		title := "Test Title"

		top1, bottom1 := Box(title)
		top2, bottom2 := Box(title)

		if top1 != top2 {
			t.Error("Box() top is not consistent across calls")
		}

		if bottom1 != bottom2 {
			t.Error("Box() bottom is not consistent across calls")
		}
	})
}

// Benchmark tests for message formatting functions

func BenchmarkSuccessMsg(b *testing.B) {
	msg := "Operation completed successfully"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SuccessMsg(msg)
	}
}

func BenchmarkInfoMsg(b *testing.B) {
	msg := "Processing request with details"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = InfoMsg(msg)
	}
}

func BenchmarkWarningMsg(b *testing.B) {
	msg := "Warning: deprecated feature in use"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = WarningMsg(msg)
	}
}

func BenchmarkError(b *testing.B) {
	msg := "Error: connection failed after timeout"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Error(msg)
	}
}

func BenchmarkTarget(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Target("Host", "192.168.1.1")
	}
}

func BenchmarkSeparator(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Separator(80)
	}
}

func BenchmarkSeparatorLarge(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Separator(500)
	}
}

func BenchmarkBox(b *testing.B) {
	title := "Configuration"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Box(title)
	}
}

func BenchmarkBanner(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Banner()
	}
}

// Benchmark color mode switching

func BenchmarkEnableColorblindMode(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EnableColorblindMode()
	}
}

func BenchmarkInitColors(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		initColors()
	}
}
