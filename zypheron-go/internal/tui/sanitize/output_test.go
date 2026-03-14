package sanitize

import (
	"strings"
	"testing"
)

// TestSanitizeOutput_BasicSafety tests that safe text passes through unchanged
func TestSanitizeOutput_BasicSafety(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain text",
			input: "Hello, World!",
			want:  "Hello, World!",
		},
		{
			name:  "text with newlines",
			input: "Line 1\nLine 2\nLine 3",
			want:  "Line 1\nLine 2\nLine 3",
		},
		{
			name:  "text with tabs",
			input: "Column1\tColumn2\tColumn3",
			want:  "Column1\tColumn2\tColumn3",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "unicode text",
			input: "Hello 世界 🌍",
			want:  "Hello 世界 🌍",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeOutput(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSanitizeOutput_RemovesCarriageReturn tests that CR is removed (security critical)
func TestSanitizeOutput_RemovesCarriageReturn(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "single CR",
			input: "Hello\rWorld",
			want:  "HelloWorld",
		},
		{
			name:  "CR at start",
			input: "\rHello",
			want:  "Hello",
		},
		{
			name:  "CR at end",
			input: "Hello\r",
			want:  "Hello",
		},
		{
			name:  "multiple CRs",
			input: "A\rB\rC\rD",
			want:  "ABCD",
		},
		{
			name:  "CRLF becomes LF",
			input: "Line1\r\nLine2\r\nLine3",
			want:  "Line1\nLine2\nLine3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeOutput(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSanitizeOutput_RemovesANSIColors tests color sequence removal
func TestSanitizeOutput_RemovesANSIColors(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "red text",
			input: "\x1b[31mRed Text\x1b[0m",
			want:  "Red Text",
		},
		{
			name:  "multiple colors",
			input: "\x1b[31mRed\x1b[32mGreen\x1b[34mBlue\x1b[0m",
			want:  "RedGreenBlue",
		},
		{
			name:  "bold text",
			input: "\x1b[1mBold\x1b[0m",
			want:  "Bold",
		},
		{
			name:  "background color",
			input: "\x1b[41mRed Background\x1b[0m",
			want:  "Red Background",
		},
		{
			name:  "256 color",
			input: "\x1b[38;5;208mOrange\x1b[0m",
			want:  "Orange",
		},
		{
			name:  "RGB color",
			input: "\x1b[38;2;255;128;0mOrange\x1b[0m",
			want:  "Orange",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeOutput(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSanitizeOutput_RemovesCursorMovement tests cursor manipulation removal
func TestSanitizeOutput_RemovesCursorMovement(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "cursor up",
			input: "Text\x1b[AMore",
			want:  "TextMore",
		},
		{
			name:  "cursor down",
			input: "Text\x1b[BMore",
			want:  "TextMore",
		},
		{
			name:  "cursor forward",
			input: "Text\x1b[CMore",
			want:  "TextMore",
		},
		{
			name:  "cursor back",
			input: "Text\x1b[DMore",
			want:  "TextMore",
		},
		{
			name:  "cursor position",
			input: "Text\x1b[10;20HMore",
			want:  "TextMore",
		},
		{
			name:  "cursor home",
			input: "Text\x1b[HMore",
			want:  "TextMore",
		},
		{
			name:  "erase display",
			input: "Text\x1b[2JMore",
			want:  "TextMore",
		},
		{
			name:  "erase line",
			input: "Text\x1b[KMore",
			want:  "TextMore",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeOutput(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSanitizeOutput_RemovesDangerousOSC tests OSC sequence removal (CRITICAL SECURITY)
func TestSanitizeOutput_RemovesDangerousOSC(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "change terminal title with BEL",
			input: "\x1b]0;Malicious Title\x07Normal Text",
			want:  "Normal Text",
		},
		{
			name:  "change terminal title with ST",
			input: "\x1b]0;Malicious Title\x1b\\Normal Text",
			want:  "Normal Text",
		},
		{
			name:  "clipboard manipulation",
			input: "\x1b]52;c;base64data\x07Text",
			want:  "Text",
		},
		{
			name:  "hyperlink OSC",
			input: "\x1b]8;;https://evil.com\x07Click Here\x1b]8;;\x07",
			want:  "Click Here",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeOutput(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSanitizeOutput_RemovesDangerousDCS tests DCS sequence removal (CRITICAL SECURITY)
func TestSanitizeOutput_RemovesDangerousDCS(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "DCS sequence with ST",
			input: "\x1bP1$r\x1b\\Normal Text",
			want:  "Normal Text",
		},
		{
			name:  "DCS sequence with BEL",
			input: "\x1bP+q436f\x07Text",
			want:  "Text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeOutput(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSanitizeOutput_RemovesDangerousAPC tests APC sequence removal (CRITICAL SECURITY)
func TestSanitizeOutput_RemovesDangerousAPC(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "APC sequence with ST",
			input: "\x1b_Malicious\x1b\\Normal Text",
			want:  "Normal Text",
		},
		{
			name:  "APC sequence with BEL",
			input: "\x1b_Payload\x07Text",
			want:  "Text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeOutput(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSanitizeOutput_RemovesDangerousPM tests Privacy Message removal
func TestSanitizeOutput_RemovesDangerousPM(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "PM sequence with ST",
			input: "\x1b^Privacy\x1b\\Normal Text",
			want:  "Normal Text",
		},
		{
			name:  "PM sequence with BEL",
			input: "\x1b^Data\x07Text",
			want:  "Text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeOutput(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSanitizeOutput_Removes8BitCSI tests 8-bit CSI removal
func TestSanitizeOutput_Removes8BitCSI(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "8-bit CSI cursor movement",
			input: "Text\x9b10;20HMore",
			want:  "TextMore",
		},
		{
			name:  "8-bit CSI color",
			input: "Text\x9b31mRed\x9b0m",
			want:  "TextRed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeOutput(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSanitizeOutput_RemovesControlCharacters tests control character removal
func TestSanitizeOutput_RemovesControlCharacters(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "NUL character",
			input: "Hello\x00World",
			want:  "HelloWorld",
		},
		{
			name:  "BEL character",
			input: "Hello\x07World",
			want:  "HelloWorld",
		},
		{
			name:  "backspace",
			input: "Hello\x08World",
			want:  "HelloWorld",
		},
		{
			name:  "vertical tab",
			input: "Hello\x0bWorld",
			want:  "HelloWorld",
		},
		{
			name:  "form feed",
			input: "Hello\x0cWorld",
			want:  "HelloWorld",
		},
		{
			name:  "DEL character",
			input: "Hello\x7fWorld",
			want:  "HelloWorld",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeOutput(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSanitizeOutputPreserveColor tests color preservation mode
func TestSanitizeOutputPreserveColor(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "preserves basic color",
			input: "\x1b[31mRed Text\x1b[0m",
			want:  "\x1b[31mRed Text\x1b[0m",
		},
		{
			name:  "preserves 256 color",
			input: "\x1b[38;5;208mOrange\x1b[0m",
			want:  "\x1b[38;5;208mOrange\x1b[0m",
		},
		{
			name:  "preserves RGB color",
			input: "\x1b[38;2;255;128;0mOrange\x1b[0m",
			want:  "\x1b[38;2;255;128;0mOrange\x1b[0m",
		},
		{
			name:  "removes cursor movement",
			input: "\x1b[31mRed\x1b[10HText\x1b[0m",
			want:  "\x1b[31mRedText\x1b[0m",
		},
		{
			name:  "removes OSC but keeps colors",
			input: "\x1b[31mRed\x1b]0;Title\x07Text\x1b[0m",
			want:  "\x1b[31mRedText\x1b[0m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeOutputPreserveColor(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeOutputPreserveColor() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestStripAllANSI tests complete ANSI stripping
func TestStripAllANSI(t *testing.T) {
	input := "\x1b[31mRed\x1b[32mGreen\x1b[34mBlue\x1b[0m"
	want := "RedGreenBlue"
	got := StripAllANSI(input)
	if got != want {
		t.Errorf("StripAllANSI() = %q, want %q", got, want)
	}
}

// TestIsOutputSafe tests safety detection
func TestIsOutputSafe(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "safe plain text",
			input: "Hello, World!",
			want:  true,
		},
		{
			name:  "safe with newlines",
			input: "Line 1\nLine 2\n",
			want:  true,
		},
		{
			name:  "safe with tabs",
			input: "Col1\tCol2\t",
			want:  true,
		},
		{
			name:  "unsafe with ANSI color",
			input: "\x1b[31mRed\x1b[0m",
			want:  false,
		},
		{
			name:  "unsafe with OSC",
			input: "\x1b]0;Title\x07",
			want:  false,
		},
		{
			name:  "unsafe with carriage return",
			input: "Hello\rWorld",
			want:  false,
		},
		{
			name:  "unsafe with NUL",
			input: "Hello\x00World",
			want:  false,
		},
		{
			name:  "unsafe with 8-bit CSI",
			input: "Text\x9b31m",
			want:  false,
		},
		{
			name:  "empty is safe",
			input: "",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsOutputSafe(tt.input)
			if got != tt.want {
				t.Errorf("IsOutputSafe() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSanitizeOutput_RealWorldAttacks tests realistic attack scenarios
func TestSanitizeOutput_RealWorldAttacks(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
		reason string
	}{
		{
			name:   "terminal title injection",
			input:  "Error: \x1b]0;pwned - rm -rf /\x07 file not found",
			want:   "Error:  file not found",
			reason: "Prevents terminal title manipulation",
		},
		{
			name:   "line overwrite attack",
			input:  "Please enter password: hunter2\rPlease enter password: ",
			want:   "Please enter password: hunter2Please enter password: ",
			reason: "Prevents CR-based line overwriting",
		},
		{
			name:   "cursor position hijack",
			input:  "Balance: $1000\x1b[10D00",
			want:   "Balance: $100000",
			reason: "Prevents cursor-based UI manipulation",
		},
		{
			name:   "clipboard injection",
			input:  "Check this: \x1b]52;c;ZWNobyBoYWNrZWQ=\x07normal text",
			want:   "Check this: normal text",
			reason: "Prevents clipboard manipulation via OSC 52",
		},
		{
			name:   "DCS terminal reprogramming",
			input:  "\x1bP1;2;3;4\x1b\\Payload",
			want:   "Payload",
			reason: "Prevents terminal reprogramming via DCS",
		},
		{
			name:   "combined attack",
			input:  "\x1b]0;Evil\x07Normal\x1b[10DText\rOverwrite\x00NUL",
			want:   "NormalTextOverwriteNUL",
			reason: "Handles multiple attack vectors simultaneously",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeOutput(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeOutput() = %q, want %q - %s", got, tt.want, tt.reason)
			}
		})
	}
}

// BenchmarkSanitizeOutput benchmarks the main sanitization function
func BenchmarkSanitizeOutput(b *testing.B) {
	inputs := []string{
		"Simple plain text without any escape sequences",
		"\x1b[31mColored text with ANSI\x1b[0m normal text",
		"\x1b]0;Terminal Title\x07Text with OSC sequence",
		"Mixed\x1b[31m colors \x1b[10H cursor \x1b]0;title\x07 and \x00 control chars",
		strings.Repeat("Long text with no escapes ", 100),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, input := range inputs {
			_ = SanitizeOutput(input)
		}
	}
}

// BenchmarkSanitizeOutputPreserveColor benchmarks color-preserving sanitization
func BenchmarkSanitizeOutputPreserveColor(b *testing.B) {
	input := "\x1b[31mRed \x1b[32mGreen \x1b[34mBlue \x1b[0mNormal \x1b]0;Title\x07Text"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SanitizeOutputPreserveColor(input)
	}
}

// BenchmarkIsOutputSafe benchmarks safety checking
func BenchmarkIsOutputSafe(b *testing.B) {
	inputs := []string{
		"Safe plain text",
		"\x1b[31mUnsafe with ANSI\x1b[0m",
		"Safe text\nwith newlines\n",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, input := range inputs {
			_ = IsOutputSafe(input)
		}
	}
}
