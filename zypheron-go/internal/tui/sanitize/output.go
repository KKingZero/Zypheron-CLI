// Package sanitize provides output sanitization functions to prevent terminal injection attacks.
// This module strips dangerous ANSI escape sequences and control characters that could be
// used to manipulate terminal behavior, execute commands, or create UI confusion attacks.
//
// Security Considerations:
// - Prevents terminal title injection (OSC sequences)
// - Blocks cursor manipulation attacks (CSI sequences)
// - Removes potentially dangerous control sequences (DCS, APC, PM)
// - Neutralizes control characters that could overwrite output
//
// Performance: Uses efficient byte-level processing with strings.Builder to minimize
// allocations in hot paths. Avoids regex for better performance characteristics.
package sanitize

import (
	"strings"
	"unicode"
)

const (
	// ANSI escape sequences start bytes
	ESC = '\x1b' // 7-bit escape
	CSI = '\x9b' // 8-bit Control Sequence Introducer

	// Control characters (kept safe)
	NUL = '\x00'
	TAB = '\t' // \x09 - allowed
	LF  = '\n' // \x0a - allowed
	CR  = '\r' // \x0d - dangerous, can overwrite lines

	// String terminator
	ST = '\x9c'
)

// dangerousSequence represents a dangerous ANSI escape sequence prefix
type dangerousSequence struct {
	prefix []byte
	name   string // for documentation/logging
}

var (
	// Dangerous escape sequences that MUST be stripped
	dangerousSequences = []dangerousSequence{
		{[]byte{ESC, ']'}, "OSC"}, // Operating System Command - can change title, clipboard
		{[]byte{ESC, '^'}, "PM"},  // Privacy Message
		{[]byte{ESC, 'P'}, "DCS"}, // Device Control String - can reprogram terminal
		{[]byte{ESC, '_'}, "APC"}, // Application Program Command
		{[]byte{ESC, 'X'}, "SOS"}, // Start of String
	}

	// Color ANSI sequences (CSI m) - safe to preserve in color mode
	// Format: ESC [ ... m
	colorPrefix = []byte{ESC, '['}
)

// SanitizeOutput removes dangerous terminal escape sequences and control characters
// while preserving safe formatting (newlines, tabs).
//
// This is the primary sanitization function for untrusted output.
//
// Removed:
// - All ANSI escape sequences (colors, cursor movement, etc.)
// - Dangerous control characters (including \r)
// - 8-bit CSI sequences
//
// Preserved:
// - Newlines (\n)
// - Tabs (\t)
// - Printable characters
func SanitizeOutput(input string) string {
	if input == "" {
		return ""
	}

	var builder strings.Builder
	builder.Grow(len(input)) // Pre-allocate for performance

	i := 0
	inputBytes := []byte(input)
	length := len(inputBytes)

	for i < length {
		ch := inputBytes[i]

		// Handle ANSI escape sequences (ESC-based)
		if ch == ESC && i+1 < length {
			// Check for dangerous sequences first
			skipLen := checkDangerousSequence(inputBytes, i)
			if skipLen > 0 {
				i += skipLen
				continue
			}

			// Handle CSI sequences: ESC [ ... (letter or @)
			if inputBytes[i+1] == '[' {
				i += skipCSISequence(inputBytes, i)
				continue
			}

			// Handle other escape sequences: ESC (letter)
			if i+1 < length && isEscapeTerminator(inputBytes[i+1]) {
				i += 2
				continue
			}

			// Unknown escape, skip the ESC character
			i++
			continue
		}

		// Handle 8-bit CSI directly (0x9B)
		if ch == CSI {
			i += skip8BitCSI(inputBytes, i)
			continue
		}

		// Handle control characters
		if ch < 0x20 { // Control character range
			if ch == TAB || ch == LF {
				// Safe control characters - preserve
				builder.WriteByte(ch)
			}
			// Skip all other control characters (including CR)
			i++
			continue
		}

		// Handle DEL character (0x7F)
		if ch == 0x7F {
			i++
			continue
		}

		// Safe character - copy to output
		builder.WriteByte(ch)
		i++
	}

	return builder.String()
}

// SanitizeOutputPreserveColor strips dangerous sequences but preserves basic ANSI colors.
//
// Use this when you want to maintain color formatting from trusted sources but still
// protect against terminal injection attacks.
//
// Preserved:
// - SGR (Select Graphic Rendition) sequences: ESC [ ... m
// - Newlines and tabs
//
// Removed:
// - Cursor movement (ESC [ ... H, etc.)
// - Terminal reprogramming (OSC, DCS, APC, PM)
// - Other dangerous control sequences
func SanitizeOutputPreserveColor(input string) string {
	if input == "" {
		return ""
	}

	var builder strings.Builder
	builder.Grow(len(input))

	i := 0
	inputBytes := []byte(input)
	length := len(inputBytes)

	for i < length {
		ch := inputBytes[i]

		// Handle ANSI escape sequences
		if ch == ESC && i+1 < length {
			// Check for dangerous sequences
			skipLen := checkDangerousSequence(inputBytes, i)
			if skipLen > 0 {
				i += skipLen
				continue
			}

			// Handle CSI sequences
			if inputBytes[i+1] == '[' {
				// Check if this is a color sequence (ends with 'm')
				seqEnd := findCSITerminator(inputBytes, i+2)
				if seqEnd > 0 && seqEnd < length && inputBytes[seqEnd] == 'm' {
					// This is an SGR (color) sequence - preserve it
					builder.Write(inputBytes[i : seqEnd+1])
					i = seqEnd + 1
					continue
				}
				// Not a color sequence - strip it
				i += skipCSISequence(inputBytes, i)
				continue
			}

			// Other escape sequences - strip
			if i+1 < length && isEscapeTerminator(inputBytes[i+1]) {
				i += 2
				continue
			}

			i++
			continue
		}

		// Handle 8-bit CSI
		if ch == CSI {
			i += skip8BitCSI(inputBytes, i)
			continue
		}

		// Handle control characters
		if ch < 0x20 {
			if ch == TAB || ch == LF {
				builder.WriteByte(ch)
			}
			i++
			continue
		}

		// Handle DEL
		if ch == 0x7F {
			i++
			continue
		}

		// Safe character
		builder.WriteByte(ch)
		i++
	}

	return builder.String()
}

// StripAllANSI removes ALL ANSI sequences including colors.
//
// Use this when you need plain text output with no formatting whatsoever,
// such as logging to files or transmitting over non-terminal channels.
func StripAllANSI(input string) string {
	return SanitizeOutput(input)
}

// IsOutputSafe checks if a string contains dangerous terminal sequences.
//
// Returns true if the output is safe to display without sanitization.
// Returns false if dangerous sequences are detected.
//
// This is useful for validation before displaying untrusted content or
// for security auditing purposes.
func IsOutputSafe(input string) bool {
	if input == "" {
		return true
	}

	inputBytes := []byte(input)
	length := len(inputBytes)

	for i := 0; i < length; i++ {
		ch := inputBytes[i]

		// Check for ESC sequences
		if ch == ESC {
			// Any ESC sequence is considered potentially unsafe
			return false
		}

		// Check for 8-bit CSI
		if ch == CSI {
			return false
		}

		// Check for dangerous control characters
		if ch < 0x20 {
			// Only TAB and LF are safe
			if ch != TAB && ch != LF {
				return false
			}
		}

		// Check for DEL
		if ch == 0x7F {
			return false
		}
	}

	return true
}

// checkDangerousSequence checks if the position starts a dangerous escape sequence.
// Returns the number of bytes to skip if dangerous, 0 otherwise.
func checkDangerousSequence(data []byte, pos int) int {
	for _, seq := range dangerousSequences {
		if matchesPrefix(data, pos, seq.prefix) {
			// Find the string terminator (ST) or end of dangerous content
			// Include prefix length in total skip count
			return len(seq.prefix) + skipUntilStringTerminator(data, pos+len(seq.prefix))
		}
	}
	return 0
}

// matchesPrefix checks if data at pos starts with prefix
func matchesPrefix(data []byte, pos int, prefix []byte) bool {
	if pos+len(prefix) > len(data) {
		return false
	}
	for i, b := range prefix {
		if data[pos+i] != b {
			return false
		}
	}
	return true
}

// skipUntilStringTerminator skips bytes until ST (String Terminator) or BEL
func skipUntilStringTerminator(data []byte, start int) int {
	length := len(data)
	for i := start; i < length; i++ {
		// String Terminator: ESC \ or ST (0x9C) or BEL (0x07)
		if data[i] == 0x07 || data[i] == ST {
			return i - start + 1
		}
		if data[i] == ESC && i+1 < length && data[i+1] == '\\' {
			return i - start + 2
		}
		// Safety: don't scan forever, limit to 1024 bytes
		if i-start > 1024 {
			return i - start
		}
	}
	// No terminator found, skip to end
	return length - start
}

// skipCSISequence skips a CSI sequence starting at pos
// CSI format: ESC [ [parameters] (intermediate bytes) (final byte)
func skipCSISequence(data []byte, pos int) int {
	if pos+1 >= len(data) || data[pos] != ESC || data[pos+1] != '[' {
		return 1
	}

	i := pos + 2
	length := len(data)

	// Skip parameter bytes (0x30-0x3F)
	for i < length && data[i] >= 0x30 && data[i] <= 0x3F {
		i++
	}

	// Skip intermediate bytes (0x20-0x2F)
	for i < length && data[i] >= 0x20 && data[i] <= 0x2F {
		i++
	}

	// Final byte (0x40-0x7E)
	if i < length && data[i] >= 0x40 && data[i] <= 0x7E {
		i++
	}

	return i - pos
}

// findCSITerminator finds the position of the CSI final byte
func findCSITerminator(data []byte, start int) int {
	length := len(data)
	i := start

	// Skip parameter bytes (0x30-0x3F) - includes digits, semicolon
	for i < length && data[i] >= 0x30 && data[i] <= 0x3F {
		i++
	}

	// Skip intermediate bytes (0x20-0x2F)
	for i < length && data[i] >= 0x20 && data[i] <= 0x2F {
		i++
	}

	// Check for final byte (0x40-0x7E)
	if i < length && data[i] >= 0x40 && data[i] <= 0x7E {
		return i
	}

	return -1
}

// skip8BitCSI skips an 8-bit CSI sequence
func skip8BitCSI(data []byte, pos int) int {
	if pos >= len(data) || data[pos] != CSI {
		return 1
	}

	i := pos + 1
	length := len(data)

	// Skip parameter bytes
	for i < length && data[i] >= 0x30 && data[i] <= 0x3F {
		i++
	}

	// Skip intermediate bytes
	for i < length && data[i] >= 0x20 && data[i] <= 0x2F {
		i++
	}

	// Final byte
	if i < length && data[i] >= 0x40 && data[i] <= 0x7E {
		i++
	}

	return i - pos
}

// isEscapeTerminator checks if a byte is a valid ESC sequence terminator
func isEscapeTerminator(b byte) bool {
	// Common escape terminators
	return (b >= 0x40 && b <= 0x5F) || unicode.IsLetter(rune(b))
}
