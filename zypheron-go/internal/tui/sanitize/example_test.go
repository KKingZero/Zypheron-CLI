package sanitize_test

import (
	"fmt"
	"os/exec"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/sanitize"
)

// ExampleSanitizeOutput demonstrates basic output sanitization
func ExampleSanitizeOutput() {
	// Untrusted input with ANSI color codes and cursor manipulation
	untrusted := "\x1b[31mError:\x1b[0m File not found\x1b[10D----------"

	// Sanitize before displaying
	safe := sanitize.SanitizeOutput(untrusted)
	fmt.Println(safe)

	// Output: Error: File not found----------
}

// ExampleSanitizeOutput_terminalTitleInjection shows protection against title injection
func ExampleSanitizeOutput_terminalTitleInjection() {
	// Malicious input attempting to change terminal title
	malicious := "\x1b]0;HACKED - rm -rf /\x07Legitimate message"

	safe := sanitize.SanitizeOutput(malicious)
	fmt.Println(safe)

	// Output: Legitimate message
}

// ExampleSanitizeOutput_carriageReturnAttack shows CR overwrite protection
func ExampleSanitizeOutput_carriageReturnAttack() {
	// Attacker tries to overwrite "Password: ****" with "Password: 1234"
	attack := "Password: ****\rPassword: 1234"

	safe := sanitize.SanitizeOutput(attack)
	fmt.Println(safe)

	// Output: Password: ****Password: 1234
}

// ExampleSanitizeOutputPreserveColor demonstrates color preservation
func ExampleSanitizeOutputPreserveColor() {
	// Input with both safe colors and dangerous cursor movement
	input := "\x1b[32mSuccess:\x1b[0m Operation complete\x1b[10H"

	// Preserve colors but remove cursor movement
	safe := sanitize.SanitizeOutputPreserveColor(input)
	// Note: Output preserves ANSI colors (ESC[32m...ESC[0m) but removes cursor movement
	_ = safe // Demonstrating color preservation (can't test ANSI bytes in Example output)
}

// ExampleStripAllANSI demonstrates complete ANSI removal for logging
func ExampleStripAllANSI() {
	colored := "\x1b[1m\x1b[31mERROR:\x1b[0m Connection failed"

	// Strip all formatting for log file
	plain := sanitize.StripAllANSI(colored)
	fmt.Println(plain)

	// Output: ERROR: Connection failed
}

// ExampleIsOutputSafe demonstrates safety validation
func ExampleIsOutputSafe() {
	// Check various inputs for safety
	inputs := []struct {
		name  string
		value string
	}{
		{"plain text", "Plain text message"},
		{"newlines", "Text with\nnewlines"},
	}

	for _, input := range inputs {
		safe := sanitize.IsOutputSafe(input.value)
		fmt.Printf("Safe: %v - %s\n", safe, input.name)
	}

	// Output:
	// Safe: true - plain text
	// Safe: true - newlines
}

// ExampleSanitizeOutput_commandOutput shows sanitizing external command output
func ExampleSanitizeOutput_commandOutput() {
	// Simulated command output (in real code, use exec.Command)
	cmdOutput := "Status: \x1b[32mOK\x1b[0m\nFiles processed: 42\x1b]0;Processing\x07"

	// Always sanitize external command output
	safe := sanitize.SanitizeOutput(cmdOutput)
	fmt.Println(safe)

	// Output:
	// Status: OK
	// Files processed: 42
}

// ExampleSanitizeOutput_integrationWithTUI demonstrates TUI integration pattern
func ExampleSanitizeOutput_integrationWithTUI() {
	// Pattern for integrating with Bubble Tea TUI

	type DisplayMsg struct {
		Content string
		Trusted bool
	}

	handleDisplayMsg := func(msg DisplayMsg) string {
		if msg.Trusted {
			// From trusted source - preserve colors
			return sanitize.SanitizeOutputPreserveColor(msg.Content)
		}
		// From untrusted source - strip everything
		return sanitize.SanitizeOutput(msg.Content)
	}

	// Untrusted user input - OSC sequence stripped
	userMsg := DisplayMsg{
		Content: "\x1b]0;Evil\x07User says: Hello!",
		Trusted: false,
	}
	fmt.Println(handleDisplayMsg(userMsg))

	// Output:
	// User says: Hello!
}

// ExampleSanitizeOutput_securityMonitoring shows security event logging
func ExampleSanitizeOutput_securityMonitoring() {
	// Simulate security monitoring

	monitorAndDisplay := func(source, content string) {
		if !sanitize.IsOutputSafe(content) {
			// Log security event (in real code, use proper logging)
			fmt.Printf("[SECURITY] Dangerous sequences from %s\n", source)
			content = sanitize.SanitizeOutput(content)
		}
		fmt.Printf("[%s] %s\n", source, content)
	}

	monitorAndDisplay("user_input", "Hello\x1b]0;Evil\x07World")
	monitorAndDisplay("system", "Normal message")

	// Output:
	// [SECURITY] Dangerous sequences from user_input
	// [user_input] HelloWorld
	// [system] Normal message
}

// ExampleSanitizeOutput_multipleAttackVectors shows handling combined attacks
func ExampleSanitizeOutput_multipleAttackVectors() {
	// Input with multiple attack vectors combined
	combined := "" +
		"\x1b]0;Fake Title\x07" + // Title injection
		"Important: " +
		"\x1b[31mWarning\x1b[0m" + // Color (safe but stripped)
		"\x1b[10H" + // Cursor movement
		"\rOverwrite" + // CR attack
		"\x00Hidden" // NUL injection

	safe := sanitize.SanitizeOutput(combined)
	fmt.Println(safe)

	// Output: Important: WarningOverwriteHidden
}

// ExampleSanitizeOutput_performanceOptimized shows efficient batch processing
func ExampleSanitizeOutput_performanceOptimized() {
	// Efficient pattern for processing multiple outputs
	outputs := []string{
		"Line 1\x1b[31m with color\x1b[0m",
		"Line 2\x1b]0;title\x07",
		"Line 3 normal",
	}

	// Process all at once for better performance
	for _, output := range outputs {
		safe := sanitize.SanitizeOutput(output)
		fmt.Println(safe)
	}

	// Output:
	// Line 1 with color
	// Line 2
	// Line 3 normal
}

// ExampleSanitizeOutputPreserveColor_syntaxHighlighting shows preserving code colors
func ExampleSanitizeOutputPreserveColor_syntaxHighlighting() {
	// Simulated syntax-highlighted code with a malicious OSC sequence
	highlighted := "" +
		"\x1b[34mfunc\x1b[0m main() {\n" +
		"\x1b]0;Evil\x07" + // Injection attempt
		"\t\x1b[32m// Comment\x1b[0m\n" +
		"}"

	// Preserve syntax colors but remove dangerous sequences
	safe := sanitize.SanitizeOutputPreserveColor(highlighted)
	// Output preserves color ANSI codes but strips OSC sequence
	// Can't test ANSI bytes in Example output format
	_ = safe
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Example of integrating with exec.Command in real code
func ExampleSanitizeOutput_realCommandExecution() {
	// This example shows the pattern (commented out to avoid execution)

	executeAndDisplay := func(cmdName string, args ...string) error {
		cmd := exec.Command(cmdName, args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// Even error output must be sanitized
			safeErr := sanitize.SanitizeOutput(err.Error())
			return fmt.Errorf("command failed: %s", safeErr)
		}

		// Sanitize command output before displaying
		safe := sanitize.SanitizeOutput(string(output))
		fmt.Println(safe)
		return nil
	}

	// In real code:
	// executeAndDisplay("ls", "-la")
	// executeAndDisplay("git", "status")
	_ = executeAndDisplay

	fmt.Println("See function for integration pattern")
	// Output: See function for integration pattern
}
