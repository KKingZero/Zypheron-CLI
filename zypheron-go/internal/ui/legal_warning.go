package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ExploitWarningState tracks whether the warning has been acknowledged this session
var (
	exploitWarningAcknowledged bool
	exploitWarningMutex        sync.Mutex
	exploitWarningTime         time.Time
)

// ExploitWarningBanner returns the legal warning banner for exploitation mode
func ExploitWarningBanner() string {
	return Danger.Sprint(`
╔═══════════════════════════════════════════════════════════════════╗
║                    ⚠️  ENTERING EXPLOITATION MODE                  ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                    ║
║  You are about to execute exploitation/post-exploitation tools.   ║
║                                                                    ║
║  By proceeding, you confirm:                                       ║
║    ✓ You have explicit written authorization to test this target  ║
║    ✓ You understand the legal implications of these actions       ║
║    ✓ You accept full responsibility for your actions              ║
║                                                                    ║
║  Unauthorized access to computer systems is illegal and may       ║
║  result in criminal prosecution under laws including:             ║
║    • Computer Fraud and Abuse Act (CFAA) - USA                    ║
║    • Computer Misuse Act - UK                                      ║
║    • Similar laws in other jurisdictions                          ║
║                                                                    ║
║  `) + Warning.Sprint("This warning will be shown once per session.") + Danger.Sprint(`                   ║
║                                                                    ║
╚═══════════════════════════════════════════════════════════════════╝
`)
}

// CheckExploitWarningAcknowledged returns whether the warning has been acknowledged
func CheckExploitWarningAcknowledged() bool {
	exploitWarningMutex.Lock()
	defer exploitWarningMutex.Unlock()
	return exploitWarningAcknowledged
}

// SetExploitWarningAcknowledged marks the warning as acknowledged
func SetExploitWarningAcknowledged() {
	exploitWarningMutex.Lock()
	defer exploitWarningMutex.Unlock()
	exploitWarningAcknowledged = true
	exploitWarningTime = time.Now()
}

// GetExploitWarningTime returns when the warning was acknowledged
func GetExploitWarningTime() time.Time {
	exploitWarningMutex.Lock()
	defer exploitWarningMutex.Unlock()
	return exploitWarningTime
}

// ShowExploitWarning displays the warning and prompts for acknowledgment
// Returns true if user acknowledged, false if they declined
// If already acknowledged this session, returns true immediately
func ShowExploitWarning() bool {
	// Check if already acknowledged this session
	if CheckExploitWarningAcknowledged() {
		return true
	}

	// Display the warning banner
	fmt.Println(ExploitWarningBanner())

	// Prompt for acknowledgment
	fmt.Printf("\n%s ", Warning.Sprint("Do you understand and accept these terms? [y/N]:"))

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println(Error("Failed to read response"))
		return false
	}

	response = strings.TrimSpace(strings.ToLower(response))

	if response == "y" || response == "yes" {
		SetExploitWarningAcknowledged()
		fmt.Println()
		fmt.Println(WarningMsg("Acknowledgment recorded. Proceeding with exploitation mode."))
		fmt.Println(Muted.Sprint(fmt.Sprintf("Session acknowledgment time: %s", time.Now().Format(time.RFC3339))))
		fmt.Println()
		return true
	}

	fmt.Println()
	fmt.Println(InfoMsg("Operation cancelled. No exploitation actions were performed."))
	return false
}

// ShowExploitWarningNonInteractive displays a warning for non-interactive mode
// and logs the acknowledgment if --yes flag was used
func ShowExploitWarningNonInteractive(assumeYes bool) bool {
	// Check if already acknowledged this session
	if CheckExploitWarningAcknowledged() {
		return true
	}

	// In non-interactive mode with --yes, show abbreviated warning
	if assumeYes {
		fmt.Println(WarningMsg("EXPLOITATION MODE - Legal terms auto-accepted via --yes flag"))
		fmt.Println(Danger.Sprint("  ⚠️  Ensure you have authorization to test the target"))
		SetExploitWarningAcknowledged()
		return true
	}

	// Non-interactive without --yes = cannot proceed
	fmt.Println(Error("Exploitation mode requires explicit acknowledgment"))
	fmt.Println(InfoMsg("Run interactively or use --yes flag to accept legal terms"))
	return false
}

// ResetExploitWarning resets the warning state (for testing purposes)
func ResetExploitWarning() {
	exploitWarningMutex.Lock()
	defer exploitWarningMutex.Unlock()
	exploitWarningAcknowledged = false
	exploitWarningTime = time.Time{}
}
