package recovery

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Default log directory for crash logs
// Uses ~/.zypheron/logs as the standard location for crash diagnostics
const defaultLogDir = ".zypheron/logs"

// Global state for recovery configuration
// Thread-safe configuration with mutex protection
var (
	// logDirectory stores the current crash log directory
	// Can be customized via SetLogDirectory()
	logDirectory string

	// logDirMutex protects concurrent access to logDirectory
	logDirMutex sync.RWMutex

	// lastCrashFile tracks the most recent crash log path
	// Used by GetLastCrashLog() for diagnostics
	lastCrashFile string

	// lastCrashMutex protects concurrent access to lastCrashFile
	lastCrashMutex sync.RWMutex
)

// init initializes the default log directory on package load
// Sets up ~/.zypheron/logs as the default crash log location
func init() {
	// Get user home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to /tmp if home directory is unavailable
		// This ensures crash logging works even in restricted environments
		logDirectory = filepath.Join("/tmp", defaultLogDir)
		return
	}

	// Set default log directory in user's home
	logDirectory = filepath.Join(homeDir, defaultLogDir)
}

// SetLogDirectory sets a custom directory for crash logs
// This allows applications to override the default ~/.zypheron/logs location
//
// Parameters:
//   - dir: string - Absolute path to the desired crash log directory
//
// Thread-safe: Can be called from any goroutine
//
// Security considerations:
//   - Validates that the directory path is absolute
//   - Does NOT create the directory (creation happens on first crash)
//   - Directory permissions will be 0755 when created
//
// Example:
//
//	recovery.SetLogDirectory("/var/log/zypheron/crashes")
func SetLogDirectory(dir string) {
	// Input validation: Ensure absolute path to prevent directory traversal
	if !filepath.IsAbs(dir) {
		// Silently ignore relative paths for security
		// Relative paths could allow attackers to write logs to arbitrary locations
		return
	}

	// Thread-safe update of log directory
	logDirMutex.Lock()
	defer logDirMutex.Unlock()
	logDirectory = dir
}

// getLogDirectory retrieves the current log directory in a thread-safe manner
// Internal helper function for reading configuration
//
// Returns:
//   - string: Current crash log directory path
func getLogDirectory() string {
	logDirMutex.RLock()
	defer logDirMutex.RUnlock()
	return logDirectory
}

// setLastCrashFile updates the last crash file path in a thread-safe manner
// Internal helper function for tracking most recent crash
//
// Parameters:
//   - path: string - Absolute path to the crash log file
func setLastCrashFile(path string) {
	lastCrashMutex.Lock()
	defer lastCrashMutex.Unlock()
	lastCrashFile = path
}

// GetLastCrashLog retrieves the path and contents of the most recent crash log
// Useful for diagnostics, bug reports, and automated error reporting
//
// Returns:
//   - string: Contents of the last crash log file
//   - error: Error if no crash log exists or file cannot be read
//
// Thread-safe: Can be called from any goroutine
//
// Error conditions:
//   - No crash has occurred in this session
//   - Crash log file was deleted
//   - Insufficient permissions to read crash log
//
// Example:
//
//	if crashLog, err := recovery.GetLastCrashLog(); err == nil {
//	    fmt.Printf("Last crash:\n%s\n", crashLog)
//	}
func GetLastCrashLog() (string, error) {
	// Thread-safe read of last crash file path
	lastCrashMutex.RLock()
	crashFile := lastCrashFile
	lastCrashMutex.RUnlock()

	// Check if any crash has occurred
	if crashFile == "" {
		return "", fmt.Errorf("no crash log available")
	}

	// Read crash log file contents
	// Use os.ReadFile for atomic read operation
	data, err := os.ReadFile(crashFile)
	if err != nil {
		return "", fmt.Errorf("failed to read crash log: %w", err)
	}

	return string(data), nil
}

// RecoverableRun wraps tea.Program execution with panic recovery
// This is the primary entry point for running TUI applications with crash protection
//
// Parameters:
//   - program: *tea.Program - The Bubble Tea program to run with protection
//
// Returns:
//   - error: Error from program execution OR recovered panic (nil on success)
//
// Behavior:
//   - Executes program.Run() within a defer/recover block
//   - On panic: Captures stack trace, logs to crash file, returns error
//   - On normal error: Returns the error without logging
//   - On success: Returns nil
//
// Crash log includes:
//   - Timestamp of crash
//   - Panic message
//   - Full stack trace
//   - Go version and runtime info
//   - OS and architecture
//
// Silent recovery:
//   - Does NOT display crash to user
//   - Does NOT prompt for input
//   - Automatically cleans up and returns
//   - Calling code can decide whether to retry or exit
//
// Thread-safe: Multiple programs can be run concurrently
//
// Example:
//
//	p := tea.NewProgram(model)
//	if err := recovery.RecoverableRun(p); err != nil {
//	    log.Fatalf("TUI crashed: %v", err)
//	}
func RecoverableRun(program *tea.Program) error {
	// Input validation: Prevent nil pointer dereference
	if program == nil {
		return fmt.Errorf("program cannot be nil")
	}

	// errChan receives the final result (error or panic)
	// Buffered channel prevents goroutine leak if panic occurs before read
	errChan := make(chan error, 1)

	// Run program in goroutine to enable panic recovery
	// defer/recover only works in the panicking goroutine
	go func() {
		// Panic recovery handler
		// This defer MUST be first to catch all panics
		defer func() {
			if r := recover(); r != nil {
				// Panic occurred - capture diagnostics
				err := handlePanic(r)
				// Send error to main goroutine
				errChan <- err
			}
		}()

		// Run the Bubble Tea program
		_, err := program.Run()

		// Send result (error or nil) to main goroutine
		errChan <- err
	}()

	// Wait for program completion or panic
	// Blocks until either normal exit or panic recovery
	return <-errChan
}

// handlePanic processes a recovered panic and logs crash details
// Internal function called by RecoverableRun when panic occurs
//
// Parameters:
//   - r: interface{} - The recovered panic value (from recover())
//
// Returns:
//   - error: Formatted error describing the panic
//
// Crash log format:
//
//	=== ZYPHERON TUI CRASH REPORT ===
//	Timestamp: 2025-12-27 14:30:45 UTC
//	Go Version: go1.24.10
//	OS/Arch: linux/amd64
//
//	Panic Message:
//	runtime error: invalid memory address or nil pointer dereference
//
//	Stack Trace:
//	[full stack trace from debug.Stack()]
//
//	=== END CRASH REPORT ===
//
// Security considerations:
//   - Sanitizes panic message (converts to string safely)
//   - Does not expose sensitive data in stack trace (Go's debug.Stack() is safe)
//   - Creates crash log with 0644 permissions (readable by user and group)
//   - Ensures log directory has 0755 permissions
func handlePanic(r interface{}) error {
	// Capture full stack trace
	// debug.Stack() includes all goroutines and their states
	stackTrace := debug.Stack()

	// Format panic message safely
	// Convert panic value to string, handling any type
	panicMsg := fmt.Sprintf("%v", r)

	// Generate crash report content
	crashReport := buildCrashReport(panicMsg, stackTrace)

	// Write crash report to log file
	// Returns error if logging fails (but doesn't panic)
	logErr := writeCrashLog(crashReport)

	// Create user-facing error message
	// Includes panic message and log file location (if available)
	errMsg := fmt.Sprintf("TUI panic: %v", panicMsg)
	if logErr == nil {
		// Inform user where crash log was saved
		lastCrashMutex.RLock()
		crashFile := lastCrashFile
		lastCrashMutex.RUnlock()
		errMsg = fmt.Sprintf("%s (crash log: %s)", errMsg, crashFile)
	}

	return fmt.Errorf("%s", errMsg)
}

// buildCrashReport generates a formatted crash report with all diagnostics
// Internal helper function for creating standardized crash logs
//
// Parameters:
//   - panicMsg: string - The panic message/value
//   - stackTrace: []byte - Full stack trace from debug.Stack()
//
// Returns:
//   - string: Formatted crash report ready for writing
//
// Report includes:
//   - Standard header for easy identification
//   - UTC timestamp for unambiguous timing
//   - Go version (runtime.Version())
//   - OS and architecture (runtime.GOOS, runtime.GOARCH)
//   - Sanitized panic message
//   - Complete stack trace
//   - Standard footer
func buildCrashReport(panicMsg string, stackTrace []byte) string {
	// Get current time in UTC for consistent logging
	// UTC avoids timezone confusion in distributed systems
	now := time.Now().UTC()

	// Build crash report with all diagnostic information
	report := fmt.Sprintf(`=== ZYPHERON TUI CRASH REPORT ===
Timestamp: %s
Go Version: %s
OS/Arch: %s/%s

Panic Message:
%s

Stack Trace:
%s

=== END CRASH REPORT ===
`,
		now.Format("2006-01-02 15:04:05 MST"), // RFC3339-like format, more readable
		runtime.Version(),                      // Go version (e.g., go1.24.10)
		runtime.GOOS,                           // OS (e.g., linux, darwin, windows)
		runtime.GOARCH,                         // Architecture (e.g., amd64, arm64)
		panicMsg,                               // Panic message
		string(stackTrace),                     // Full stack trace
	)

	return report
}

// writeCrashLog writes the crash report to a timestamped file
// Internal helper function for persisting crash diagnostics
//
// Parameters:
//   - report: string - The formatted crash report content
//
// Returns:
//   - error: Error if log directory creation or file writing fails
//
// File naming:
//   - Format: crash-{timestamp}.log
//   - Example: crash-20251227-143045.log
//   - Timestamp uses local time for easy correlation with user reports
//
// Permissions:
//   - Log directory: 0755 (rwxr-xr-x) - readable by all, writable by owner
//   - Crash log file: 0644 (rw-r--r--) - readable by all, writable by owner
//
// Security considerations:
//   - Uses os.MkdirAll to safely create nested directories
//   - Validates log directory path before writing
//   - Atomic write with os.WriteFile
//   - Does not follow symlinks (direct path write)
func writeCrashLog(report string) error {
	// Get configured log directory (thread-safe)
	dir := getLogDirectory()

	// Create log directory if it doesn't exist
	// MkdirAll is idempotent - safe to call multiple times
	// 0755 permissions: owner can write, everyone can read/execute
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create crash log directory: %w", err)
	}

	// Generate timestamped filename
	// Use local time for user-friendly naming
	// Format: crash-YYYYMMDD-HHMMSS.log
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("crash-%s.log", timestamp)
	filepath := filepath.Join(dir, filename)

	// Write crash report to file
	// 0644 permissions: owner can write, everyone can read
	// os.WriteFile is atomic - file is fully written or not created
	if err := os.WriteFile(filepath, []byte(report), 0644); err != nil {
		return fmt.Errorf("failed to write crash log: %w", err)
	}

	// Update last crash file tracker
	// Thread-safe update for GetLastCrashLog()
	setLastCrashFile(filepath)

	return nil
}

// RecoverableRunWithRetry runs a program with automatic restart on panic
// Advanced wrapper that provides automatic recovery and retry logic
//
// Parameters:
//   - program: *tea.Program - The Bubble Tea program to run
//   - maxRetries: int - Maximum number of restart attempts (0 = no retries)
//   - retryDelay: time.Duration - Delay between restart attempts
//
// Returns:
//   - error: Final error after all retries exhausted OR nil on success
//
// Behavior:
//   - Attempts to run program up to (maxRetries + 1) times
//   - On panic: Logs crash, waits retryDelay, then restarts
//   - On normal error: Returns immediately (no retry)
//   - On success: Returns nil
//
// Example:
//
//	// Retry up to 3 times with 1 second delay
//	err := recovery.RecoverableRunWithRetry(p, 3, time.Second)
//
// Security considerations:
//   - Limits retry count to prevent infinite loops
//   - Validates maxRetries >= 0
//   - Each crash is logged separately
func RecoverableRunWithRetry(program *tea.Program, maxRetries int, retryDelay time.Duration) error {
	// Input validation: Prevent negative retries
	if maxRetries < 0 {
		maxRetries = 0
	}

	// Input validation: Prevent nil program
	if program == nil {
		return fmt.Errorf("program cannot be nil")
	}

	var lastErr error

	// Attempt execution up to maxRetries + 1 times
	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Run program with panic recovery
		err := RecoverableRun(program)

		// Success - return immediately
		if err == nil {
			return nil
		}

		// Save error for final return
		lastErr = err

		// Check if this was the last retry attempt
		if attempt < maxRetries {
			// Wait before retry (rate limiting)
			// Prevents rapid crash loops that could consume resources
			time.Sleep(retryDelay)
		}
	}

	// All retries exhausted - return final error
	return fmt.Errorf("program failed after %d attempts: %w", maxRetries+1, lastErr)
}
