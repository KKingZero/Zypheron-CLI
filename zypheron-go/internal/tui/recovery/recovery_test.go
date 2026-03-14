package recovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func hasTTY() bool {
	_, err := os.Open("/dev/tty")
	return err == nil
}

// testModel is a simple Bubble Tea model for testing
type testModel struct {
	shouldPanic bool
	panicMsg    string
}

func (m testModel) Init() tea.Cmd {
	return nil
}

func (m testModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Trigger panic if configured
	if m.shouldPanic {
		panic(m.panicMsg)
	}
	return m, tea.Quit
}

func (m testModel) View() string {
	return "test"
}

// TestRecoverableRun_Success tests successful program execution
func TestRecoverableRun_Success(t *testing.T) {
	if !hasTTY() {
		t.Skip("skipping: no TTY available")
	}
	// Create a program that completes normally
	model := testModel{shouldPanic: false}
	program := tea.NewProgram(model, tea.WithoutRenderer())

	// Run with recovery wrapper
	err := RecoverableRun(program)

	// Should complete without error
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
}

// TestRecoverableRun_Panic tests panic recovery and logging
func TestRecoverableRun_Panic(t *testing.T) {
	if !hasTTY() {
		t.Skip("skipping: no TTY available")
	}
	// Setup: Create temporary directory for crash logs
	tempDir := t.TempDir()
	SetLogDirectory(tempDir)

	// Create a program that panics
	panicMessage := "test panic message"
	model := testModel{shouldPanic: true, panicMsg: panicMessage}
	program := tea.NewProgram(model, tea.WithoutRenderer())

	// Run with recovery wrapper
	err := RecoverableRun(program)

	// Should return error with panic message
	if err == nil {
		t.Fatal("Expected error from panic, got nil")
	}

	// Error should contain panic message
	if !strings.Contains(err.Error(), panicMessage) {
		t.Errorf("Error should contain panic message '%s', got: %v", panicMessage, err)
	}

	// Crash log should be created
	crashLog, err := GetLastCrashLog()
	if err != nil {
		t.Fatalf("Failed to get crash log: %v", err)
	}

	// Verify crash log contents
	if !strings.Contains(crashLog, panicMessage) {
		t.Errorf("Crash log should contain panic message '%s'", panicMessage)
	}
	if !strings.Contains(crashLog, "ZYPHERON TUI CRASH REPORT") {
		t.Error("Crash log should contain header")
	}
	if !strings.Contains(crashLog, "Stack Trace:") {
		t.Error("Crash log should contain stack trace")
	}

	// Verify crash log file exists on disk
	lastCrashMutex.RLock()
	crashFile := lastCrashFile
	lastCrashMutex.RUnlock()

	if _, err := os.Stat(crashFile); os.IsNotExist(err) {
		t.Error("Crash log file should exist on disk")
	}
}

// TestRecoverableRun_NilProgram tests nil program validation
func TestRecoverableRun_NilProgram(t *testing.T) {
	err := RecoverableRun(nil)

	if err == nil {
		t.Fatal("Expected error for nil program, got nil")
	}

	if !strings.Contains(err.Error(), "program cannot be nil") {
		t.Errorf("Error should indicate nil program, got: %v", err)
	}
}

// TestSetLogDirectory tests custom log directory configuration
func TestSetLogDirectory(t *testing.T) {
	// Test valid absolute path
	testDir := "/tmp/test-crash-logs"
	SetLogDirectory(testDir)

	// Verify directory was set
	currentDir := getLogDirectory()
	if currentDir != testDir {
		t.Errorf("Expected log directory '%s', got '%s'", testDir, currentDir)
	}

	// Test relative path (should be ignored for security)
	originalDir := getLogDirectory()
	SetLogDirectory("relative/path")

	// Directory should remain unchanged
	if getLogDirectory() != originalDir {
		t.Error("Relative paths should be ignored")
	}
}

// TestGetLastCrashLog_NoCrash tests behavior when no crash has occurred
func TestGetLastCrashLog_NoCrash(t *testing.T) {
	// Reset last crash file
	setLastCrashFile("")

	_, err := GetLastCrashLog()

	if err == nil {
		t.Fatal("Expected error when no crash log exists, got nil")
	}

	if !strings.Contains(err.Error(), "no crash log available") {
		t.Errorf("Error should indicate no crash log, got: %v", err)
	}
}

// TestBuildCrashReport tests crash report formatting
func TestBuildCrashReport(t *testing.T) {
	panicMsg := "test panic"
	stackTrace := []byte("goroutine 1:\ntest stack trace")

	report := buildCrashReport(panicMsg, stackTrace)

	// Verify required sections
	requiredSections := []string{
		"ZYPHERON TUI CRASH REPORT",
		"Timestamp:",
		"Go Version:",
		"OS/Arch:",
		"Panic Message:",
		panicMsg,
		"Stack Trace:",
		"test stack trace",
		"END CRASH REPORT",
	}

	for _, section := range requiredSections {
		if !strings.Contains(report, section) {
			t.Errorf("Crash report missing section: %s", section)
		}
	}
}

// TestWriteCrashLog tests crash log file writing
func TestWriteCrashLog(t *testing.T) {
	// Setup: Create temporary directory
	tempDir := t.TempDir()
	SetLogDirectory(tempDir)

	// Write crash log
	testReport := "test crash report content"
	err := writeCrashLog(testReport)

	if err != nil {
		t.Fatalf("Failed to write crash log: %v", err)
	}

	// Verify file was created
	lastCrashMutex.RLock()
	crashFile := lastCrashFile
	lastCrashMutex.RUnlock()

	if crashFile == "" {
		t.Fatal("Last crash file should be set")
	}

	// Verify file exists
	if _, err := os.Stat(crashFile); os.IsNotExist(err) {
		t.Fatal("Crash log file should exist")
	}

	// Verify file contents
	content, err := os.ReadFile(crashFile)
	if err != nil {
		t.Fatalf("Failed to read crash log: %v", err)
	}

	if string(content) != testReport {
		t.Errorf("Crash log content mismatch. Expected: %s, Got: %s", testReport, string(content))
	}

	// Verify filename format
	filename := filepath.Base(crashFile)
	if !strings.HasPrefix(filename, "crash-") {
		t.Errorf("Crash log filename should start with 'crash-', got: %s", filename)
	}
	if !strings.HasSuffix(filename, ".log") {
		t.Errorf("Crash log filename should end with '.log', got: %s", filename)
	}
}

// TestRecoverableRunWithRetry_Success tests successful execution with retry wrapper
func TestRecoverableRunWithRetry_Success(t *testing.T) {
	if !hasTTY() {
		t.Skip("skipping: no TTY available")
	}
	model := testModel{shouldPanic: false}
	program := tea.NewProgram(model, tea.WithoutRenderer())

	err := RecoverableRunWithRetry(program, 3, 100*time.Millisecond)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
}

// TestRecoverableRunWithRetry_Panic tests retry behavior on panic
func TestRecoverableRunWithRetry_Panic(t *testing.T) {
	if !hasTTY() {
		t.Skip("skipping: no TTY available")
	}
	// Setup: Create temporary directory for crash logs
	tempDir := t.TempDir()
	SetLogDirectory(tempDir)

	// Create a program that always panics
	model := testModel{shouldPanic: true, panicMsg: "persistent panic"}
	program := tea.NewProgram(model, tea.WithoutRenderer())

	// Run with retries
	maxRetries := 2
	startTime := time.Now()
	err := RecoverableRunWithRetry(program, maxRetries, 50*time.Millisecond)
	duration := time.Since(startTime)

	// Should fail after all retries
	if err == nil {
		t.Fatal("Expected error after retries, got nil")
	}

	// Error should indicate number of attempts
	if !strings.Contains(err.Error(), "after") {
		t.Errorf("Error should indicate retry attempts, got: %v", err)
	}

	// Should have taken at least maxRetries * retryDelay
	minDuration := time.Duration(maxRetries) * 50 * time.Millisecond
	if duration < minDuration {
		t.Errorf("Should have waited for retries. Expected >= %v, got %v", minDuration, duration)
	}
}

// TestRecoverableRunWithRetry_NilProgram tests nil program validation
func TestRecoverableRunWithRetry_NilProgram(t *testing.T) {
	err := RecoverableRunWithRetry(nil, 3, time.Second)

	if err == nil {
		t.Fatal("Expected error for nil program, got nil")
	}

	if !strings.Contains(err.Error(), "program cannot be nil") {
		t.Errorf("Error should indicate nil program, got: %v", err)
	}
}

// TestRecoverableRunWithRetry_NegativeRetries tests negative retry validation
func TestRecoverableRunWithRetry_NegativeRetries(t *testing.T) {
	model := testModel{shouldPanic: true, panicMsg: "test"}
	program := tea.NewProgram(model, tea.WithoutRenderer())

	// Setup temp directory
	tempDir := t.TempDir()
	SetLogDirectory(tempDir)

	// Negative retries should be treated as 0 (single attempt)
	startTime := time.Now()
	err := RecoverableRunWithRetry(program, -5, 100*time.Millisecond)
	duration := time.Since(startTime)

	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	// Should complete quickly (no retries)
	if duration > 500*time.Millisecond {
		t.Errorf("Should not retry with negative maxRetries. Duration: %v", duration)
	}
}

// TestConcurrentRecovery tests thread safety of concurrent panic recovery
func TestConcurrentRecovery(t *testing.T) {
	if !hasTTY() {
		t.Skip("skipping: no TTY available")
	}
	// Setup: Create temporary directory for crash logs
	tempDir := t.TempDir()
	SetLogDirectory(tempDir)

	// Run multiple programs concurrently, some panicking
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			shouldPanic := id%2 == 0
			model := testModel{
				shouldPanic: shouldPanic,
				panicMsg:    "concurrent panic",
			}
			program := tea.NewProgram(model, tea.WithoutRenderer())
			_ = RecoverableRun(program)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify crash log was created (at least one panic should have occurred)
	crashLog, err := GetLastCrashLog()
	if err != nil {
		t.Fatalf("Expected crash log from concurrent panics: %v", err)
	}

	if !strings.Contains(crashLog, "concurrent panic") {
		t.Error("Crash log should contain panic message from concurrent execution")
	}
}

// BenchmarkRecoverableRun_NoPanic benchmarks overhead of recovery wrapper
func BenchmarkRecoverableRun_NoPanic(b *testing.B) {
	model := testModel{shouldPanic: false}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		program := tea.NewProgram(model, tea.WithoutRenderer())
		_ = RecoverableRun(program)
	}
}

// BenchmarkRecoverableRun_Panic benchmarks panic recovery performance
func BenchmarkRecoverableRun_Panic(b *testing.B) {
	// Setup: Create temporary directory for crash logs
	tempDir := b.TempDir()
	SetLogDirectory(tempDir)

	model := testModel{shouldPanic: true, panicMsg: "benchmark panic"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		program := tea.NewProgram(model, tea.WithoutRenderer())
		_ = RecoverableRun(program)
	}
}
