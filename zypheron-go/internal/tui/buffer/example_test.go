package buffer_test

import (
	"fmt"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/buffer"
)

// Example_basicUsage demonstrates basic ring buffer operations
func Example_basicUsage() {
	// Create a ring buffer with capacity for 100 log lines
	rb := buffer.NewRingBuffer(100)

	// Write some log lines
	rb.Write("Application started", buffer.LevelInfo)
	rb.Write("Configuration loaded", buffer.LevelSuccess)
	rb.Write("Warning: low memory", buffer.LevelWarn)
	rb.Write("Critical error occurred", buffer.LevelError)

	// Check buffer size
	fmt.Printf("Buffer contains %d lines (capacity: %d)\n", rb.Len(), rb.Capacity())

	// Read first 2 lines
	lines := rb.Read(0, 2)
	for _, line := range lines {
		fmt.Printf("[%s] %s\n", line.Level, line.Content)
	}

	// Output:
	// Buffer contains 4 lines (capacity: 100)
	// [info] Application started
	// [success] Configuration loaded
}

// Example_circularOverwrite demonstrates ring buffer wrap-around behavior
func Example_circularOverwrite() {
	// Create a small buffer that holds only 3 lines
	rb := buffer.NewRingBuffer(3)

	// Write 5 lines (will overwrite oldest 2)
	rb.Write("Line 1", buffer.LevelInfo)
	rb.Write("Line 2", buffer.LevelInfo)
	rb.Write("Line 3", buffer.LevelInfo)
	rb.Write("Line 4", buffer.LevelInfo) // Overwrites Line 1
	rb.Write("Line 5", buffer.LevelInfo) // Overwrites Line 2

	// Buffer now contains: Line 3, Line 4, Line 5
	lines := rb.ExportLines()
	for i, line := range lines {
		fmt.Printf("Position %d: %s\n", i, line.Content)
	}

	// Output:
	// Position 0: Line 3
	// Position 1: Line 4
	// Position 2: Line 5
}

// Example_customTimestamp demonstrates using custom timestamps
func Example_customTimestamp() {
	rb := buffer.NewRingBuffer(10)

	// Write a log line with a specific timestamp (e.g., from a log file)
	pastTime := time.Date(2025, 12, 27, 10, 30, 0, 0, time.UTC)
	rb.WriteWithTimestamp("Historical event", buffer.LevelInfo, pastTime)

	// Regular write uses current time
	rb.Write("Current event", buffer.LevelInfo)

	lines := rb.ExportLines()
	for _, line := range lines {
		fmt.Printf("%s: %s\n", line.Timestamp.Format("2006-01-02 15:04:05"), line.Content)
	}
}

// Example_export demonstrates exporting buffer contents
func Example_export() {
	rb := buffer.NewRingBuffer(10)

	// Add some log entries with known timestamp for consistent output
	ts := time.Date(2025, 12, 27, 14, 30, 0, 0, time.UTC)
	rb.WriteWithTimestamp("Server started", buffer.LevelInfo, ts)
	rb.WriteWithTimestamp("Database connected", buffer.LevelSuccess, ts.Add(time.Second))
	rb.WriteWithTimestamp("API ready", buffer.LevelInfo, ts.Add(2*time.Second))

	// Export as formatted string (suitable for saving to file)
	exported := rb.Export()
	fmt.Print(exported)

	// Output:
	// [2025-12-27 14:30:00] [info] Server started
	// [2025-12-27 14:30:01] [success] Database connected
	// [2025-12-27 14:30:02] [info] API ready
}

// Example_concurrentUsage demonstrates thread-safe concurrent access
func Example_concurrentUsage() {
	rb := buffer.NewRingBuffer(1000)

	// Safe to write from multiple goroutines
	go func() {
		for i := 0; i < 100; i++ {
			rb.Write(fmt.Sprintf("Worker 1 - task %d", i), buffer.LevelInfo)
		}
	}()

	go func() {
		for i := 0; i < 100; i++ {
			rb.Write(fmt.Sprintf("Worker 2 - task %d", i), buffer.LevelInfo)
		}
	}()

	// Safe to read while writing
	go func() {
		for i := 0; i < 10; i++ {
			lines := rb.Read(0, 10)
			_ = lines // Process lines
		}
	}()

	// All operations are thread-safe
	time.Sleep(100 * time.Millisecond)
	fmt.Printf("Final buffer size: %d\n", rb.Len())
}

// Example_clear demonstrates clearing the buffer
func Example_clear() {
	rb := buffer.NewRingBuffer(100)

	// Add entries
	rb.Write("Entry 1", buffer.LevelInfo)
	rb.Write("Entry 2", buffer.LevelInfo)
	rb.Write("Entry 3", buffer.LevelInfo)

	fmt.Printf("Before clear: %d lines\n", rb.Len())

	// Clear all entries
	rb.Clear()

	fmt.Printf("After clear: %d lines\n", rb.Len())

	// Buffer is ready for new entries
	rb.Write("New entry", buffer.LevelInfo)
	fmt.Printf("After new write: %d lines\n", rb.Len())

	// Output:
	// Before clear: 3 lines
	// After clear: 0 lines
	// After new write: 1 lines
}
