package buffer

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestNewRingBuffer verifies buffer initialization
func TestNewRingBuffer(t *testing.T) {
	tests := []struct {
		name             string
		capacity         int
		expectedCapacity int
	}{
		{
			name:             "positive capacity",
			capacity:         100,
			expectedCapacity: 100,
		},
		{
			name:             "zero capacity uses default",
			capacity:         0,
			expectedCapacity: DefaultCapacity,
		},
		{
			name:             "negative capacity uses default",
			capacity:         -50,
			expectedCapacity: DefaultCapacity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb := NewRingBuffer(tt.capacity)
			if rb == nil {
				t.Fatal("NewRingBuffer returned nil")
			}
			if rb.Capacity() != tt.expectedCapacity {
				t.Errorf("capacity = %d, want %d", rb.Capacity(), tt.expectedCapacity)
			}
			if rb.Len() != 0 {
				t.Errorf("initial length = %d, want 0", rb.Len())
			}
		})
	}
}

// TestWrite verifies basic write operations
func TestWrite(t *testing.T) {
	rb := NewRingBuffer(5)

	// Write single entry
	rb.Write("test line 1", LevelInfo)
	if rb.Len() != 1 {
		t.Errorf("length after 1 write = %d, want 1", rb.Len())
	}

	// Write multiple entries
	rb.Write("test line 2", LevelWarn)
	rb.Write("test line 3", LevelError)
	if rb.Len() != 3 {
		t.Errorf("length after 3 writes = %d, want 3", rb.Len())
	}
}

// TestWriteWithTimestamp verifies custom timestamp handling
func TestWriteWithTimestamp(t *testing.T) {
	rb := NewRingBuffer(10)
	ts := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	rb.WriteWithTimestamp("timestamped line", LevelSuccess, ts)

	lines := rb.ExportLines()
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	if !lines[0].Timestamp.Equal(ts) {
		t.Errorf("timestamp = %v, want %v", lines[0].Timestamp, ts)
	}
}

// TestCircularOverwrite verifies oldest entries are overwritten
func TestCircularOverwrite(t *testing.T) {
	capacity := 3
	rb := NewRingBuffer(capacity)

	// Fill buffer
	rb.Write("line 1", LevelInfo)
	rb.Write("line 2", LevelInfo)
	rb.Write("line 3", LevelInfo)

	if rb.Len() != capacity {
		t.Errorf("length = %d, want %d", rb.Len(), capacity)
	}

	// Overwrite oldest
	rb.Write("line 4", LevelInfo)
	rb.Write("line 5", LevelInfo)

	if rb.Len() != capacity {
		t.Errorf("length after overwrite = %d, want %d", rb.Len(), capacity)
	}

	// Verify oldest entries were overwritten
	lines := rb.ExportLines()
	if lines[0].Content != "line 3" {
		t.Errorf("oldest line = %q, want %q", lines[0].Content, "line 3")
	}
	if lines[1].Content != "line 4" {
		t.Errorf("middle line = %q, want %q", lines[1].Content, "line 4")
	}
	if lines[2].Content != "line 5" {
		t.Errorf("newest line = %q, want %q", lines[2].Content, "line 5")
	}
}

// TestRead verifies reading with various offsets and counts
func TestRead(t *testing.T) {
	rb := NewRingBuffer(10)
	for i := 1; i <= 5; i++ {
		rb.Write(fmt.Sprintf("line %d", i), LevelInfo)
	}

	tests := []struct {
		name     string
		offset   int
		count    int
		expected []string
	}{
		{
			name:     "read from start",
			offset:   0,
			count:    2,
			expected: []string{"line 1", "line 2"},
		},
		{
			name:     "read from middle",
			offset:   2,
			count:    2,
			expected: []string{"line 3", "line 4"},
		},
		{
			name:     "read beyond available",
			offset:   3,
			count:    10,
			expected: []string{"line 4", "line 5"},
		},
		{
			name:     "invalid negative offset",
			offset:   -1,
			count:    5,
			expected: []string{},
		},
		{
			name:     "offset beyond size",
			offset:   10,
			count:    5,
			expected: []string{},
		},
		{
			name:     "zero count",
			offset:   0,
			count:    0,
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := rb.Read(tt.offset, tt.count)
			if len(lines) != len(tt.expected) {
				t.Errorf("read returned %d lines, want %d", len(lines), len(tt.expected))
				return
			}
			for i, expected := range tt.expected {
				if lines[i].Content != expected {
					t.Errorf("line[%d] = %q, want %q", i, lines[i].Content, expected)
				}
			}
		})
	}
}

// TestReadAfterOverwrite verifies reading after circular overwrite
func TestReadAfterOverwrite(t *testing.T) {
	rb := NewRingBuffer(3)

	// Fill and overwrite
	for i := 1; i <= 5; i++ {
		rb.Write(fmt.Sprintf("line %d", i), LevelInfo)
	}

	// Should have lines 3, 4, 5
	lines := rb.Read(0, 3)
	expected := []string{"line 3", "line 4", "line 5"}

	if len(lines) != len(expected) {
		t.Fatalf("read returned %d lines, want %d", len(lines), len(expected))
	}

	for i, exp := range expected {
		if lines[i].Content != exp {
			t.Errorf("line[%d] = %q, want %q", i, lines[i].Content, exp)
		}
	}
}

// TestClear verifies buffer clearing
func TestClear(t *testing.T) {
	rb := NewRingBuffer(10)

	rb.Write("line 1", LevelInfo)
	rb.Write("line 2", LevelInfo)
	rb.Write("line 3", LevelInfo)

	if rb.Len() != 3 {
		t.Errorf("length before clear = %d, want 3", rb.Len())
	}

	rb.Clear()

	if rb.Len() != 0 {
		t.Errorf("length after clear = %d, want 0", rb.Len())
	}

	lines := rb.ExportLines()
	if len(lines) != 0 {
		t.Errorf("ExportLines after clear returned %d lines, want 0", len(lines))
	}

	// Verify we can write after clear
	rb.Write("new line", LevelInfo)
	if rb.Len() != 1 {
		t.Errorf("length after write post-clear = %d, want 1", rb.Len())
	}
}

// TestExport verifies string export functionality
func TestExport(t *testing.T) {
	rb := NewRingBuffer(10)

	// Empty buffer
	if export := rb.Export(); export != "" {
		t.Errorf("export of empty buffer = %q, want empty string", export)
	}

	// Add entries with known timestamp
	ts := time.Date(2025, 12, 27, 10, 30, 0, 0, time.UTC)
	rb.WriteWithTimestamp("info message", LevelInfo, ts)
	rb.WriteWithTimestamp("error message", LevelError, ts.Add(time.Second))

	export := rb.Export()
	if export == "" {
		t.Error("export of non-empty buffer is empty")
	}

	// Verify format contains key components
	if !contains(export, "[info]") {
		t.Error("export missing info level")
	}
	if !contains(export, "[error]") {
		t.Error("export missing error level")
	}
	if !contains(export, "info message") {
		t.Error("export missing info message content")
	}
	if !contains(export, "error message") {
		t.Error("export missing error message content")
	}
}

// TestExportLines verifies slice export functionality
func TestExportLines(t *testing.T) {
	rb := NewRingBuffer(5)

	// Empty buffer
	if lines := rb.ExportLines(); len(lines) != 0 {
		t.Errorf("ExportLines on empty buffer returned %d lines, want 0", len(lines))
	}

	// Add entries
	rb.Write("line 1", LevelInfo)
	rb.Write("line 2", LevelWarn)
	rb.Write("line 3", LevelError)

	lines := rb.ExportLines()
	if len(lines) != 3 {
		t.Fatalf("ExportLines returned %d lines, want 3", len(lines))
	}

	// Verify order and content
	expected := []struct {
		content string
		level   string
	}{
		{"line 1", LevelInfo},
		{"line 2", LevelWarn},
		{"line 3", LevelError},
	}

	for i, exp := range expected {
		if lines[i].Content != exp.content {
			t.Errorf("line[%d].Content = %q, want %q", i, lines[i].Content, exp.content)
		}
		if lines[i].Level != exp.level {
			t.Errorf("line[%d].Level = %q, want %q", i, lines[i].Level, exp.level)
		}
	}
}

// TestConcurrentWrites verifies thread-safety of concurrent writes
func TestConcurrentWrites(t *testing.T) {
	rb := NewRingBuffer(1000)
	const goroutines = 10
	const writesPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Launch concurrent writers
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				rb.Write(fmt.Sprintf("goroutine %d line %d", id, j), LevelInfo)
			}
		}(i)
	}

	wg.Wait()

	// Verify expected number of entries
	expectedLen := goroutines * writesPerGoroutine
	if rb.Len() != expectedLen {
		t.Errorf("length after concurrent writes = %d, want %d", rb.Len(), expectedLen)
	}
}

// TestConcurrentReadsWrites verifies thread-safety of concurrent reads and writes
func TestConcurrentReadsWrites(t *testing.T) {
	rb := NewRingBuffer(500)
	const duration = 100 * time.Millisecond

	var wg sync.WaitGroup
	done := make(chan struct{})

	// Writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		counter := 0
		for {
			select {
			case <-done:
				return
			default:
				rb.Write(fmt.Sprintf("line %d", counter), LevelInfo)
				counter++
				time.Sleep(time.Microsecond)
			}
		}
	}()

	// Reader goroutines
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					rb.Read(0, 10)
					rb.Len()
					rb.ExportLines()
					time.Sleep(time.Microsecond)
				}
			}
		}()
	}

	// Run for specified duration
	time.Sleep(duration)
	close(done)
	wg.Wait()

	// If we got here without panics or data races, test passed
}

// TestConcurrentClearAndWrite verifies thread-safety of clear operations
func TestConcurrentClearAndWrite(t *testing.T) {
	rb := NewRingBuffer(100)
	const duration = 50 * time.Millisecond

	var wg sync.WaitGroup
	done := make(chan struct{})

	// Writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		counter := 0
		for {
			select {
			case <-done:
				return
			default:
				rb.Write(fmt.Sprintf("line %d", counter), LevelInfo)
				counter++
			}
		}
	}()

	// Clearer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				rb.Clear()
				time.Sleep(time.Millisecond)
			}
		}
	}()

	time.Sleep(duration)
	close(done)
	wg.Wait()

	// Verify buffer is in valid state
	len := rb.Len()
	cap := rb.Capacity()
	if len < 0 || len > cap {
		t.Errorf("invalid state: len=%d, cap=%d", len, cap)
	}
}

// TestLogLineLevels verifies all log level constants work
func TestLogLineLevels(t *testing.T) {
	rb := NewRingBuffer(10)

	levels := []string{LevelInfo, LevelWarn, LevelError, LevelSuccess}
	for i, level := range levels {
		rb.Write(fmt.Sprintf("message %d", i), level)
	}

	lines := rb.ExportLines()
	if len(lines) != len(levels) {
		t.Fatalf("got %d lines, want %d", len(lines), len(levels))
	}

	for i, level := range levels {
		if lines[i].Level != level {
			t.Errorf("line[%d].Level = %q, want %q", i, lines[i].Level, level)
		}
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsAtIndex(s, substr))
}

func containsAtIndex(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Benchmark tests

func BenchmarkWrite(b *testing.B) {
	rb := NewRingBuffer(10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Write("benchmark log line", LevelInfo)
	}
}

func BenchmarkRead(b *testing.B) {
	rb := NewRingBuffer(10000)
	for i := 0; i < 5000; i++ {
		rb.Write(fmt.Sprintf("line %d", i), LevelInfo)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Read(0, 100)
	}
}

func BenchmarkExportLines(b *testing.B) {
	rb := NewRingBuffer(10000)
	for i := 0; i < 10000; i++ {
		rb.Write(fmt.Sprintf("line %d", i), LevelInfo)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.ExportLines()
	}
}

func BenchmarkConcurrentWrites(b *testing.B) {
	rb := NewRingBuffer(10000)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rb.Write("concurrent log line", LevelInfo)
		}
	})
}
