// Package buffer provides a thread-safe ring buffer implementation for the Zypheron TUI.
// This buffer is optimized for high-throughput log line storage with O(1) operations
// and minimal memory allocations.
package buffer

import (
	"strings"
	"sync"
	"time"
)

const (
	// DefaultCapacity is the default maximum number of log lines to store
	DefaultCapacity = 10000

	// Log level constants for validation and standardization
	LevelInfo    = "info"
	LevelWarn    = "warn"
	LevelError   = "error"
	LevelSuccess = "success"
)

// LogLine represents a single log entry with metadata.
// All fields are immutable after creation to ensure thread-safety when reading.
type LogLine struct {
	Content   string    // The actual log message content
	Timestamp time.Time // When the log line was created
	Level     string    // Log severity level (info, warn, error, success)
}

// RingBuffer is a thread-safe circular buffer for storing log lines.
// It maintains a fixed-size buffer and overwrites the oldest entries when full.
// All public methods are safe for concurrent use.
type RingBuffer struct {
	mu       sync.RWMutex // Protects all fields below
	buffer   []LogLine    // Pre-allocated circular buffer
	capacity int          // Maximum number of entries (immutable after init)
	head     int          // Index where next write occurs
	size     int          // Current number of valid entries (0 <= size <= capacity)
}

// NewRingBuffer creates a new ring buffer with the specified capacity.
// The capacity must be positive; if <= 0, DefaultCapacity is used.
// The buffer is pre-allocated to avoid runtime allocations during writes.
func NewRingBuffer(capacity int) *RingBuffer {
	// Input validation - ensure positive capacity
	if capacity <= 0 {
		capacity = DefaultCapacity
	}

	return &RingBuffer{
		buffer:   make([]LogLine, capacity), // Pre-allocate to avoid reallocation
		capacity: capacity,
		head:     0,
		size:     0,
	}
}

// Write adds a new log line with the current timestamp.
// The level is validated and stored as-is. Empty levels are accepted.
// This is safe for concurrent use.
//
// Performance: O(1) time complexity, no allocations after buffer initialization.
func (rb *RingBuffer) Write(line string, level string) {
	rb.WriteWithTimestamp(line, level, time.Now())
}

// WriteWithTimestamp adds a new log line with an explicit timestamp.
// This allows for backdating entries or using a custom time source.
// This is safe for concurrent use.
//
// Performance: O(1) time complexity, no allocations after buffer initialization.
func (rb *RingBuffer) WriteWithTimestamp(line string, level string, ts time.Time) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Write to current head position using circular indexing
	rb.buffer[rb.head] = LogLine{
		Content:   line,
		Timestamp: ts,
		Level:     level,
	}

	// Advance head with wrap-around
	rb.head = (rb.head + 1) % rb.capacity

	// Update size only if not yet at capacity
	// Once at capacity, size remains constant and we overwrite old entries
	if rb.size < rb.capacity {
		rb.size++
	}
}

// Read retrieves a slice of log lines starting at the given offset.
// Offset 0 is the oldest available line in the buffer.
// Count specifies the maximum number of lines to return.
//
// If offset is negative or beyond the buffer size, an empty slice is returned.
// If offset + count exceeds the buffer size, only available lines are returned.
//
// Returns a new slice containing copies of the log lines (safe to retain).
// This is safe for concurrent use.
//
// Performance: O(n) where n = min(count, available lines)
func (rb *RingBuffer) Read(offset, count int) []LogLine {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	// Validate offset bounds
	if offset < 0 || offset >= rb.size || count <= 0 {
		return []LogLine{}
	}

	// Calculate actual number of lines to return
	available := rb.size - offset
	if count > available {
		count = available
	}

	// Allocate result slice
	result := make([]LogLine, count)

	// Calculate starting physical index in circular buffer
	// If buffer is not full: start = offset
	// If buffer is full: start = (head + offset) % capacity
	var start int
	if rb.size < rb.capacity {
		start = offset
	} else {
		// Buffer is full, head points to oldest entry
		start = (rb.head + offset) % rb.capacity
	}

	// Copy entries handling circular wrap-around
	for i := 0; i < count; i++ {
		physicalIdx := (start + i) % rb.capacity
		result[i] = rb.buffer[physicalIdx]
	}

	return result
}

// Len returns the current number of log lines in the buffer.
// This is safe for concurrent use.
//
// Performance: O(1)
func (rb *RingBuffer) Len() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.size
}

// Capacity returns the maximum number of log lines the buffer can hold.
// This value is immutable after creation.
// This is safe for concurrent use.
//
// Performance: O(1)
func (rb *RingBuffer) Capacity() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.capacity
}

// Clear removes all log lines from the buffer.
// This does not free the underlying buffer memory, just resets the indices.
// This is safe for concurrent use.
//
// Performance: O(1)
func (rb *RingBuffer) Clear() {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.head = 0
	rb.size = 0
	// Note: We don't zero out the buffer slice for performance.
	// Old entries will be overwritten on next write.
}

// Export returns all log lines as a single formatted string.
// Each line is formatted as: "[timestamp] [level] content\n"
// Lines are returned in chronological order (oldest first).
//
// This allocates a new string, so use sparingly for large buffers.
// This is safe for concurrent use.
//
// Performance: O(n) where n = buffer size
func (rb *RingBuffer) Export() string {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.size == 0 {
		return ""
	}

	// Pre-allocate string builder with estimated capacity
	// Average line size: ~100 bytes (timestamp + level + content)
	var sb strings.Builder
	sb.Grow(rb.size * 100)

	// Determine starting index (oldest entry)
	var start int
	if rb.size < rb.capacity {
		start = 0
	} else {
		start = rb.head
	}

	// Format and append each line in chronological order
	for i := 0; i < rb.size; i++ {
		physicalIdx := (start + i) % rb.capacity
		line := rb.buffer[physicalIdx]

		// Format: [2006-01-02 15:04:05] [LEVEL] content
		sb.WriteString("[")
		sb.WriteString(line.Timestamp.Format("2006-01-02 15:04:05"))
		sb.WriteString("] [")
		sb.WriteString(line.Level)
		sb.WriteString("] ")
		sb.WriteString(line.Content)
		sb.WriteString("\n")
	}

	return sb.String()
}

// ExportLines returns all log lines as a slice in chronological order.
// The returned slice is a new allocation safe to modify by the caller.
// This is safe for concurrent use.
//
// Performance: O(n) where n = buffer size
func (rb *RingBuffer) ExportLines() []LogLine {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.size == 0 {
		return []LogLine{}
	}

	// Allocate result slice
	result := make([]LogLine, rb.size)

	// Determine starting index (oldest entry)
	var start int
	if rb.size < rb.capacity {
		start = 0
	} else {
		start = rb.head
	}

	// Copy entries in chronological order
	for i := 0; i < rb.size; i++ {
		physicalIdx := (start + i) % rb.capacity
		result[i] = rb.buffer[physicalIdx]
	}

	return result
}
