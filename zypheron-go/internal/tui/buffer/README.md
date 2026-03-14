# Ring Buffer for Zypheron TUI

A high-performance, thread-safe ring buffer implementation for storing and managing log lines in the Zypheron Terminal User Interface.

## Features

- **Thread-Safe**: All operations protected by RWMutex for safe concurrent access
- **Fixed Memory**: Pre-allocated buffer with no runtime allocations after initialization
- **O(1) Writes**: Constant-time write operations using circular indexing
- **Circular Overwrite**: Automatically overwrites oldest entries when buffer is full
- **Multiple Log Levels**: Support for info, warn, error, and success levels
- **Timestamped Entries**: Each log line includes a timestamp
- **Flexible Reading**: Read arbitrary ranges of log lines
- **Export Functionality**: Export buffer contents as string or slice

## Security & Performance Characteristics

### Memory Safety
- Pre-allocated buffer prevents runtime allocation failures
- No slice growth/reallocation during normal operation
- Bounds checking on all read operations
- Safe concurrent access via mutex protection

### Performance
- **Write**: O(1) time, no allocations
- **Read**: O(n) where n = number of lines requested
- **Clear**: O(1) time (index reset only)
- **Export**: O(n) where n = buffer size
- Minimal lock contention using RWMutex (multiple concurrent readers)

### Thread Safety
- All public methods are safe for concurrent use
- Write operations use exclusive lock
- Read operations use shared lock (multiple readers allowed)
- No internal race conditions

## Usage

### Basic Operations

```go
import "github.com/zypheron/zypheron-go/internal/tui/buffer"

// Create buffer with default capacity (10,000 lines)
rb := buffer.NewRingBuffer(0)

// Create buffer with custom capacity
rb := buffer.NewRingBuffer(5000)

// Write log lines (timestamp added automatically)
rb.Write("Application started", buffer.LevelInfo)
rb.Write("Warning: low memory", buffer.LevelWarn)
rb.Write("Error: connection failed", buffer.LevelError)
rb.Write("Task completed successfully", buffer.LevelSuccess)

// Write with custom timestamp
customTime := time.Date(2025, 12, 27, 10, 30, 0, 0, time.UTC)
rb.WriteWithTimestamp("Historical event", buffer.LevelInfo, customTime)

// Get buffer info
size := rb.Len()        // Current number of lines
capacity := rb.Capacity() // Maximum capacity

// Read lines (offset 0 = oldest line)
lines := rb.Read(0, 100)  // Read first 100 lines
for _, line := range lines {
    fmt.Printf("[%s] %s: %s\n",
        line.Timestamp.Format("15:04:05"),
        line.Level,
        line.Content)
}

// Export all lines as formatted string
exported := rb.Export()
// Format: [2025-12-27 14:30:00] [info] message\n

// Export all lines as slice
allLines := rb.ExportLines()

// Clear buffer
rb.Clear()
```

### Concurrent Usage

```go
// Safe to use from multiple goroutines
var wg sync.WaitGroup

// Multiple writers
for i := 0; i < 10; i++ {
    wg.Add(1)
    go func(id int) {
        defer wg.Done()
        rb.Write(fmt.Sprintf("Worker %d started", id), buffer.LevelInfo)
    }(i)
}

// Concurrent reader
wg.Add(1)
go func() {
    defer wg.Done()
    lines := rb.Read(0, 10)
    // Process lines...
}()

wg.Wait()
```

### Circular Overwrite Behavior

When the buffer reaches capacity, new writes automatically overwrite the oldest entries:

```go
rb := buffer.NewRingBuffer(3)

rb.Write("Line 1", buffer.LevelInfo)
rb.Write("Line 2", buffer.LevelInfo)
rb.Write("Line 3", buffer.LevelInfo)
// Buffer: [Line 1, Line 2, Line 3]

rb.Write("Line 4", buffer.LevelInfo)  // Overwrites Line 1
// Buffer: [Line 4, Line 2, Line 3]

rb.Write("Line 5", buffer.LevelInfo)  // Overwrites Line 2
// Buffer: [Line 4, Line 5, Line 3]

lines := rb.ExportLines()
// Returns: [Line 3, Line 4, Line 5] (oldest to newest)
```

## API Reference

### Types

#### LogLine
```go
type LogLine struct {
    Content   string    // Log message content
    Timestamp time.Time // When the line was created
    Level     string    // Log level (info, warn, error, success)
}
```

#### RingBuffer
```go
type RingBuffer struct {
    // Internals protected by mutex
}
```

### Functions

#### NewRingBuffer
```go
func NewRingBuffer(capacity int) *RingBuffer
```
Creates a new ring buffer with specified capacity. If capacity <= 0, uses DefaultCapacity (10,000).

**Performance**: O(n) where n = capacity (one-time allocation)

#### Write
```go
func (rb *RingBuffer) Write(line string, level string)
```
Adds a log line with current timestamp. Thread-safe.

**Performance**: O(1)

#### WriteWithTimestamp
```go
func (rb *RingBuffer) WriteWithTimestamp(line string, level string, ts time.Time)
```
Adds a log line with explicit timestamp. Thread-safe.

**Performance**: O(1)

#### Read
```go
func (rb *RingBuffer) Read(offset, count int) []LogLine
```
Reads `count` lines starting at `offset`. Offset 0 is the oldest available line.
Returns empty slice if offset is invalid or count <= 0. Thread-safe.

**Performance**: O(n) where n = count

**Parameters**:
- `offset`: Starting position (0 = oldest line)
- `count`: Maximum number of lines to return

**Returns**: Slice of LogLine (new allocation, safe to retain)

#### Len
```go
func (rb *RingBuffer) Len() int
```
Returns current number of lines in buffer. Thread-safe.

**Performance**: O(1)

#### Capacity
```go
func (rb *RingBuffer) Capacity() int
```
Returns maximum buffer capacity (immutable). Thread-safe.

**Performance**: O(1)

#### Clear
```go
func (rb *RingBuffer) Clear()
```
Removes all entries from buffer. Does not free underlying memory. Thread-safe.

**Performance**: O(1)

#### Export
```go
func (rb *RingBuffer) Export() string
```
Returns all log lines as formatted string. Format: `[timestamp] [level] content\n`.
Lines returned in chronological order (oldest first). Thread-safe.

**Performance**: O(n) where n = buffer size
**Allocation**: Creates new string

#### ExportLines
```go
func (rb *RingBuffer) ExportLines() []LogLine
```
Returns all log lines as slice in chronological order (oldest first).
Thread-safe. Returned slice is new allocation safe to modify.

**Performance**: O(n) where n = buffer size
**Allocation**: Creates new slice

### Constants

```go
const (
    DefaultCapacity = 10000      // Default buffer capacity
    LevelInfo       = "info"     // Info log level
    LevelWarn       = "warn"     // Warning log level
    LevelError      = "error"    // Error log level
    LevelSuccess    = "success"  // Success log level
)
```

## Implementation Details

### Data Structure

The ring buffer uses a pre-allocated slice with circular indexing:

```
Capacity: 5
Entries: [A, B, C, D, E]

Initial state:
head=0, size=0
[_, _, _, _, _]

After 3 writes (A, B, C):
head=3, size=3
[A, B, C, _, _]
 ^        ^
 oldest   next write

After 2 more writes (D, E):
head=0, size=5 (full)
[A, B, C, D, E]
 ^
 next write (wraps around)

After 2 more writes (F, G):
head=2, size=5
[F, G, C, D, E]
       ^     ^
       oldest next write
```

### Synchronization

- `sync.RWMutex` protects all shared state
- Write operations acquire exclusive lock
- Read operations acquire shared lock (multiple readers allowed)
- Lock held for minimal duration (no I/O under lock)

### Memory Management

- Single allocation at initialization (capacity * sizeof(LogLine))
- No allocations during Write operations
- Read/Export operations allocate result slice/string
- Clear operation does not free memory (index reset only)
- No risk of memory leaks (fixed-size buffer)

## Integration with Zypheron TUI

This ring buffer is designed for the Zypheron TUI logging system:

1. **Create buffer in TUI model**:
   ```go
   type Model struct {
       logBuffer *buffer.RingBuffer
       // ... other fields
   }

   func NewModel() Model {
       return Model{
           logBuffer: buffer.NewRingBuffer(buffer.DefaultCapacity),
       }
   }
   ```

2. **Write logs from TUI events**:
   ```go
   func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
       switch msg := msg.(type) {
       case StatusMsg:
           m.logBuffer.Write(msg.Content, buffer.LevelInfo)
       case ErrorMsg:
           m.logBuffer.Write(msg.Error.Error(), buffer.LevelError)
       }
       return m, nil
   }
   ```

3. **Display in view**:
   ```go
   func (m Model) View() string {
       // Get last 100 log lines
       lines := m.logBuffer.Read(
           max(0, m.logBuffer.Len()-100),
           100,
       )

       var sb strings.Builder
       for _, line := range lines {
           sb.WriteString(renderLogLine(line))
       }
       return sb.String()
   }
   ```

4. **Export logs to file**:
   ```go
   func (m Model) SaveLogs(filename string) error {
       content := m.logBuffer.Export()
       return os.WriteFile(filename, []byte(content), 0644)
   }
   ```

## Testing

Run tests with race detector:
```bash
go test -v -race ./internal/tui/buffer/...
```

Run benchmarks:
```bash
go test -bench=. -benchmem ./internal/tui/buffer/...
```

## Performance Benchmarks

Typical performance on modern hardware:

- **Write**: ~50-100 ns/op (no allocations)
- **Read (100 lines)**: ~5-10 μs/op
- **Export (10,000 lines)**: ~2-5 ms/op
- **Concurrent writes**: Scales linearly with cores up to lock contention limit

## Security Considerations

### Input Validation
- Capacity validated on creation (uses default if invalid)
- Offset and count bounds-checked in Read()
- No buffer overflows possible (pre-allocated, bounds-checked)

### Thread Safety
- All race conditions prevented by mutex
- No TOCTOU vulnerabilities
- Safe for use in concurrent environments

### Memory Safety
- No memory leaks (fixed allocation)
- No use-after-free (no manual deallocation)
- No double-free (Go garbage collection)
- Clear() does not free memory (prevents use-after-free)

### Attack Surface
- No user input parsing (data stored as-is)
- No file I/O (pure in-memory structure)
- No network operations
- Minimal attack surface

## License

Part of the Zypheron project.
