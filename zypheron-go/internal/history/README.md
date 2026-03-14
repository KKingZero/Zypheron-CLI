# History Package

The history package provides comprehensive scan history management for Zypheron CLI, tracking all past security scans with detailed metadata and statistics.

## Features

- **Persistent Storage**: Stores scan history in `~/.zypheron/history/history.json`
- **Automatic Rotation**: Rotates history file when it exceeds 10MB
- **Thread-Safe**: All operations are protected by mutex locks
- **Rich Querying**: Filter by target, date range, or search across all fields
- **Statistics**: Aggregated stats including success rate, scan counts by tool, and more
- **Import/Export**: Export history to JSON for backup or import from other sources

## Data Structure

### HistoryEntry

Each scan is stored as a `HistoryEntry` with the following fields:

```go
type HistoryEntry struct {
    ID            string     // Unique identifier for the scan
    Timestamp     time.Time  // When the scan was executed
    Target        string     // Target host/IP/domain
    ScanType      string     // Type of scan (port-scan, vuln-scan, etc.)
    Tool          string     // Tool used (nmap, nikto, etc.)
    Duration      int64      // Duration in milliseconds
    Status        ScanStatus // success, failed, or cancelled
    FindingsCount int        // Total number of findings
    VulnCount     int        // Number of vulnerabilities found
    SessionID     string     // Links to full session data
    Tags          []string   // Custom tags for categorization
}
```

### HistoryStats

Aggregated statistics across all scans:

```go
type HistoryStats struct {
    TotalScans     int                // Total number of scans
    TotalFindings  int                // Total findings across all scans
    TotalVulns     int                // Total vulnerabilities found
    ScansByTool    map[string]int     // Count of scans per tool
    ScansByTarget  map[string]int     // Count of scans per target
    ScansByStatus  map[ScanStatus]int // Count by status
    LastScanTime   *time.Time         // When the last scan occurred
    AvgDuration    int64              // Average scan duration (ms)
    TotalDuration  int64              // Total time spent scanning (ms)
    SuccessRate    float64            // Percentage of successful scans
}
```

## Core Functions

### Creating a Manager

```go
// Use default path (~/.zypheron/history/history.json)
manager, err := history.NewManager()

// Or specify a custom path
manager, err := history.NewManagerWithPath("/path/to/history.json")
```

### Adding Entries

```go
entry := &history.HistoryEntry{
    ID:            uuid.New().String(),
    Timestamp:     time.Now(),
    Target:        "example.com",
    ScanType:      "port-scan",
    Tool:          "nmap",
    Duration:      45000, // milliseconds
    Status:        history.StatusSuccess,
    FindingsCount: 15,
    VulnCount:     3,
    SessionID:     "session-123",
    Tags:          []string{"production", "web"},
}

err := manager.AddEntry(entry)
```

### Retrieving History

```go
// Get last 10 scans
entries, err := manager.GetHistory(10, 0)

// Get all scans (limit = 0)
entries, err := manager.GetHistory(0, 0)

// Get scans with pagination (limit=10, offset=20)
entries, err := manager.GetHistory(10, 20)

// Get scans for a specific target
entries, err := manager.GetHistoryByTarget("example.com")

// Get scans within a date range
start := time.Now().Add(-7 * 24 * time.Hour)
end := time.Now()
entries, err := manager.GetHistoryByDateRange(start, end)

// Search across all fields
entries, err := manager.SearchHistory("nmap")
entries, err := manager.SearchHistory("failed")
entries, err := manager.SearchHistory("production")
```

### Statistics

```go
stats, err := manager.GetStats()

fmt.Printf("Total scans: %d\n", stats.TotalScans)
fmt.Printf("Success rate: %.2f%%\n", stats.SuccessRate)
fmt.Printf("Most used tool: %v\n", stats.ScansByTool)
```

### Management Operations

```go
// Delete a specific entry
err := manager.DeleteEntry("entry-id-123")

// Clear all history
err := manager.ClearHistory()

// Export to file
err := manager.ExportHistory("/path/to/backup.json")

// Import from file (replace existing)
err := manager.ImportHistory("/path/to/backup.json", false)

// Import from file (merge with existing)
err := manager.ImportHistory("/path/to/backup.json", true)
```

## Usage Examples

### Integration with Scan Commands

```go
func executeScan(target, tool string) error {
    manager, err := history.NewManager()
    if err != nil {
        return err
    }

    scanID := uuid.New().String()
    startTime := time.Now()

    // Execute scan
    result, scanErr := runTool(tool, target)

    // Record in history
    entry := &history.HistoryEntry{
        ID:            scanID,
        Timestamp:     startTime,
        Target:        target,
        ScanType:      determineScanType(tool),
        Tool:          tool,
        Duration:      time.Since(startTime).Milliseconds(),
        Status:        determineStatus(scanErr),
        FindingsCount: len(result.Findings),
        VulnCount:     countVulnerabilities(result),
        SessionID:     getCurrentSessionID(),
        Tags:          []string{"cli"},
    }

    manager.AddEntry(entry)
    return scanErr
}
```

### Displaying Recent Scans

```go
func showRecentScans() {
    manager, _ := history.NewManager()
    entries, _ := manager.GetHistory(10, 0)

    fmt.Println("Recent Scans:")
    for i, entry := range entries {
        fmt.Printf("%d. [%s] %s - %s (%s) - %d findings\n",
            i+1,
            entry.Timestamp.Format("2006-01-02 15:04"),
            entry.Target,
            entry.Tool,
            entry.Status,
            entry.FindingsCount,
        )
    }
}
```

### AutoPent Session Tracking

```go
func trackAutoPentSession(sessionID, target string, phases []Phase) {
    manager, _ := history.NewManager()

    for i, phase := range phases {
        entry := &history.HistoryEntry{
            ID:            fmt.Sprintf("%s-phase-%d", sessionID, i+1),
            Timestamp:     time.Now(),
            Target:        target,
            ScanType:      phase.Type,
            Tool:          phase.Tool,
            Duration:      phase.Duration,
            Status:        history.StatusSuccess,
            FindingsCount: len(phase.Findings),
            VulnCount:     phase.VulnCount,
            SessionID:     sessionID,
            Tags:          []string{"autopent", fmt.Sprintf("phase-%d", i+1)},
        }
        manager.AddEntry(entry)
    }
}
```

## Storage Details

### File Location

Default: `~/.zypheron/history/history.json`

### File Format

JSON array of HistoryEntry objects, formatted with indentation for readability:

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2026-01-18T10:30:00Z",
    "target": "example.com",
    "scan_type": "port-scan",
    "tool": "nmap",
    "duration": 45000,
    "status": "success",
    "findings_count": 15,
    "vuln_count": 3,
    "session_id": "session-123",
    "tags": ["production", "web"]
  }
]
```

### Automatic Rotation

When the history file exceeds 10MB:
1. Current file is renamed to `history.json.YYYYMMDD-HHMMSS.bak`
2. New file is created with the most recent 50% of entries (minimum 100)
3. Old backups are NOT automatically deleted

## Error Handling

All functions return errors with descriptive context:

```go
if err := manager.AddEntry(entry); err != nil {
    log.Printf("Failed to add entry to history: %v", err)
    // Scan can continue even if history fails
}
```

The history system is designed to be non-critical - if history operations fail, the main scan functionality should continue.

## Thread Safety

All public methods are thread-safe. Internal operations use a read-write mutex:
- Read operations (`GetHistory`, `SearchHistory`, etc.) use read locks
- Write operations (`AddEntry`, `DeleteEntry`, etc.) use exclusive locks

## Testing

Run the test suite:

```bash
go test ./internal/history/...
```

Tests cover:
- Entry validation
- CRUD operations
- Searching and filtering
- Statistics calculation
- Import/Export functionality
- File rotation
- Thread safety (via concurrent test execution)

## Performance Considerations

- **In-Memory Operations**: All filtering/searching loads the full history into memory
- **Scalability**: Designed for personal use (thousands of scans, not millions)
- **I/O**: Each write operation rewrites the entire file (acceptable for typical usage)
- **Rotation**: Automatic file rotation prevents unbounded growth

For production deployments with high scan volumes, consider:
- Implementing a database backend
- Adding indexes for faster searching
- Implementing incremental writes instead of full rewrites

## Future Enhancements

Potential improvements for v2:
- SQLite backend for better performance with large datasets
- Configurable retention policies (e.g., auto-delete entries older than 90 days)
- Real-time stats caching to avoid recalculation
- Compression for archived history files
- Integration with reporting system for automated reports
