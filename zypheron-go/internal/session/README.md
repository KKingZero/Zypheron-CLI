# Session Management System

A comprehensive session management system for Zypheron CLI that enables saving, resuming, and managing scan sessions with full state persistence.

## Features

- **Full State Persistence**: Save complete scan state including progress, results, and chat history
- **Auto-Save**: Automatic session saving every 30 seconds during active scans
- **Session Resume**: Resume paused or interrupted scans from exact point of interruption
- **Session History**: Track and list all historical sessions
- **Automatic Cleanup**: Auto-clean sessions older than configurable days
- **Rich Metadata**: Store scan results, findings, vulnerabilities, and AI analysis
- **Thread-Safe**: Concurrent-safe operations using mutex locks
- **Active Session Tracking**: Manage currently active scan session

## Installation

The session package is part of the Zypheron CLI internal packages. Import it:

```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/session"
```

## Quick Start

### Basic Usage

```go
// Create session manager
manager, err := session.NewSessionManager()
if err != nil {
    log.Fatal(err)
}

// Create a new session
sess := session.NewSession("192.168.1.1", session.ScanTypeNmap)

// Add findings and progress
sess.UpdateProgress(25.0, "port discovery", 1, 4)
sess.AddFinding(session.Finding{
    Type:        "port",
    Title:       "Open Port 22",
    Description: "SSH service detected",
    Severity:    "info",
})

// Save session
if err := manager.Save(sess); err != nil {
    log.Fatal(err)
}
```

### Auto-Save During Scans

```go
// Create session
sess := session.NewSession("example.com", session.ScanTypeNuclei)

// Enable auto-save (saves every 30 seconds)
sess.StartAutoSave(manager)
defer sess.StopAutoSave()

// Set as active session
manager.SetActiveSession(sess)
defer manager.ClearActiveSession()

// Perform scan work - session automatically saves every 30s
for i := 0; i <= 100; i += 10 {
    sess.UpdateProgress(float64(i), "scanning", i/10, 10)
    time.Sleep(3 * time.Second)
}

// Mark complete
sess.Complete()
manager.Save(sess)
```

### Resume a Session

```go
// Load existing session
sess, err := manager.Load("session-uuid")
if err != nil {
    log.Fatal(err)
}

// Resume if paused
if sess.Status == session.StatusPaused {
    sess.Resume()
    manager.SetActiveSession(sess)

    // Continue scan from previous state
    // Previous progress: sess.Progress.Percentage
    // Previous findings: sess.Results.ParsedFindings
}
```

## Core Types

### Session

The main session structure containing all scan state:

```go
type Session struct {
    SessionID   string          // Unique UUID
    StartTime   time.Time       // When scan started
    EndTime     time.Time       // When scan ended (if completed)
    Target      string          // Scan target
    ScanType    ScanType        // Type of scan
    Status      SessionStatus   // Current status
    Progress    ScanProgress    // Progress tracking
    Results     ScanResults     // Scan findings and results
    ChatHistory []ChatMessage   // AI conversation context
    Tags        []string        // Custom tags
    Environment map[string]interface{} // Environment metadata
}
```

### SessionStatus

Session lifecycle states:

- `StatusRunning`: Session is actively running
- `StatusPaused`: Session is temporarily paused
- `StatusCompleted`: Session finished successfully
- `StatusFailed`: Session failed or was interrupted

### ScanType

Supported scan types:

- `ScanTypeNmap`: Network mapping and port scanning
- `ScanTypeNikto`: Web server scanning
- `ScanTypeNuclei`: Vulnerability template scanning
- `ScanTypeWPScan`: WordPress vulnerability scanning
- `ScanTypeSQLMap`: SQL injection testing
- `ScanTypeMetasploit`: Metasploit framework scans
- `ScanTypeDirb`: Directory brute forcing
- `ScanTypeGobuster`: URI brute forcing
- `ScanTypeCustom`: Custom scan type

### ScanProgress

Track scan progress:

```go
type ScanProgress struct {
    Percentage      float64   // 0.0 to 100.0
    CurrentPhase    string    // Current scan phase
    StepsTotal      int       // Total steps
    StepsCompleted  int       // Completed steps
    LastUpdate      time.Time // Last progress update
}
```

### Finding

Individual scan finding:

```go
type Finding struct {
    ID          string
    Type        string    // port, service, directory, vulnerability
    Title       string
    Description string
    Severity    string    // info, low, medium, high, critical
    Timestamp   time.Time
    Details     map[string]interface{}
}
```

### Vulnerability

Security vulnerability:

```go
type Vulnerability struct {
    ID               string
    CVEID            string
    Title            string
    Description      string
    Severity         string
    CVSSScore        float64
    Port             int
    Service          string
    ExploitAvailable bool
    Remediation      string
    References       []string
}
```

## SessionManager API

### Create Manager

```go
manager, err := session.NewSessionManager()
```

Creates a new session manager. Sessions are stored in `~/.zypheron/sessions/`.

### Save Session

```go
err := manager.Save(sess)
```

Persists session to disk as JSON file: `~/.zypheron/sessions/{session-id}.json`

### Load Session

```go
sess, err := manager.Load(sessionID)
```

Loads a session from disk by ID.

### List Sessions

```go
summaries, err := manager.ListSessions()
```

Returns all sessions sorted by newest first. Returns `[]SessionSummary`.

### Delete Session

```go
err := manager.DeleteSession(sessionID)
```

Permanently deletes a session from storage.

### Active Session Management

```go
// Set active session
manager.SetActiveSession(sess)

// Get active session
active, err := manager.GetActiveSession()

// Clear active session
manager.ClearActiveSession()
```

Manages the currently active scan session. Only one session can be active at a time.

### Cleanup Old Sessions

```go
err := manager.CleanupOldSessions(30) // Delete sessions older than 30 days
```

Automatically removes sessions older than specified days. Integrates with `config.MaxHistoryDays`.

### Find Sessions

```go
// Find by target
sessions, err := manager.FindSessionsByTarget("example.com")

// Find by scan type
sessions, err := manager.FindSessionsByScanType(session.ScanTypeNmap)
```

Filter sessions by target or scan type.

## Session Methods

### Status Management

```go
sess.Pause()                           // Pause session
sess.Resume()                          // Resume session
sess.Complete()                        // Mark as completed
sess.Fail()                            // Mark as failed
sess.UpdateStatus(session.StatusRunning)
```

### Progress Tracking

```go
sess.UpdateProgress(50.0, "vulnerability scanning", 5, 10)
```

Update progress percentage, current phase, and step counters.

### Results Management

```go
// Add findings
sess.AddFinding(finding)

// Add vulnerabilities
sess.AddVulnerability(vuln)

// Append scan output
sess.AppendRawOutput("Nmap scan output...\n")

// Set AI analysis
sess.SetAIAnalysis("AI-generated analysis...")

// Set summary
sess.SetSummary("Scan completed with 3 findings")
```

### Chat History

```go
sess.AddChatMessage("user", "Scan this target")
sess.AddChatMessage("assistant", "Starting scan...")
sess.AddChatMessage("system", "Scan completed")
```

Maintains conversation context for AI integration.

### Metadata and Tags

```go
// Add tags
sess.AddTag("production")
sess.AddTag("high-priority")

// Set metadata
sess.SetMetadata("scan_duration", 120.5)
sess.SetMetadata("tool_version", "7.94")

// Set environment info
sess.SetEnvironmentInfo("os", "Kali Linux")
sess.SetEnvironmentInfo("kernel", "6.1.0")
```

### Query Methods

```go
// Get session duration
duration := sess.GetDuration()

// Check if active
isActive := sess.IsActive()
```

## Storage Format

Sessions are stored as JSON files in `~/.zypheron/sessions/`:

```
~/.zypheron/
└── sessions/
    ├── 550e8400-e29b-41d4-a716-446655440000.json
    ├── 6ba7b810-9dad-11d1-80b4-00c04fd430c8.json
    └── ...
```

File permissions: `0600` (read/write for owner only)

### Example JSON Structure

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "start_time": "2024-01-18T10:30:00Z",
  "end_time": "2024-01-18T10:45:00Z",
  "target": "192.168.1.1",
  "scan_type": "nmap",
  "status": "completed",
  "progress": {
    "percentage": 100.0,
    "current_phase": "completed",
    "steps_total": 4,
    "steps_completed": 4,
    "last_update": "2024-01-18T10:45:00Z"
  },
  "results": {
    "raw_output": "Starting Nmap 7.94...",
    "parsed_findings": [...],
    "vulnerabilities": [...],
    "summary": "Scan completed successfully",
    "ai_analysis": "..."
  },
  "chat_history": [
    {
      "timestamp": "2024-01-18T10:30:00Z",
      "role": "user",
      "content": "Scan this target"
    }
  ],
  "tags": ["production"],
  "environment": {
    "os": "Kali Linux",
    "nmap_version": "7.94"
  }
}
```

## Integration with Zypheron Config

The session manager integrates with Zypheron's configuration:

```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"

cfg := config.Get()

// Auto-save configuration
if cfg.AutoSaveSession {
    sess.StartAutoSave(manager)
}

// Auto-cleanup configuration
manager.CleanupOldSessions(cfg.MaxHistoryDays)

// Last session tracking
cfg.LastSession = sess.SessionID
config.SaveToFile()
```

## Best Practices

### 1. Always Use Auto-Save for Long Scans

```go
sess := session.NewSession(target, scanType)
sess.StartAutoSave(manager)
defer sess.StopAutoSave()
```

### 2. Properly Handle Active Sessions

```go
manager.SetActiveSession(sess)
defer manager.ClearActiveSession()
```

### 3. Complete Sessions Properly

```go
defer func() {
    if sess.IsActive() {
        sess.Complete()
        manager.Save(sess)
    }
}()
```

### 4. Regular Cleanup

```go
// Run periodically (e.g., on startup)
manager.CleanupOldSessions(config.Get().MaxHistoryDays)
```

### 5. Thread Safety

All session methods are thread-safe. The manager can be used concurrently:

```go
var wg sync.WaitGroup

// Multiple goroutines can save different sessions
wg.Add(2)
go func() {
    defer wg.Done()
    manager.Save(sess1)
}()
go func() {
    defer wg.Done()
    manager.Save(sess2)
}()
wg.Wait()
```

## Error Handling

All functions return meaningful errors:

```go
sess, err := manager.Load(sessionID)
if err != nil {
    if strings.Contains(err.Error(), "not found") {
        // Session doesn't exist
    } else {
        // Other error (permissions, disk full, etc.)
    }
}
```

## Testing

Run the test suite:

```bash
go test ./internal/session/...
```

Run with coverage:

```bash
go test -cover ./internal/session/...
```

Run specific test:

```bash
go test -run TestSessionManager ./internal/session/...
```

## Examples

See `example_usage.go` for comprehensive usage examples including:

- Basic session creation and management
- Auto-save configuration
- Session resume workflow
- Listing and filtering sessions
- Cleanup operations
- Complete scan workflow
- Error handling patterns

## License

Part of Zypheron CLI project.
