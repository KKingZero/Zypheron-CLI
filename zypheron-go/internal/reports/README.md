# Reports Package

JSON export for Zypheron scan sessions. Designed for programmatic access to scan results and automation pipelines.

## Features

- JSON-only export (structured, parseable output)
- Minimal dependencies (standard library + session package)
- Default output: `~/.zypheron/reports/`
- Comprehensive report data: metadata, findings, vulnerabilities, summaries

## Quick Start

```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/reports"

// Export with auto-naming to default directory
err := reports.GenerateReport(session, "")
// Saves to: ~/.zypheron/reports/report_<id>_<timestamp>.json
```

## API Reference

### ExportJSON

```go
func ExportJSON(sess *session.Session, outputPath string) error
```

Exports a session to JSON at the specified path. Creates parent directories as needed.

**Parameters:**
- `sess` -- session to export (must not be nil)
- `outputPath` -- full file path for the report

**Errors:** nil session, JSON marshal failure, directory creation failure, write failure.

### GenerateReport

```go
func GenerateReport(sess *session.Session, outputPath string) error
```

Exports a session with automatic filename generation (`report_<sessionid>_<timestamp>.json`).

**Parameters:**
- `sess` -- session to export (must not be nil)
- `outputPath` -- directory path, or empty string for default (`~/.zypheron/reports/`)

### GetDefaultReportPath

```go
func GetDefaultReportPath() (string, error)
```

Returns the default report directory: `~/.zypheron/reports`.

## Data Structures

```go
type Report struct {
    Metadata        ReportMetadata            `json:"metadata"`
    Summary         ReportSummary             `json:"summary"`
    Findings        []session.Finding         `json:"findings"`
    Vulnerabilities []session.Vulnerability   `json:"vulnerabilities"`
    RawOutput       string                    `json:"raw_output,omitempty"`
    AIAnalysis      string                    `json:"ai_analysis,omitempty"`
    Notes           string                    `json:"notes,omitempty"`
}

type ReportMetadata struct {
    SessionID string    `json:"session_id"`
    Target    string    `json:"target"`
    Tool      string    `json:"tool"`
    Timestamp time.Time `json:"timestamp"`
    Duration  string    `json:"duration"`
    Status    string    `json:"status"`
}

type ReportSummary struct {
    TotalFindings        int `json:"total_findings"`
    TotalVulnerabilities int `json:"total_vulnerabilities"`
    CriticalCount        int `json:"critical_count"`
    HighCount            int `json:"high_count"`
    MediumCount          int `json:"medium_count"`
    LowCount             int `json:"low_count"`
    InfoCount            int `json:"info_count"`
}
```

## JSON Report Structure

```json
{
  "metadata": {
    "session_id": "uuid-string",
    "target": "192.168.1.100",
    "tool": "nmap",
    "timestamp": "2026-01-18T10:00:00Z",
    "duration": "5m30s",
    "status": "completed"
  },
  "summary": {
    "total_findings": 10,
    "total_vulnerabilities": 3,
    "critical_count": 1,
    "high_count": 1,
    "medium_count": 1,
    "low_count": 0,
    "info_count": 0
  },
  "findings": [
    {
      "id": "uuid",
      "type": "port",
      "title": "Open Port 22",
      "severity": "info",
      "timestamp": "2026-01-18T10:00:00Z"
    }
  ],
  "vulnerabilities": [
    {
      "id": "uuid",
      "cve_id": "CVE-2023-1234",
      "title": "SQL Injection",
      "severity": "critical",
      "cvss_score": 9.8,
      "port": 80,
      "service": "http",
      "exploit_available": true,
      "remediation": "Use parameterized queries"
    }
  ]
}
```

## Usage Examples

### Export After Scan

```go
sess := session.NewSession("192.168.1.100", session.ScanTypeNmap)
// ... perform scan ...
sess.Complete()

if err := reports.GenerateReport(sess, ""); err != nil {
    log.Printf("Warning: Failed to export report: %v", err)
}
```

### Custom Output Path

```go
err := reports.ExportJSON(sess, "/var/log/zypheron/scan_report.json")
```

### Batch Export

```go
manager, _ := session.NewSessionManager()
summaries, _ := manager.ListSessions()

for _, summary := range summaries {
    sess, err := manager.Load(summary.SessionID)
    if err != nil {
        continue
    }
    reports.GenerateReport(sess, "")
}
```

### CLI Integration (Cobra)

```go
var exportCmd = &cobra.Command{
    Use:   "export [session-id]",
    Short: "Export scan report to JSON",
    Args:  cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        manager, _ := session.NewSessionManager()
        sess, err := manager.Load(args[0])
        if err != nil {
            return fmt.Errorf("session not found: %s", args[0])
        }

        outputPath, _ := cmd.Flags().GetString("output")
        if outputPath == "" {
            return reports.GenerateReport(sess, "")
        }
        return reports.ExportJSON(sess, outputPath)
    },
}
```

### Parse Exported Reports

```bash
# With jq
cat report.json | jq '.summary'
cat report.json | jq '.vulnerabilities[] | select(.severity=="critical")'
```

```go
data, _ := os.ReadFile("report.json")
var report reports.Report
json.Unmarshal(data, &report)

for _, vuln := range report.Vulnerabilities {
    if vuln.Severity == "critical" {
        fmt.Printf("CRITICAL: %s (CVSS %.1f)\n", vuln.Title, vuln.CVSSScore)
    }
}
```

## Error Handling

```go
err := reports.ExportJSON(sess, outputPath)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "session cannot be nil"):
        // Invalid session
    case strings.Contains(err.Error(), "failed to create output directory"):
        // Permission denied or invalid path
    case strings.Contains(err.Error(), "failed to write"):
        // Disk full or write error
    }
}
```

## Auto-Export After Scan

Add automatic report generation to scan commands:

```go
func runScan(cmd *cobra.Command, args []string) error {
    // ... scan execution ...
    sess.Complete()

    if autoExport {
        if err := reports.GenerateReport(sess, ""); err != nil {
            fmt.Fprintf(os.Stderr, "Warning: Failed to export report: %v\n", err)
        } else {
            defaultPath, _ := reports.GetDefaultReportPath()
            fmt.Printf("Report saved to: %s\n", defaultPath)
        }
    }
    return nil
}
```

## Configuration Integration

Add report settings to `~/.zypheron/config.yaml`:

```yaml
reports:
  auto_export: true
  output_directory: ~/.zypheron/reports
  include_raw_output: true
```

## Parallel Export

For large numbers of sessions:

```go
var wg sync.WaitGroup
for _, id := range sessionIDs {
    wg.Add(1)
    go func(id string) {
        defer wg.Done()
        sess, _ := manager.Load(id)
        reports.GenerateReport(sess, "")
    }(id)
}
wg.Wait()
```

## File Permissions

- Report directories: `0755`
- Report files: `0644`

## File Locations

```
~/.zypheron/
+-- sessions/          # Session storage
+-- reports/           # Exported reports
    +-- report_<id>_<timestamp>.json
```

## Testing

```bash
go test -v ./internal/reports/
go test -cover ./internal/reports/
```

## Dependencies

- Standard library: `encoding/json`, `fmt`, `os`, `path/filepath`, `time`
- Internal: `github.com/KKingZero/Cobra-AI/zypheron-go/internal/session`

No external dependencies.
