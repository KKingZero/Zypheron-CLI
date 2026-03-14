# Reports Package

The reports package provides JSON export functionality for Zypheron scan sessions in the OSS release. It is designed for advanced users who need programmatic access to scan results, while richer report presentation stays aligned with Zypheron's AI-native tooling direction.

## Features

- **JSON Export Only**: Clean, structured JSON output suitable for parsing and automation
- **Minimal Dependencies**: Relies only on standard library and session package
- **Default Output Location**: `~/.zypheron/reports/`
- **Comprehensive Report Data**: Includes metadata, findings, vulnerabilities, and summaries

## Usage

### Basic Export

```go
import (
    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/reports"
    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/session"
)

// Create or load a session
sess := session.NewSession("192.168.1.100", session.ScanTypeNmap)

// Export to specific path
err := reports.ExportJSON(sess, "/path/to/report.json")
if err != nil {
    log.Fatal(err)
}
```

### Generate Report with Auto-naming

```go
// Generates report with automatic filename in default directory
// Format: report_<sessionid>_<timestamp>.json
// Location: ~/.zypheron/reports/
err := reports.GenerateReport(sess, "")
if err != nil {
    log.Fatal(err)
}

// Or specify custom directory (filename still auto-generated)
err := reports.GenerateReport(sess, "/custom/directory")
if err != nil {
    log.Fatal(err)
}
```

### Get Default Report Path

```go
defaultPath, err := reports.GetDefaultReportPath()
if err != nil {
    log.Fatal(err)
}
// Returns: /home/user/.zypheron/reports
```

## JSON Report Structure

The exported JSON report contains the following structure:

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
      "description": "SSH port is open",
      "severity": "info",
      "timestamp": "2026-01-18T10:00:00Z",
      "details": {}
    }
  ],
  "vulnerabilities": [
    {
      "id": "uuid",
      "cve_id": "CVE-2023-1234",
      "title": "SQL Injection",
      "description": "SQL injection in login form",
      "severity": "critical",
      "cvss_score": 9.8,
      "port": 80,
      "service": "http",
      "exploit_available": true,
      "remediation": "Use parameterized queries",
      "references": ["https://example.com/advisory"]
    }
  ],
  "raw_output": "Full raw output from scan tool...",
  "ai_analysis": "AI-generated analysis if available",
  "notes": "User notes"
}
```

## API Reference

### ExportJSON

```go
func ExportJSON(sess *session.Session, outputPath string) error
```

Exports a session to JSON format at the specified path.

**Parameters:**
- `sess`: The session to export (must not be nil)
- `outputPath`: Full path including filename where report will be saved

**Returns:**
- `error`: nil on success, error describing failure otherwise

**Errors:**
- Session is nil
- Failed to marshal JSON
- Failed to create output directory
- Failed to write file

### GenerateReport

```go
func GenerateReport(sess *session.Session, outputPath string) error
```

Wrapper function that exports a session with automatic filename generation.

**Parameters:**
- `sess`: The session to export (must not be nil)
- `outputPath`: Directory path (empty string for default `~/.zypheron/reports/`)

**Returns:**
- `error`: nil on success, error describing failure otherwise

**Behavior:**
- If `outputPath` is empty: uses `~/.zypheron/reports/`
- If `outputPath` is a directory: generates filename in that directory
- Filename format: `report_<sessionid>_<timestamp>.json`

### GetDefaultReportPath

```go
func GetDefaultReportPath() (string, error)
```

Returns the default report directory path.

**Returns:**
- `string`: Path to default reports directory (`~/.zypheron/reports`)
- `error`: Error if unable to determine home directory

## Error Handling

All functions return descriptive errors that can be checked and handled:

```go
err := reports.ExportJSON(sess, outputPath)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "session cannot be nil"):
        log.Println("Invalid session provided")
    case strings.Contains(err.Error(), "failed to create output directory"):
        log.Println("Permission denied or invalid path")
    case strings.Contains(err.Error(), "failed to write"):
        log.Println("Disk full or permission issue")
    default:
        log.Printf("Unexpected error: %v", err)
    }
}
```

## File Permissions

- Report directories are created with `0755` permissions
- Report files are written with `0644` permissions (read/write for owner, read for others)

## Advanced Usage

### Programmatic Report Processing

Since reports are in JSON format, they can be easily parsed and processed:

```go
import (
    "encoding/json"
    "os"
)

type Report struct {
    Metadata        ReportMetadata       `json:"metadata"`
    Summary         ReportSummary        `json:"summary"`
    Vulnerabilities []Vulnerability      `json:"vulnerabilities"`
}

data, _ := os.ReadFile("report.json")
var report Report
json.Unmarshal(data, &report)

// Process vulnerabilities
for _, vuln := range report.Vulnerabilities {
    if vuln.Severity == "critical" {
        // Handle critical vulnerabilities
    }
}
```

## Design Philosophy

This package follows these principles:

1. **Simplicity**: JSON-only export keeps the codebase minimal and maintainable
2. **Automation-Friendly**: Structured JSON output is easy to parse and integrate with other tools
3. **Security-Conscious**: Restrictive file permissions protect sensitive scan data
4. **Convention Over Configuration**: Sensible defaults minimize configuration needs
5. **Error Transparency**: Clear error messages aid in debugging and troubleshooting

## Future Considerations

For users requiring additional export formats (HTML, Markdown, PDF), consider the enterprise version or implement custom formatters using the JSON output as a base.
