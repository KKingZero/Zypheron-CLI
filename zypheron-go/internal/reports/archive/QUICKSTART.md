# Quick Start Guide - Reports Package

## Installation

The package is ready to use - no installation needed. It's part of the Zypheron CLI codebase.

**Location**: `/home/zero/Downloads/Zypheron project/Zypheron CLI/zypheron-go/internal/reports/`

## 30-Second Quick Start

```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/reports"

// After completing a scan session:
err := reports.GenerateReport(session, "")
// Report saved to ~/.zypheron/reports/report_<id>_<timestamp>.json
```

That's it! The report is now in your reports directory.

## Common Usage Scenarios

### Scenario 1: Export After Every Scan

```go
package main

import (
    "fmt"
    "log"
    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/reports"
    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/session"
)

func runScan(target string) error {
    // Create and run scan
    sess := session.NewSession(target, session.ScanTypeNmap)

    // ... perform scan operations ...

    // Mark complete
    sess.Complete()

    // Auto-export report
    if err := reports.GenerateReport(sess, ""); err != nil {
        log.Printf("Warning: Failed to export report: %v", err)
    } else {
        fmt.Println("✓ Report saved to ~/.zypheron/reports/")
    }

    return nil
}
```

### Scenario 2: Custom Output Location

```go
func exportToCustomLocation(sess *session.Session) error {
    outputPath := "/var/log/zypheron/scan_report.json"
    return reports.ExportJSON(sess, outputPath)
}
```

### Scenario 3: Batch Export All Sessions

```go
func exportAllSessions() error {
    manager, _ := session.NewSessionManager()
    summaries, _ := manager.ListSessions()

    for _, summary := range summaries {
        sess, err := manager.Load(summary.SessionID)
        if err != nil {
            continue
        }

        reports.GenerateReport(sess, "")
        fmt.Printf("✓ Exported: %s\n", summary.Target)
    }

    return nil
}
```

### Scenario 4: Export and Parse

```go
import (
    "encoding/json"
    "os"
)

func exportAndAnalyze(sess *session.Session) error {
    // Export
    tmpFile := "/tmp/report.json"
    if err := reports.ExportJSON(sess, tmpFile); err != nil {
        return err
    }

    // Read back
    data, _ := os.ReadFile(tmpFile)
    var report reports.Report
    json.Unmarshal(data, &report)

    // Analyze
    fmt.Printf("Critical vulnerabilities: %d\n", report.Summary.CriticalCount)
    for _, vuln := range report.Vulnerabilities {
        if vuln.Severity == "critical" {
            fmt.Printf("  - %s\n", vuln.Title)
        }
    }

    return nil
}
```

## CLI Integration Example

Add this to your Cobra command:

```go
var exportCmd = &cobra.Command{
    Use:   "export [session-id]",
    Short: "Export scan report to JSON",
    Args:  cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        sessionID := args[0]

        // Load session
        manager, _ := session.NewSessionManager()
        sess, err := manager.Load(sessionID)
        if err != nil {
            return fmt.Errorf("session not found: %s", sessionID)
        }

        // Export
        outputPath, _ := cmd.Flags().GetString("output")
        if outputPath == "" {
            err = reports.GenerateReport(sess, "")
        } else {
            err = reports.ExportJSON(sess, outputPath)
        }

        if err != nil {
            return err
        }

        fmt.Println("✓ Report exported successfully")
        return nil
    },
}

func init() {
    exportCmd.Flags().StringP("output", "o", "", "Output path")
    rootCmd.AddCommand(exportCmd)
}
```

## Command Line Usage (After Integration)

```bash
# Export specific session (auto-named)
zypheron export abc123-def456

# Export to specific file
zypheron export abc123-def456 --output /path/to/report.json

# Export to specific directory (auto-named)
zypheron export abc123-def456 --output /path/to/dir/

# Export all sessions
zypheron export-all
```

## Default File Locations

```
~/.zypheron/
├── sessions/          # Session storage
│   └── abc123.json
└── reports/           # Exported reports (this package)
    ├── report_abc123_20260118_104500.json
    ├── report_def456_20260118_105500.json
    └── report_ghi789_20260118_110500.json
```

## Sample Report Structure

```json
{
  "metadata": {
    "session_id": "abc123-def456-ghi789",
    "target": "example.com",
    "tool": "nmap",
    "timestamp": "2026-01-18T10:45:00Z",
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
      "id": "finding-1",
      "type": "port",
      "title": "Open Port 443",
      "description": "HTTPS port is accessible",
      "severity": "info",
      "timestamp": "2026-01-18T10:45:30Z"
    }
  ],
  "vulnerabilities": [
    {
      "id": "vuln-1",
      "cve_id": "CVE-2023-1234",
      "title": "SQL Injection",
      "description": "SQL injection in login form",
      "severity": "critical",
      "cvss_score": 9.8,
      "port": 443,
      "service": "https",
      "exploit_available": true,
      "remediation": "Use parameterized queries"
    }
  ]
}
```

## Error Handling

```go
err := reports.ExportJSON(sess, outputPath)
if err != nil {
    // Check error type
    switch {
    case strings.Contains(err.Error(), "session cannot be nil"):
        fmt.Println("Error: Invalid session")
    case strings.Contains(err.Error(), "permission denied"):
        fmt.Println("Error: Permission denied - check output directory")
    case strings.Contains(err.Error(), "no space left"):
        fmt.Println("Error: Disk full")
    default:
        fmt.Printf("Error: %v\n", err)
    }
}
```

## Programmatic Report Parsing

```bash
# Export report
zypheron export session-id -o report.json

# Parse with jq
cat report.json | jq '.summary'
cat report.json | jq '.vulnerabilities[] | select(.severity=="critical")'

# Parse with Python
python3 << EOF
import json
with open('report.json') as f:
    report = json.load(f)
    print(f"Critical: {report['summary']['critical_count']}")
EOF

# Parse with Go
go run << EOF
package main
import ("encoding/json"; "fmt"; "os")
func main() {
    data, _ := os.ReadFile("report.json")
    var report map[string]interface{}
    json.Unmarshal(data, &report)
    summary := report["summary"].(map[string]interface{})
    fmt.Printf("Critical: %.0f\n", summary["critical_count"].(float64))
}
EOF
```

## Testing Your Integration

```go
func TestReportExport(t *testing.T) {
    // Create test session
    sess := session.NewSession("test.example.com", session.ScanTypeNmap)
    sess.AddVulnerability(session.Vulnerability{
        Title:    "Test Vuln",
        Severity: "high",
    })
    sess.Complete()

    // Export
    tmpDir := t.TempDir()
    err := reports.GenerateReport(sess, tmpDir)
    if err != nil {
        t.Fatalf("Export failed: %v", err)
    }

    // Verify file exists
    files, _ := os.ReadDir(tmpDir)
    if len(files) == 0 {
        t.Fatal("No report generated")
    }

    // Verify content
    data, _ := os.ReadFile(filepath.Join(tmpDir, files[0].Name()))
    var report reports.Report
    json.Unmarshal(data, &report)

    if report.Summary.TotalVulnerabilities != 1 {
        t.Errorf("Expected 1 vulnerability, got %d",
            report.Summary.TotalVulnerabilities)
    }
}
```

## Performance Tips

1. **Batch Operations**: Export multiple sessions in parallel:
```go
var wg sync.WaitGroup
for _, sessionID := range sessionIDs {
    wg.Add(1)
    go func(id string) {
        defer wg.Done()
        sess, _ := manager.Load(id)
        reports.GenerateReport(sess, "")
    }(sessionID)
}
wg.Wait()
```

2. **Large Sessions**: The JSON marshaling is efficient, but for very large raw outputs (>10MB), consider:
```go
// Exclude raw output for massive scans
sess.Results.RawOutput = "" // Clear before export
```

3. **Disk Space**: Monitor reports directory:
```bash
du -sh ~/.zypheron/reports/
# Clean old reports if needed
find ~/.zypheron/reports/ -mtime +30 -delete
```

## Troubleshooting

**Q: Report file is empty**
```go
// Check if session completed
if sess.Status != session.StatusCompleted {
    sess.Complete()
}
```

**Q: Permission denied**
```bash
# Check directory permissions
chmod 755 ~/.zypheron/reports/

# Or export to different location
reports.ExportJSON(sess, "/tmp/report.json")
```

**Q: Report missing vulnerabilities**
```go
// Ensure vulnerabilities were added to session
fmt.Printf("Vulnerabilities: %d\n", len(sess.Results.Vulnerabilities))
```

## Next Steps

1. Read [README.md](./README.md) for detailed API documentation
2. Check [INTEGRATION.md](./INTEGRATION.md) for CLI integration examples
3. Review [demo.go](./demo.go) for a complete working example
4. Run tests: `go test ./internal/reports/`

## Support

- Package location: `/home/zero/Downloads/Zypheron project/Zypheron CLI/zypheron-go/internal/reports/`
- Documentation: See README.md and INTEGRATION.md
- Examples: See example_test.go and demo.go
- Tests: Run `go test -v ./internal/reports/`

---

**Ready to use!** No additional setup required.
