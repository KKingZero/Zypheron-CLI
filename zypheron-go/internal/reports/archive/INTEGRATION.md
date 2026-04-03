# Integration Guide

This guide shows how to integrate the reports package into Zypheron CLI commands.

## CLI Command Example

Here's how to add a report export command to your CLI:

```go
package commands

import (
    "fmt"
    "github.com/spf13/cobra"
    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/reports"
    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/session"
)

var exportCmd = &cobra.Command{
    Use:   "export [session-id]",
    Short: "Export scan session to JSON report",
    Long: `Export a completed scan session to a JSON report file.

The report will be saved to ~/.zypheron/reports/ by default.
You can specify a custom output path with the --output flag.`,
    Args: cobra.ExactArgs(1),
    RunE: runExport,
}

var (
    outputPath string
)

func init() {
    exportCmd.Flags().StringVarP(&outputPath, "output", "o", "",
        "Output path for the report (default: ~/.zypheron/reports/)")
}

func runExport(cmd *cobra.Command, args []string) error {
    sessionID := args[0]

    // Load the session
    manager, err := session.NewSessionManager()
    if err != nil {
        return fmt.Errorf("failed to create session manager: %w", err)
    }

    sess, err := manager.Load(sessionID)
    if err != nil {
        return fmt.Errorf("failed to load session: %w", err)
    }

    // Generate the report
    if outputPath == "" {
        // Use default path with auto-generated filename
        err = reports.GenerateReport(sess, "")
    } else {
        // Use specified path
        err = reports.ExportJSON(sess, outputPath)
    }

    if err != nil {
        return fmt.Errorf("failed to export report: %w", err)
    }

    if outputPath == "" {
        defaultPath, _ := reports.GetDefaultReportPath()
        fmt.Printf("Report exported successfully to %s\n", defaultPath)
    } else {
        fmt.Printf("Report exported successfully to %s\n", outputPath)
    }

    return nil
}
```

## Auto-Export After Scan

Add automatic report generation after a scan completes:

```go
func runScan(cmd *cobra.Command, args []string) error {
    // ... scan execution code ...

    // Mark session as complete
    sess.Complete()

    // Auto-export if enabled
    if autoExport {
        fmt.Println("\nGenerating scan report...")

        if err := reports.GenerateReport(sess, ""); err != nil {
            // Don't fail the scan if export fails
            fmt.Fprintf(os.Stderr, "Warning: Failed to export report: %v\n", err)
        } else {
            defaultPath, _ := reports.GetDefaultReportPath()
            fmt.Printf("Report saved to: %s\n", defaultPath)
        }
    }

    return nil
}
```

## Batch Export

Export multiple sessions:

```go
func exportAllSessions() error {
    manager, err := session.NewSessionManager()
    if err != nil {
        return err
    }

    summaries, err := manager.ListSessions()
    if err != nil {
        return err
    }

    fmt.Printf("Exporting %d sessions...\n", len(summaries))

    for _, summary := range summaries {
        sess, err := manager.Load(summary.SessionID)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Warning: Failed to load session %s: %v\n",
                summary.SessionID, err)
            continue
        }

        if err := reports.GenerateReport(sess, ""); err != nil {
            fmt.Fprintf(os.Stderr, "Warning: Failed to export session %s: %v\n",
                summary.SessionID, err)
            continue
        }

        fmt.Printf("Exported: %s (%s)\n", summary.SessionID, summary.Target)
    }

    return nil
}
```

## Custom Report Processing

Process reports programmatically:

```go
import (
    "encoding/json"
    "os"
)

func analyzeReport(reportPath string) error {
    data, err := os.ReadFile(reportPath)
    if err != nil {
        return err
    }

    var report reports.Report
    if err := json.Unmarshal(data, &report); err != nil {
        return err
    }

    // Process critical vulnerabilities
    fmt.Printf("\nCritical Issues (%d):\n", report.Summary.CriticalCount)
    for _, vuln := range report.Vulnerabilities {
        if vuln.Severity == "critical" {
            fmt.Printf("  - %s (CVSS: %.1f)\n", vuln.Title, vuln.CVSSScore)
            fmt.Printf("    Remediation: %s\n", vuln.Remediation)
        }
    }

    return nil
}
```

## Error Handling Best Practices

```go
func exportWithErrorHandling(sess *session.Session, path string) {
    err := reports.ExportJSON(sess, path)
    if err != nil {
        switch {
        case strings.Contains(err.Error(), "permission denied"):
            fmt.Fprintln(os.Stderr, "Error: Permission denied. Try a different output directory.")
        case strings.Contains(err.Error(), "no space left"):
            fmt.Fprintln(os.Stderr, "Error: Disk full. Free up space and try again.")
        case strings.Contains(err.Error(), "session cannot be nil"):
            fmt.Fprintln(os.Stderr, "Error: Invalid session. The session may be corrupted.")
        default:
            fmt.Fprintf(os.Stderr, "Error exporting report: %v\n", err)
        }
        os.Exit(1)
    }
}
```

## Configuration Integration

Add report export settings to your config file:

```yaml
# ~/.zypheron/config.yaml
reports:
  auto_export: true
  output_directory: ~/.zypheron/reports
  include_raw_output: true
  compression: false  # Future feature
```

```go
type ReportConfig struct {
    AutoExport        bool   `yaml:"auto_export"`
    OutputDirectory   string `yaml:"output_directory"`
    IncludeRawOutput  bool   `yaml:"include_raw_output"`
}

func loadReportConfig() (*ReportConfig, error) {
    // Load from config file
    config := &ReportConfig{
        AutoExport:       true,
        OutputDirectory:  "",  // Use default
        IncludeRawOutput: true,
    }

    // ... load from viper or config file ...

    return config, nil
}
```

## Testing Integration

```go
func TestExportCommand(t *testing.T) {
    // Create test session
    sess := session.NewSession("test.example.com", session.ScanTypeNmap)
    sess.Complete()

    // Save session
    manager, _ := session.NewSessionManager()
    manager.Save(sess)

    // Test export command
    tmpDir := t.TempDir()
    cmd := exportCmd
    cmd.SetArgs([]string{sess.SessionID, "--output", filepath.Join(tmpDir, "test.json")})

    err := cmd.Execute()
    if err != nil {
        t.Fatalf("Export command failed: %v", err)
    }

    // Verify report exists
    if _, err := os.Stat(filepath.Join(tmpDir, "test.json")); os.IsNotExist(err) {
        t.Fatal("Report file was not created")
    }
}
```

## API Integration

For the API server, expose report export as an endpoint:

```go
func handleExportReport(w http.ResponseWriter, r *http.Request) {
    sessionID := r.URL.Query().Get("session_id")

    manager, err := session.NewSessionManager()
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    sess, err := manager.Load(sessionID)
    if err != nil {
        http.Error(w, "Session not found", http.StatusNotFound)
        return
    }

    // Build report
    report := reports.buildReport(sess)

    // Return as JSON
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Content-Disposition",
        fmt.Sprintf("attachment; filename=\"report_%s.json\"", sess.SessionID[:8]))

    json.NewEncoder(w).Encode(report)
}
```

## Background Export Queue

For enterprise use cases, implement background export processing:

```go
type ExportQueue struct {
    queue   chan *session.Session
    workers int
}

func NewExportQueue(workers int) *ExportQueue {
    q := &ExportQueue{
        queue:   make(chan *session.Session, 100),
        workers: workers,
    }

    for i := 0; i < workers; i++ {
        go q.worker()
    }

    return q
}

func (q *ExportQueue) worker() {
    for sess := range q.queue {
        if err := reports.GenerateReport(sess, ""); err != nil {
            log.Printf("Failed to export session %s: %v", sess.SessionID, err)
        }
    }
}

func (q *ExportQueue) Enqueue(sess *session.Session) {
    q.queue <- sess
}
```

## Migration from Legacy Formats

If you have existing reports in other formats:

```go
func migrateLegacyReports(legacyDir string) error {
    files, err := os.ReadDir(legacyDir)
    if err != nil {
        return err
    }

    for _, file := range files {
        if filepath.Ext(file.Name()) != ".txt" {
            continue
        }

        // Parse legacy format
        sess, err := parseLegacyReport(filepath.Join(legacyDir, file.Name()))
        if err != nil {
            log.Printf("Failed to parse %s: %v", file.Name(), err)
            continue
        }

        // Export to new JSON format
        if err := reports.GenerateReport(sess, ""); err != nil {
            log.Printf("Failed to export %s: %v", file.Name(), err)
        }
    }

    return nil
}
```
