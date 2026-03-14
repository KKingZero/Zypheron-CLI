package reports

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/session"
)

// ReportMetadata contains metadata about the scan session
type ReportMetadata struct {
	SessionID string    `json:"session_id"`
	Target    string    `json:"target"`
	Tool      string    `json:"tool"`
	Timestamp time.Time `json:"timestamp"`
	Duration  string    `json:"duration"`
	Status    string    `json:"status"`
}

// ReportSummary provides a high-level summary of the scan results
type ReportSummary struct {
	TotalFindings        int `json:"total_findings"`
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	CriticalCount        int `json:"critical_count"`
	HighCount            int `json:"high_count"`
	MediumCount          int `json:"medium_count"`
	LowCount             int `json:"low_count"`
	InfoCount            int `json:"info_count"`
}

// Report represents the complete JSON report structure
type Report struct {
	Metadata        ReportMetadata            `json:"metadata"`
	Summary         ReportSummary             `json:"summary"`
	Findings        []session.Finding         `json:"findings"`
	Vulnerabilities []session.Vulnerability   `json:"vulnerabilities"`
	RawOutput       string                    `json:"raw_output,omitempty"`
	AIAnalysis      string                    `json:"ai_analysis,omitempty"`
	Notes           string                    `json:"notes,omitempty"`
}

// ExportJSON exports a session to JSON format
// This is the primary export function for the open-source free tier
func ExportJSON(sess *session.Session, outputPath string) error {
	if sess == nil {
		return fmt.Errorf("session cannot be nil")
	}

	// Build the report structure
	report := buildReport(sess)

	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report to JSON: %w", err)
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write to file with restrictive permissions
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	return nil
}

// GenerateReport generates a report in the specified format
// Format can be "json", "html", "markdown", or "pdf"
// If outputPath is empty, a default path is generated
func GenerateReport(sess *session.Session, format string, outputPath string) error {
	if sess == nil {
		return fmt.Errorf("session cannot be nil")
	}

	// If outputPath is empty or a directory, generate a default filename
	if outputPath == "" || isDirectory(outputPath) {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}

		baseDir := filepath.Join(homeDir, ".zypheron", "reports")
		if outputPath != "" && isDirectory(outputPath) {
			baseDir = outputPath
		}

		ext := format
		if ext == "markdown" {
			ext = "md"
		}

		timestamp := time.Now().Format("20060102_150405")
		filename := fmt.Sprintf("report_%s_%s.%s", sess.SessionID[:8], timestamp, ext)
		outputPath = filepath.Join(baseDir, filename)
	}

	switch format {
	case "json":
		return ExportJSON(sess, outputPath)
	case "html":
		return ExportHTML(sess, outputPath)
	case "markdown":
		return ExportMarkdown(sess, outputPath)
	case "pdf":
		return ExportPDF(sess, outputPath)
	default:
		return fmt.Errorf("unsupported report format: %s", format)
	}
}

// buildReport constructs a Report from a Session
func buildReport(sess *session.Session) Report {
	// Calculate duration
	duration := sess.GetDuration().Round(time.Second).String()

	// Build metadata
	metadata := ReportMetadata{
		SessionID: sess.SessionID,
		Target:    sess.Target,
		Tool:      string(sess.ScanType),
		Timestamp: sess.StartTime,
		Duration:  duration,
		Status:    string(sess.Status),
	}

	// Build summary with severity counts
	summary := buildSummary(sess)

	return Report{
		Metadata:        metadata,
		Summary:         summary,
		Findings:        sess.Results.ParsedFindings,
		Vulnerabilities: sess.Results.Vulnerabilities,
		RawOutput:       sess.Results.RawOutput,
		AIAnalysis:      sess.Results.AIAnalysis,
		Notes:           sess.Notes,
	}
}

// buildSummary generates summary statistics from session data
func buildSummary(sess *session.Session) ReportSummary {
	summary := ReportSummary{
		TotalFindings:        len(sess.Results.ParsedFindings),
		TotalVulnerabilities: len(sess.Results.Vulnerabilities),
	}

	// Count vulnerabilities by severity
	for _, vuln := range sess.Results.Vulnerabilities {
		switch vuln.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		case "info":
			summary.InfoCount++
		}
	}

	return summary
}

// isDirectory checks if a path is a directory
func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// GetDefaultReportPath returns the default report directory path
func GetDefaultReportPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	return filepath.Join(homeDir, ".zypheron", "reports"), nil
}
