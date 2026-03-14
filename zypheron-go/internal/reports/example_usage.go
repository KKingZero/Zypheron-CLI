package reports

// Example usage of the report export system
//
// This file provides examples of how to use the report export functions.
// It is not executed as part of the package but serves as documentation.

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/session"
)

// ExampleBasicUsage demonstrates basic report generation
func ExampleBasicUsage() {
	// Create or load a session
	sess := session.NewSession("example.com", session.ScanTypeNmap)

	// Add some vulnerabilities
	sess.AddVulnerability(session.Vulnerability{
		CVEID:            "CVE-2023-1234",
		Title:            "Remote Code Execution",
		Description:      "Critical vulnerability allowing remote code execution",
		Severity:         "critical",
		CVSSScore:        9.8,
		Port:             22,
		Service:          "SSH",
		ExploitAvailable: true,
		Remediation:      "Update to latest version",
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
		},
	})

	// Export to different formats
	homeDir, _ := os.UserHomeDir()
	reportsDir := filepath.Join(homeDir, ".zypheron", "reports")

	// Export as JSON
	if err := ExportJSON(sess, filepath.Join(reportsDir, "report.json")); err != nil {
		log.Printf("Failed to export JSON: %v", err)
	}

	// Export as HTML
	if err := ExportHTML(sess, filepath.Join(reportsDir, "report.html")); err != nil {
		log.Printf("Failed to export HTML: %v", err)
	}

	// Export as Markdown
	if err := ExportMarkdown(sess, filepath.Join(reportsDir, "report.md")); err != nil {
		log.Printf("Failed to export Markdown: %v", err)
	}

	// Export as PDF (requires Chrome/Chromium)
	if err := ExportPDF(sess, filepath.Join(reportsDir, "report.pdf")); err != nil {
		log.Printf("Failed to export PDF: %v", err)
	}

	fmt.Println("Reports generated successfully")
}

// ExampleUnifiedExport demonstrates using the GenerateReport function
func ExampleUnifiedExport() {
	sess := session.NewSession("example.com", session.ScanTypeNmap)

	// Add vulnerabilities...

	// Generate report with automatic format detection and default path
	// This will create: ~/.zypheron/reports/report_<session_id>_<timestamp>.html
	if err := GenerateReport(sess, "html", ""); err != nil {
		log.Printf("Failed to generate report: %v", err)
	}

	// Or specify custom path
	if err := GenerateReport(sess, "json", "/tmp/my-report.json"); err != nil {
		log.Printf("Failed to generate report: %v", err)
	}
}

// ExampleCustomConfiguration demonstrates using custom report configurations
func ExampleCustomConfiguration() {
	sess := session.NewSession("example.com", session.ScanTypeNmap)

	// Add vulnerabilities...

	// Create custom configuration
	config := &ReportConfig{
		IncludeRawOutput:       true,  // Include raw scan output
		IncludeChatHistory:     true,  // Include AI conversation
		GroupBySeverity:        true,  // Group vulnerabilities by severity
		IncludeRecommendations: true,  // Include AI recommendations
		CompactMode:            false, // Full detailed report
	}

	// Export with custom configuration
	if err := ExportHTMLWithConfig(sess, "/tmp/report.html", config); err != nil {
		log.Printf("Failed to export HTML: %v", err)
	}

	// Compact mode (minimal report)
	compactConfig := &ReportConfig{
		IncludeRawOutput:       false,
		IncludeChatHistory:     false,
		GroupBySeverity:        true,
		IncludeRecommendations: false,
		CompactMode:            true,
	}

	if err := ExportMarkdownWithConfig(sess, "/tmp/compact-report.md", compactConfig); err != nil {
		log.Printf("Failed to export Markdown: %v", err)
	}
}

// ExampleBatchExport demonstrates exporting multiple sessions
func ExampleBatchExport() {
	// Create session manager
	manager, err := session.NewSessionManager()
	if err != nil {
		log.Fatalf("Failed to create session manager: %v", err)
	}

	// List all sessions
	summaries, err := manager.ListSessions()
	if err != nil {
		log.Fatalf("Failed to list sessions: %v", err)
	}

	// Export each session
	homeDir, _ := os.UserHomeDir()
	reportsDir := filepath.Join(homeDir, ".zypheron", "reports", "batch")
	os.MkdirAll(reportsDir, 0755)

	for _, summary := range summaries {
		// Load full session
		sess, err := manager.Load(summary.SessionID)
		if err != nil {
			log.Printf("Failed to load session %s: %v", summary.SessionID, err)
			continue
		}

		// Generate report filename
		filename := fmt.Sprintf("report_%s_%s.html",
			summary.SessionID[:8],
			summary.StartTime.Format("20060102"),
		)

		// Export as HTML
		outputPath := filepath.Join(reportsDir, filename)
		if err := ExportHTML(sess, outputPath); err != nil {
			log.Printf("Failed to export session %s: %v", summary.SessionID, err)
			continue
		}

		fmt.Printf("Exported: %s\n", outputPath)
	}
}

// ExampleIntegrationWithCommands demonstrates using reports in a CLI command
func ExampleIntegrationWithCommands() {
	// This would typically be called from a Cobra command handler

	// Load an existing session
	manager, _ := session.NewSessionManager()
	sess, err := manager.Load("some-session-id")
	if err != nil {
		log.Fatalf("Failed to load session: %v", err)
	}

	// User specifies output format via flag
	format := "html" // from --format flag
	output := ""     // from --output flag (empty = default path)

	// Generate report
	if err := GenerateReport(sess, format, output); err != nil {
		log.Fatalf("Failed to generate report: %v", err)
	}

	fmt.Printf("Report generated successfully in %s format\n", format)
}

// ExampleErrorHandling demonstrates proper error handling
func ExampleErrorHandling() {
	sess := session.NewSession("example.com", session.ScanTypeNmap)

	// Try to export to various formats
	formats := []string{"json", "html", "markdown", "pdf"}

	for _, format := range formats {
		outputPath := fmt.Sprintf("/tmp/report.%s", format)

		if err := GenerateReport(sess, format, outputPath); err != nil {
			// Handle specific error types
			switch {
			case os.IsPermission(err):
				log.Printf("Permission denied: %v", err)
			case os.IsNotExist(err):
				log.Printf("Directory does not exist: %v", err)
			default:
				log.Printf("Failed to generate %s report: %v", format, err)
			}
			continue
		}

		fmt.Printf("Successfully generated %s report\n", format)
	}
}
