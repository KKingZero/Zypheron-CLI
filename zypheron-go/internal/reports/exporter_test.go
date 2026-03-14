package reports

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/session"
)

// TestExportJSON verifies JSON export functionality
func TestExportJSON(t *testing.T) {
	// Create a test session with sample data
	sess := createTestSession()

	// Create temporary directory for test output
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test_report.json")

	// Export to JSON
	err := ExportJSON(sess, outputPath)
	if err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatalf("Report file was not created: %s", outputPath)
	}

	// Verify file is not empty
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("Failed to stat report file: %v", err)
	}

	if info.Size() == 0 {
		t.Fatal("Report file is empty")
	}
}

// TestGenerateReport verifies the wrapper function
func TestGenerateReport(t *testing.T) {
	sess := createTestSession()

	// Test with custom directory
	tmpDir := t.TempDir()
	err := GenerateReport(sess, "json", tmpDir)
	if err != nil {
		t.Fatalf("GenerateReport failed: %v", err)
	}

	// Verify a report file was created in the directory
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read directory: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("No report file was generated")
	}
}

// TestBuildSummary verifies summary generation
func TestBuildSummary(t *testing.T) {
	sess := createTestSession()
	summary := buildSummary(sess)

	if summary.TotalVulnerabilities != 3 {
		t.Errorf("Expected 3 vulnerabilities, got %d", summary.TotalVulnerabilities)
	}

	if summary.CriticalCount != 1 {
		t.Errorf("Expected 1 critical vulnerability, got %d", summary.CriticalCount)
	}

	if summary.HighCount != 1 {
		t.Errorf("Expected 1 high vulnerability, got %d", summary.HighCount)
	}

	if summary.MediumCount != 1 {
		t.Errorf("Expected 1 medium vulnerability, got %d", summary.MediumCount)
	}
}

// TestExportJSONNilSession verifies error handling for nil session
func TestExportJSONNilSession(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test_report.json")

	err := ExportJSON(nil, outputPath)
	if err == nil {
		t.Fatal("Expected error for nil session, got nil")
	}
}

// createTestSession creates a sample session for testing
func createTestSession() *session.Session {
	sess := session.NewSession("192.168.1.100", session.ScanTypeNmap)

	// Add some findings
	sess.AddFinding(session.Finding{
		Type:        "port",
		Title:       "Open Port 22",
		Description: "SSH port is open",
		Severity:    "info",
	})

	sess.AddFinding(session.Finding{
		Type:        "service",
		Title:       "Apache HTTP Server",
		Description: "Apache 2.4.41 detected",
		Severity:    "info",
	})

	// Add vulnerabilities with different severities
	sess.AddVulnerability(session.Vulnerability{
		Title:       "SQL Injection",
		Description: "SQL injection vulnerability in login form",
		Severity:    "critical",
		CVSSScore:   9.8,
		Port:        80,
		Service:     "http",
		Remediation: "Implement parameterized queries",
	})

	sess.AddVulnerability(session.Vulnerability{
		Title:       "Cross-Site Scripting (XSS)",
		Description: "Reflected XSS in search parameter",
		Severity:    "high",
		CVSSScore:   7.4,
		Port:        80,
		Service:     "http",
		Remediation: "Sanitize user input",
	})

	sess.AddVulnerability(session.Vulnerability{
		Title:       "Directory Listing Enabled",
		Description: "Server allows directory browsing",
		Severity:    "medium",
		CVSSScore:   5.3,
		Port:        80,
		Service:     "http",
		Remediation: "Disable directory listing in web server config",
	})

	// Set raw output
	sess.AppendRawOutput("Starting Nmap scan...\nHost is up\n22/tcp open ssh\n80/tcp open http\n")

	// Set summary
	sess.SetSummary("Scan completed. Found 2 open ports and 3 vulnerabilities.")

	// Complete the session
	sess.Complete()
	time.Sleep(10 * time.Millisecond) // Ensure duration is non-zero

	return sess
}
