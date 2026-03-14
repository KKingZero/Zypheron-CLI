package reports_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/reports"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/session"
)

// Example_exportJSON demonstrates basic JSON export usage
func Example_exportJSON() {
	// Create a sample session
	sess := session.NewSession("example.com", session.ScanTypeNmap)

	// Add some findings
	sess.AddFinding(session.Finding{
		Type:        "port",
		Title:       "Open Port 443",
		Description: "HTTPS port is open",
		Severity:    "info",
	})

	// Add a vulnerability
	sess.AddVulnerability(session.Vulnerability{
		Title:       "Weak SSL Configuration",
		Description: "Server supports deprecated TLS 1.0",
		Severity:    "medium",
		CVSSScore:   5.0,
		Port:        443,
		Service:     "https",
		Remediation: "Disable TLS 1.0 and enable TLS 1.2+",
	})

	sess.Complete()

	// Export to specific path
	tmpDir := os.TempDir()
	outputPath := filepath.Join(tmpDir, "example_report.json")

	err := reports.ExportJSON(sess, outputPath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Report exported successfully")
	// Output: Report exported successfully
}

// Example_generateReport demonstrates automatic report generation
func Example_generateReport() {
	// Create a sample session
	sess := session.NewSession("192.168.1.1", session.ScanTypeNuclei)

	sess.AddVulnerability(session.Vulnerability{
		Title:       "XSS Vulnerability",
		Description: "Reflected XSS in search parameter",
		Severity:    "high",
		CVSSScore:   7.4,
	})

	sess.Complete()

	// Generate report with auto-naming in temp directory
	tmpDir := os.TempDir()
	err := reports.GenerateReport(sess, "json", tmpDir)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Report generated successfully")
	// Output: Report generated successfully
}

// Example_getDefaultReportPath shows how to get the default report directory
func Example_getDefaultReportPath() {
	defaultPath, err := reports.GetDefaultReportPath()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Default report directory: %s\n", filepath.Base(defaultPath))
	// Output: Default report directory: reports
}
