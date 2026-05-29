package export_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/export"
	"github.com/KKingZero/Cobra-AI/zypheron-go/pkg/types"
)

// Example_basicExport demonstrates basic SARIF export
func Example_basicExport() {
	// Create a sample scan result
	cveID := "CVE-2023-12345"
	cvssScore := 7.5
	host := "example.com"
	port := 443

	scanResult := &types.ScanResult{
		ID:        "scan-001",
		Timestamp: time.Now(),
		Target:    "example.com",
		Tool:      "nmap",
		Ports:     "1-1000",
		Output:    "Nmap scan output here...",
		Duration:  45.5,
		Success:   true,
		Vulnerabilities: []types.Vulnerability{
			{
				ID:          "vuln-001",
				Title:       "Outdated SSL/TLS Configuration",
				Description: "The server supports outdated SSL/TLS protocols",
				Severity:    "high",
				CVEID:       &cveID,
				CVSSScore:   &cvssScore,
				Host:        &host,
				Port:        &port,
			},
		},
	}

	// Export to SARIF file
	err := export.ExportScanResultToSARIF(scanResult, filepath.Join(tempDir(), "output.sarif"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("SARIF export completed successfully")
	// Output: SARIF export completed successfully
}

// Example_advancedExport demonstrates advanced SARIF export with custom configuration
func Example_advancedExport() {
	// Create exporter with custom settings
	exporter := export.NewSARIFExporter("zypheron-scanner", "1.0.0")
	exporter.SetOrganization("Zypheron Security")
	exporter.SetInformationURI("https://github.com/your-org/zypheron")

	// Add custom properties
	exporter.AddProperty("scan_mode", "comprehensive")
	exporter.AddProperty("environment", "production")

	// Add multiple vulnerabilities
	vulnerabilities := []types.Vulnerability{
		{
			ID:          "vuln-001",
			Title:       "SQL Injection Vulnerability",
			Description: "User input is not properly sanitized",
			Severity:    "critical",
		},
		{
			ID:          "vuln-002",
			Title:       "Cross-Site Scripting (XSS)",
			Description: "Reflected XSS vulnerability found",
			Severity:    "high",
		},
	}

	for _, vuln := range vulnerabilities {
		if err := exporter.AddResult(vuln); err != nil {
			log.Printf("Failed to add vulnerability: %v", err)
			continue
		}
	}

	// Export to file
	if err := exporter.ExportToFile(filepath.Join(tempDir(), "advanced-output.sarif")); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Advanced SARIF export completed")
	// Output: Advanced SARIF export completed
}

// Example_exportToBytes demonstrates exporting to byte array
func Example_exportToBytes() {
	scanResult := &types.ScanResult{
		ID:        "scan-002",
		Timestamp: time.Now(),
		Target:    "api.example.com",
		Tool:      "nikto",
		Success:   true,
	}

	// Export to bytes
	data, err := export.ExportScanResultToSARIFBytes(scanResult)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated SARIF document with %d bytes\n", len(data))
	// Output will vary based on timestamp, but format is consistent
}

// Example_withInvocationMetadata demonstrates adding invocation metadata
func Example_withInvocationMetadata() {
	exporter := export.NewSARIFExporter("zypheron", "1.0.0")

	// Add invocation information
	invocation := export.SARIFInvocation{
		CommandLine:         "zypheron scan example.com --ports 1-1000",
		StartTimeUTC:        time.Now().UTC().Format(time.RFC3339),
		EndTimeUTC:          time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339),
		ExecutionSuccessful: true,
		Properties: &export.SARIFProperties{
			Data: map[string]interface{}{
				"target": "example.com",
				"ports":  "1-1000",
			},
		},
	}

	exporter.AddInvocation(invocation)

	// Add a vulnerability
	vuln := types.Vulnerability{
		ID:          "vuln-001",
		Title:       "Open Port",
		Description: "Port 22 is open and accessible",
		Severity:    "info",
	}

	if err := exporter.AddResult(vuln); err != nil {
		log.Fatal(err)
	}

	// Export
	if err := exporter.ExportToFile(filepath.Join(tempDir(), "with-invocation.sarif")); err != nil {
		log.Fatal(err)
	}

	fmt.Println("SARIF with invocation metadata exported")
	// Output: SARIF with invocation metadata exported
}

// Example_filteringBySevierty demonstrates filtering vulnerabilities by severity
func Example_filteringBySeverity() {
	exporter := export.NewSARIFExporter("zypheron", "1.0.0")

	// Sample vulnerabilities with mixed severities
	allVulnerabilities := []types.Vulnerability{
		{ID: "vuln-001", Title: "Critical Issue", Severity: "critical"},
		{ID: "vuln-002", Title: "High Issue", Severity: "high"},
		{ID: "vuln-003", Title: "Medium Issue", Severity: "medium"},
		{ID: "vuln-004", Title: "Low Issue", Severity: "low"},
		{ID: "vuln-005", Title: "Info", Severity: "info"},
	}

	// Export only critical and high severity findings
	for _, vuln := range allVulnerabilities {
		if vuln.Severity == "critical" || vuln.Severity == "high" {
			if err := exporter.AddResult(vuln); err != nil {
				log.Printf("Failed to add: %v", err)
			}
		}
	}

	if err := exporter.ExportToFile(filepath.Join(tempDir(), "critical-high-only.sarif")); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Filtered SARIF export completed")
	// Output: Filtered SARIF export completed
}

// Example_multipleScans demonstrates combining multiple scan results
func Example_multipleScans() {
	exporter := export.NewSARIFExporter("zypheron-multi", "1.0.0")

	// Multiple scan results from different tools
	scans := []*types.ScanResult{
		{
			ID:     "scan-001",
			Target: "example.com",
			Tool:   "nmap",
			Vulnerabilities: []types.Vulnerability{
				{ID: "nmap-001", Title: "Open Port 22", Severity: "info"},
			},
		},
		{
			ID:     "scan-002",
			Target: "example.com",
			Tool:   "nikto",
			Vulnerabilities: []types.Vulnerability{
				{ID: "nikto-001", Title: "Outdated Server", Severity: "medium"},
			},
		},
	}

	// Add all scan results
	for _, scan := range scans {
		if err := exporter.AddResultFromScanResult(scan); err != nil {
			log.Printf("Failed to add scan %s: %v", scan.ID, err)
		}
	}

	if err := exporter.ExportToFile(filepath.Join(tempDir(), "combined-scans.sarif")); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Combined scans exported to SARIF")
	// Output: Combined scans exported to SARIF
}

// Example_errorHandling demonstrates proper error handling
func Example_errorHandling() {
	scanResult := &types.ScanResult{
		ID:     "scan-003",
		Target: "example.com",
		Tool:   "zypheron",
	}

	// Attempt export with proper error handling
	if err := export.ExportScanResultToSARIF(scanResult, "/tmp/results.sarif"); err != nil {
		// Log the error
		log.Printf("Export failed: %v", err)

		// Try alternative location
		if err := export.ExportScanResultToSARIF(scanResult, "./results.sarif"); err != nil {
			log.Fatal("All export attempts failed")
		}
	}

	fmt.Println("Export succeeded")
	// Output will depend on file system permissions
}

// Example_withCVEInformation demonstrates including CVE details
func Example_withCVEInformation() {
	exporter := export.NewSARIFExporter("zypheron", "1.0.0")

	// Vulnerability with full CVE information
	cveID := "CVE-2023-12345"
	cvssScore := 9.8
	remediation := "Update to version 2.0.0 or apply security patch KB12345"
	host := "vulnerable.example.com"
	port := 443

	vuln := types.Vulnerability{
		ID:               "vuln-cve-001",
		Title:            "Remote Code Execution",
		Description:      "A critical remote code execution vulnerability exists in the authentication module",
		Severity:         "critical",
		CVEID:            &cveID,
		CVSSScore:        &cvssScore,
		Host:             &host,
		Port:             &port,
		Remediation:      &remediation,
		ExploitAvailable: true,
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
			"https://example.com/security-advisory/2023-001",
		},
	}

	if err := exporter.AddResult(vuln); err != nil {
		log.Fatal(err)
	}

	if err := exporter.ExportToFile(filepath.Join(tempDir(), "cve-details.sarif")); err != nil {
		log.Fatal(err)
	}

	fmt.Println("SARIF with CVE information exported")
	// Output: SARIF with CVE information exported
}

func tempDir() string {
	return filepath.Clean(os.TempDir())
}
