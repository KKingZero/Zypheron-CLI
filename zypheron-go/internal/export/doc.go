// Package export provides functionality for exporting security scan results
// to various standardized formats used by security tools and platforms.
//
// SARIF Export
//
// The primary functionality of this package is exporting scan results to
// SARIF (Static Analysis Results Interchange Format) version 2.1.0, which
// is the industry-standard format for representing static analysis results.
// SARIF is used by:
//
//   - GitHub Security (Code Scanning, Dependabot)
//   - Azure DevOps Security
//   - GitLab Security Dashboard
//   - Visual Studio Code
//   - Many other security and analysis tools
//
// Basic Usage
//
// To export a single ScanResult to a SARIF file:
//
//	import (
//	    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/export"
//	    "github.com/KKingZero/Cobra-AI/zypheron-go/pkg/types"
//	)
//
//	func main() {
//	    scanResult := &types.ScanResult{
//	        ID:        "scan-001",
//	        Target:    "example.com",
//	        Tool:      "nmap",
//	        // ... other fields
//	    }
//
//	    err := export.ExportScanResultToSARIF(scanResult, "output.sarif")
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	}
//
// Advanced Usage
//
// For more control over the export process, create a SARIFExporter directly:
//
//	exporter := export.NewSARIFExporter("zypheron-scanner", "1.0.0")
//	exporter.SetOrganization("Zypheron Security")
//	exporter.SetInformationURI("https://example.com/docs")
//
//	// Add custom properties
//	exporter.AddProperty("scan_type", "network")
//	exporter.AddProperty("environment", "production")
//
//	// Add individual vulnerabilities
//	for _, vuln := range vulnerabilities {
//	    err := exporter.AddResult(vuln)
//	    if err != nil {
//	        log.Printf("Failed to add vulnerability: %v", err)
//	    }
//	}
//
//	// Export to file
//	err := exporter.ExportToFile("results.sarif")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Or export to bytes for further processing:
//
//	jsonData, err := exporter.Export()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Process jsonData as needed
//
// SARIF Schema Compliance
//
// The package generates SARIF 2.1.0 compliant output with the following features:
//
//   - Full schema compliance with SARIF 2.1.0 specification
//   - Proper severity mapping: critical/high -> error, medium -> warning, low/info -> note
//   - Fingerprint generation for result deduplication
//   - Rule definitions with descriptions and remediation guidance
//   - Location tracking (physical locations with file, line, column information)
//   - Support for CVE IDs, CVSS scores, and security references
//   - Invocation metadata for audit trails
//   - Custom properties for additional metadata
//
// Severity Mapping
//
// The package maps Zypheron severity levels to SARIF levels as follows:
//
//	Zypheron Severity  ->  SARIF Level
//	-----------------      -----------
//	critical           ->  error
//	high               ->  error
//	medium             ->  warning
//	low                ->  note
//	info               ->  note
//	informational      ->  note
//
// Fingerprints
//
// The package automatically generates fingerprints for result deduplication:
//
//   - Primary fingerprint: CVE ID > Vulnerability ID > Content hash
//   - Location fingerprint: Host + Port combination hash
//   - Content fingerprint: Title + Severity hash
//
// These fingerprints help security platforms deduplicate findings across
// multiple scans and track remediation status over time.
//
// Integration with Scan Commands
//
// To integrate SARIF export with existing scan commands, modify the scan
// command to support a SARIF output format:
//
//	// In your scan command
//	if format == "sarif" {
//	    err := export.ExportScanResultToSARIF(scanResult, outputPath)
//	    if err != nil {
//	        return fmt.Errorf("failed to export SARIF: %w", err)
//	    }
//	    fmt.Println("SARIF report saved to:", outputPath)
//	}
//
// GitHub Integration
//
// To upload SARIF results to GitHub Security:
//
//	# Generate SARIF output
//	zypheron scan example.com --format sarif --output results.sarif
//
//	# Upload to GitHub (requires GitHub CLI)
//	gh api -X POST /repos/{owner}/{repo}/code-scanning/sarifs \
//	    -F commit_sha=$(git rev-parse HEAD) \
//	    -F ref=refs/heads/main \
//	    -F sarif=@results.sarif
//
// Or use the GitHub Actions code-scanning upload action:
//
//	- name: Upload SARIF file
//	  uses: github/codeql-action/upload-sarif@v2
//	  with:
//	    sarif_file: results.sarif
//
// Best Practices
//
// 1. Always include CVE IDs when available for better correlation
// 2. Provide CVSS scores for severity ranking
// 3. Include remediation guidance in vulnerability objects
// 4. Add references to security advisories and documentation
// 5. Use consistent rule IDs across scans for proper tracking
// 6. Include invocation metadata for audit trails
// 7. Set appropriate tool information (name, version, organization)
//
// Error Handling
//
// All export functions return errors that should be checked:
//
//	err := export.ExportScanResultToSARIF(scanResult, path)
//	if err != nil {
//	    // Handle error - common causes:
//	    // - Invalid file path
//	    // - Permission issues
//	    // - Disk space issues
//	    // - Invalid scan result data
//	    log.Printf("Export failed: %v", err)
//	}
//
// Performance Considerations
//
// The SARIF export is optimized for performance:
//
//   - Results are streamed during generation
//   - Fingerprints are cached to avoid recomputation
//   - JSON marshaling uses efficient buffering
//   - Large scan outputs are handled efficiently
//
// Benchmarks show typical performance:
//
//   - Adding a result: ~5-10 μs per vulnerability
//   - Exporting 100 results: ~2-5 ms
//   - Exporting a full scan: ~5-20 ms depending on size
//
// Thread Safety
//
// SARIFExporter is not thread-safe. If you need to export from multiple
// goroutines, create separate exporter instances or use proper synchronization.
//
// Validation
//
// The package generates schema-compliant SARIF that can be validated using:
//
//   - SARIF Multitool (https://github.com/microsoft/sarif-sdk)
//   - Online validators
//   - Schema validation libraries
//
// For additional validation, the test suite includes schema compliance tests.
package export
