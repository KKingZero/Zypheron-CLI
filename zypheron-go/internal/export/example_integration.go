package export

// This file contains example code for integrating SARIF export with scan commands.
// These examples show how to modify existing scan commands to support SARIF output.

/*
Example 1: Basic SARIF Export Integration

Add to your scan command in internal/commands/scan.go:

	// After scan completion and result processing...
	if format == "sarif" {
		if err := export.ExportScanResultToSARIF(scanResult, output); err != nil {
			return fmt.Errorf("failed to export SARIF: %w", err)
		}
		fmt.Println(ui.SuccessMsg(fmt.Sprintf("SARIF report saved to: %s", output)))
		return nil
	}

Example 2: Advanced SARIF Export with Custom Metadata

	if format == "sarif" {
		exporter := export.NewSARIFExporter(scanResult.Tool, "1.0.0")
		exporter.SetOrganization("Zypheron Security")
		exporter.AddProperty("scan_mode", scanMode)
		exporter.AddProperty("scan_duration_seconds", scanResult.Duration)

		if err := exporter.AddResultFromScanResult(scanResult); err != nil {
			return fmt.Errorf("failed to add scan results: %w", err)
		}

		if err := exporter.ExportToFile(output); err != nil {
			return fmt.Errorf("failed to export SARIF: %w", err)
		}

		fmt.Println(ui.SuccessMsg(fmt.Sprintf("SARIF report saved to: %s", output)))
		return nil
	}

Example 3: Adding SARIF Format to Existing Format Detection

In internal/report/report.go, add SARIF to the format switch:

	func GenerateReport(scanResult *types.ScanResult, format string, outputPath string) error {
		var content string
		var err error

		switch strings.ToLower(format) {
		case "sarif":
			return export.ExportScanResultToSARIF(scanResult, outputPath)
		case "html":
			content, err = GenerateHTMLReport(scanResult)
		// ... existing cases ...
		}
	}

And in DetectFormatFromExtension:

	func DetectFormatFromExtension(filename string) string {
		ext := strings.ToLower(filepath.Ext(filename))
		switch ext {
		case ".sarif":
			return "sarif"
		case ".html", ".htm":
			return "html"
		// ... existing cases ...
		}
	}

Example 4: CLI Flag Support

Add to scan command flags:

	cmd.Flags().StringVar(&format, "format", "text", "Output format (text, json, html, markdown, pdf, sarif)")

Example 5: Multiple Format Export

Export to multiple formats simultaneously:

	// Export to primary format
	if err := saveReport(scanResult, output, format); err != nil {
		return fmt.Errorf("failed to save primary report: %w", err)
	}

	// Also export to SARIF for CI/CD integration
	if os.Getenv("CI") == "true" || exportSARIF {
		sarifPath := strings.TrimSuffix(output, filepath.Ext(output)) + ".sarif"
		if err := export.ExportScanResultToSARIF(scanResult, sarifPath); err != nil {
			fmt.Println(ui.WarningMsg(fmt.Sprintf("Failed to export SARIF: %s", err)))
		} else {
			fmt.Println(ui.InfoMsg(fmt.Sprintf("SARIF report also saved to: %s", sarifPath)))
		}
	}

Example 6: GitHub Actions Integration

Create a GitHub Actions workflow (.github/workflows/security-scan.yml):

	name: Security Scan
	on:
	  push:
	    branches: [ main ]
	  pull_request:
	    branches: [ main ]

	jobs:
	  scan:
	    runs-on: ubuntu-latest
	    steps:
	      - uses: actions/checkout@v3

	      - name: Run Zypheron Security Scan
	        run: |
	          zypheron scan ${{ github.event.repository.url }} \
	            --format sarif \
	            --output results.sarif

	      - name: Upload SARIF to GitHub Security
	        uses: github/codeql-action/upload-sarif@v2
	        with:
	          sarif_file: results.sarif

Example 7: Error Handling Best Practices

	func exportWithRetry(scanResult *types.ScanResult, path string) error {
		const maxRetries = 3
		var err error

		for i := 0; i < maxRetries; i++ {
			err = export.ExportScanResultToSARIF(scanResult, path)
			if err == nil {
				return nil
			}

			// Check if it's a permanent error
			if os.IsPermission(err) {
				return fmt.Errorf("permission denied: %w", err)
			}

			// Retry on temporary errors
			time.Sleep(time.Duration(i+1) * time.Second)
		}

		return fmt.Errorf("failed after %d retries: %w", maxRetries, err)
	}

Example 8: Streaming Large Results

For very large scan results, consider streaming:

	func exportLargeScan(scanResults []*types.ScanResult, outputDir string) error {
		for i, scanResult := range scanResults {
			outputPath := filepath.Join(outputDir, fmt.Sprintf("scan-%d.sarif", i))
			if err := export.ExportScanResultToSARIF(scanResult, outputPath); err != nil {
				return fmt.Errorf("failed to export scan %d: %w", i, err)
			}
		}
		return nil
	}

Example 9: Custom Vulnerability Filtering

Export only high/critical vulnerabilities:

	func exportCriticalFindings(scanResult *types.ScanResult, path string) error {
		exporter := export.NewSARIFExporter(scanResult.Tool, "1.0.0")

		for _, vuln := range scanResult.Vulnerabilities {
			if vuln.Severity == "critical" || vuln.Severity == "high" {
				if err := exporter.AddResult(vuln); err != nil {
					return err
				}
			}
		}

		return exporter.ExportToFile(path)
	}

Example 10: Integration with Existing Storage

Save SARIF alongside database storage:

	// Save to database
	if scanStore != nil {
		if err := scanStore.SaveScan(scanResult); err != nil {
			fmt.Println(ui.WarningMsg(fmt.Sprintf("Failed to save scan: %s", err)))
		}
	}

	// Export to SARIF for external tools
	if output != "" {
		sarifPath := filepath.Join(filepath.Dir(output), scanResult.ID+".sarif")
		if err := export.ExportScanResultToSARIF(scanResult, sarifPath); err != nil {
			fmt.Println(ui.WarningMsg(fmt.Sprintf("Failed to export SARIF: %s", err)))
		}
	}

Example 11: Validation Before Upload

	func validateAndExportSARIF(scanResult *types.ScanResult, path string) error {
		// Export to bytes first for validation
		data, err := export.ExportScanResultToSARIFBytes(scanResult)
		if err != nil {
			return fmt.Errorf("failed to generate SARIF: %w", err)
		}

		// Validate JSON structure
		var log export.SARIFLog
		if err := json.Unmarshal(data, &log); err != nil {
			return fmt.Errorf("invalid SARIF JSON: %w", err)
		}

		// Check required fields
		if log.Version != export.SARIFVersion {
			return fmt.Errorf("invalid SARIF version: %s", log.Version)
		}

		// Write to file
		if err := os.WriteFile(path, data, 0644); err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}

		return nil
	}

Example 12: Azure DevOps Integration

Upload SARIF to Azure DevOps:

	# Azure DevOps Pipeline (azure-pipelines.yml)
	- task: PublishBuildArtifacts@1
	  inputs:
	    pathtoPublish: 'results.sarif'
	    artifactName: 'CodeAnalysisLogs'
	    publishLocation: 'Container'

	# Or use the Advanced Security task
	- task: AdvancedSecurity-Publish@1
	  inputs:
	    SarifFile: 'results.sarif'

Example 13: GitLab Integration

	# .gitlab-ci.yml
	security-scan:
	  script:
	    - zypheron scan $CI_PROJECT_URL --format sarif --output gl-sast-report.sarif
	  artifacts:
	    reports:
	      sast: gl-sast-report.sarif
*/
