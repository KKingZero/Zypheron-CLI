package export

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/pkg/types"
)

// TestNewSARIFExporter tests creating a new SARIF exporter
func TestNewSARIFExporter(t *testing.T) {
	exporter := NewSARIFExporter("test-tool", "1.0.0")

	if exporter == nil {
		t.Fatal("expected exporter to be non-nil")
	}

	if exporter.toolName != "test-tool" {
		t.Errorf("expected tool name 'test-tool', got %s", exporter.toolName)
	}

	if exporter.toolVersion != "1.0.0" {
		t.Errorf("expected tool version '1.0.0', got %s", exporter.toolVersion)
	}

	if exporter.rules == nil {
		t.Error("expected rules map to be initialized")
	}

	if exporter.results == nil {
		t.Error("expected results slice to be initialized")
	}
}

// TestSetInformationURI tests setting information URI
func TestSetInformationURI(t *testing.T) {
	exporter := NewSARIFExporter("test-tool", "1.0.0")
	uri := "https://example.com/tool"
	exporter.SetInformationURI(uri)

	if exporter.informationURI != uri {
		t.Errorf("expected information URI %s, got %s", uri, exporter.informationURI)
	}
}

// TestSetOrganization tests setting organization
func TestSetOrganization(t *testing.T) {
	exporter := NewSARIFExporter("test-tool", "1.0.0")
	org := "Test Security Inc"
	exporter.SetOrganization(org)

	if exporter.organization != org {
		t.Errorf("expected organization %s, got %s", org, exporter.organization)
	}
}

// TestAddProperty tests adding custom properties
func TestAddProperty(t *testing.T) {
	exporter := NewSARIFExporter("test-tool", "1.0.0")
	exporter.AddProperty("custom_key", "custom_value")

	if val, ok := exporter.properties.Data["custom_key"]; !ok {
		t.Error("expected custom_key to be set")
	} else if val != "custom_value" {
		t.Errorf("expected custom_value, got %v", val)
	}
}

// TestMapSeverityToLevel tests severity to level mapping
func TestMapSeverityToLevel(t *testing.T) {
	exporter := NewSARIFExporter("test-tool", "1.0.0")

	tests := []struct {
		severity string
		expected string
	}{
		{"critical", LevelError},
		{"CRITICAL", LevelError},
		{"high", LevelError},
		{"HIGH", LevelError},
		{"medium", LevelWarning},
		{"MEDIUM", LevelWarning},
		{"low", LevelNote},
		{"LOW", LevelNote},
		{"info", LevelNote},
		{"INFO", LevelNote},
		{"informational", LevelNote},
		{"unknown", LevelWarning},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			level := exporter.mapSeverityToLevel(tt.severity)
			if level != tt.expected {
				t.Errorf("severity %s: expected level %s, got %s", tt.severity, tt.expected, level)
			}
		})
	}
}

// TestAddResult tests adding a vulnerability result
func TestAddResult(t *testing.T) {
	exporter := NewSARIFExporter("test-tool", "1.0.0")

	cveID := "CVE-2023-12345"
	cvssScore := 7.5
	host := "example.com"
	port := 443
	remediation := "Update to version 2.0"

	vuln := types.Vulnerability{
		ID:               "vuln-001",
		Title:            "SQL Injection Vulnerability",
		Description:      "A SQL injection vulnerability was found",
		Severity:         "high",
		CVEID:            &cveID,
		CVSSScore:        &cvssScore,
		Host:             &host,
		Port:             &port,
		Remediation:      &remediation,
		ExploitAvailable: true,
		References:       []string{"https://example.com/vuln/001"},
	}

	err := exporter.AddResult(vuln)
	if err != nil {
		t.Fatalf("failed to add result: %v", err)
	}

	if len(exporter.results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(exporter.results))
	}

	result := exporter.results[0]

	// Check rule ID
	if result.RuleID != cveID {
		t.Errorf("expected rule ID %s, got %s", cveID, result.RuleID)
	}

	// Check level
	expectedLevel := LevelError
	if result.Level != expectedLevel {
		t.Errorf("expected level %s, got %s", expectedLevel, result.Level)
	}

	// Check message
	if result.Message.Text != vuln.Description {
		t.Errorf("expected message '%s', got '%s'", vuln.Description, result.Message.Text)
	}

	// Check properties
	if result.Properties == nil {
		t.Fatal("expected properties to be set")
	}

	if val, ok := result.Properties.Data["cvss_score"]; !ok {
		t.Error("expected cvss_score in properties")
	} else if val != cvssScore {
		t.Errorf("expected CVSS score %f, got %v", cvssScore, val)
	}

	if val, ok := result.Properties.Data["cve_id"]; !ok {
		t.Error("expected cve_id in properties")
	} else if val != cveID {
		t.Errorf("expected CVE ID %s, got %v", cveID, val)
	}

	// Check exploit available tag
	exploitAvailable, ok := result.Properties.Data["exploit_available"]
	if !ok || !exploitAvailable.(bool) {
		t.Error("expected exploit_available to be true")
	}

	// Check locations
	if len(result.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(result.Locations))
	}

	location := result.Locations[0]
	if location.Properties == nil {
		t.Fatal("expected location properties to be set")
	}

	if val, ok := location.Properties.Data["host"]; !ok || val != host {
		t.Errorf("expected host %s, got %v", host, val)
	}

	if val, ok := location.Properties.Data["port"]; !ok || val != port {
		t.Errorf("expected port %d, got %v", port, val)
	}

	// Check rule was created
	if len(exporter.rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(exporter.rules))
	}

	rule, exists := exporter.rules[cveID]
	if !exists {
		t.Fatal("expected rule to exist for CVE ID")
	}

	if rule.Name != vuln.Title {
		t.Errorf("expected rule name '%s', got '%s'", vuln.Title, rule.Name)
	}
}

// TestAddResultFromScanResult tests adding results from a scan result
func TestAddResultFromScanResult(t *testing.T) {
	exporter := NewSARIFExporter("nmap", "1.0.0")

	cveID := "CVE-2023-12345"
	cvssScore := 8.5

	scanResult := &types.ScanResult{
		ID:        "scan-001",
		Timestamp: time.Now(),
		Target:    "example.com",
		Tool:      "nmap",
		Ports:     "1-1000",
		Output:    "Scan output here",
		Duration:  45.5,
		Success:   true,
		Vulnerabilities: []types.Vulnerability{
			{
				ID:          "vuln-001",
				Title:       "Test Vulnerability",
				Description: "This is a test vulnerability",
				Severity:    "critical",
				CVEID:       &cveID,
				CVSSScore:   &cvssScore,
			},
		},
		AIAnalysis: "AI analysis results",
		Metadata: map[string]string{
			"test": "value",
		},
	}

	err := exporter.AddResultFromScanResult(scanResult)
	if err != nil {
		t.Fatalf("failed to add scan result: %v", err)
	}

	// Check results
	if len(exporter.results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(exporter.results))
	}

	// Check invocations
	if len(exporter.invocations) != 1 {
		t.Fatalf("expected 1 invocation, got %d", len(exporter.invocations))
	}

	invocation := exporter.invocations[0]
	if !invocation.ExecutionSuccessful {
		t.Error("expected execution to be successful")
	}

	// Check properties
	if val, ok := exporter.properties.Data["scan_target"]; !ok || val != scanResult.Target {
		t.Errorf("expected scan_target %s, got %v", scanResult.Target, val)
	}

	if val, ok := exporter.properties.Data["ai_analysis"]; !ok || val != scanResult.AIAnalysis {
		t.Errorf("expected ai_analysis to be set")
	}
}

// TestExport tests exporting to JSON
func TestExport(t *testing.T) {
	exporter := NewSARIFExporter("test-tool", "1.0.0")
	exporter.SetOrganization("Test Org")

	cveID := "CVE-2023-12345"
	vuln := types.Vulnerability{
		ID:          "vuln-001",
		Title:       "Test Vulnerability",
		Description: "Test description",
		Severity:    "high",
		CVEID:       &cveID,
	}

	err := exporter.AddResult(vuln)
	if err != nil {
		t.Fatalf("failed to add result: %v", err)
	}

	data, err := exporter.Export()
	if err != nil {
		t.Fatalf("failed to export: %v", err)
	}

	// Verify it's valid JSON
	var sarifLog SARIFLog
	if err := json.Unmarshal(data, &sarifLog); err != nil {
		t.Fatalf("failed to unmarshal SARIF JSON: %v", err)
	}

	// Verify SARIF structure
	if sarifLog.Version != SARIFVersion {
		t.Errorf("expected version %s, got %s", SARIFVersion, sarifLog.Version)
	}

	if sarifLog.Schema != SchemaURI {
		t.Errorf("expected schema %s, got %s", SchemaURI, sarifLog.Schema)
	}

	if len(sarifLog.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarifLog.Runs))
	}

	run := sarifLog.Runs[0]
	if run.Tool.Driver.Name != "test-tool" {
		t.Errorf("expected tool name 'test-tool', got %s", run.Tool.Driver.Name)
	}

	if run.Tool.Driver.Organization != "Test Org" {
		t.Errorf("expected organization 'Test Org', got %s", run.Tool.Driver.Organization)
	}

	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}

	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(run.Tool.Driver.Rules))
	}
}

// TestExportToFile tests exporting to a file
func TestExportToFile(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test-output.sarif")

	exporter := NewSARIFExporter("test-tool", "1.0.0")

	vuln := types.Vulnerability{
		ID:          "vuln-001",
		Title:       "Test Vulnerability",
		Description: "Test description",
		Severity:    "medium",
	}

	err := exporter.AddResult(vuln)
	if err != nil {
		t.Fatalf("failed to add result: %v", err)
	}

	err = exporter.ExportToFile(outputPath)
	if err != nil {
		t.Fatalf("failed to export to file: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("output file does not exist")
	}

	// Read and verify content
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	var sarifLog SARIFLog
	if err := json.Unmarshal(data, &sarifLog); err != nil {
		t.Fatalf("failed to unmarshal SARIF JSON from file: %v", err)
	}

	if len(sarifLog.Runs) == 0 {
		t.Fatal("expected at least one run in SARIF output")
	}
}

// TestExportToFileWithNestedDirectory tests exporting to a nested directory
func TestExportToFileWithNestedDirectory(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "subdir1", "subdir2", "output.sarif")

	exporter := NewSARIFExporter("test-tool", "1.0.0")

	vuln := types.Vulnerability{
		ID:          "vuln-001",
		Title:       "Test",
		Description: "Test",
		Severity:    "low",
	}

	err := exporter.AddResult(vuln)
	if err != nil {
		t.Fatalf("failed to add result: %v", err)
	}

	err = exporter.ExportToFile(outputPath)
	if err != nil {
		t.Fatalf("failed to export to nested directory: %v", err)
	}

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("output file does not exist in nested directory")
	}
}

// TestExportScanResultToSARIF tests the convenience function
func TestExportScanResultToSARIF(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "scan-result.sarif")

	scanResult := &types.ScanResult{
		ID:        "scan-001",
		Timestamp: time.Now(),
		Target:    "192.168.1.1",
		Tool:      "nmap",
		Ports:     "1-1000",
		Output:    "Scan output",
		Duration:  30.0,
		Success:   true,
		Vulnerabilities: []types.Vulnerability{
			{
				ID:          "vuln-001",
				Title:       "Open Port",
				Description: "Port 22 is open",
				Severity:    "info",
			},
		},
	}

	err := ExportScanResultToSARIF(scanResult, outputPath)
	if err != nil {
		t.Fatalf("failed to export scan result: %v", err)
	}

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("output file does not exist")
	}

	// Verify content
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	var sarifLog SARIFLog
	if err := json.Unmarshal(data, &sarifLog); err != nil {
		t.Fatalf("failed to unmarshal SARIF: %v", err)
	}

	if len(sarifLog.Runs) == 0 {
		t.Fatal("expected at least one run")
	}

	run := sarifLog.Runs[0]
	if run.Tool.Driver.Name != "nmap" {
		t.Errorf("expected tool name 'nmap', got %s", run.Tool.Driver.Name)
	}
}

// TestExportScanResultToSARIFBytes tests exporting to bytes
func TestExportScanResultToSARIFBytes(t *testing.T) {
	scanResult := &types.ScanResult{
		ID:        "scan-001",
		Timestamp: time.Now(),
		Target:    "example.com",
		Tool:      "nikto",
		Ports:     "80,443",
		Output:    "Scan output",
		Duration:  60.5,
		Success:   true,
		Vulnerabilities: []types.Vulnerability{
			{
				ID:          "vuln-001",
				Title:       "Outdated Server",
				Description: "Server software is outdated",
				Severity:    "medium",
			},
		},
	}

	data, err := ExportScanResultToSARIFBytes(scanResult)
	if err != nil {
		t.Fatalf("failed to export to bytes: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("expected non-empty data")
	}

	// Verify it's valid JSON
	var sarifLog SARIFLog
	if err := json.Unmarshal(data, &sarifLog); err != nil {
		t.Fatalf("failed to unmarshal SARIF: %v", err)
	}
}

// TestGenerateFingerprints tests fingerprint generation
func TestGenerateFingerprints(t *testing.T) {
	exporter := NewSARIFExporter("test-tool", "1.0.0")

	tests := []struct {
		name         string
		vuln         types.Vulnerability
		expectedKeys []string
	}{
		{
			name: "with CVE ID",
			vuln: types.Vulnerability{
				ID:    "vuln-001",
				Title: "Test",
				CVEID: stringPtr("CVE-2023-12345"),
			},
			expectedKeys: []string{"cve", "primary", "content"},
		},
		{
			name: "with host and port",
			vuln: types.Vulnerability{
				ID:    "vuln-002",
				Title: "Test",
				Host:  stringPtr("example.com"),
				Port:  intPtr(443),
			},
			expectedKeys: []string{"vulnerability_id", "location", "content", "primary"},
		},
		{
			name: "minimal",
			vuln: types.Vulnerability{
				Title:    "Test Vulnerability",
				Severity: "high",
			},
			expectedKeys: []string{"content", "primary"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fingerprints := exporter.generateFingerprints(tt.vuln)

			for _, key := range tt.expectedKeys {
				if _, exists := fingerprints[key]; !exists {
					t.Errorf("expected fingerprint key %s to exist", key)
				}
			}

			// Primary fingerprint should always exist
			if _, exists := fingerprints["primary"]; !exists {
				t.Error("expected primary fingerprint to exist")
			}
		})
	}
}

// TestGetRuleID tests rule ID generation
func TestGetRuleID(t *testing.T) {
	exporter := NewSARIFExporter("test-tool", "1.0.0")

	tests := []struct {
		name     string
		vuln     types.Vulnerability
		expected string
	}{
		{
			name: "with CVE ID",
			vuln: types.Vulnerability{
				CVEID: stringPtr("CVE-2023-12345"),
				Title: "Test Vulnerability",
			},
			expected: "CVE-2023-12345",
		},
		{
			name: "with vulnerability ID",
			vuln: types.Vulnerability{
				ID:    "VULN-001",
				Title: "Test Vulnerability",
			},
			expected: "VULN-001",
		},
		{
			name: "from title",
			vuln: types.Vulnerability{
				Title: "SQL Injection Vulnerability",
			},
			expected: "sql-injection-vulnerability",
		},
		{
			name: "title with special characters",
			vuln: types.Vulnerability{
				Title: "Cross-Site Scripting (XSS) Attack!",
			},
			expected: "cross-site-scripting-xss-attack",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleID := exporter.getRuleID(tt.vuln)
			if ruleID != tt.expected {
				t.Errorf("expected rule ID %s, got %s", tt.expected, ruleID)
			}
		})
	}
}

// TestSARIFSchemaCompliance tests that the generated SARIF is schema-compliant
func TestSARIFSchemaCompliance(t *testing.T) {
	exporter := NewSARIFExporter("zypheron-test", "1.0.0")

	scanResult := &types.ScanResult{
		ID:        "scan-test-001",
		Timestamp: time.Now(),
		Target:    "test.example.com",
		Tool:      "zypheron-test",
		Ports:     "1-65535",
		Output:    "Test scan output",
		Duration:  120.5,
		Success:   true,
		Vulnerabilities: []types.Vulnerability{
			{
				ID:               "vuln-001",
				Title:            "Critical Security Issue",
				Description:      "A critical security vulnerability was discovered",
				Severity:         "critical",
				CVEID:            stringPtr("CVE-2023-99999"),
				CVSSScore:        floatPtr(9.8),
				Host:             stringPtr("test.example.com"),
				Port:             intPtr(443),
				Remediation:      stringPtr("Update to latest version"),
				ExploitAvailable: true,
				References:       []string{"https://example.com/advisory/001"},
			},
		},
		AIAnalysis: "AI detected potential exploit patterns",
	}

	err := exporter.AddResultFromScanResult(scanResult)
	if err != nil {
		t.Fatalf("failed to add scan result: %v", err)
	}

	data, err := exporter.Export()
	if err != nil {
		t.Fatalf("failed to export: %v", err)
	}

	var sarifLog SARIFLog
	if err := json.Unmarshal(data, &sarifLog); err != nil {
		t.Fatalf("failed to unmarshal SARIF: %v", err)
	}

	// Verify required fields per SARIF 2.1.0 spec
	if sarifLog.Version != SARIFVersion {
		t.Errorf("invalid version: expected %s, got %s", SARIFVersion, sarifLog.Version)
	}

	if sarifLog.Schema != SchemaURI {
		t.Errorf("invalid schema: expected %s, got %s", SchemaURI, sarifLog.Schema)
	}

	if len(sarifLog.Runs) == 0 {
		t.Fatal("runs array is empty")
	}

	run := sarifLog.Runs[0]

	// Verify tool
	if run.Tool.Driver.Name == "" {
		t.Error("tool driver name is required")
	}

	// Verify results
	if len(run.Results) == 0 {
		t.Fatal("results array is empty")
	}

	for i, result := range run.Results {
		if result.RuleID == "" {
			t.Errorf("result %d: ruleId is required", i)
		}

		if result.Message.Text == "" {
			t.Errorf("result %d: message.text is required", i)
		}

		// Verify level is valid
		validLevels := map[string]bool{
			LevelNone:    true,
			LevelNote:    true,
			LevelWarning: true,
			LevelError:   true,
		}
		if result.Level != "" && !validLevels[result.Level] {
			t.Errorf("result %d: invalid level %s", i, result.Level)
		}
	}

	// Verify rules
	if len(run.Tool.Driver.Rules) == 0 {
		t.Error("rules array should not be empty when results are present")
	}

	for i, rule := range run.Tool.Driver.Rules {
		if rule.ID == "" {
			t.Errorf("rule %d: id is required", i)
		}
	}
}

// TestMultipleVulnerabilities tests handling multiple vulnerabilities
func TestMultipleVulnerabilities(t *testing.T) {
	exporter := NewSARIFExporter("test-tool", "1.0.0")

	vulnerabilities := []types.Vulnerability{
		{
			ID:          "vuln-001",
			Title:       "Critical Issue",
			Description: "Critical vulnerability",
			Severity:    "critical",
		},
		{
			ID:          "vuln-002",
			Title:       "High Issue",
			Description: "High severity vulnerability",
			Severity:    "high",
		},
		{
			ID:          "vuln-003",
			Title:       "Medium Issue",
			Description: "Medium severity vulnerability",
			Severity:    "medium",
		},
		{
			ID:          "vuln-004",
			Title:       "Low Issue",
			Description: "Low severity vulnerability",
			Severity:    "low",
		},
		{
			ID:          "vuln-005",
			Title:       "Info Issue",
			Description: "Informational finding",
			Severity:    "info",
		},
	}

	for _, vuln := range vulnerabilities {
		err := exporter.AddResult(vuln)
		if err != nil {
			t.Fatalf("failed to add result: %v", err)
		}
	}

	if len(exporter.results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(exporter.results))
	}

	if len(exporter.rules) != 5 {
		t.Fatalf("expected 5 rules, got %d", len(exporter.rules))
	}

	data, err := exporter.Export()
	if err != nil {
		t.Fatalf("failed to export: %v", err)
	}

	var sarifLog SARIFLog
	if err := json.Unmarshal(data, &sarifLog); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(sarifLog.Runs[0].Results) != 5 {
		t.Errorf("expected 5 results in output, got %d", len(sarifLog.Runs[0].Results))
	}
}

// Helper functions

func stringPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}

func floatPtr(f float64) *float64 {
	return &f
}

// Benchmarks

func BenchmarkAddResult(b *testing.B) {
	exporter := NewSARIFExporter("test-tool", "1.0.0")
	vuln := types.Vulnerability{
		ID:          "vuln-001",
		Title:       "Test Vulnerability",
		Description: "Test description",
		Severity:    "high",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = exporter.AddResult(vuln)
	}
}

func BenchmarkExport(b *testing.B) {
	exporter := NewSARIFExporter("test-tool", "1.0.0")

	// Add some results
	for i := 0; i < 100; i++ {
		vuln := types.Vulnerability{
			ID:          fmt.Sprintf("vuln-%03d", i),
			Title:       "Test Vulnerability",
			Description: "Test description",
			Severity:    "medium",
		}
		_ = exporter.AddResult(vuln)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.Export()
	}
}

func BenchmarkExportScanResult(b *testing.B) {
	vulnerabilities := make([]types.Vulnerability, 50)
	for i := 0; i < 50; i++ {
		vulnerabilities[i] = types.Vulnerability{
			ID:          fmt.Sprintf("vuln-%03d", i),
			Title:       "Test Vulnerability",
			Description: "Test description",
			Severity:    "medium",
		}
	}

	scanResult := &types.ScanResult{
		ID:              "scan-001",
		Timestamp:       time.Now(),
		Target:          "example.com",
		Tool:            "test-tool",
		Ports:           "1-1000",
		Output:          "Scan output",
		Duration:        45.5,
		Success:         true,
		Vulnerabilities: vulnerabilities,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ExportScanResultToSARIFBytes(scanResult)
	}
}

func BenchmarkGenerateFingerprints(b *testing.B) {
	exporter := NewSARIFExporter("test-tool", "1.0.0")
	cveID := "CVE-2023-12345"
	host := "example.com"
	port := 443

	vuln := types.Vulnerability{
		ID:       "vuln-001",
		Title:    "Test Vulnerability",
		Severity: "high",
		CVEID:    &cveID,
		Host:     &host,
		Port:     &port,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = exporter.generateFingerprints(vuln)
	}
}
