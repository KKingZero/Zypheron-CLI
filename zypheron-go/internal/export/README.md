# SARIF Export Package

This package provides SARIF (Static Analysis Results Interchange Format) export functionality for Zypheron security scan results.

## Overview

SARIF 2.1.0 is the industry-standard format for representing static analysis results. This package enables Zypheron CLI to export scan results in a format that's compatible with:

- **GitHub Security** (Code Scanning, Dependabot)
- **Azure DevOps Security**
- **GitLab Security Dashboard**
- **Visual Studio Code**
- **SonarQube**
- **Many other security platforms**

## Features

### SARIF 2.1.0 Schema Compliance
- Full compliance with SARIF 2.1.0 specification
- Validated against official JSON schema
- Compatible with all major security platforms

### Comprehensive Metadata
- Tool information (name, version, organization)
- Rule definitions with descriptions
- Severity mapping (critical/high/medium/low/info)
- CVSS scores and CVE IDs
- Remediation guidance
- Security references

### Deduplication Support
- Automatic fingerprint generation
- CVE-based fingerprints
- Location-based fingerprints (host:port)
- Content-based fingerprints
- Enables result tracking across multiple scans

### Rich Location Information
- Physical locations (file paths, line numbers)
- Logical locations (functions, modules)
- Network locations (hosts, ports)
- Region information with context

### Invocation Metadata
- Execution timestamps
- Command-line arguments
- Success/failure status
- Error messages
- Custom properties

## Installation

The package is part of the Zypheron CLI project. No additional installation is required.

## Quick Start

### Basic Usage

```go
import (
    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/export"
    "github.com/KKingZero/Cobra-AI/zypheron-go/pkg/types"
)

// Export a scan result to SARIF file
scanResult := &types.ScanResult{
    ID:        "scan-001",
    Target:    "example.com",
    Tool:      "nmap",
    // ... other fields
}

err := export.ExportScanResultToSARIF(scanResult, "output.sarif")
if err != nil {
    log.Fatal(err)
}
```

### Advanced Usage

```go
// Create exporter with custom configuration
exporter := export.NewSARIFExporter("zypheron-scanner", "1.0.0")
exporter.SetOrganization("Zypheron Security")
exporter.SetInformationURI("https://github.com/your-org/zypheron")

// Add custom properties
exporter.AddProperty("scan_mode", "aggressive")
exporter.AddProperty("environment", "production")

// Add individual vulnerabilities
for _, vuln := range vulnerabilities {
    err := exporter.AddResult(vuln)
    if err != nil {
        log.Printf("Failed to add vulnerability: %v", err)
    }
}

// Export to file
err := exporter.ExportToFile("results.sarif")
if err != nil {
    log.Fatal(err)
}
```

### Export to Bytes

```go
// Export to byte array for further processing
data, err := export.ExportScanResultToSARIFBytes(scanResult)
if err != nil {
    log.Fatal(err)
}

// Upload to API, store in database, etc.
uploadToSecurityPlatform(data)
```

## CLI Integration

### Add SARIF Format Support

Modify `internal/report/report.go`:

```go
func GenerateReport(scanResult *types.ScanResult, format string, outputPath string) error {
    switch strings.ToLower(format) {
    case "sarif":
        return export.ExportScanResultToSARIF(scanResult, outputPath)
    case "html":
        // ... existing code
    }
}
```

### Update Format Detection

```go
func DetectFormatFromExtension(filename string) string {
    ext := strings.ToLower(filepath.Ext(filename))
    switch ext {
    case ".sarif":
        return "sarif"
    // ... existing cases
    }
}
```

### Usage Examples

```bash
# Export scan results to SARIF
zypheron scan example.com --format sarif --output results.sarif

# Auto-detect format from file extension
zypheron scan example.com --output results.sarif

# Export with AI analysis included
zypheron scan example.com --ai-analysis --format sarif --output results.sarif
```

## Severity Mapping

The package maps Zypheron severity levels to SARIF levels:

| Zypheron Severity | SARIF Level | Description |
|------------------|-------------|-------------|
| `critical`       | `error`     | Critical security issues requiring immediate attention |
| `high`           | `error`     | High severity vulnerabilities |
| `medium`         | `warning`   | Medium severity issues |
| `low`            | `note`      | Low severity findings |
| `info`           | `note`      | Informational findings |

## Fingerprints

Fingerprints enable result deduplication and tracking across scans:

### Primary Fingerprint
1. CVE ID (if available)
2. Vulnerability ID (if no CVE)
3. Content hash (title + severity)

### Location Fingerprint
- Hash of `host:port` combination
- Enables tracking of network-based vulnerabilities

### Content Fingerprint
- Hash of `title:severity`
- Useful for identical vulnerabilities across different locations

## GitHub Integration

### GitHub Actions Workflow

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      actions: read
      contents: read

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
          category: zypheron-security-scan
```

### Manual Upload with GitHub CLI

```bash
# Generate SARIF
zypheron scan example.com --format sarif --output results.sarif

# Upload to GitHub
gh api -X POST /repos/{owner}/{repo}/code-scanning/sarifs \
  -F commit_sha=$(git rev-parse HEAD) \
  -F ref=refs/heads/main \
  -F sarif=@results.sarif
```

## Azure DevOps Integration

### Azure Pipeline Configuration

Add to `azure-pipelines.yml`:

```yaml
steps:
- script: |
    zypheron scan $(TARGET_URL) --format sarif --output results.sarif
  displayName: 'Run Security Scan'

- task: PublishBuildArtifacts@1
  inputs:
    pathtoPublish: 'results.sarif'
    artifactName: 'CodeAnalysisLogs'
    publishLocation: 'Container'
```

### Advanced Security Task

```yaml
- task: AdvancedSecurity-Publish@1
  inputs:
    SarifFile: 'results.sarif'
```

## GitLab Integration

### GitLab CI Configuration

Add to `.gitlab-ci.yml`:

```yaml
security-scan:
  stage: test
  script:
    - zypheron scan $CI_PROJECT_URL --format sarif --output gl-sast-report.sarif
  artifacts:
    reports:
      sast: gl-sast-report.sarif
```

## Testing

### Run Tests

```bash
cd internal/export
go test -v
```

### Run Benchmarks

```bash
go test -bench=. -benchmem
```

### Test Coverage

```bash
go test -cover -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## API Reference

### Types

#### `SARIFExporter`
Main exporter type for creating SARIF documents.

**Methods:**
- `NewSARIFExporter(toolName, toolVersion string) *SARIFExporter`
- `SetInformationURI(uri string)`
- `SetOrganization(org string)`
- `AddProperty(key string, value interface{})`
- `AddResult(vuln types.Vulnerability) error`
- `AddResultFromScanResult(scanResult *types.ScanResult) error`
- `Export() ([]byte, error)`
- `ExportToFile(path string) error`

### Functions

#### `ExportScanResultToSARIF`
```go
func ExportScanResultToSARIF(scanResult *types.ScanResult, outputPath string) error
```
Convenience function to export a scan result to a SARIF file.

#### `ExportScanResultToSARIFBytes`
```go
func ExportScanResultToSARIFBytes(scanResult *types.ScanResult) ([]byte, error)
```
Convenience function to export a scan result to SARIF bytes.

## Performance

Typical performance characteristics:

| Operation | Time | Notes |
|-----------|------|-------|
| Add single result | ~5-10 μs | Per vulnerability |
| Export 100 results | ~2-5 ms | Including JSON marshaling |
| Export full scan | ~5-20 ms | Depends on result count |
| File write | ~1-5 ms | Depends on disk I/O |

## Best Practices

### 1. Include CVE IDs
Always provide CVE IDs when available for better correlation:

```go
vuln.CVEID = stringPtr("CVE-2023-12345")
```

### 2. Add CVSS Scores
Include CVSS scores for accurate severity ranking:

```go
vuln.CVSSScore = floatPtr(7.5)
```

### 3. Provide Remediation
Include actionable remediation guidance:

```go
vuln.Remediation = stringPtr("Update to version 2.0.0 or later")
```

### 4. Add References
Link to security advisories and documentation:

```go
vuln.References = []string{
    "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
    "https://example.com/security-advisory-001",
}
```

### 5. Set Tool Information
Configure tool metadata for better tracking:

```go
exporter.SetOrganization("Your Organization")
exporter.SetInformationURI("https://your-docs.example.com")
```

### 6. Handle Errors Gracefully
Always check and handle errors:

```go
if err := export.ExportScanResultToSARIF(result, path); err != nil {
    log.Printf("Failed to export SARIF: %v", err)
    // Implement fallback or retry logic
}
```

### 7. Validate Output
Verify SARIF output before uploading:

```go
data, err := export.ExportScanResultToSARIFBytes(result)
if err != nil {
    return err
}

var log export.SARIFLog
if err := json.Unmarshal(data, &log); err != nil {
    return fmt.Errorf("invalid SARIF: %w", err)
}
```

## Troubleshooting

### Common Issues

#### File Permission Errors
```go
// Ensure directory exists and is writable
dir := filepath.Dir(outputPath)
if err := os.MkdirAll(dir, 0755); err != nil {
    return fmt.Errorf("failed to create directory: %w", err)
}
```

#### Invalid JSON Output
```go
// Validate SARIF structure
var sarifLog export.SARIFLog
if err := json.Unmarshal(data, &sarifLog); err != nil {
    log.Printf("Invalid SARIF JSON: %v", err)
}
```

#### Missing Required Fields
Ensure all required fields are populated:
- `scanResult.ID`
- `scanResult.Target`
- `scanResult.Tool`
- `vuln.Title`
- `vuln.Description`
- `vuln.Severity`

## Validation

### Schema Validation

Use the SARIF Multitool for validation:

```bash
# Install SARIF Multitool
npm install -g @microsoft/sarif-multitool

# Validate SARIF file
sarif validate results.sarif
```

### Online Validators

- [SARIF Web Validator](https://sarifweb.azurewebsites.net/Validation)
- [GitHub SARIF Validator](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)

## Resources

- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [SARIF Tutorials](https://github.com/microsoft/sarif-tutorials)
- [GitHub Code Scanning Documentation](https://docs.github.com/en/code-security/code-scanning)
- [SARIF Multitool](https://github.com/microsoft/sarif-sdk)
- [SARIF Viewer for VS Code](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)

## Contributing

When contributing to this package:

1. Maintain SARIF 2.1.0 schema compliance
2. Add tests for new features
3. Update documentation
4. Run benchmarks to ensure performance
5. Validate output with SARIF tools

## License

This package is part of the Zypheron CLI project. See the main project LICENSE file for details.

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Consult the main Zypheron documentation
- Review SARIF specification for format details
