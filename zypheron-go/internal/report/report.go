package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/validation"
	"github.com/KKingZero/Cobra-AI/zypheron-go/pkg/types"
	"github.com/jung-kurt/gofpdf/v2"
	"github.com/olekukonko/tablewriter"
)

// GenerateReport generates a report in the specified format
func GenerateReport(scanResult *types.ScanResult, format string, outputPath string) error {
	// SECURITY FIX: Validate output path to prevent path traversal
	if err := validation.ValidateFilePath(outputPath); err != nil {
		return fmt.Errorf("invalid output path: %w", err)
	}

	var content string
	var err error

	switch strings.ToLower(format) {
	case "html":
		content, err = GenerateHTMLReport(scanResult)
	case "markdown", "md":
		content, err = GenerateMarkdownReport(scanResult)
	case "json":
		jsonBytes, jsonErr := json.MarshalIndent(scanResult, "", "  ")
		if jsonErr != nil {
			return fmt.Errorf("failed to marshal JSON: %w", jsonErr)
		}
		content = string(jsonBytes)
	case "pdf":
		return GeneratePDFReport(scanResult, outputPath)
	case "text", "txt", "":
		content, err = GenerateTextReport(scanResult)
	default:
		return fmt.Errorf("unsupported format: %s (supported: text, html, markdown, json, pdf)", format)
	}

	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write report file: %w", err)
	}

	return nil
}

// DetectFormatFromExtension detects report format from file extension
func DetectFormatFromExtension(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".html", ".htm":
		return "html"
	case ".md", ".markdown":
		return "markdown"
	case ".json":
		return "json"
	case ".pdf":
		return "pdf"
	default:
		return "text"
	}
}

// GenerateHTMLReport generates an HTML report
func GenerateHTMLReport(scanResult *types.ScanResult) (string, error) {
	var html strings.Builder

	// Count vulnerabilities by severity
	severityCounts := make(map[string]int)
	for _, vuln := range scanResult.Vulnerabilities {
		severityCounts[vuln.Severity]++
	}

	html.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zypheron Security Scan Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        .content {
            padding: 40px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .summary-card h3 {
            font-size: 0.9em;
            text-transform: uppercase;
            color: #666;
            margin-bottom: 10px;
        }
        .summary-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        .vuln-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .vuln-table th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        .vuln-table td {
            padding: 12px;
            border-bottom: 1px solid #e0e0e0;
        }
        .vuln-table tr:hover {
            background: #f8f9fa;
        }
        .severity-critical {
            background: #fee;
            color: #c00;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        .severity-high {
            background: #ffeaa7;
            color: #d63031;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        .severity-medium {
            background: #fff3cd;
            color: #856404;
            padding: 4px 8px;
            border-radius: 4px;
        }
        .severity-low {
            background: #d1ecf1;
            color: #0c5460;
            padding: 4px 8px;
            border-radius: 4px;
        }
        .metadata {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
        }
        .metadata-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #e0e0e0;
        }
        .metadata-item:last-child {
            border-bottom: none;
        }
        .metadata-label {
            font-weight: 600;
            color: #666;
        }
        .metadata-value {
            color: #333;
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
            border-top: 1px solid #e0e0e0;
        }
        pre {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            border: 1px solid #e0e0e0;
        }
        code {
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🐍 Zypheron</h1>
            <div class="subtitle">Security Scan Report</div>
        </div>
        <div class="content">
            <div class="summary">
                <div class="summary-card">
                    <h3>Target</h3>
                    <div class="value">` + escapeHTML(scanResult.Target) + `</div>
                </div>
                <div class="summary-card">
                    <h3>Tool</h3>
                    <div class="value">` + escapeHTML(scanResult.Tool) + `</div>
                </div>
                <div class="summary-card">
                    <h3>Vulnerabilities</h3>
                    <div class="value">` + fmt.Sprintf("%d", len(scanResult.Vulnerabilities)) + `</div>
                </div>
                <div class="summary-card">
                    <h3>Status</h3>
                    <div class="value">` + statusText(scanResult.Success) + `</div>
                </div>
            </div>

            <div class="section">
                <h2>Executive Summary</h2>
                <p>This report contains the results of a security scan performed on <strong>` + escapeHTML(scanResult.Target) + `</strong> using <strong>` + escapeHTML(scanResult.Tool) + `</strong>.</p>
                <p>The scan was completed on <strong>` + scanResult.Timestamp.Format("January 2, 2006 at 3:04 PM") + `</strong> and took <strong>` + fmt.Sprintf("%.2f", scanResult.Duration) + ` seconds</strong>.</p>
                `)

	if len(scanResult.Vulnerabilities) > 0 {
		html.WriteString(`
                <div style="margin-top: 20px;">
                    <h3>Vulnerability Summary</h3>
                    <ul>`)
		for severity, count := range severityCounts {
			if count > 0 {
				severityTitle := strings.ToUpper(severity[:1]) + strings.ToLower(severity[1:])
				html.WriteString(fmt.Sprintf(`<li><strong>%s</strong>: %d</li>`, severityTitle, count))
			}
		}
		html.WriteString(`</ul></div>`)
	}

	if scanResult.AIAnalysis != "" {
		html.WriteString(`
                <div style="margin-top: 20px;">
                    <h3>AI Analysis</h3>
                    <div style="background: #e8f4f8; padding: 15px; border-radius: 4px; border-left: 4px solid #667eea;">
                        ` + escapeHTML(scanResult.AIAnalysis) + `
                    </div>
                </div>`)
	}

	html.WriteString(`
            </div>

            <div class="section">
                <h2>Vulnerabilities</h2>`)

	if len(scanResult.Vulnerabilities) == 0 {
		html.WriteString(`<p style="color: #28a745; font-weight: bold;">✓ No vulnerabilities detected.</p>`)
	} else {
		html.WriteString(`
                <table class="vuln-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Title</th>
                            <th>Severity</th>
                            <th>Description</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>`)

		for _, vuln := range scanResult.Vulnerabilities {
			severityClass := "severity-" + strings.ToLower(vuln.Severity)
			severityTitle := strings.ToUpper(vuln.Severity[:1]) + strings.ToLower(vuln.Severity[1:])
			html.WriteString(fmt.Sprintf(`
                        <tr>
                            <td>%s</td>
                            <td><strong>%s</strong></td>
                            <td><span class="%s">%s</span></td>
                            <td>%s</td>
                            <td>`, escapeHTML(vuln.ID), escapeHTML(vuln.Title), severityClass, severityTitle, escapeHTML(truncate(vuln.Description, 100))))

			var details []string
			if vuln.CVEID != nil {
				details = append(details, fmt.Sprintf("CVE: %s", *vuln.CVEID))
			}
			if vuln.CVSSScore != nil {
				details = append(details, fmt.Sprintf("CVSS: %.1f", *vuln.CVSSScore))
			}
			if vuln.Port != nil {
				details = append(details, fmt.Sprintf("Port: %d", *vuln.Port))
			}
			if vuln.ExploitAvailable {
				details = append(details, "Exploit Available")
			}

			if len(details) > 0 {
				html.WriteString(strings.Join(details, ", "))
			} else {
				html.WriteString("-")
			}

			html.WriteString(`</td>
                        </tr>`)

			// Add full description in expandable section
			if len(vuln.Description) > 100 {
				html.WriteString(fmt.Sprintf(`
                        <tr class="vuln-detail" style="display: none;">
                            <td colspan="5">
                                <div style="padding: 15px; background: #f8f9fa; border-radius: 4px;">
                                    <h4>Full Description</h4>
                                    <p>%s</p>`, escapeHTML(vuln.Description)))

				if vuln.Remediation != nil && *vuln.Remediation != "" {
					html.WriteString(fmt.Sprintf(`
                                    <h4>Remediation</h4>
                                    <p>%s</p>`, escapeHTML(*vuln.Remediation)))
				}

				if len(vuln.References) > 0 {
					html.WriteString(`<h4>References</h4><ul>`)
					for _, ref := range vuln.References {
						html.WriteString(fmt.Sprintf(`<li><a href="%s" target="_blank">%s</a></li>`, escapeHTML(ref), escapeHTML(ref)))
					}
					html.WriteString(`</ul>`)
				}

				html.WriteString(`</div></td></tr>`)
			}
		}

		html.WriteString(`
                    </tbody>
                </table>`)
	}

	html.WriteString(`
            </div>

            <div class="section">
                <h2>Scan Details</h2>
                <div class="metadata">
                    <div class="metadata-item">
                        <span class="metadata-label">Scan ID:</span>
                        <span class="metadata-value">` + escapeHTML(scanResult.ID) + `</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Timestamp:</span>
                        <span class="metadata-value">` + scanResult.Timestamp.Format("2006-01-02 15:04:05 MST") + `</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Target:</span>
                        <span class="metadata-value">` + escapeHTML(scanResult.Target) + `</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Tool:</span>
                        <span class="metadata-value">` + escapeHTML(scanResult.Tool) + `</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Ports:</span>
                        <span class="metadata-value">` + escapeHTML(scanResult.Ports) + `</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Duration:</span>
                        <span class="metadata-value">` + fmt.Sprintf("%.2f seconds", scanResult.Duration) + `</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Status:</span>
                        <span class="metadata-value">` + statusText(scanResult.Success) + `</span>
                    </div>`)

	if scanResult.ErrorMessage != "" {
		html.WriteString(`
                    <div class="metadata-item">
                        <span class="metadata-label">Error:</span>
                        <span class="metadata-value" style="color: #c00;">` + escapeHTML(scanResult.ErrorMessage) + `</span>
                    </div>`)
	}

	if len(scanResult.Metadata) > 0 {
		for key, value := range scanResult.Metadata {
			html.WriteString(fmt.Sprintf(`
                    <div class="metadata-item">
                        <span class="metadata-label">%s:</span>
                        <span class="metadata-value">%s</span>
                    </div>`, escapeHTML(key), escapeHTML(value)))
		}
	}

	html.WriteString(`
                </div>
            </div>`)

	if scanResult.Output != "" {
		html.WriteString(`
            <div class="section">
                <h2>Raw Output</h2>
                <pre><code>` + escapeHTML(scanResult.Output) + `</code></pre>
            </div>`)
	}

	html.WriteString(`
        </div>
        <div class="footer">
            <p>Generated by Zypheron Security Testing Platform</p>
            <p>Report generated on ` + time.Now().Format("January 2, 2006 at 3:04 PM") + `</p>
        </div>
    </div>
</body>
</html>`)

	return html.String(), nil
}

// GenerateMarkdownReport generates a Markdown report
func GenerateMarkdownReport(scanResult *types.ScanResult) (string, error) {
	var md strings.Builder

	md.WriteString("# Zypheron Security Scan Report\n\n")
	md.WriteString(fmt.Sprintf("**Generated:** %s\n\n", scanResult.Timestamp.Format("January 2, 2006 at 3:04 PM")))

	md.WriteString("## Executive Summary\n\n")
	md.WriteString(fmt.Sprintf("- **Target:** %s\n", scanResult.Target))
	md.WriteString(fmt.Sprintf("- **Tool:** %s\n", scanResult.Tool))
	md.WriteString(fmt.Sprintf("- **Ports:** %s\n", scanResult.Ports))
	md.WriteString(fmt.Sprintf("- **Duration:** %.2f seconds\n", scanResult.Duration))
	md.WriteString(fmt.Sprintf("- **Status:** %s\n", statusText(scanResult.Success)))
	md.WriteString(fmt.Sprintf("- **Vulnerabilities Found:** %d\n\n", len(scanResult.Vulnerabilities)))

	if len(scanResult.Vulnerabilities) > 0 {
		md.WriteString("## Vulnerabilities\n\n")

		for i, vuln := range scanResult.Vulnerabilities {
			md.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, vuln.Title))
			md.WriteString(fmt.Sprintf("**Severity:** %s\n\n", vuln.Severity))
			md.WriteString(fmt.Sprintf("**Description:** %s\n\n", vuln.Description))

			if vuln.CVEID != nil {
				md.WriteString(fmt.Sprintf("**CVE:** %s\n\n", *vuln.CVEID))
			}
			if vuln.CVSSScore != nil {
				md.WriteString(fmt.Sprintf("**CVSS Score:** %.1f\n\n", *vuln.CVSSScore))
			}
			if vuln.Port != nil {
				md.WriteString(fmt.Sprintf("**Port:** %d\n\n", *vuln.Port))
			}
			if vuln.Host != nil {
				md.WriteString(fmt.Sprintf("**Host:** %s\n\n", *vuln.Host))
			}
			if vuln.Remediation != nil && *vuln.Remediation != "" {
				md.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", *vuln.Remediation))
			}
			if vuln.ExploitAvailable {
				md.WriteString("**⚠ Exploit Available**\n\n")
			}
			if len(vuln.References) > 0 {
				md.WriteString("**References:**\n")
				for _, ref := range vuln.References {
					md.WriteString(fmt.Sprintf("- %s\n", ref))
				}
				md.WriteString("\n")
			}
			md.WriteString("---\n\n")
		}
	} else {
		md.WriteString("## Vulnerabilities\n\n")
		md.WriteString("✓ No vulnerabilities detected.\n\n")
	}

	if scanResult.AIAnalysis != "" {
		md.WriteString("## AI Analysis\n\n")
		md.WriteString(scanResult.AIAnalysis + "\n\n")
	}

	md.WriteString("## Scan Details\n\n")
	md.WriteString(fmt.Sprintf("- **Scan ID:** %s\n", scanResult.ID))
	md.WriteString(fmt.Sprintf("- **Timestamp:** %s\n", scanResult.Timestamp.Format("2006-01-02 15:04:05 MST")))
	md.WriteString(fmt.Sprintf("- **Target:** %s\n", scanResult.Target))
	md.WriteString(fmt.Sprintf("- **Tool:** %s\n", scanResult.Tool))
	md.WriteString(fmt.Sprintf("- **Ports:** %s\n", scanResult.Ports))
	md.WriteString(fmt.Sprintf("- **Duration:** %.2f seconds\n", scanResult.Duration))
	md.WriteString(fmt.Sprintf("- **Status:** %s\n", statusText(scanResult.Success)))

	if scanResult.ErrorMessage != "" {
		md.WriteString(fmt.Sprintf("- **Error:** %s\n", scanResult.ErrorMessage))
	}

	if len(scanResult.Metadata) > 0 {
		md.WriteString("\n**Metadata:**\n")
		for key, value := range scanResult.Metadata {
			md.WriteString(fmt.Sprintf("- %s: %s\n", key, value))
		}
	}

	if scanResult.Output != "" {
		md.WriteString("\n## Raw Output\n\n")
		md.WriteString("```\n")
		md.WriteString(scanResult.Output)
		md.WriteString("\n```\n")
	}

	md.WriteString(fmt.Sprintf("\n---\n\n*Generated by Zypheron Security Testing Platform on %s*\n", time.Now().Format("January 2, 2006 at 3:04 PM")))

	return md.String(), nil
}

// GeneratePDFReport generates a PDF report using gofpdf
func GeneratePDFReport(scanResult *types.ScanResult, outputPath string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 20)

	// Count vulnerabilities by severity
	severityCounts := make(map[string]int)
	for _, vuln := range scanResult.Vulnerabilities {
		severityCounts[vuln.Severity]++
	}

	// Page 1: Cover Page
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 24)
	pdf.SetTextColor(102, 126, 234) // Purple color
	pdf.CellFormat(0, 30, "Zypheron", "", 0, "C", false, 0, "")
	pdf.Ln(15)
	pdf.SetFont("Arial", "B", 18)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 20, "Security Scan Report", "", 0, "C", false, 0, "")
	pdf.Ln(20)
	pdf.SetFont("Arial", "", 12)
	pdf.CellFormat(0, 10, fmt.Sprintf("Target: %s", scanResult.Target), "", 0, "C", false, 0, "")
	pdf.Ln(8)
	pdf.CellFormat(0, 10, fmt.Sprintf("Generated: %s", scanResult.Timestamp.Format("January 2, 2006 at 3:04 PM")), "", 0, "C", false, 0, "")
	pdf.Ln(30)

	// Summary box
	pdf.SetFillColor(248, 249, 250)
	pdf.Rect(20, 100, 170, 60, "F")
	pdf.SetFont("Arial", "B", 14)
	pdf.SetXY(25, 105)
	pdf.Cell(0, 8, "Executive Summary")
	pdf.SetFont("Arial", "", 11)
	pdf.SetXY(25, 115)
	pdf.Cell(0, 6, fmt.Sprintf("Tool: %s", scanResult.Tool))
	pdf.SetXY(25, 122)
	pdf.Cell(0, 6, fmt.Sprintf("Ports: %s", scanResult.Ports))
	pdf.SetXY(25, 129)
	pdf.Cell(0, 6, fmt.Sprintf("Duration: %.2f seconds", scanResult.Duration))
	pdf.SetXY(25, 136)
	statusText := "Success"
	if !scanResult.Success {
		statusText = "Failed"
		pdf.SetTextColor(200, 0, 0)
	}
	pdf.Cell(0, 6, fmt.Sprintf("Status: %s", statusText))
	pdf.SetTextColor(0, 0, 0)
	pdf.SetXY(25, 143)
	pdf.Cell(0, 6, fmt.Sprintf("Vulnerabilities Found: %d", len(scanResult.Vulnerabilities)))

	// Vulnerability summary
	if len(scanResult.Vulnerabilities) > 0 {
		pdf.Ln(20)
		pdf.SetFont("Arial", "B", 14)
		pdf.Cell(0, 10, "Vulnerability Summary")
		pdf.Ln(8)
		pdf.SetFont("Arial", "", 11)
		for severity, count := range severityCounts {
			if count > 0 {
				severityTitle := strings.ToUpper(severity[:1]) + strings.ToLower(severity[1:])
				pdf.Cell(0, 6, fmt.Sprintf("  %s: %d", severityTitle, count))
				pdf.Ln(6)
			}
		}
	}

	// Page 2: Scan Details
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 15, "Scan Details")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 11)

	details := []struct {
		Label string
		Value string
	}{
		{"Scan ID:", scanResult.ID},
		{"Timestamp:", scanResult.Timestamp.Format("2006-01-02 15:04:05 MST")},
		{"Target:", scanResult.Target},
		{"Tool:", scanResult.Tool},
		{"Ports:", scanResult.Ports},
		{"Duration:", fmt.Sprintf("%.2f seconds", scanResult.Duration)},
		{"Status:", statusText},
	}

	for _, detail := range details {
		pdf.SetFont("Arial", "B", 11)
		pdf.Cell(40, 8, detail.Label)
		pdf.SetFont("Arial", "", 11)
		pdf.Cell(0, 8, detail.Value)
		pdf.Ln(8)
	}

	if scanResult.ErrorMessage != "" {
		pdf.Ln(5)
		pdf.SetTextColor(200, 0, 0)
		pdf.SetFont("Arial", "B", 11)
		pdf.Cell(0, 8, fmt.Sprintf("Error: %s", scanResult.ErrorMessage))
		pdf.SetTextColor(0, 0, 0)
		pdf.Ln(8)
	}

	if len(scanResult.Metadata) > 0 {
		pdf.Ln(5)
		pdf.SetFont("Arial", "B", 11)
		pdf.Cell(0, 8, "Metadata:")
		pdf.Ln(8)
		pdf.SetFont("Arial", "", 10)
		for key, value := range scanResult.Metadata {
			pdf.Cell(0, 6, fmt.Sprintf("  %s: %s", key, value))
			pdf.Ln(6)
		}
	}

	// AI Analysis section
	if scanResult.AIAnalysis != "" {
		pdf.AddPage()
		pdf.SetFont("Arial", "B", 16)
		pdf.Cell(0, 15, "AI Analysis")
		pdf.Ln(10)
		pdf.SetFont("Arial", "", 11)
		pdf.MultiCell(0, 6, scanResult.AIAnalysis, "", "", false)
	}

	// Vulnerabilities section
	if len(scanResult.Vulnerabilities) > 0 {
		pdf.AddPage()
		pdf.SetFont("Arial", "B", 16)
		pdf.Cell(0, 15, "Vulnerabilities")
		pdf.Ln(10)

		for i, vuln := range scanResult.Vulnerabilities {
			// Check if we need a new page
			if pdf.GetY() > 250 {
				pdf.AddPage()
			}

			// Vulnerability header
			pdf.SetFont("Arial", "B", 12)
			pdf.SetTextColor(0, 0, 0)
			pdf.Cell(0, 10, fmt.Sprintf("%d. %s", i+1, vuln.Title))
			pdf.Ln(8)

			// Severity badge
			pdf.SetFont("Arial", "B", 10)
			severityColor := getSeverityColor(vuln.Severity)
			pdf.SetTextColor(severityColor.R, severityColor.G, severityColor.B)
			severityTitle := vuln.Severity
			if len(vuln.Severity) > 0 {
				severityTitle = strings.ToUpper(vuln.Severity[:1]) + strings.ToLower(vuln.Severity[1:])
			}
			pdf.Cell(0, 6, fmt.Sprintf("Severity: %s", severityTitle))
			pdf.SetTextColor(0, 0, 0)
			pdf.Ln(8)

			// Description
			pdf.SetFont("Arial", "", 10)
			pdf.MultiCell(0, 6, vuln.Description, "", "", false)
			pdf.Ln(5)

			// Details
			pdf.SetFont("Arial", "", 9)
			if vuln.CVEID != nil {
				pdf.Cell(0, 5, fmt.Sprintf("CVE: %s", *vuln.CVEID))
				pdf.Ln(5)
			}
			if vuln.CVSSScore != nil {
				pdf.Cell(0, 5, fmt.Sprintf("CVSS Score: %.1f", *vuln.CVSSScore))
				pdf.Ln(5)
			}
			if vuln.Port != nil {
				pdf.Cell(0, 5, fmt.Sprintf("Port: %d", *vuln.Port))
				pdf.Ln(5)
			}
			if vuln.Host != nil {
				pdf.Cell(0, 5, fmt.Sprintf("Host: %s", *vuln.Host))
				pdf.Ln(5)
			}
			if vuln.ExploitAvailable {
				pdf.SetTextColor(200, 0, 0)
				pdf.Cell(0, 5, "⚠ Exploit Available")
				pdf.SetTextColor(0, 0, 0)
				pdf.Ln(5)
			}

			// Remediation
			if vuln.Remediation != nil && *vuln.Remediation != "" {
				pdf.Ln(3)
				pdf.SetFont("Arial", "B", 10)
				pdf.Cell(0, 6, "Remediation:")
				pdf.Ln(5)
				pdf.SetFont("Arial", "", 9)
				pdf.MultiCell(0, 5, *vuln.Remediation, "", "", false)
			}

			// References
			if len(vuln.References) > 0 {
				pdf.Ln(3)
				pdf.SetFont("Arial", "B", 10)
				pdf.Cell(0, 6, "References:")
				pdf.Ln(5)
				pdf.SetFont("Arial", "", 9)
				for _, ref := range vuln.References {
					pdf.Cell(0, 5, fmt.Sprintf("  • %s", ref))
					pdf.Ln(5)
				}
			}

			pdf.Ln(8)
			pdf.Line(20, pdf.GetY(), 190, pdf.GetY())
			pdf.Ln(5)
		}
	}

	// Footer on all pages
	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Arial", "I", 8)
		pdf.SetTextColor(128, 128, 128)
		pdf.CellFormat(0, 10, fmt.Sprintf("Generated by Zypheron Security Testing Platform - Page %d", pdf.PageNo()), "", 0, "C", false, 0, "")
	})

	// Save PDF
	if err := pdf.OutputFileAndClose(outputPath); err != nil {
		return fmt.Errorf("failed to save PDF: %w", err)
	}

	return nil
}

// Color represents RGB color values
type Color struct {
	R, G, B int
}

// getSeverityColor returns color for severity level
func getSeverityColor(severity string) Color {
	switch strings.ToLower(severity) {
	case "critical":
		return Color{R: 200, G: 0, B: 0} // Red
	case "high":
		return Color{R: 255, G: 165, B: 0} // Orange
	case "medium":
		return Color{R: 255, G: 200, B: 0} // Yellow
	case "low":
		return Color{R: 0, G: 128, B: 255} // Blue
	default:
		return Color{R: 128, G: 128, B: 128} // Gray
	}
}

// Helper functions

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func statusText(success bool) string {
	if success {
		return "✓ Success"
	}
	return "✗ Failed"
}

// GenerateTextReport generates a formatted text report with ASCII tables
func GenerateTextReport(scanResult *types.ScanResult) (string, error) {
	var output strings.Builder

	// Header
	output.WriteString("╔══════════════════════════════════════════════════════════════════════╗\n")
	output.WriteString("║              ZYPHERON SECURITY SCAN REPORT                           ║\n")
	output.WriteString("╚══════════════════════════════════════════════════════════════════════╝\n\n")

	// Executive Summary Table
	output.WriteString("EXECUTIVE SUMMARY\n")
	output.WriteString(strings.Repeat("─", 70) + "\n\n")

	summaryBuf := new(bytes.Buffer)
	summaryTable := tablewriter.NewWriter(summaryBuf)
	summaryTable.SetHeader([]string{"Property", "Value"})
	summaryTable.SetBorder(true)
	summaryTable.SetAlignment(tablewriter.ALIGN_LEFT)
	summaryTable.SetHeaderAlignment(tablewriter.ALIGN_LEFT)

	summaryTable.Append([]string{"Target", scanResult.Target})
	summaryTable.Append([]string{"Tool", scanResult.Tool})
	summaryTable.Append([]string{"Ports", scanResult.Ports})
	summaryTable.Append([]string{"Duration", fmt.Sprintf("%.2f seconds", scanResult.Duration)})
	summaryTable.Append([]string{"Status", statusText(scanResult.Success)})
	summaryTable.Append([]string{"Timestamp", scanResult.Timestamp.Format("2006-01-02 15:04:05 MST")})
	summaryTable.Append([]string{"Vulnerabilities Found", fmt.Sprintf("%d", len(scanResult.Vulnerabilities))})

	summaryTable.Render()
	output.WriteString(summaryBuf.String())
	output.WriteString("\n")

	// Vulnerability Summary by Severity
	if len(scanResult.Vulnerabilities) > 0 {
		severityCounts := make(map[string]int)
		for _, vuln := range scanResult.Vulnerabilities {
			severityCounts[vuln.Severity]++
		}

		output.WriteString("VULNERABILITY SUMMARY BY SEVERITY\n")
		output.WriteString(strings.Repeat("─", 70) + "\n\n")

		severityBuf := new(bytes.Buffer)
		severityTable := tablewriter.NewWriter(severityBuf)
		severityTable.SetHeader([]string{"Severity", "Count"})
		severityTable.SetBorder(true)
		severityTable.SetAlignment(tablewriter.ALIGN_LEFT)

		for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
			if count, exists := severityCounts[severity]; exists && count > 0 {
				severityTable.Append([]string{severity, fmt.Sprintf("%d", count)})
			}
		}

		severityTable.Render()
		output.WriteString(severityBuf.String())
		output.WriteString("\n")
	}

	// Vulnerabilities Details Table
	if len(scanResult.Vulnerabilities) > 0 {
		output.WriteString("VULNERABILITIES DETAILS\n")
		output.WriteString(strings.Repeat("─", 70) + "\n\n")

		vulnBuf := new(bytes.Buffer)
		vulnTable := tablewriter.NewWriter(vulnBuf)
		vulnTable.SetHeader([]string{"ID", "Title", "Severity", "CVSS", "Port", "Exploit"})
		vulnTable.SetBorder(true)
		vulnTable.SetAlignment(tablewriter.ALIGN_LEFT)
		vulnTable.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		vulnTable.SetAutoWrapText(false)
		vulnTable.SetRowLine(true)

		for _, vuln := range scanResult.Vulnerabilities {
			id := vuln.ID
			if len(id) > 15 {
				id = id[:12] + "..."
			}

			title := vuln.Title
			if len(title) > 30 {
				title = title[:27] + "..."
			}

			cvss := "N/A"
			if vuln.CVSSScore != nil {
				cvss = fmt.Sprintf("%.1f", *vuln.CVSSScore)
			}

			port := "N/A"
			if vuln.Port != nil {
				port = fmt.Sprintf("%d", *vuln.Port)
			}

			exploit := "No"
			if vuln.ExploitAvailable {
				exploit = "⚠ YES"
			}

			vulnTable.Append([]string{id, title, vuln.Severity, cvss, port, exploit})
		}

		vulnTable.Render()
		output.WriteString(vulnBuf.String())
		output.WriteString("\n")

		// Detailed vulnerability descriptions
		output.WriteString("DETAILED VULNERABILITY DESCRIPTIONS\n")
		output.WriteString(strings.Repeat("─", 70) + "\n\n")

		for i, vuln := range scanResult.Vulnerabilities {
			output.WriteString(fmt.Sprintf("[%d] %s\n", i+1, vuln.Title))
			output.WriteString(strings.Repeat("┄", 70) + "\n")
			output.WriteString(fmt.Sprintf("ID:          %s\n", vuln.ID))
			output.WriteString(fmt.Sprintf("Severity:    %s\n", vuln.Severity))

			if vuln.CVEID != nil {
				output.WriteString(fmt.Sprintf("CVE ID:      %s\n", *vuln.CVEID))
			}
			if vuln.CVSSScore != nil {
				output.WriteString(fmt.Sprintf("CVSS Score:  %.1f\n", *vuln.CVSSScore))
			}
			if vuln.Port != nil {
				output.WriteString(fmt.Sprintf("Port:        %d\n", *vuln.Port))
			}
			if vuln.Host != nil {
				output.WriteString(fmt.Sprintf("Host:        %s\n", *vuln.Host))
			}
			if vuln.ExploitAvailable {
				output.WriteString("⚠ EXPLOIT AVAILABLE\n")
			}

			output.WriteString(fmt.Sprintf("\nDescription:\n%s\n", wrapText(vuln.Description, 68)))

			if vuln.Remediation != nil && *vuln.Remediation != "" {
				output.WriteString(fmt.Sprintf("\nRemediation:\n%s\n", wrapText(*vuln.Remediation, 68)))
			}

			if len(vuln.References) > 0 {
				output.WriteString("\nReferences:\n")
				for _, ref := range vuln.References {
					output.WriteString(fmt.Sprintf("  • %s\n", ref))
				}
			}

			output.WriteString("\n" + strings.Repeat("═", 70) + "\n\n")
		}
	} else {
		output.WriteString("VULNERABILITIES\n")
		output.WriteString(strings.Repeat("─", 70) + "\n\n")
		output.WriteString("✓ No vulnerabilities detected.\n\n")
	}

	// AI Analysis
	if scanResult.AIAnalysis != "" {
		output.WriteString("AI ANALYSIS\n")
		output.WriteString(strings.Repeat("─", 70) + "\n\n")
		output.WriteString(wrapText(scanResult.AIAnalysis, 68) + "\n\n")
	}

	// Scan Metadata
	output.WriteString("SCAN METADATA\n")
	output.WriteString(strings.Repeat("─", 70) + "\n\n")

	metaBuf := new(bytes.Buffer)
	metaTable := tablewriter.NewWriter(metaBuf)
	metaTable.SetHeader([]string{"Property", "Value"})
	metaTable.SetBorder(true)
	metaTable.SetAlignment(tablewriter.ALIGN_LEFT)

	metaTable.Append([]string{"Scan ID", scanResult.ID})
	metaTable.Append([]string{"Timestamp", scanResult.Timestamp.Format("2006-01-02 15:04:05 MST")})
	metaTable.Append([]string{"Target", scanResult.Target})
	metaTable.Append([]string{"Tool", scanResult.Tool})
	metaTable.Append([]string{"Ports", scanResult.Ports})
	metaTable.Append([]string{"Duration", fmt.Sprintf("%.2f seconds", scanResult.Duration)})
	metaTable.Append([]string{"Success", statusText(scanResult.Success)})

	if scanResult.ErrorMessage != "" {
		metaTable.Append([]string{"Error", scanResult.ErrorMessage})
	}

	if len(scanResult.Metadata) > 0 {
		for key, value := range scanResult.Metadata {
			metaTable.Append([]string{key, value})
		}
	}

	metaTable.Render()
	output.WriteString(metaBuf.String())
	output.WriteString("\n")

	// Raw Output (optional, truncated if too long)
	if scanResult.Output != "" {
		output.WriteString("RAW SCAN OUTPUT\n")
		output.WriteString(strings.Repeat("─", 70) + "\n\n")

		rawOutput := scanResult.Output
		if len(rawOutput) > 2000 {
			rawOutput = rawOutput[:2000] + "\n\n[... output truncated ...]"
		}
		output.WriteString(rawOutput + "\n\n")
	}

	// Footer
	output.WriteString(strings.Repeat("─", 70) + "\n")
	output.WriteString(fmt.Sprintf("Generated by Zypheron Security Testing Platform\n"))
	output.WriteString(fmt.Sprintf("Report generated on %s\n", time.Now().Format("January 2, 2006 at 3:04 PM")))
	output.WriteString(strings.Repeat("─", 70) + "\n")

	return output.String(), nil
}

// wrapText wraps text to specified width
func wrapText(text string, width int) string {
	if len(text) <= width {
		return text
	}

	var result strings.Builder
	words := strings.Fields(text)
	lineLen := 0

	for i, word := range words {
		wordLen := len(word)

		if lineLen+wordLen+1 > width {
			result.WriteString("\n")
			result.WriteString(word)
			lineLen = wordLen
		} else {
			if i > 0 {
				result.WriteString(" ")
				lineLen++
			}
			result.WriteString(word)
			lineLen += wordLen
		}
	}

	return result.String()
}

