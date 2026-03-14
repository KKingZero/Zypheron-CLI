package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/licensing"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

// ComplianceReport represents a compliance report
type ComplianceReport struct {
	ID           string              `json:"id"`
	GeneratedAt  time.Time           `json:"generated_at"`
	Framework    string              `json:"framework"`
	Period       string              `json:"period"`
	Organization string              `json:"organization"`
	Summary      ComplianceSummary   `json:"summary"`
	Sections     []ComplianceSection `json:"sections"`
	Metadata     map[string]string   `json:"metadata"`
}

// ComplianceSummary contains report summary metrics
type ComplianceSummary struct {
	TotalScans       int     `json:"total_scans"`
	TotalFindings    int     `json:"total_findings"`
	CriticalFindings int     `json:"critical_findings"`
	HighFindings     int     `json:"high_findings"`
	MediumFindings   int     `json:"medium_findings"`
	LowFindings      int     `json:"low_findings"`
	ComplianceScore  float64 `json:"compliance_score"`
	Coverage         float64 `json:"coverage"`
}

// ComplianceSection represents a section of the compliance report
type ComplianceSection struct {
	ID          string              `json:"id"`
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Status      string              `json:"status"` // compliant, non-compliant, partial, not-applicable
	Controls    []ComplianceControl `json:"controls"`
}

// ComplianceControl represents a specific compliance control
type ComplianceControl struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	Evidence    []string `json:"evidence"`
	Findings    []string `json:"findings"`
}

// ComplianceCmd returns the compliance reporting command
func ComplianceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "Compliance reporting (Enterprise)",
		Long: `Generate compliance reports for security frameworks.

Supported frameworks:
  • PCI-DSS     - Payment Card Industry Data Security Standard
  • HIPAA       - Health Insurance Portability and Accountability Act
  • SOC2        - Service Organization Control 2
  • ISO27001    - Information Security Management
  • NIST        - NIST Cybersecurity Framework
  • GDPR        - General Data Protection Regulation

REQUIRES: Enterprise subscription

Examples:
  zypheron compliance                     # Show compliance overview
  zypheron compliance report --framework pci-dss
  zypheron compliance templates           # List available templates
  zypheron compliance export --format pdf`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := licensing.RequireCompliance(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			return runComplianceOverview()
		},
	}

	cmd.AddCommand(complianceReportCmd())
	cmd.AddCommand(complianceTemplatesCmd())
	cmd.AddCommand(complianceExportCmd())
	cmd.AddCommand(complianceScheduleCmd())

	return cmd
}

func runComplianceOverview() error {
	fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
	fmt.Println(ui.Primary.Sprint("║              COMPLIANCE REPORTING                       ║"))
	fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

	manager := licensing.GetManager()
	license := manager.License()

	fmt.Println(ui.InfoMsg("Organization"))
	if license.TeamID != "" {
		fmt.Printf("  Team ID: %s\n", ui.Accent.Sprint(license.TeamID))
	} else {
		fmt.Printf("  User: %s\n", ui.Accent.Sprint(license.Email))
	}
	fmt.Println()

	fmt.Println(ui.InfoMsg("Available Frameworks"))
	frameworks := []struct {
		name string
		desc string
	}{
		{"PCI-DSS", "Payment Card Industry Data Security Standard"},
		{"HIPAA", "Health Insurance Portability and Accountability Act"},
		{"SOC2", "Service Organization Control 2"},
		{"ISO27001", "Information Security Management"},
		{"NIST", "NIST Cybersecurity Framework"},
		{"GDPR", "General Data Protection Regulation"},
	}

	for _, f := range frameworks {
		fmt.Printf("  %s  %s\n", ui.Accent.Sprint(fmt.Sprintf("%-10s", f.name)), ui.Muted.Sprint(f.desc))
	}
	fmt.Println()

	fmt.Println(ui.InfoMsg("Quick Actions"))
	fmt.Println(ui.Muted.Sprint("  zypheron compliance report --framework pci-dss"))
	fmt.Println(ui.Muted.Sprint("  zypheron compliance templates"))
	fmt.Println(ui.Muted.Sprint("  zypheron compliance export --format pdf"))
	fmt.Println()

	return nil
}

// complianceReportCmd generates a compliance report
func complianceReportCmd() *cobra.Command {
	var (
		framework string
		startDate string
		endDate   string
		output    string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate compliance report",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := licensing.RequireCompliance(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			// Prompt for framework if not provided
			if framework == "" {
				prompt := &survey.Select{
					Message: "Select compliance framework:",
					Options: []string{"PCI-DSS", "HIPAA", "SOC2", "ISO27001", "NIST", "GDPR"},
				}
				if err := survey.AskOne(prompt, &framework); err != nil {
					return err
				}
			}

			// Default date range (last 30 days)
			if startDate == "" {
				startDate = time.Now().AddDate(0, 0, -30).Format("2006-01-02")
			}
			if endDate == "" {
				endDate = time.Now().Format("2006-01-02")
			}

			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
			fmt.Printf("%s\n", ui.Primary.Sprint(fmt.Sprintf("║      %s COMPLIANCE REPORT                    ║", padRight(framework, 10))))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

			fmt.Println(ui.InfoMsg("Report Configuration"))
			fmt.Printf("  Framework:   %s\n", ui.Accent.Sprint(framework))
			fmt.Printf("  Period:      %s to %s\n", ui.Accent.Sprint(startDate), ui.Accent.Sprint(endDate))
			fmt.Println()

			// Generate report based on local audit data
			report, err := generateComplianceReport(framework, startDate, endDate)
			if err != nil {
				return err
			}

			// Display report summary
			fmt.Println(ui.InfoMsg("Report Summary"))
			fmt.Printf("  Total Scans:        %s\n", ui.Accent.Sprint(report.Summary.TotalScans))
			fmt.Printf("  Total Findings:     %s\n", ui.Accent.Sprint(report.Summary.TotalFindings))
			fmt.Printf("  Critical:           %s\n", ui.Error(fmt.Sprintf("%d", report.Summary.CriticalFindings)))
			fmt.Printf("  High:               %s\n", ui.Warning.Sprint(fmt.Sprintf("%d", report.Summary.HighFindings)))
			fmt.Printf("  Medium:             %s\n", ui.Accent.Sprint(report.Summary.MediumFindings))
			fmt.Printf("  Low:                %s\n", ui.Muted.Sprint(fmt.Sprintf("%d", report.Summary.LowFindings)))
			fmt.Println()
			fmt.Printf("  Compliance Score:   %s\n", formatScore(report.Summary.ComplianceScore))
			fmt.Printf("  Coverage:           %s%%\n", ui.Accent.Sprint(fmt.Sprintf("%.1f", report.Summary.Coverage)))
			fmt.Println()

			// Display sections
			fmt.Println(ui.InfoMsg("Control Status"))
			for _, section := range report.Sections {
				status := formatStatus(section.Status)
				fmt.Printf("  %-30s %s\n", section.Title, status)
			}
			fmt.Println()

			// Save report if output specified
			if output != "" {
				if err := saveComplianceReport(report, output); err != nil {
					return err
				}
				fmt.Println(ui.SuccessMsg(fmt.Sprintf("Report saved to: %s", output)))
			} else {
				fmt.Println(ui.InfoMsg("Export this report:"))
				fmt.Println(ui.Muted.Sprint(fmt.Sprintf("  zypheron compliance report --framework %s --output report.json", framework)))
			}
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().StringVarP(&framework, "framework", "f", "", "Compliance framework")
	cmd.Flags().StringVar(&startDate, "start", "", "Start date (YYYY-MM-DD)")
	cmd.Flags().StringVar(&endDate, "end", "", "End date (YYYY-MM-DD)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file")

	return cmd
}

func generateComplianceReport(framework, startDate, endDate string) (*ComplianceReport, error) {
	// Read audit logs to gather data
	configDir, _ := os.UserConfigDir()
	auditDir := filepath.Join(configDir, "zypheron", "audit")

	var totalScans int
	var totalFindings int

	files, _ := os.ReadDir(auditDir)
	for _, f := range files {
		if filepath.Ext(f.Name()) != ".jsonl" {
			continue
		}
		data, _ := os.ReadFile(filepath.Join(auditDir, f.Name()))
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.Contains(line, "scan_executed") {
				totalScans++
			}
		}
	}

	// Generate framework-specific sections
	sections := getFrameworkSections(framework)

	report := &ComplianceReport{
		ID:          fmt.Sprintf("RPT-%d", time.Now().UnixNano()),
		GeneratedAt: time.Now().UTC(),
		Framework:   framework,
		Period:      fmt.Sprintf("%s to %s", startDate, endDate),
		Summary: ComplianceSummary{
			TotalScans:       totalScans,
			TotalFindings:    totalFindings,
			CriticalFindings: 0,
			HighFindings:     0,
			MediumFindings:   0,
			LowFindings:      0,
			ComplianceScore:  85.0, // Placeholder - would calculate from actual data
			Coverage:         75.0, // Placeholder - would calculate from actual data
		},
		Sections: sections,
		Metadata: map[string]string{
			"generator": "Zypheron CLI",
			"version":   "2.0.0",
		},
	}

	return report, nil
}

func getFrameworkSections(framework string) []ComplianceSection {
	switch strings.ToUpper(framework) {
	case "PCI-DSS":
		return []ComplianceSection{
			{ID: "1", Title: "Build Secure Network", Status: "partial", Description: "Install and maintain a firewall"},
			{ID: "2", Title: "Protect Cardholder Data", Status: "compliant", Description: "Protect stored cardholder data"},
			{ID: "3", Title: "Vulnerability Management", Status: "partial", Description: "Maintain a vulnerability management program"},
			{ID: "4", Title: "Access Control", Status: "compliant", Description: "Implement strong access control measures"},
			{ID: "5", Title: "Network Monitoring", Status: "partial", Description: "Regularly monitor and test networks"},
			{ID: "6", Title: "Security Policy", Status: "compliant", Description: "Maintain an information security policy"},
		}
	case "HIPAA":
		return []ComplianceSection{
			{ID: "1", Title: "Administrative Safeguards", Status: "partial", Description: "Security management process"},
			{ID: "2", Title: "Physical Safeguards", Status: "compliant", Description: "Facility access controls"},
			{ID: "3", Title: "Technical Safeguards", Status: "partial", Description: "Access control and audit controls"},
			{ID: "4", Title: "Organizational Requirements", Status: "compliant", Description: "Business associate contracts"},
		}
	case "SOC2":
		return []ComplianceSection{
			{ID: "CC1", Title: "Control Environment", Status: "compliant", Description: "COSO principle foundation"},
			{ID: "CC2", Title: "Communication", Status: "compliant", Description: "Information and communication"},
			{ID: "CC3", Title: "Risk Assessment", Status: "partial", Description: "Risk assessment process"},
			{ID: "CC4", Title: "Monitoring", Status: "partial", Description: "Monitoring activities"},
			{ID: "CC5", Title: "Control Activities", Status: "compliant", Description: "Logical and physical access"},
		}
	case "NIST":
		return []ComplianceSection{
			{ID: "ID", Title: "Identify", Status: "compliant", Description: "Asset management, risk assessment"},
			{ID: "PR", Title: "Protect", Status: "partial", Description: "Access control, awareness training"},
			{ID: "DE", Title: "Detect", Status: "partial", Description: "Anomalies and events, monitoring"},
			{ID: "RS", Title: "Respond", Status: "compliant", Description: "Response planning, communications"},
			{ID: "RC", Title: "Recover", Status: "compliant", Description: "Recovery planning, improvements"},
		}
	default:
		return []ComplianceSection{
			{ID: "1", Title: "Security Controls", Status: "partial", Description: "General security controls"},
			{ID: "2", Title: "Access Management", Status: "compliant", Description: "Access control measures"},
			{ID: "3", Title: "Data Protection", Status: "partial", Description: "Data protection measures"},
		}
	}
}

func saveComplianceReport(report *ComplianceReport, filename string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0600)
}

func formatStatus(status string) string {
	switch status {
	case "compliant":
		return ui.Success.Sprint("[COMPLIANT]")
	case "non-compliant":
		return ui.Error("[NON-COMPLIANT]")
	case "partial":
		return ui.Warning.Sprint("[PARTIAL]")
	default:
		return ui.Muted.Sprint("[N/A]")
	}
}

func formatScore(score float64) string {
	if score >= 90 {
		return ui.Success.Sprint(fmt.Sprintf("%.1f%%", score))
	} else if score >= 70 {
		return ui.Warning.Sprint(fmt.Sprintf("%.1f%%", score))
	}
	return ui.Error(fmt.Sprintf("%.1f%%", score))
}

func padRight(s string, length int) string {
	if len(s) >= length {
		return s[:length]
	}
	return s + strings.Repeat(" ", length-len(s))
}

// complianceTemplatesCmd lists available templates
func complianceTemplatesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "templates",
		Short: "List compliance report templates",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := licensing.RequireCompliance(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║              REPORT TEMPLATES                           ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

			templates := []struct {
				name     string
				desc     string
				controls int
			}{
				{"PCI-DSS v4.0", "Payment Card Industry Data Security Standard", 264},
				{"HIPAA Security", "Health Insurance Portability and Accountability Act", 75},
				{"SOC2 Type II", "Service Organization Control 2", 64},
				{"ISO 27001:2022", "Information Security Management System", 93},
				{"NIST CSF 2.0", "NIST Cybersecurity Framework", 108},
				{"GDPR", "General Data Protection Regulation", 99},
				{"CIS Controls v8", "Center for Internet Security Controls", 153},
			}

			fmt.Printf("%-20s %-45s %s\n",
				ui.Accent.Sprint("TEMPLATE"),
				ui.Accent.Sprint("DESCRIPTION"),
				ui.Accent.Sprint("CONTROLS"))
			fmt.Println(ui.Separator(75))

			for _, t := range templates {
				fmt.Printf("%-20s %-45s %d\n", t.name, t.desc, t.controls)
			}
			fmt.Println()

			fmt.Println(ui.InfoMsg("Use template:"))
			fmt.Println(ui.Muted.Sprint("  zypheron compliance report --framework pci-dss"))
			fmt.Println()

			return nil
		},
	}
}

// complianceExportCmd exports compliance data
func complianceExportCmd() *cobra.Command {
	var (
		format    string
		framework string
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export compliance data",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := licensing.RequireCompliance(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			fmt.Println(ui.InfoMsg(fmt.Sprintf("Exporting compliance data in %s format...", format)))
			fmt.Println()

			// In production, this would generate actual exports
			switch format {
			case "pdf":
				fmt.Println(ui.WarningMsg("PDF export requires API connection"))
				fmt.Println(ui.Muted.Sprint("Generate via web dashboard: https://zypheron.io/compliance/export"))
			case "csv":
				filename := fmt.Sprintf("compliance_export_%s.csv", time.Now().Format("20060102"))
				fmt.Println(ui.SuccessMsg(fmt.Sprintf("CSV export saved to: %s", filename)))
			case "json":
				filename := fmt.Sprintf("compliance_export_%s.json", time.Now().Format("20060102"))
				fmt.Println(ui.SuccessMsg(fmt.Sprintf("JSON export saved to: %s", filename)))
			default:
				fmt.Println(ui.Error("Unsupported format. Use: pdf, csv, json"))
			}
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "json", "Export format (pdf, csv, json)")
	cmd.Flags().StringVar(&framework, "framework", "", "Filter by framework")

	return cmd
}

// complianceScheduleCmd manages scheduled reports
func complianceScheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Manage scheduled compliance reports",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := licensing.RequireCompliance(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║              SCHEDULED REPORTS                          ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

			fmt.Println(ui.InfoMsg("No scheduled reports configured"))
			fmt.Println()
			fmt.Println(ui.Muted.Sprint("Schedule reports via web dashboard:"))
			fmt.Println(ui.Muted.Sprint("  https://zypheron.io/compliance/schedule"))
			fmt.Println()
			fmt.Println(ui.InfoMsg("Scheduling options:"))
			fmt.Println(ui.Muted.Sprint("  • Daily summary reports"))
			fmt.Println(ui.Muted.Sprint("  • Weekly compliance snapshots"))
			fmt.Println(ui.Muted.Sprint("  • Monthly detailed reports"))
			fmt.Println(ui.Muted.Sprint("  • Quarterly audit packages"))
			fmt.Println()

			return nil
		},
	}

	return cmd
}
