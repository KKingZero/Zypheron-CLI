package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/report"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/session"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/storage"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/pkg/types"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

// ReportCmd returns the report generation command
func ReportCmd() *cobra.Command {
	var (
		format     string
		output     string
		last       bool
		list       bool
		includeRaw bool
		includeChat bool
	)

	cmd := &cobra.Command{
		Use:   "report [session-id or scan-id]",
		Short: "Generate reports from scan sessions",
		Long: `Generate PDF, HTML, Markdown, or JSON reports from completed scans.

Reports can be generated from:
  • Session IDs (from autopent, interactive scans)
  • Scan IDs (from zypheron scan)

Examples:
  zypheron report abc123                    # Generate PDF (default)
  zypheron report abc123 --format html      # Generate HTML
  zypheron report abc123 --format md        # Generate Markdown
  zypheron report --last                    # Report from last scan
  zypheron report --list                    # List available sessions`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Handle --list flag
			if list {
				return listAvailableSources()
			}

			// Determine the source ID
			var sourceID string
			var sourceType string // "session" or "scan"

			if last {
				// Get the most recent scan or session
				id, srcType, err := getMostRecentSource()
				if err != nil {
					return err
				}
				sourceID = id
				sourceType = srcType
				fmt.Printf("%s Using most recent %s: %s\n\n", ui.Success.Sprint("✓"), sourceType, ui.Accent.Sprint(sourceID))
			} else if len(args) > 0 {
				sourceID = args[0]
				// Try to determine source type
				sourceType = detectSourceType(sourceID)
			} else {
				// Interactive selection
				id, srcType, err := selectSourceInteractively()
				if err != nil {
					return err
				}
				sourceID = id
				sourceType = srcType
			}

			// Load the scan result
			scanResult, err := loadScanResult(sourceID, sourceType, includeRaw, includeChat)
			if err != nil {
				return fmt.Errorf("failed to load scan data: %w", err)
			}

			// Determine output filename
			outputPath := output
			if outputPath == "" {
				outputPath = generateReportFilename(scanResult.Target, format)
			}

			// Auto-detect format from extension if not specified
			if format == "" {
				format = report.DetectFormatFromExtension(outputPath)
				if format == "text" {
					format = "pdf" // Default to PDF
				}
			}

			// Ensure correct extension
			outputPath = ensureExtension(outputPath, format)

			// Print header
			fmt.Printf("\n%s\n", ui.Primary.Sprint("╔═══════════════════════════════════════╗"))
			fmt.Printf("%s\n", ui.Primary.Sprint("║  ZYPHERON REPORT GENERATOR             ║"))
			fmt.Printf("%s\n\n", ui.Primary.Sprint("╚═══════════════════════════════════════╝"))

			// Show report configuration
			fmt.Printf("%s\n", ui.InfoMsg("Report Configuration:"))
			fmt.Println(ui.Separator(50))
			fmt.Printf("  Source:    %s (%s)\n", ui.Accent.Sprint(sourceID), sourceType)
			fmt.Printf("  Target:    %s\n", ui.Accent.Sprint(scanResult.Target))
			fmt.Printf("  Format:    %s\n", ui.Accent.Sprint(strings.ToUpper(format)))
			fmt.Printf("  Output:    %s\n", ui.Accent.Sprint(outputPath))
			fmt.Printf("  Vulns:     %d\n", len(scanResult.Vulnerabilities))
			fmt.Println(ui.Separator(50))
			fmt.Println()

			// Generate report
			fmt.Print(ui.InfoMsg("Generating report... "))

			if err := report.GenerateReport(scanResult, format, outputPath); err != nil {
				fmt.Println(ui.Error("FAILED"))
				return fmt.Errorf("failed to generate report: %w", err)
			}

			fmt.Println(ui.Success.Sprint("DONE"))
			fmt.Println()

			// Get absolute path for display
			absPath, _ := filepath.Abs(outputPath)

			fmt.Println(ui.SuccessMsg(fmt.Sprintf("Report saved to: %s", absPath)))
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "", "Output format: pdf, html, md, json, text (default: pdf)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path (default: auto-generated)")
	cmd.Flags().BoolVar(&last, "last", false, "Generate report from most recent scan")
	cmd.Flags().BoolVar(&list, "list", false, "List available sessions and scans")
	cmd.Flags().BoolVar(&includeRaw, "include-raw", false, "Include raw tool output in report")
	cmd.Flags().BoolVar(&includeChat, "include-chat", true, "Include AI chat history in report")

	return cmd
}

// listAvailableSources lists all available sessions and scans
func listAvailableSources() error {
	fmt.Printf("\n%s\n\n", ui.Primary.Sprint("Available Report Sources"))

	// List sessions
	sessionMgr, err := session.NewSessionManager()
	if err == nil {
		sessions, err := sessionMgr.ListSessions()
		if err == nil && len(sessions) > 0 {
			fmt.Println(ui.InfoMsg("Sessions (from autopent, interactive scans):"))
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"ID", "Date", "Target", "Type", "Status", "Vulns"})
			table.SetBorder(false)

			for _, s := range sessions {
				if len(sessions) > 10 {
					// Show only first 10
					break
				}
				id := s.SessionID
				if len(id) > 12 {
					id = id[:12] + "..."
				}
				table.Append([]string{
					id,
					s.StartTime.Format("2006-01-02 15:04"),
					truncateString(s.Target, 25),
					string(s.ScanType),
					string(s.Status),
					fmt.Sprintf("%d", s.VulnCount),
				})
			}
			table.Render()
			fmt.Println()
		}
	}

	// List scans
	scanStore, err := storage.NewScanStorage()
	if err == nil {
		scans, err := scanStore.ListScans()
		if err == nil && len(scans) > 0 {
			fmt.Println(ui.InfoMsg("Scans (from zypheron scan):"))
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"ID", "Date", "Target", "Tool", "Status", "Vulns"})
			table.SetBorder(false)

			count := 0
			for _, s := range scans {
				if count >= 10 {
					break
				}
				id := s.ID
				if len(id) > 20 {
					id = id[:20] + "..."
				}
				status := "✓"
				if !s.Success {
					status = "✗"
				}
				table.Append([]string{
					id,
					s.Timestamp.Format("2006-01-02 15:04"),
					truncateString(s.Target, 25),
					s.Tool,
					status,
					fmt.Sprintf("%d", s.VulnCount),
				})
				count++
			}
			table.Render()
			fmt.Println()
		}
	}

	fmt.Println(ui.Muted.Sprint("Usage: zypheron report <id> [--format pdf|html|md|json]"))
	fmt.Println()

	return nil
}

// getMostRecentSource returns the most recent session or scan
func getMostRecentSource() (string, string, error) {
	var latestTime time.Time
	var latestID string
	var latestType string

	// Check sessions
	sessionMgr, err := session.NewSessionManager()
	if err == nil {
		sessions, err := sessionMgr.ListSessions()
		if err == nil && len(sessions) > 0 {
			if sessions[0].StartTime.After(latestTime) {
				latestTime = sessions[0].StartTime
				latestID = sessions[0].SessionID
				latestType = "session"
			}
		}
	}

	// Check scans
	scanStore, err := storage.NewScanStorage()
	if err == nil {
		scans, err := scanStore.ListScans()
		if err == nil && len(scans) > 0 {
			if scans[0].Timestamp.After(latestTime) {
				latestTime = scans[0].Timestamp
				latestID = scans[0].ID
				latestType = "scan"
			}
		}
	}

	if latestID == "" {
		return "", "", fmt.Errorf("no sessions or scans found. Run a scan first with: zypheron scan <target>")
	}

	return latestID, latestType, nil
}

// detectSourceType tries to determine if the ID is a session or scan
func detectSourceType(id string) string {
	// Sessions typically use UUID format
	// Scans typically use format: tool-target-timestamp

	// Try loading as scan first (more common)
	scanStore, err := storage.NewScanStorage()
	if err == nil {
		if _, err := scanStore.LoadScan(id); err == nil {
			return "scan"
		}
	}

	// Try loading as session
	sessionMgr, err := session.NewSessionManager()
	if err == nil {
		if _, err := sessionMgr.Load(id); err == nil {
			return "session"
		}
	}

	// Default to scan
	return "scan"
}

// selectSourceInteractively shows an interactive picker for source selection
func selectSourceInteractively() (string, string, error) {
	var options []string
	optionMap := make(map[string]struct {
		id      string
		srcType string
	})

	// Collect sessions
	sessionMgr, err := session.NewSessionManager()
	if err == nil {
		sessions, err := sessionMgr.ListSessions()
		if err == nil {
			for i, s := range sessions {
				if i >= 5 {
					break
				}
				label := fmt.Sprintf("[Session] %s - %s (%s)", s.Target, s.StartTime.Format("2006-01-02 15:04"), s.Status)
				options = append(options, label)
				optionMap[label] = struct {
					id      string
					srcType string
				}{id: s.SessionID, srcType: "session"}
			}
		}
	}

	// Collect scans
	scanStore, err := storage.NewScanStorage()
	if err == nil {
		scans, err := scanStore.ListScans()
		if err == nil {
			for i, s := range scans {
				if i >= 5 {
					break
				}
				status := "success"
				if !s.Success {
					status = "failed"
				}
				label := fmt.Sprintf("[Scan] %s - %s (%s, %d vulns)", s.Target, s.Timestamp.Format("2006-01-02 15:04"), status, s.VulnCount)
				options = append(options, label)
				optionMap[label] = struct {
					id      string
					srcType string
				}{id: s.ID, srcType: "scan"}
			}
		}
	}

	if len(options) == 0 {
		return "", "", fmt.Errorf("no sessions or scans found. Run a scan first with: zypheron scan <target>")
	}

	var selected string
	prompt := &survey.Select{
		Message: "Select a source for the report:",
		Options: options,
	}

	if err := survey.AskOne(prompt, &selected); err != nil {
		return "", "", fmt.Errorf("selection cancelled")
	}

	source := optionMap[selected]
	return source.id, source.srcType, nil
}

// loadScanResult loads a scan result from either a session or scan
func loadScanResult(id, sourceType string, includeRaw, includeChat bool) (*types.ScanResult, error) {
	if sourceType == "session" {
		return loadFromSession(id, includeRaw, includeChat)
	}
	return loadFromScan(id)
}

// loadFromSession converts a session to ScanResult
func loadFromSession(sessionID string, includeRaw, includeChat bool) (*types.ScanResult, error) {
	sessionMgr, err := session.NewSessionManager()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize session manager: %w", err)
	}

	sess, err := sessionMgr.Load(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	// Convert session vulnerabilities to types.Vulnerability
	var vulns []types.Vulnerability
	for _, v := range sess.Results.Vulnerabilities {
		var cvssPtr *float64
		if v.CVSSScore > 0 {
			cvssPtr = &v.CVSSScore
		}

		var cvePtr *string
		if v.CVEID != "" {
			cvePtr = &v.CVEID
		}

		var portPtr *int
		if v.Port > 0 {
			portPtr = &v.Port
		}

		var remPtr *string
		if v.Remediation != "" {
			remPtr = &v.Remediation
		}

		vulns = append(vulns, types.Vulnerability{
			ID:               v.ID,
			Title:            v.Title,
			Description:      v.Description,
			Severity:         v.Severity,
			CVSSScore:        cvssPtr,
			CVEID:            cvePtr,
			Port:             portPtr,
			Remediation:      remPtr,
			ExploitAvailable: v.ExploitAvailable,
			References:       v.References,
		})
	}

	// Build AI analysis from chat history if requested
	aiAnalysis := sess.Results.AIAnalysis
	if includeChat && len(sess.ChatHistory) > 0 {
		var chatSummary strings.Builder
		chatSummary.WriteString("AI Conversation Summary:\n\n")
		for _, msg := range sess.ChatHistory {
			if msg.Role == "assistant" && len(msg.Content) > 50 {
				chatSummary.WriteString(fmt.Sprintf("- %s\n", truncateString(msg.Content, 200)))
			}
		}
		if chatSummary.Len() > 50 {
			aiAnalysis = chatSummary.String()
		}
	}

	// Calculate duration
	duration := sess.EndTime.Sub(sess.StartTime).Seconds()
	if duration <= 0 {
		duration = time.Since(sess.StartTime).Seconds()
	}

	// Build output
	output := ""
	if includeRaw {
		output = sess.Results.RawOutput
	}

	// Build metadata
	metadata := make(map[string]string)
	metadata["session_id"] = sess.SessionID
	metadata["scan_type"] = string(sess.ScanType)
	metadata["status"] = string(sess.Status)
	if sess.Progress.CurrentPhase != "" {
		metadata["phase"] = sess.Progress.CurrentPhase
	}

	result := &types.ScanResult{
		ID:              sess.SessionID,
		Timestamp:       sess.StartTime,
		Target:          sess.Target,
		Tool:            string(sess.ScanType),
		Ports:           "", // Sessions may not have port info
		Output:          output,
		Vulnerabilities: vulns,
		AIAnalysis:      aiAnalysis,
		Duration:        duration,
		Success:         sess.Status == session.StatusCompleted,
		Metadata:        metadata,
	}

	return result, nil
}

// loadFromScan loads a scan result directly
func loadFromScan(scanID string) (*types.ScanResult, error) {
	scanStore, err := storage.NewScanStorage()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize scan storage: %w", err)
	}

	scan, err := scanStore.LoadScan(scanID)
	if err != nil {
		return nil, fmt.Errorf("scan not found: %s", scanID)
	}

	return scan, nil
}

// generateReportFilename generates a filename following the naming convention
func generateReportFilename(target, format string) string {
	safeTarget := sanitizeFilename(target)
	date := time.Now().Format("2006-01-02_150405")

	// Default format to pdf
	if format == "" {
		format = "pdf"
	}

	return fmt.Sprintf("zypheron_%s_%s.%s", safeTarget, date, format)
}

// sanitizeFilename removes or replaces characters that are unsafe for filenames
func sanitizeFilename(s string) string {
	// Replace common URL/path separators
	s = strings.ReplaceAll(s, "://", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "..", "_")

	// Remove any remaining special characters
	reg := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	s = reg.ReplaceAllString(s, "_")

	// Collapse multiple underscores
	reg = regexp.MustCompile(`_+`)
	s = reg.ReplaceAllString(s, "_")

	// Trim leading/trailing underscores
	s = strings.Trim(s, "_")

	// Limit length
	if len(s) > 50 {
		s = s[:50]
	}

	return s
}

// ensureExtension ensures the output path has the correct extension for the format
func ensureExtension(path, format string) string {
	ext := filepath.Ext(path)

	expectedExt := "." + format
	if format == "markdown" {
		expectedExt = ".md"
	}

	if ext == "" {
		return path + expectedExt
	}

	// If extension doesn't match, append the correct one
	if ext != expectedExt {
		return path + expectedExt
	}

	return path
}

// truncateString truncates a string to maxLen with ellipsis
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
