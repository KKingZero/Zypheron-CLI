//go:build example
// +build example

package session

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"
)

// This file demonstrates how to integrate the session management system
// into Zypheron CLI commands (e.g., scan, recon, etc.)

// IntegratedScanExample shows how to use sessions in a scan command
func IntegratedScanExample(target string, scanType ScanType, resumeSessionID string) error {
	cfg := config.Get()
	manager, err := NewSessionManager()
	if err != nil {
		return fmt.Errorf("failed to create session manager: %w", err)
	}

	var sess *Session

	// Resume existing session or create new one
	if resumeSessionID != "" {
		sess, err = manager.Load(resumeSessionID)
		if err != nil {
			return fmt.Errorf("failed to load session: %w", err)
		}
		fmt.Printf("Resuming session %s (%.1f%% complete)\n", sess.SessionID, sess.Progress.Percentage)
		sess.Resume()
		sess.AddChatMessage("system", "Session resumed")
	} else {
		sess = NewSession(target, scanType)
		fmt.Printf("Created new session: %s\n", sess.SessionID)
		sess.AddChatMessage("system", "Session started")
	}

	// Set environment metadata
	sess.SetEnvironmentInfo("os", "Kali Linux")
	sess.SetEnvironmentInfo("cli_version", "2.0.0")

	// Enable auto-save if configured
	if cfg.AutoSaveSession {
		sess.StartAutoSave(manager)
		defer sess.StopAutoSave()
	}

	// Set as active session
	manager.SetActiveSession(sess)
	defer manager.ClearActiveSession()

	// Update last session in config
	cfg.LastSession = sess.SessionID
	config.SaveToFile()

	// Perform the actual scan
	err = performScan(sess, manager)

	// Always save final state
	if saveErr := manager.Save(sess); saveErr != nil {
		fmt.Printf("Warning: failed to save session: %v\n", saveErr)
	}

	return err
}

// performScan executes the scan and updates session state
func performScan(sess *Session, manager *SessionManager) error {
	// Phase 1: Reconnaissance (0-25%)
	sess.UpdateProgress(0, "reconnaissance", 0, 4)
	sess.AddChatMessage("assistant", "Starting reconnaissance phase...")

	if err := runReconPhase(sess); err != nil {
		sess.Fail()
		sess.AddChatMessage("system", fmt.Sprintf("Scan failed: %v", err))
		return err
	}

	sess.UpdateProgress(25, "reconnaissance", 1, 4)

	// Phase 2: Port Scanning (25-50%)
	sess.UpdateProgress(25, "port scanning", 1, 4)
	sess.AddChatMessage("assistant", "Scanning ports and services...")

	if err := runPortScanPhase(sess); err != nil {
		sess.Fail()
		sess.AddChatMessage("system", fmt.Sprintf("Scan failed: %v", err))
		return err
	}

	sess.UpdateProgress(50, "port scanning", 2, 4)

	// Phase 3: Vulnerability Scanning (50-75%)
	sess.UpdateProgress(50, "vulnerability scanning", 2, 4)
	sess.AddChatMessage("assistant", "Detecting vulnerabilities...")

	if err := runVulnScanPhase(sess); err != nil {
		sess.Fail()
		sess.AddChatMessage("system", fmt.Sprintf("Scan failed: %v", err))
		return err
	}

	sess.UpdateProgress(75, "vulnerability scanning", 3, 4)

	// Phase 4: Analysis (75-100%)
	sess.UpdateProgress(75, "AI analysis", 3, 4)
	sess.AddChatMessage("assistant", "Analyzing results...")

	if err := runAnalysisPhase(sess); err != nil {
		sess.Fail()
		sess.AddChatMessage("system", fmt.Sprintf("Analysis failed: %v", err))
		return err
	}

	// Complete
	sess.Complete()
	sess.AddChatMessage("assistant", "Scan completed successfully!")

	// Print summary
	printScanSummary(sess)

	return nil
}

// runReconPhase executes reconnaissance
func runReconPhase(sess *Session) error {
	sess.AppendRawOutput("=== Reconnaissance Phase ===\n")

	// Example: DNS lookup, WHOIS, etc.
	sess.AddFinding(Finding{
		Type:        "dns",
		Title:       "DNS Resolution",
		Description: fmt.Sprintf("Target %s resolved", sess.Target),
		Severity:    "info",
		Details: map[string]interface{}{
			"ip": "192.168.1.1",
		},
	})

	return nil
}

// runPortScanPhase executes port scanning
func runPortScanPhase(sess *Session) error {
	sess.AppendRawOutput("=== Port Scanning Phase ===\n")

	// Example nmap execution (simplified)
	cmd := exec.Command("nmap", "-p-", "--open", sess.Target)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nmap failed: %w", err)
	}

	sess.AppendRawOutput(string(output))

	// Parse output and add findings
	if strings.Contains(string(output), "22/tcp") {
		sess.AddFinding(Finding{
			Type:        "port",
			Title:       "Open Port 22",
			Description: "SSH service detected",
			Severity:    "info",
			Details: map[string]interface{}{
				"port":     22,
				"protocol": "tcp",
				"service":  "ssh",
			},
		})
	}

	return nil
}

// runVulnScanPhase executes vulnerability scanning
func runVulnScanPhase(sess *Session) error {
	sess.AppendRawOutput("=== Vulnerability Scanning Phase ===\n")

	// Example vulnerability detection
	sess.AddVulnerability(Vulnerability{
		CVEID:       "CVE-2024-1234",
		Title:       "Example Vulnerability",
		Description: "A sample vulnerability for demonstration",
		Severity:    "medium",
		CVSSScore:   5.3,
		Port:        22,
		Service:     "ssh",
		Remediation: "Update to latest version",
	})

	return nil
}

// runAnalysisPhase executes AI analysis
func runAnalysisPhase(sess *Session) error {
	sess.AppendRawOutput("=== Analysis Phase ===\n")

	// Generate summary
	findingsCount := len(sess.Results.ParsedFindings)
	vulnCount := len(sess.Results.Vulnerabilities)

	summary := fmt.Sprintf("Scan completed. Found %d findings and %d vulnerabilities.",
		findingsCount, vulnCount)
	sess.SetSummary(summary)

	// AI analysis (simplified)
	analysis := fmt.Sprintf(
		"Target %s has been analyzed. "+
			"Detected %d open ports and services. "+
			"Found %d potential security issues. "+
			"Recommend further investigation of high-severity findings.",
		sess.Target, findingsCount, vulnCount)
	sess.SetAIAnalysis(analysis)

	return nil
}

// printScanSummary displays scan results
func printScanSummary(sess *Session) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("SCAN SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Session ID:  %s\n", sess.SessionID)
	fmt.Printf("Target:      %s\n", sess.Target)
	fmt.Printf("Scan Type:   %s\n", sess.ScanType)
	fmt.Printf("Status:      %s\n", sess.Status)
	fmt.Printf("Duration:    %s\n", sess.GetDuration())
	fmt.Printf("Findings:    %d\n", len(sess.Results.ParsedFindings))
	fmt.Printf("Vulnerabilities: %d\n", len(sess.Results.Vulnerabilities))

	// Count by severity
	criticalCount, highCount, mediumCount, lowCount := 0, 0, 0, 0
	for _, v := range sess.Results.Vulnerabilities {
		switch v.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		}
	}

	if len(sess.Results.Vulnerabilities) > 0 {
		fmt.Printf("  - Critical: %d\n", criticalCount)
		fmt.Printf("  - High:     %d\n", highCount)
		fmt.Printf("  - Medium:   %d\n", mediumCount)
		fmt.Printf("  - Low:      %d\n", lowCount)
	}

	if sess.Results.Summary != "" {
		fmt.Printf("\nSummary:\n%s\n", sess.Results.Summary)
	}

	if sess.Results.AIAnalysis != "" {
		fmt.Printf("\nAI Analysis:\n%s\n", sess.Results.AIAnalysis)
	}

	fmt.Println(strings.Repeat("=", 60))
}

// CLICommandExamples shows how to expose session management via CLI
func CLICommandExamples() {
	// These would be integrated into your Cobra commands

	// Example 1: Start new scan with auto-save
	// zypheron scan -t example.com --save-session

	// Example 2: Resume existing session
	// zypheron scan --resume <session-id>

	// Example 3: List all sessions
	// zypheron session list

	// Example 4: View session details
	// zypheron session show <session-id>

	// Example 5: Delete old sessions
	// zypheron session cleanup --days 30

	// Example 6: Export session results
	// zypheron session export <session-id> --format json

	// Example 7: Get active session
	// zypheron session active
}

// SessionListCommand demonstrates listing sessions (for CLI integration)
func SessionListCommand(limit int, scanTypeFilter string) error {
	manager, err := NewSessionManager()
	if err != nil {
		return err
	}

	var summaries []SessionSummary

	if scanTypeFilter != "" {
		summaries, err = manager.FindSessionsByScanType(ScanType(scanTypeFilter))
	} else {
		summaries, err = manager.ListSessions()
	}

	if err != nil {
		return err
	}

	if limit > 0 && len(summaries) > limit {
		summaries = summaries[:limit]
	}

	// Print header
	fmt.Println(strings.Repeat("=", 100))
	fmt.Printf("%-36s %-20s %-15s %-10s %-8s %-8s\n",
		"SESSION ID", "TARGET", "TYPE", "STATUS", "VULNS", "PROGRESS")
	fmt.Println(strings.Repeat("=", 100))

	// Print sessions
	for _, s := range summaries {
		statusIcon := getStatusIcon(s.Status)
		fmt.Printf("%-36s %-20s %-15s %-10s %-8d %.1f%%\n",
			s.SessionID[:36],
			truncate(s.Target, 20),
			s.ScanType,
			statusIcon,
			s.VulnCount,
			s.ProgressPercent)
	}

	fmt.Println(strings.Repeat("=", 100))
	fmt.Printf("Total sessions: %d\n", len(summaries))

	return nil
}

// SessionShowCommand demonstrates showing session details
func SessionShowCommand(sessionID string) error {
	manager, err := NewSessionManager()
	if err != nil {
		return err
	}

	sess, err := manager.Load(sessionID)
	if err != nil {
		return err
	}

	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("SESSION: %s\n", sess.SessionID)
	fmt.Println(strings.Repeat("=", 80))

	fmt.Printf("Target:      %s\n", sess.Target)
	fmt.Printf("Scan Type:   %s\n", sess.ScanType)
	fmt.Printf("Status:      %s\n", sess.Status)
	fmt.Printf("Started:     %s\n", sess.StartTime.Format(time.RFC3339))

	if !sess.EndTime.IsZero() {
		fmt.Printf("Ended:       %s\n", sess.EndTime.Format(time.RFC3339))
		fmt.Printf("Duration:    %s\n", sess.GetDuration())
	} else {
		fmt.Printf("Running for: %s\n", sess.GetDuration())
	}

	fmt.Printf("\nProgress:    %.1f%%\n", sess.Progress.Percentage)
	fmt.Printf("Phase:       %s\n", sess.Progress.CurrentPhase)
	fmt.Printf("Steps:       %d/%d\n", sess.Progress.StepsCompleted, sess.Progress.StepsTotal)

	fmt.Printf("\nFindings:    %d\n", len(sess.Results.ParsedFindings))
	fmt.Printf("Vulnerabilities: %d\n", len(sess.Results.Vulnerabilities))

	if len(sess.Tags) > 0 {
		fmt.Printf("Tags:        %s\n", strings.Join(sess.Tags, ", "))
	}

	if len(sess.ChatHistory) > 0 {
		fmt.Printf("\nChat History: %d messages\n", len(sess.ChatHistory))
		for i, msg := range sess.ChatHistory {
			if i >= 5 {
				fmt.Printf("... and %d more messages\n", len(sess.ChatHistory)-5)
				break
			}
			fmt.Printf("  [%s] %s: %s\n",
				msg.Timestamp.Format("15:04:05"),
				msg.Role,
				truncate(msg.Content, 60))
		}
	}

	fmt.Println(strings.Repeat("=", 80))

	return nil
}

// SessionCleanupCommand demonstrates cleanup command
func SessionCleanupCommand(days int, dryRun bool) error {
	manager, err := NewSessionManager()
	if err != nil {
		return err
	}

	if dryRun {
		// List sessions that would be deleted
		cutoffTime := time.Now().AddDate(0, 0, -days)
		summaries, err := manager.ListSessions()
		if err != nil {
			return err
		}

		count := 0
		fmt.Printf("Sessions older than %d days (before %s):\n",
			days, cutoffTime.Format("2006-01-02"))

		for _, s := range summaries {
			if s.StartTime.Before(cutoffTime) {
				fmt.Printf("  - %s (%s) - %s\n",
					s.SessionID, s.Target, s.StartTime.Format("2006-01-02"))
				count++
			}
		}

		fmt.Printf("\nTotal: %d sessions would be deleted\n", count)
		return nil
	}

	// Actually delete
	err = manager.CleanupOldSessions(days)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully cleaned up sessions older than %d days\n", days)
	return nil
}

// Helper functions

func getStatusIcon(status SessionStatus) string {
	switch status {
	case StatusRunning:
		return "▶ Running"
	case StatusPaused:
		return "⏸ Paused"
	case StatusCompleted:
		return "✓ Complete"
	case StatusFailed:
		return "✗ Failed"
	default:
		return string(status)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
