package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/licensing"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	Timestamp   time.Time         `json:"timestamp"`
	Action      string            `json:"action"`
	User        string            `json:"user"`
	Target      string            `json:"target,omitempty"`
	Tool        string            `json:"tool,omitempty"`
	Success     bool              `json:"success"`
	TokensUsed  int64             `json:"tokens_used,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
	SessionID   string            `json:"session_id"`
	DeviceID    string            `json:"device_id"`
}

// AuditLogger handles local audit logging
type AuditLogger struct {
	logFile   string
	sessionID string
	deviceID  string
	userEmail string
}

var globalAuditLogger *AuditLogger

// InitAuditLogger initializes the audit logger
func InitAuditLogger() error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}

	auditDir := filepath.Join(configDir, "zypheron", "audit")
	if err := os.MkdirAll(auditDir, 0700); err != nil {
		return err
	}

	// Daily log files
	logFile := filepath.Join(auditDir, fmt.Sprintf("audit_%s.jsonl", time.Now().Format("2006-01-02")))

	manager := licensing.GetManager()
	license := manager.License()

	globalAuditLogger = &AuditLogger{
		logFile:   logFile,
		sessionID: generateSessionID(),
		deviceID:  license.DeviceID,
		userEmail: license.Email,
	}

	return nil
}

// GetAuditLogger returns the global audit logger
func GetAuditLogger() *AuditLogger {
	return globalAuditLogger
}

// Log records an audit entry
func (a *AuditLogger) Log(action, target, tool string, success bool, tokensUsed int64, details map[string]string) error {
	if a == nil {
		return nil
	}

	entry := AuditEntry{
		Timestamp:  time.Now().UTC(),
		Action:     action,
		User:       a.userEmail,
		Target:     target,
		Tool:       tool,
		Success:    success,
		TokensUsed: tokensUsed,
		Details:    details,
		SessionID:  a.sessionID,
		DeviceID:   a.deviceID,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(a.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(string(data) + "\n")
	return err
}

// LogScan records a scan operation
func (a *AuditLogger) LogScan(target, tool string, success bool, details map[string]string) {
	if a != nil {
		a.Log("scan_executed", target, tool, success, 0, details)
	}
}

// LogExploit records an exploitation attempt
func (a *AuditLogger) LogExploit(target, tool string, success bool, details map[string]string) {
	if a != nil {
		a.Log("exploit_run", target, tool, success, 0, details)
	}
}

// LogAIQuery records an AI query
func (a *AuditLogger) LogAIQuery(provider string, tokensUsed int64, success bool, details map[string]string) {
	if a != nil {
		a.Log("ai_query", "", provider, success, tokensUsed, details)
	}
}

// LogAuth records authentication events
func (a *AuditLogger) LogAuth(action string, success bool, details map[string]string) {
	if a != nil {
		a.Log(action, "", "", success, 0, details)
	}
}

// LogTeamAction records team management actions
func (a *AuditLogger) LogTeamAction(action, targetUser string, success bool, details map[string]string) {
	if a != nil {
		a.Log(action, targetUser, "", success, 0, details)
	}
}

func generateSessionID() string {
	return fmt.Sprintf("sess_%d", time.Now().UnixNano())
}

// AuditCmd returns the audit command for viewing local audit logs
func AuditCmd() *cobra.Command {
	var (
		limit  int
		action string
		format string
		export string
	)

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "View local audit logs (Enterprise)",
		Long: `View and export local audit logs for compliance and security review.

Audit logs track:
  - Scan operations (targets, tools, results)
  - Exploitation attempts
  - AI queries and token usage
  - Authentication events
  - Team management actions

REQUIRES: Enterprise subscription for full features

Examples:
  zypheron audit                      # View recent audit entries
  zypheron audit --limit 100          # View last 100 entries
  zypheron audit --action scan        # Filter by action type
  zypheron audit --export audit.json  # Export to file`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check for enterprise license for full audit features
			if err := licensing.RequireAuditLogs(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║              LOCAL AUDIT LOG                            ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

			// Get audit log directory
			configDir, err := os.UserConfigDir()
			if err != nil {
				return err
			}
			auditDir := filepath.Join(configDir, "zypheron", "audit")

			// Find today's log file
			logFile := filepath.Join(auditDir, fmt.Sprintf("audit_%s.jsonl", time.Now().Format("2006-01-02")))

			if _, err := os.Stat(logFile); os.IsNotExist(err) {
				fmt.Println(ui.InfoMsg("No audit entries for today"))
				fmt.Println()
				fmt.Println(ui.Muted.Sprint("Audit logs are created when you use Zypheron tools."))
				fmt.Println(ui.Muted.Sprint("Try running a scan to generate audit entries."))
				fmt.Println()
				return nil
			}

			// Read and parse entries
			entries, err := readAuditEntries(logFile, limit, action)
			if err != nil {
				return err
			}

			if len(entries) == 0 {
				fmt.Println(ui.InfoMsg("No matching audit entries found"))
				return nil
			}

			// Display or export
			if export != "" {
				return exportAuditEntries(entries, export, format)
			}

			displayAuditEntries(entries, format)
			return nil
		},
	}

	cmd.Flags().IntVarP(&limit, "limit", "n", 50, "Number of entries to show")
	cmd.Flags().StringVarP(&action, "action", "a", "", "Filter by action type (scan, exploit, ai_query, auth)")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format (table, json)")
	cmd.Flags().StringVarP(&export, "export", "e", "", "Export to file")

	cmd.AddCommand(auditSummaryCmd())
	cmd.AddCommand(auditClearCmd())

	return cmd
}

func readAuditEntries(logFile string, limit int, actionFilter string) ([]AuditEntry, error) {
	data, err := os.ReadFile(logFile)
	if err != nil {
		return nil, err
	}

	var entries []AuditEntry
	lines := splitLines(string(data))

	for i := len(lines) - 1; i >= 0 && len(entries) < limit; i-- {
		line := lines[i]
		if line == "" {
			continue
		}

		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		if actionFilter != "" && entry.Action != actionFilter {
			continue
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func displayAuditEntries(entries []AuditEntry, format string) {
	if format == "json" {
		data, _ := json.MarshalIndent(entries, "", "  ")
		fmt.Println(string(data))
		return
	}

	// Table format
	fmt.Printf("%-20s %-15s %-25s %-10s %s\n",
		ui.Accent.Sprint("TIMESTAMP"),
		ui.Accent.Sprint("ACTION"),
		ui.Accent.Sprint("TARGET/TOOL"),
		ui.Accent.Sprint("STATUS"),
		ui.Accent.Sprint("TOKENS"))
	fmt.Println(ui.Separator(80))

	for _, entry := range entries {
		status := ui.Success.Sprint("OK")
		if !entry.Success {
			status = ui.Error("FAIL")
		}

		targetTool := entry.Target
		if entry.Tool != "" {
			if targetTool != "" {
				targetTool += " / " + entry.Tool
			} else {
				targetTool = entry.Tool
			}
		}
		if len(targetTool) > 25 {
			targetTool = targetTool[:22] + "..."
		}

		tokens := "-"
		if entry.TokensUsed > 0 {
			tokens = formatTokens(entry.TokensUsed)
		}

		fmt.Printf("%-20s %-15s %-25s %-10s %s\n",
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			entry.Action,
			targetTool,
			status,
			tokens)
	}
	fmt.Println()
}

func exportAuditEntries(entries []AuditEntry, filename, format string) error {
	var data []byte
	var err error

	if format == "json" {
		data, err = json.MarshalIndent(entries, "", "  ")
	} else {
		// CSV format
		csv := "timestamp,action,user,target,tool,success,tokens_used,session_id,device_id\n"
		for _, e := range entries {
			csv += fmt.Sprintf("%s,%s,%s,%s,%s,%t,%d,%s,%s\n",
				e.Timestamp.Format(time.RFC3339),
				e.Action,
				e.User,
				e.Target,
				e.Tool,
				e.Success,
				e.TokensUsed,
				e.SessionID,
				e.DeviceID)
		}
		data = []byte(csv)
	}

	if err != nil {
		return err
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return err
	}

	fmt.Println(ui.SuccessMsg(fmt.Sprintf("Exported %d entries to %s", len(entries), filename)))
	return nil
}

// auditSummaryCmd shows audit summary statistics
func auditSummaryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "summary",
		Short: "Show audit summary statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := licensing.RequireAuditLogs(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║              AUDIT SUMMARY                              ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════╝\n"))

			configDir, _ := os.UserConfigDir()
			auditDir := filepath.Join(configDir, "zypheron", "audit")

			// Count entries by action type
			files, err := os.ReadDir(auditDir)
			if err != nil {
				fmt.Println(ui.InfoMsg("No audit logs found"))
				return nil
			}

			actionCounts := make(map[string]int)
			var totalTokens int64
			var totalEntries int

			for _, f := range files {
				if filepath.Ext(f.Name()) != ".jsonl" {
					continue
				}

				data, err := os.ReadFile(filepath.Join(auditDir, f.Name()))
				if err != nil {
					continue
				}

				lines := splitLines(string(data))
				for _, line := range lines {
					if line == "" {
						continue
					}
					var entry AuditEntry
					if err := json.Unmarshal([]byte(line), &entry); err != nil {
						continue
					}
					actionCounts[entry.Action]++
					totalTokens += entry.TokensUsed
					totalEntries++
				}
			}

			fmt.Println(ui.InfoMsg("Summary Statistics"))
			fmt.Printf("  Total Entries:    %s\n", ui.Accent.Sprint(totalEntries))
			fmt.Printf("  Total Tokens:     %s\n", ui.Accent.Sprint(formatTokens(totalTokens)))
			fmt.Printf("  Log Files:        %s\n", ui.Accent.Sprint(len(files)))
			fmt.Println()

			fmt.Println(ui.InfoMsg("Actions by Type"))
			for action, count := range actionCounts {
				fmt.Printf("  %-20s %d\n", action, count)
			}
			fmt.Println()

			return nil
		},
	}
}

// auditClearCmd clears old audit logs
func auditClearCmd() *cobra.Command {
	var days int

	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Clear old audit logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := licensing.RequireAuditLogs(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			configDir, _ := os.UserConfigDir()
			auditDir := filepath.Join(configDir, "zypheron", "audit")

			cutoff := time.Now().AddDate(0, 0, -days)
			files, err := os.ReadDir(auditDir)
			if err != nil {
				return err
			}

			var removed int
			for _, f := range files {
				if filepath.Ext(f.Name()) != ".jsonl" {
					continue
				}

				info, err := f.Info()
				if err != nil {
					continue
				}

				if info.ModTime().Before(cutoff) {
					os.Remove(filepath.Join(auditDir, f.Name()))
					removed++
				}
			}

			fmt.Println(ui.SuccessMsg(fmt.Sprintf("Removed %d log files older than %d days", removed, days)))
			return nil
		},
	}

	cmd.Flags().IntVarP(&days, "days", "d", 30, "Remove logs older than N days")

	return cmd
}
