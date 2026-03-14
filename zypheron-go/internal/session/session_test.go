package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewSession(t *testing.T) {
	session := NewSession("192.168.1.1", ScanTypeNmap)

	if session.SessionID == "" {
		t.Error("SessionID should not be empty")
	}

	if session.Target != "192.168.1.1" {
		t.Errorf("Expected target '192.168.1.1', got '%s'", session.Target)
	}

	if session.ScanType != ScanTypeNmap {
		t.Errorf("Expected scan type '%s', got '%s'", ScanTypeNmap, session.ScanType)
	}

	if session.Status != StatusRunning {
		t.Errorf("Expected status '%s', got '%s'", StatusRunning, session.Status)
	}

	if session.Progress.Percentage != 0.0 {
		t.Errorf("Expected progress 0.0, got %f", session.Progress.Percentage)
	}
}

func TestSessionManager(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "zypheron-session-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create manager with custom directory
	manager := &SessionManager{
		sessionsDir: tmpDir,
	}

	// Create a new session
	session := NewSession("example.com", ScanTypeNuclei)
	session.AddChatMessage("user", "Start scan on example.com")
	session.AddChatMessage("assistant", "Starting nuclei scan...")

	// Save session
	if err := manager.Save(session); err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Load session
	loadedSession, err := manager.Load(session.SessionID)
	if err != nil {
		t.Fatalf("Failed to load session: %v", err)
	}

	// Verify loaded session
	if loadedSession.SessionID != session.SessionID {
		t.Errorf("SessionID mismatch: expected %s, got %s", session.SessionID, loadedSession.SessionID)
	}

	if loadedSession.Target != session.Target {
		t.Errorf("Target mismatch: expected %s, got %s", session.Target, loadedSession.Target)
	}

	if len(loadedSession.ChatHistory) != 2 {
		t.Errorf("Expected 2 chat messages, got %d", len(loadedSession.ChatHistory))
	}
}

func TestListSessions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zypheron-session-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	manager := &SessionManager{
		sessionsDir: tmpDir,
	}

	// Create multiple sessions
	session1 := NewSession("target1.com", ScanTypeNmap)
	session2 := NewSession("target2.com", ScanTypeNikto)
	session3 := NewSession("target3.com", ScanTypeNuclei)

	// Add some vulnerabilities to session1
	session1.AddVulnerability(Vulnerability{
		Title:    "SQL Injection",
		Severity: "critical",
	})
	session1.AddVulnerability(Vulnerability{
		Title:    "XSS",
		Severity: "high",
	})

	// Save all sessions
	manager.Save(session1)
	time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	manager.Save(session2)
	time.Sleep(10 * time.Millisecond)
	manager.Save(session3)

	// List sessions
	summaries, err := manager.ListSessions()
	if err != nil {
		t.Fatalf("Failed to list sessions: %v", err)
	}

	if len(summaries) != 3 {
		t.Errorf("Expected 3 sessions, got %d", len(summaries))
	}

	// Verify newest first (session3 should be first)
	if summaries[0].SessionID != session3.SessionID {
		t.Error("Sessions not sorted by newest first")
	}

	// Verify vulnerability counts for session1
	for _, summary := range summaries {
		if summary.SessionID == session1.SessionID {
			if summary.VulnCount != 2 {
				t.Errorf("Expected 2 vulnerabilities, got %d", summary.VulnCount)
			}
			if summary.CriticalCount != 1 {
				t.Errorf("Expected 1 critical vulnerability, got %d", summary.CriticalCount)
			}
			if summary.HighCount != 1 {
				t.Errorf("Expected 1 high vulnerability, got %d", summary.HighCount)
			}
		}
	}
}

func TestDeleteSession(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zypheron-session-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	manager := &SessionManager{
		sessionsDir: tmpDir,
	}

	session := NewSession("delete-test.com", ScanTypeNmap)
	manager.Save(session)

	// Verify session exists
	_, err = manager.Load(session.SessionID)
	if err != nil {
		t.Fatalf("Session should exist: %v", err)
	}

	// Delete session
	err = manager.DeleteSession(session.SessionID)
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}

	// Verify session is deleted
	_, err = manager.Load(session.SessionID)
	if err == nil {
		t.Error("Session should not exist after deletion")
	}
}

func TestSessionProgress(t *testing.T) {
	session := NewSession("progress-test.com", ScanTypeNmap)

	session.UpdateProgress(50.0, "vulnerability scanning", 5, 10)

	if session.Progress.Percentage != 50.0 {
		t.Errorf("Expected progress 50.0, got %f", session.Progress.Percentage)
	}

	if session.Progress.CurrentPhase != "vulnerability scanning" {
		t.Errorf("Expected phase 'vulnerability scanning', got '%s'", session.Progress.CurrentPhase)
	}

	if session.Progress.StepsCompleted != 5 {
		t.Errorf("Expected 5 steps completed, got %d", session.Progress.StepsCompleted)
	}

	if session.Progress.StepsTotal != 10 {
		t.Errorf("Expected 10 total steps, got %d", session.Progress.StepsTotal)
	}
}

func TestSessionStatus(t *testing.T) {
	session := NewSession("status-test.com", ScanTypeNmap)

	// Test initial status
	if session.Status != StatusRunning {
		t.Errorf("Expected initial status 'running', got '%s'", session.Status)
	}

	// Test pause
	session.Pause()
	if session.Status != StatusPaused {
		t.Errorf("Expected status 'paused', got '%s'", session.Status)
	}

	// Test resume
	session.Resume()
	if session.Status != StatusRunning {
		t.Errorf("Expected status 'running', got '%s'", session.Status)
	}

	// Test complete
	session.Complete()
	if session.Status != StatusCompleted {
		t.Errorf("Expected status 'completed', got '%s'", session.Status)
	}

	if session.EndTime.IsZero() {
		t.Error("EndTime should be set after completion")
	}

	if session.Progress.Percentage != 100.0 {
		t.Errorf("Expected progress 100.0 after completion, got %f", session.Progress.Percentage)
	}
}

func TestSessionChatHistory(t *testing.T) {
	session := NewSession("chat-test.com", ScanTypeNmap)

	session.AddChatMessage("user", "Scan this target")
	session.AddChatMessage("assistant", "Starting scan...")
	session.AddChatMessage("system", "Scan completed")

	if len(session.ChatHistory) != 3 {
		t.Errorf("Expected 3 chat messages, got %d", len(session.ChatHistory))
	}

	if session.ChatHistory[0].Role != "user" {
		t.Errorf("Expected first message role 'user', got '%s'", session.ChatHistory[0].Role)
	}

	if session.ChatHistory[1].Content != "Starting scan..." {
		t.Errorf("Expected second message content 'Starting scan...', got '%s'", session.ChatHistory[1].Content)
	}
}

func TestSessionFindings(t *testing.T) {
	session := NewSession("findings-test.com", ScanTypeNmap)

	finding := Finding{
		Type:        "port",
		Title:       "Open Port 80",
		Description: "HTTP service detected",
		Severity:    "info",
	}

	session.AddFinding(finding)

	if len(session.Results.ParsedFindings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(session.Results.ParsedFindings))
	}

	addedFinding := session.Results.ParsedFindings[0]

	// Verify ID was generated
	if addedFinding.ID == "" {
		t.Error("Finding ID should be generated")
	}

	// Verify timestamp was set
	if addedFinding.Timestamp.IsZero() {
		t.Error("Finding timestamp should be set")
	}

	if addedFinding.Title != "Open Port 80" {
		t.Errorf("Expected title 'Open Port 80', got '%s'", addedFinding.Title)
	}
}

func TestSessionVulnerabilities(t *testing.T) {
	session := NewSession("vuln-test.com", ScanTypeNuclei)

	vuln := Vulnerability{
		CVEID:            "CVE-2024-1234",
		Title:            "Remote Code Execution",
		Description:      "Allows arbitrary code execution",
		Severity:         "critical",
		CVSSScore:        9.8,
		Port:             443,
		Service:          "https",
		ExploitAvailable: true,
		Remediation:      "Update to latest version",
		References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
	}

	session.AddVulnerability(vuln)

	if len(session.Results.Vulnerabilities) != 1 {
		t.Errorf("Expected 1 vulnerability, got %d", len(session.Results.Vulnerabilities))
	}

	addedVuln := session.Results.Vulnerabilities[0]

	// Verify ID was generated
	if addedVuln.ID == "" {
		t.Error("Vulnerability ID should be generated")
	}

	if addedVuln.CVSSScore != 9.8 {
		t.Errorf("Expected CVSS score 9.8, got %f", addedVuln.CVSSScore)
	}
}

func TestCleanupOldSessions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zypheron-session-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	manager := &SessionManager{
		sessionsDir: tmpDir,
	}

	// Create an old session (manually set old timestamp)
	oldSession := NewSession("old-target.com", ScanTypeNmap)
	oldSession.StartTime = time.Now().AddDate(0, 0, -35) // 35 days ago

	// Create a recent session
	recentSession := NewSession("recent-target.com", ScanTypeNmap)

	manager.Save(oldSession)
	manager.Save(recentSession)

	// Cleanup sessions older than 30 days
	err = manager.CleanupOldSessions(30)
	if err != nil {
		t.Fatalf("Failed to cleanup old sessions: %v", err)
	}

	// Verify old session is deleted
	_, err = manager.Load(oldSession.SessionID)
	if err == nil {
		t.Error("Old session should be deleted")
	}

	// Verify recent session still exists
	_, err = manager.Load(recentSession.SessionID)
	if err != nil {
		t.Errorf("Recent session should still exist: %v", err)
	}
}

func TestFindSessionsByTarget(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zypheron-session-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	manager := &SessionManager{
		sessionsDir: tmpDir,
	}

	// Create sessions with different targets
	session1 := NewSession("target.com", ScanTypeNmap)
	session2 := NewSession("target.com", ScanTypeNikto)
	session3 := NewSession("other-target.com", ScanTypeNmap)

	manager.Save(session1)
	manager.Save(session2)
	manager.Save(session3)

	// Find sessions for "target.com"
	matches, err := manager.FindSessionsByTarget("target.com")
	if err != nil {
		t.Fatalf("Failed to find sessions by target: %v", err)
	}

	if len(matches) != 2 {
		t.Errorf("Expected 2 sessions for 'target.com', got %d", len(matches))
	}
}

func TestFindSessionsByScanType(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zypheron-session-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	manager := &SessionManager{
		sessionsDir: tmpDir,
	}

	// Create sessions with different scan types
	session1 := NewSession("target1.com", ScanTypeNmap)
	session2 := NewSession("target2.com", ScanTypeNmap)
	session3 := NewSession("target3.com", ScanTypeNikto)

	manager.Save(session1)
	manager.Save(session2)
	manager.Save(session3)

	// Find nmap sessions
	matches, err := manager.FindSessionsByScanType(ScanTypeNmap)
	if err != nil {
		t.Fatalf("Failed to find sessions by scan type: %v", err)
	}

	if len(matches) != 2 {
		t.Errorf("Expected 2 nmap sessions, got %d", len(matches))
	}
}

func TestActiveSession(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zypheron-session-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	manager := &SessionManager{
		sessionsDir: tmpDir,
	}

	// Initially no active session
	_, err = manager.GetActiveSession()
	if err == nil {
		t.Error("Should return error when no active session")
	}

	// Set active session
	session := NewSession("active-test.com", ScanTypeNmap)
	manager.SetActiveSession(session)

	// Get active session
	activeSession, err := manager.GetActiveSession()
	if err != nil {
		t.Fatalf("Failed to get active session: %v", err)
	}

	if activeSession.SessionID != session.SessionID {
		t.Errorf("Active session ID mismatch: expected %s, got %s", session.SessionID, activeSession.SessionID)
	}

	// Clear active session
	manager.ClearActiveSession()

	_, err = manager.GetActiveSession()
	if err == nil {
		t.Error("Should return error after clearing active session")
	}
}

func TestSessionMetadata(t *testing.T) {
	session := NewSession("metadata-test.com", ScanTypeNmap)

	session.SetMetadata("scan_duration", 120.5)
	session.SetMetadata("tool_version", "7.94")
	session.SetEnvironmentInfo("os", "Kali Linux")
	session.SetEnvironmentInfo("kernel", "6.1.0")

	if len(session.Results.Metadata) != 2 {
		t.Errorf("Expected 2 metadata entries, got %d", len(session.Results.Metadata))
	}

	if len(session.Environment) != 2 {
		t.Errorf("Expected 2 environment entries, got %d", len(session.Environment))
	}

	if session.Results.Metadata["tool_version"] != "7.94" {
		t.Errorf("Expected tool_version '7.94', got '%v'", session.Results.Metadata["tool_version"])
	}
}

func TestSessionTags(t *testing.T) {
	session := NewSession("tags-test.com", ScanTypeNmap)

	session.AddTag("production")
	session.AddTag("high-priority")
	session.AddTag("production") // Duplicate

	if len(session.Tags) != 2 {
		t.Errorf("Expected 2 unique tags, got %d", len(session.Tags))
	}
}

func TestSessionDuration(t *testing.T) {
	session := NewSession("duration-test.com", ScanTypeNmap)

	// Active session - should return time since start
	time.Sleep(100 * time.Millisecond)
	duration := session.GetDuration()
	if duration < 100*time.Millisecond {
		t.Error("Duration should be at least 100ms")
	}

	// Completed session - should return end-start time
	session.Complete()
	duration = session.GetDuration()
	if duration < 100*time.Millisecond {
		t.Error("Duration should be preserved after completion")
	}
}

func TestSessionIsActive(t *testing.T) {
	session := NewSession("active-test.com", ScanTypeNmap)

	if !session.IsActive() {
		t.Error("New session should be active")
	}

	session.Pause()
	if !session.IsActive() {
		t.Error("Paused session should be considered active")
	}

	session.Complete()
	if session.IsActive() {
		t.Error("Completed session should not be active")
	}
}

func TestAutoSave(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zypheron-session-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	manager := &SessionManager{
		sessionsDir: tmpDir,
	}

	session := NewSession("autosave-test.com", ScanTypeNmap)

	// Initial save
	manager.Save(session)

	// Verify file exists
	sessionFile := filepath.Join(tmpDir, session.SessionID+".json")
	if _, err := os.Stat(sessionFile); os.IsNotExist(err) {
		t.Error("Session file should exist after save")
	}

	// Test that StopAutoSave doesn't panic even if auto-save wasn't started
	session.StopAutoSave()
}
