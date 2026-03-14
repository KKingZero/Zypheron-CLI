package session

import (
	"fmt"
	"time"
)

// ExampleBasicUsage demonstrates basic session management
func ExampleBasicUsage() {
	// Create a new session manager
	manager, err := NewSessionManager()
	if err != nil {
		panic(err)
	}

	// Create a new session
	session := NewSession("192.168.1.1", ScanTypeNmap)

	// Add some chat history
	session.AddChatMessage("user", "Scan 192.168.1.1 for open ports")
	session.AddChatMessage("assistant", "Starting Nmap scan on 192.168.1.1...")

	// Update progress
	session.UpdateProgress(25.0, "port discovery", 1, 4)

	// Add a finding
	session.AddFinding(Finding{
		Type:        "port",
		Title:       "Open Port 22",
		Description: "SSH service detected",
		Severity:    "info",
		Details: map[string]interface{}{
			"port":    22,
			"service": "ssh",
			"version": "OpenSSH 8.9",
		},
	})

	// Add a vulnerability
	session.AddVulnerability(Vulnerability{
		CVEID:            "CVE-2024-1234",
		Title:            "SSH Weak Encryption",
		Description:      "Server supports weak encryption algorithms",
		Severity:         "medium",
		CVSSScore:        5.3,
		Port:             22,
		Service:          "ssh",
		ExploitAvailable: false,
		Remediation:      "Update SSH configuration to disable weak ciphers",
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
		},
	})

	// Save session
	if err := manager.Save(session); err != nil {
		panic(err)
	}

	// Set as active session
	manager.SetActiveSession(session)

	// Later, load the session
	loadedSession, err := manager.Load(session.SessionID)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Loaded session: %s\n", loadedSession.SessionID)
	fmt.Printf("Target: %s\n", loadedSession.Target)
	fmt.Printf("Status: %s\n", loadedSession.Status)
	fmt.Printf("Progress: %.1f%%\n", loadedSession.Progress.Percentage)
}

// ExampleAutoSave demonstrates automatic session saving
func ExampleAutoSave() {
	manager, _ := NewSessionManager()

	// Create a new session
	session := NewSession("example.com", ScanTypeNuclei)

	// Start auto-save (saves every 30 seconds)
	session.StartAutoSave(manager)
	defer session.StopAutoSave()

	// Simulate scan work
	for i := 0; i <= 100; i += 10 {
		time.Sleep(1 * time.Second)

		session.UpdateProgress(float64(i), "scanning", i/10, 10)
		session.AppendRawOutput(fmt.Sprintf("Progress: %d%%\n", i))

		// Session is automatically saved every 30 seconds
	}

	// Mark as complete
	session.Complete()

	// Final save
	manager.Save(session)
}

// ExampleResumeSession demonstrates resuming a paused session
func ExampleResumeSession() {
	manager, _ := NewSessionManager()

	// Load an existing session
	sessionID := "some-session-id"
	session, err := manager.Load(sessionID)
	if err != nil {
		panic(err)
	}

	// Check if session can be resumed
	if session.Status == StatusPaused {
		// Resume the session
		session.Resume()
		manager.SetActiveSession(session)

		fmt.Printf("Resumed session %s\n", session.SessionID)
		fmt.Printf("Previous progress: %.1f%%\n", session.Progress.Percentage)

		// Continue scan from where it left off
		session.AddChatMessage("system", "Session resumed")

		// Continue work...
		session.UpdateProgress(75.0, "exploitation", 3, 4)

		// Save updated state
		manager.Save(session)
	}
}

// ExampleListAndFilter demonstrates listing and filtering sessions
func ExampleListAndFilter() {
	manager, _ := NewSessionManager()

	// List all sessions
	allSessions, err := manager.ListSessions()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Total sessions: %d\n\n", len(allSessions))

	// Display recent sessions
	fmt.Println("Recent Sessions:")
	for i, summary := range allSessions {
		if i >= 10 {
			break // Show only 10 most recent
		}

		fmt.Printf("ID: %s\n", summary.SessionID)
		fmt.Printf("  Target: %s\n", summary.Target)
		fmt.Printf("  Type: %s\n", summary.ScanType)
		fmt.Printf("  Status: %s\n", summary.Status)
		fmt.Printf("  Vulnerabilities: %d (Critical: %d, High: %d)\n",
			summary.VulnCount, summary.CriticalCount, summary.HighCount)
		fmt.Printf("  Started: %s\n", summary.StartTime.Format(time.RFC3339))
		fmt.Println()
	}

	// Find sessions for specific target
	targetSessions, err := manager.FindSessionsByTarget("example.com")
	if err != nil {
		panic(err)
	}

	fmt.Printf("\nSessions for example.com: %d\n", len(targetSessions))

	// Find sessions by scan type
	nmapSessions, err := manager.FindSessionsByScanType(ScanTypeNmap)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Nmap sessions: %d\n", len(nmapSessions))
}

// ExampleCleanup demonstrates cleaning up old sessions
func ExampleCleanup() {
	manager, _ := NewSessionManager()

	// Cleanup sessions older than 30 days
	maxDays := 30
	err := manager.CleanupOldSessions(maxDays)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Cleaned up sessions older than %d days\n", maxDays)
}

// ExampleCompleteWorkflow demonstrates a complete scanning workflow
func ExampleCompleteWorkflow() {
	// Initialize manager
	manager, err := NewSessionManager()
	if err != nil {
		panic(err)
	}

	// Create new session
	target := "scanme.nmap.org"
	session := NewSession(target, ScanTypeNmap)

	// Set environment info
	session.SetEnvironmentInfo("os", "Kali Linux 2024.1")
	session.SetEnvironmentInfo("nmap_version", "7.94")

	// Add tags
	session.AddTag("public-scan")
	session.AddTag("practice")

	// Start auto-save
	session.StartAutoSave(manager)
	defer session.StopAutoSave()

	// Set as active session
	manager.SetActiveSession(session)
	defer manager.ClearActiveSession()

	// Phase 1: Port Discovery
	session.UpdateProgress(0, "port discovery", 0, 4)
	session.AddChatMessage("assistant", "Starting port discovery scan...")

	// Simulate port scan
	session.AppendRawOutput("Starting Nmap 7.94\n")
	session.AppendRawOutput("Scanning scanme.nmap.org [1000 ports]\n")

	session.AddFinding(Finding{
		Type:        "port",
		Title:       "Open Port 22",
		Description: "SSH service running",
		Severity:    "info",
		Details: map[string]interface{}{
			"port":    22,
			"service": "ssh",
			"state":   "open",
		},
	})

	session.UpdateProgress(25, "port discovery", 1, 4)

	// Phase 2: Service Detection
	session.UpdateProgress(25, "service detection", 1, 4)
	session.AddChatMessage("assistant", "Detecting services and versions...")

	session.AppendRawOutput("PORT   STATE SERVICE VERSION\n")
	session.AppendRawOutput("22/tcp open  ssh     OpenSSH 8.9\n")

	session.UpdateProgress(50, "service detection", 2, 4)

	// Phase 3: Vulnerability Scanning
	session.UpdateProgress(50, "vulnerability scanning", 2, 4)
	session.AddChatMessage("assistant", "Scanning for known vulnerabilities...")

	session.AddVulnerability(Vulnerability{
		Title:       "Outdated OpenSSH Version",
		Description: "Server running outdated OpenSSH version with known vulnerabilities",
		Severity:    "medium",
		CVSSScore:   5.3,
		Port:        22,
		Service:     "ssh",
		Remediation: "Update OpenSSH to latest stable version",
	})

	session.UpdateProgress(75, "vulnerability scanning", 3, 4)

	// Phase 4: Analysis
	session.UpdateProgress(75, "AI analysis", 3, 4)
	session.AddChatMessage("assistant", "Analyzing results with AI...")

	session.SetAIAnalysis("The target has limited attack surface with only SSH exposed. " +
		"The detected SSH version has a medium severity vulnerability. " +
		"Recommend updating to the latest version and implementing key-based authentication.")

	session.SetSummary("Scan completed successfully. Found 1 open port with 1 medium severity vulnerability.")

	// Complete the session
	session.Complete()
	session.AddChatMessage("assistant", "Scan completed successfully!")

	// Final save
	if err := manager.Save(session); err != nil {
		panic(err)
	}

	// Display summary
	fmt.Printf("Session ID: %s\n", session.SessionID)
	fmt.Printf("Target: %s\n", session.Target)
	fmt.Printf("Duration: %s\n", session.GetDuration())
	fmt.Printf("Status: %s\n", session.Status)
	fmt.Printf("Findings: %d\n", len(session.Results.ParsedFindings))
	fmt.Printf("Vulnerabilities: %d\n", len(session.Results.Vulnerabilities))
	fmt.Printf("Chat Messages: %d\n", len(session.ChatHistory))
}

// ExampleErrorHandling demonstrates proper error handling
func ExampleErrorHandling() {
	manager, err := NewSessionManager()
	if err != nil {
		fmt.Printf("Failed to create manager: %v\n", err)
		return
	}

	// Try to load non-existent session
	_, err = manager.Load("non-existent-id")
	if err != nil {
		fmt.Printf("Expected error: %v\n", err)
	}

	// Try to get active session when none is set
	_, err = manager.GetActiveSession()
	if err != nil {
		fmt.Printf("Expected error: %v\n", err)
	}

	// Try to delete non-existent session
	err = manager.DeleteSession("non-existent-id")
	if err != nil {
		fmt.Printf("Expected error: %v\n", err)
	}
}

// ExampleMultipleActiveSessions demonstrates handling multiple sessions
func ExampleMultipleActiveSessions() {
	manager, _ := NewSessionManager()

	// Create multiple sessions (e.g., for different targets)
	session1 := NewSession("target1.com", ScanTypeNmap)
	session2 := NewSession("target2.com", ScanTypeNuclei)
	session3 := NewSession("target3.com", ScanTypeNikto)

	// Save all sessions
	manager.Save(session1)
	manager.Save(session2)
	manager.Save(session3)

	// Switch between sessions
	manager.SetActiveSession(session1)
	fmt.Printf("Active: %s\n", session1.Target)

	// Do some work on session1
	session1.UpdateProgress(50, "scanning", 5, 10)

	// Switch to session2
	manager.SetActiveSession(session2)
	fmt.Printf("Active: %s\n", session2.Target)

	// Do some work on session2
	session2.UpdateProgress(30, "reconnaissance", 3, 10)

	// Get current active session
	active, _ := manager.GetActiveSession()
	fmt.Printf("Currently active: %s\n", active.Target)
}

// ExampleSessionPersistence demonstrates session state persistence
func ExampleSessionPersistence() {
	manager, _ := NewSessionManager()

	// Create and configure a session
	session := NewSession("persistent-target.com", ScanTypeNmap)
	session.AddChatMessage("user", "Start comprehensive scan")
	session.UpdateProgress(30, "scanning", 3, 10)
	session.AddFinding(Finding{
		Type:     "port",
		Title:    "Open Port 80",
		Severity: "info",
	})

	// Save session
	sessionID := session.SessionID
	manager.Save(session)

	// Later (or in different process), load the session
	loadedSession, err := manager.Load(sessionID)
	if err != nil {
		panic(err)
	}

	// All state is preserved
	fmt.Printf("Progress: %.1f%%\n", loadedSession.Progress.Percentage)
	fmt.Printf("Phase: %s\n", loadedSession.Progress.CurrentPhase)
	fmt.Printf("Findings: %d\n", len(loadedSession.Results.ParsedFindings))
	fmt.Printf("Chat History: %d messages\n", len(loadedSession.ChatHistory))

	// Continue from where we left off
	loadedSession.UpdateProgress(60, "analysis", 6, 10)
	manager.Save(loadedSession)
}
