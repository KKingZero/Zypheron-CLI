// Package session provides comprehensive session management for Zypheron CLI.
//
// The session package enables saving, resuming, and managing scan sessions with
// full state persistence. It supports automatic saving, progress tracking, and
// maintains complete scan history including chat context, findings, and vulnerabilities.
//
// # Key Features
//
//   - Full state persistence to disk as JSON
//   - Auto-save every 30 seconds during active scans
//   - Resume interrupted or paused sessions
//   - Track scan progress with phases and percentages
//   - Store findings, vulnerabilities, and AI analysis
//   - Maintain chat history for AI conversation context
//   - Thread-safe concurrent operations
//   - Automatic cleanup of old sessions
//   - Active session tracking
//
// # Quick Start
//
// Basic usage:
//
//	manager, err := session.NewSessionManager()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	sess := session.NewSession("192.168.1.1", session.ScanTypeNmap)
//	sess.UpdateProgress(25.0, "port discovery", 1, 4)
//	manager.Save(sess)
//
// # Auto-Save
//
// Enable automatic session saving:
//
//	sess.StartAutoSave(manager)
//	defer sess.StopAutoSave()
//
//	// Session automatically saves every 30 seconds
//	// Continue with scan work...
//
// # Resume Session
//
// Load and resume an existing session:
//
//	sess, err := manager.Load(sessionID)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if sess.Status == session.StatusPaused {
//	    sess.Resume()
//	    manager.SetActiveSession(sess)
//	}
//
// # Storage
//
// Sessions are stored in ~/.zypheron/sessions/ as JSON files with 0600 permissions.
// Each session has a unique UUID as filename: {session-id}.json
//
// # Integration
//
// The session package integrates with Zypheron's configuration system:
//
//	cfg := config.Get()
//	if cfg.AutoSaveSession {
//	    sess.StartAutoSave(manager)
//	}
//	manager.CleanupOldSessions(cfg.MaxHistoryDays)
//
// # Thread Safety
//
// All operations are thread-safe. The Session type uses mutex locks to protect
// concurrent access to session state. Multiple goroutines can safely:
//
//   - Update session progress
//   - Add findings and vulnerabilities
//   - Append to chat history
//   - Save/load sessions concurrently
//
// # Session Lifecycle
//
// A typical session lifecycle:
//
//	1. Create: NewSession(target, scanType)
//	2. Configure: Set metadata, tags, environment info
//	3. Execute: Update progress, add findings, append output
//	4. Save: Auto-save or manual Save()
//	5. Complete: Call Complete() or Fail()
//	6. Persist: Final Save()
//
// # Example Workflow
//
//	manager, _ := session.NewSessionManager()
//	sess := session.NewSession("example.com", session.ScanTypeNmap)
//
//	sess.StartAutoSave(manager)
//	defer sess.StopAutoSave()
//
//	manager.SetActiveSession(sess)
//	defer manager.ClearActiveSession()
//
//	sess.AddChatMessage("user", "Scan this target")
//	sess.UpdateProgress(0, "initializing", 0, 4)
//
//	// Perform scan phases...
//	sess.AddFinding(session.Finding{
//	    Type:     "port",
//	    Title:    "Open Port 22",
//	    Severity: "info",
//	})
//
//	sess.Complete()
//	manager.Save(sess)
//
// For more examples, see example_usage.go and integration_example.go.
package session
