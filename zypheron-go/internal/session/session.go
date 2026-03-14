package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SessionStatus represents the current state of a session
type SessionStatus string

const (
	StatusRunning   SessionStatus = "running"
	StatusPaused    SessionStatus = "paused"
	StatusCompleted SessionStatus = "completed"
	StatusFailed    SessionStatus = "failed"
)

// ScanType represents different types of scans
type ScanType string

const (
	ScanTypeNmap       ScanType = "nmap"
	ScanTypeNikto      ScanType = "nikto"
	ScanTypeNuclei     ScanType = "nuclei"
	ScanTypeWPScan     ScanType = "wpscan"
	ScanTypeSQLMap     ScanType = "sqlmap"
	ScanTypeMetasploit ScanType = "metasploit"
	ScanTypeDirb       ScanType = "dirb"
	ScanTypeGobuster   ScanType = "gobuster"
	ScanTypeCustom     ScanType = "custom"
)

// ChatMessage represents a single message in the AI conversation
type ChatMessage struct {
	Timestamp time.Time `json:"timestamp"`
	Role      string    `json:"role"` // user, assistant, system
	Content   string    `json:"content"`
}

// ScanProgress tracks the progress of a scan session
type ScanProgress struct {
	Percentage     float64   `json:"percentage"`    // 0.0 to 100.0
	CurrentPhase   string    `json:"current_phase"` // e.g., "reconnaissance", "vulnerability scanning", "exploitation"
	StepsTotal     int       `json:"steps_total"`
	StepsCompleted int       `json:"steps_completed"`
	LastUpdate     time.Time `json:"last_update"`
}

// ScanResults holds the output and findings from a scan
type ScanResults struct {
	RawOutput       string                 `json:"raw_output"`
	ParsedFindings  []Finding              `json:"parsed_findings"`
	Vulnerabilities []Vulnerability        `json:"vulnerabilities"`
	Summary         string                 `json:"summary"`
	AIAnalysis      string                 `json:"ai_analysis,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// Finding represents a discovered item during scanning
type Finding struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // port, service, directory, vulnerability
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"` // info, low, medium, high, critical
	Timestamp   time.Time              `json:"timestamp"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID               string   `json:"id"`
	CVEID            string   `json:"cve_id,omitempty"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Severity         string   `json:"severity"`
	CVSSScore        float64  `json:"cvss_score,omitempty"`
	Port             int      `json:"port,omitempty"`
	Service          string   `json:"service,omitempty"`
	ExploitAvailable bool     `json:"exploit_available"`
	Remediation      string   `json:"remediation,omitempty"`
	References       []string `json:"references,omitempty"`
}

// Session represents a complete scan session
type Session struct {
	// Core identification
	SessionID string    `json:"session_id"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time,omitempty"`

	// Scan configuration
	Target   string   `json:"target"`
	ScanType ScanType `json:"scan_type"`

	// Status tracking
	Status   SessionStatus `json:"status"`
	Progress ScanProgress  `json:"progress"`

	// Results and data
	Results     ScanResults   `json:"results"`
	ChatHistory []ChatMessage `json:"chat_history"`

	// Metadata
	UserID      string                 `json:"user_id,omitempty"`
	ProjectID   string                 `json:"project_id,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Notes       string                 `json:"notes,omitempty"`
	Environment map[string]interface{} `json:"environment,omitempty"` // OS, tool versions, etc.

	// Internal tracking
	mu             sync.RWMutex `json:"-"`
	autoSaveTicker *time.Ticker `json:"-"`
	stopAutoSave   chan bool    `json:"-"`
}

// SessionSummary provides a brief overview of a session
type SessionSummary struct {
	SessionID       string        `json:"session_id"`
	StartTime       time.Time     `json:"start_time"`
	EndTime         time.Time     `json:"end_time,omitempty"`
	Target          string        `json:"target"`
	ScanType        ScanType      `json:"scan_type"`
	Status          SessionStatus `json:"status"`
	VulnCount       int           `json:"vuln_count"`
	CriticalCount   int           `json:"critical_count"`
	HighCount       int           `json:"high_count"`
	ProgressPercent float64       `json:"progress_percent"`
}

// SessionManager handles session persistence and lifecycle
type SessionManager struct {
	sessionsDir   string
	mu            sync.RWMutex
	activeSession *Session
}

// NewSessionManager creates a new session manager instance
func NewSessionManager() (*SessionManager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	sessionsDir := filepath.Join(homeDir, ".zypheron", "sessions")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(sessionsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create sessions directory: %w", err)
	}

	return &SessionManager{
		sessionsDir: sessionsDir,
	}, nil
}

// NewSession creates a new scan session
func NewSession(target string, scanType ScanType) *Session {
	now := time.Now()

	session := &Session{
		SessionID: uuid.New().String(),
		StartTime: now,
		Target:    target,
		ScanType:  scanType,
		Status:    StatusRunning,
		Progress: ScanProgress{
			Percentage:   0.0,
			CurrentPhase: "initializing",
			LastUpdate:   now,
		},
		Results: ScanResults{
			ParsedFindings:  []Finding{},
			Vulnerabilities: []Vulnerability{},
			Metadata:        make(map[string]interface{}),
		},
		ChatHistory:  []ChatMessage{},
		Tags:         []string{},
		Environment:  make(map[string]interface{}),
		stopAutoSave: make(chan bool),
	}

	return session
}

// Save persists a session to disk
func (sm *SessionManager) Save(session *Session) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}

	session.mu.RLock()
	defer session.mu.RUnlock()

	filename := fmt.Sprintf("%s.json", session.SessionID)
	filepath := filepath.Join(sm.sessionsDir, filename)

	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	if err := os.WriteFile(filepath, data, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	return nil
}

// Load retrieves a session from disk
func (sm *SessionManager) Load(sessionID string) (*Session, error) {
	filename := fmt.Sprintf("%s.json", sessionID)
	filepath := filepath.Join(sm.sessionsDir, filename)

	data, err := os.ReadFile(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("session not found: %s", sessionID)
		}
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	// Initialize runtime fields
	session.stopAutoSave = make(chan bool)

	return &session, nil
}

// ListSessions returns all sessions, newest first
func (sm *SessionManager) ListSessions() ([]SessionSummary, error) {
	files, err := os.ReadDir(sm.sessionsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read sessions directory: %w", err)
	}

	var summaries []SessionSummary

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		sessionID := file.Name()[:len(file.Name())-5] // Remove .json extension
		session, err := sm.Load(sessionID)
		if err != nil {
			// Skip invalid session files
			continue
		}

		// Count vulnerabilities by severity
		criticalCount := 0
		highCount := 0
		for _, vuln := range session.Results.Vulnerabilities {
			switch vuln.Severity {
			case "critical":
				criticalCount++
			case "high":
				highCount++
			}
		}

		summary := SessionSummary{
			SessionID:       session.SessionID,
			StartTime:       session.StartTime,
			EndTime:         session.EndTime,
			Target:          session.Target,
			ScanType:        session.ScanType,
			Status:          session.Status,
			VulnCount:       len(session.Results.Vulnerabilities),
			CriticalCount:   criticalCount,
			HighCount:       highCount,
			ProgressPercent: session.Progress.Percentage,
		}

		summaries = append(summaries, summary)
	}

	// Sort by start time, newest first
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].StartTime.After(summaries[j].StartTime)
	})

	return summaries, nil
}

// DeleteSession removes a session from storage
func (sm *SessionManager) DeleteSession(sessionID string) error {
	filename := fmt.Sprintf("%s.json", sessionID)
	filepath := filepath.Join(sm.sessionsDir, filename)

	if err := os.Remove(filepath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("session not found: %s", sessionID)
		}
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}

// GetActiveSession returns the currently active session
func (sm *SessionManager) GetActiveSession() (*Session, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.activeSession == nil {
		return nil, fmt.Errorf("no active session")
	}

	return sm.activeSession, nil
}

// SetActiveSession sets the currently active session
func (sm *SessionManager) SetActiveSession(session *Session) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Stop auto-save on previous session if exists
	if sm.activeSession != nil {
		sm.activeSession.StopAutoSave()
	}

	sm.activeSession = session
}

// ClearActiveSession clears the currently active session
func (sm *SessionManager) ClearActiveSession() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.activeSession != nil {
		sm.activeSession.StopAutoSave()
	}

	sm.activeSession = nil
}

// CleanupOldSessions removes sessions older than maxDays
func (sm *SessionManager) CleanupOldSessions(maxDays int) error {
	if maxDays <= 0 {
		return fmt.Errorf("maxDays must be positive")
	}

	cutoffTime := time.Now().AddDate(0, 0, -maxDays)

	files, err := os.ReadDir(sm.sessionsDir)
	if err != nil {
		return fmt.Errorf("failed to read sessions directory: %w", err)
	}

	deletedCount := 0

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		sessionID := file.Name()[:len(file.Name())-5]
		session, err := sm.Load(sessionID)
		if err != nil {
			continue
		}

		// Delete if session is older than cutoff
		if session.StartTime.Before(cutoffTime) {
			if err := sm.DeleteSession(sessionID); err == nil {
				deletedCount++
			}
		}
	}

	return nil
}

// FindSessionsByTarget finds all sessions for a specific target
func (sm *SessionManager) FindSessionsByTarget(target string) ([]SessionSummary, error) {
	summaries, err := sm.ListSessions()
	if err != nil {
		return nil, err
	}

	var matches []SessionSummary
	for _, summary := range summaries {
		if summary.Target == target {
			matches = append(matches, summary)
		}
	}

	return matches, nil
}

// FindSessionsByScanType finds all sessions of a specific scan type
func (sm *SessionManager) FindSessionsByScanType(scanType ScanType) ([]SessionSummary, error) {
	summaries, err := sm.ListSessions()
	if err != nil {
		return nil, err
	}

	var matches []SessionSummary
	for _, summary := range summaries {
		if summary.ScanType == scanType {
			matches = append(matches, summary)
		}
	}

	return matches, nil
}

// Session Methods

// StartAutoSave begins automatic session saving every 30 seconds
func (s *Session) StartAutoSave(manager *SessionManager) {
	s.mu.Lock()

	// Stop existing auto-save if running
	if s.autoSaveTicker != nil {
		s.autoSaveTicker.Stop()
	}

	// Create new ticker and capture references for safe goroutine access
	ticker := time.NewTicker(30 * time.Second)
	s.autoSaveTicker = ticker
	stopChan := s.stopAutoSave

	// Release lock BEFORE spawning goroutine to prevent deadlock
	s.mu.Unlock()

	go func() {
		// Panic recovery to prevent goroutine leak on crashes
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "auto-save panic recovered: %v\n", r)
			}
		}()

		for {
			select {
			case <-ticker.C: // Use captured reference, not s.autoSaveTicker
				if err := manager.Save(s); err != nil {
					// Log error but don't stop auto-save
					fmt.Fprintf(os.Stderr, "auto-save failed: %v\n", err)
				}
			case <-stopChan: // Use captured reference, not s.stopAutoSave
				return
			}
		}
	}()
}

// StopAutoSave stops the automatic session saving
func (s *Session) StopAutoSave() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.autoSaveTicker != nil {
		s.autoSaveTicker.Stop()
		s.autoSaveTicker = nil
	}

	select {
	case s.stopAutoSave <- true:
	default:
	}
}

// UpdateProgress updates the session's progress information
func (s *Session) UpdateProgress(percentage float64, phase string, stepsCompleted, stepsTotal int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Progress.Percentage = percentage
	s.Progress.CurrentPhase = phase
	s.Progress.StepsCompleted = stepsCompleted
	s.Progress.StepsTotal = stepsTotal
	s.Progress.LastUpdate = time.Now()
}

// UpdateStatus updates the session status
func (s *Session) UpdateStatus(status SessionStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Status = status

	if status == StatusCompleted || status == StatusFailed {
		s.EndTime = time.Now()
	}
}

// AddChatMessage adds a message to the chat history
func (s *Session) AddChatMessage(role, content string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	message := ChatMessage{
		Timestamp: time.Now(),
		Role:      role,
		Content:   content,
	}

	s.ChatHistory = append(s.ChatHistory, message)
}

// AddFinding adds a finding to the session results
func (s *Session) AddFinding(finding Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if finding.ID == "" {
		finding.ID = uuid.New().String()
	}

	if finding.Timestamp.IsZero() {
		finding.Timestamp = time.Now()
	}

	s.Results.ParsedFindings = append(s.Results.ParsedFindings, finding)
}

// AddVulnerability adds a vulnerability to the session results
func (s *Session) AddVulnerability(vuln Vulnerability) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if vuln.ID == "" {
		vuln.ID = uuid.New().String()
	}

	s.Results.Vulnerabilities = append(s.Results.Vulnerabilities, vuln)
}

// AppendRawOutput appends output to the session's raw output
func (s *Session) AppendRawOutput(output string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Results.RawOutput += output
}

// SetAIAnalysis sets the AI analysis for the session
func (s *Session) SetAIAnalysis(analysis string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Results.AIAnalysis = analysis
}

// SetSummary sets the summary for the session
func (s *Session) SetSummary(summary string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Results.Summary = summary
}

// AddTag adds a tag to the session
func (s *Session) AddTag(tag string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if tag already exists
	for _, existingTag := range s.Tags {
		if existingTag == tag {
			return
		}
	}

	s.Tags = append(s.Tags, tag)
}

// SetMetadata sets a metadata key-value pair
func (s *Session) SetMetadata(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Results.Metadata == nil {
		s.Results.Metadata = make(map[string]interface{})
	}

	s.Results.Metadata[key] = value
}

// SetEnvironmentInfo sets environment information
func (s *Session) SetEnvironmentInfo(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Environment == nil {
		s.Environment = make(map[string]interface{})
	}

	s.Environment[key] = value
}

// GetDuration returns the duration of the session
func (s *Session) GetDuration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.EndTime.IsZero() {
		return time.Since(s.StartTime)
	}

	return s.EndTime.Sub(s.StartTime)
}

// IsActive returns whether the session is currently active (running or paused)
func (s *Session) IsActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.Status == StatusRunning || s.Status == StatusPaused
}

// Pause pauses the session
func (s *Session) Pause() {
	s.UpdateStatus(StatusPaused)
}

// Resume resumes a paused session
func (s *Session) Resume() {
	s.UpdateStatus(StatusRunning)
}

// Complete marks the session as completed
func (s *Session) Complete() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Status = StatusCompleted
	s.EndTime = time.Now()
	s.Progress.Percentage = 100.0
}

// Fail marks the session as failed
func (s *Session) Fail() {
	s.UpdateStatus(StatusFailed)
}
