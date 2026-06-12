package loot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Standard loot directory structure under ~/.zypheron/loot/<session-id>/
const (
	DirPorts       = "ports"
	DirServices    = "services"
	DirHosts       = "hosts"
	DirCreds       = "creds"
	DirVulns       = "vulns"
	DirFindings    = "findings"
	DirScreenshots = "screenshots"
	DirWeb         = "web"
	DirCloud       = "cloud"
	DirAD          = "ad"
	DirAttack      = "attack"
	DirReports     = "reports"
	DirRaw         = "raw"
)

var Subdirs = []string{
	DirPorts, DirServices, DirHosts, DirCreds, DirVulns,
	DirFindings, DirScreenshots, DirWeb, DirCloud, DirAD,
	DirAttack, DirReports, DirRaw,
}

// SessionMeta is written to session.json in the loot root.
type SessionMeta struct {
	SessionID string    `json:"session_id"`
	Target    string    `json:"target"`
	StartedAt time.Time `json:"started_at"`
	Mode      string    `json:"mode"`
	Provider  string    `json:"provider,omitempty"`
	Model     string    `json:"model,omitempty"`
	Status    string    `json:"status"`
}

// TimelineEntry is a single line in timeline.log (JSONL format).
type TimelineEntry struct {
	Timestamp time.Time `json:"ts"`
	Phase     string    `json:"phase"`
	Tool      string    `json:"tool,omitempty"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail,omitempty"`
	Status    string    `json:"status"`
}

// LootManager handles loot directory lifecycle for a session.
type LootManager struct {
	BaseDir    string // ~/.zypheron/loot
	SessionID  string
	SessionDir string // BaseDir/<session-id>
}

// BaseLootDir returns ~/.zypheron/loot
func BaseLootDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, ".zypheron", "loot")
}

// NewLootManager creates a loot manager for the given session.
// If sessionID is empty, one is generated from the timestamp.
func NewLootManager(sessionID string) *LootManager {
	if sessionID == "" {
		sessionID = fmt.Sprintf("session-%s", time.Now().Format("20060102-150405"))
	}
	base := BaseLootDir()
	return &LootManager{
		BaseDir:    base,
		SessionID:  sessionID,
		SessionDir: filepath.Join(base, sessionID),
	}
}

// Init creates the full directory tree and session.json.
func (lm *LootManager) Init(target, mode, provider, model string) error {
	// Create all subdirs
	for _, sub := range Subdirs {
		dir := filepath.Join(lm.SessionDir, sub)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create loot dir %s: %w", sub, err)
		}
	}

	// Write session.json
	meta := SessionMeta{
		SessionID: lm.SessionID,
		Target:    target,
		StartedAt: time.Now(),
		Mode:      mode,
		Provider:  provider,
		Model:     model,
		Status:    "in_progress",
	}
	return lm.writeJSON("session.json", meta)
}

// LogTimeline appends a JSONL entry to timeline.log.
func (lm *LootManager) LogTimeline(phase, tool, action, detail, status string) error {
	entry := TimelineEntry{
		Timestamp: time.Now(),
		Phase:     phase,
		Tool:      tool,
		Action:    action,
		Detail:    detail,
		Status:    status,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(
		filepath.Join(lm.SessionDir, "timeline.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600,
	)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(data, '\n'))
	return err
}

// SaveLoot writes data to the appropriate subdirectory.
func (lm *LootManager) SaveLoot(category, filename string, data []byte) error {
	path := filepath.Clean(filepath.Join(lm.SessionDir, category, filename))
	// SECURITY: Verify path stays within session directory
	if !strings.HasPrefix(path, lm.SessionDir+string(filepath.Separator)) {
		return fmt.Errorf("path traversal detected: %q resolves outside session directory", filename)
	}
	// SECURITY: Resolve symlinks and re-check containment
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to create loot dir: %w", err)
	}
	realPath, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}
	realSession, _ := filepath.EvalSymlinks(lm.SessionDir)
	if !strings.HasPrefix(realPath, realSession+string(filepath.Separator)) && realPath != realSession {
		return fmt.Errorf("symlink escape detected: %q resolves outside session directory", filename)
	}
	// SECURITY (M-09): open the final file with O_NOFOLLOW so a symlink swapped
	// in at the final component (after the EvalSymlinks recheck) is not followed
	// to a target outside the session directory. O_TRUNC preserves the previous
	// overwrite semantics of os.WriteFile.
	finalPath := filepath.Join(realPath, filepath.Base(path))
	f, err := os.OpenFile(finalPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|noFollowOpenFlag(), 0600)
	if err != nil {
		return fmt.Errorf("failed to open loot file: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("failed to write loot file: %w", err)
	}
	return nil
}

// SaveLootJSON marshals v to JSON and writes it.
func (lm *LootManager) SaveLootJSON(category, filename string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return lm.SaveLoot(category, filename, data)
}

// GetPath returns the full path for a loot file.
func (lm *LootManager) GetPath(category, filename string) string {
	return filepath.Join(lm.SessionDir, category, filename)
}

// Finalize marks the session as complete.
func (lm *LootManager) Finalize(status string) error {
	metaPath := filepath.Join(lm.SessionDir, "session.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return err
	}
	var meta SessionMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return err
	}
	meta.Status = status
	return lm.writeJSON("session.json", meta)
}

// ListSessions returns all session IDs in the loot directory.
func ListSessions() ([]string, error) {
	base := BaseLootDir()
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var sessions []string
	for _, e := range entries {
		if e.IsDir() {
			sessions = append(sessions, e.Name())
		}
	}
	return sessions, nil
}

func (lm *LootManager) writeJSON(filename string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(lm.SessionDir, filename), data, 0600)
}
