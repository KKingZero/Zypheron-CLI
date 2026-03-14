package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// MaxHistoryFileSize is the maximum size before rotation (10MB)
	MaxHistoryFileSize = 10 * 1024 * 1024
	// DefaultHistoryDir is the default directory for history storage
	DefaultHistoryDir = ".zypheron/history"
	// HistoryFileName is the name of the history file
	HistoryFileName = "history.json"
)

// ScanStatus represents the status of a scan
type ScanStatus string

const (
	StatusSuccess   ScanStatus = "success"
	StatusFailed    ScanStatus = "failed"
	StatusCancelled ScanStatus = "cancelled"
)

// HistoryEntry represents a single scan entry in the history
type HistoryEntry struct {
	ID            string     `json:"id"`
	Timestamp     time.Time  `json:"timestamp"`
	Target        string     `json:"target"`
	ScanType      string     `json:"scan_type"`
	Tool          string     `json:"tool"`
	Duration      int64      `json:"duration"` // Duration in milliseconds
	Status        ScanStatus `json:"status"`
	FindingsCount int        `json:"findings_count"`
	VulnCount     int        `json:"vuln_count"`
	SessionID     string     `json:"session_id"`
	Tags          []string   `json:"tags,omitempty"`
}

// HistoryStats contains aggregated statistics about scan history
type HistoryStats struct {
	TotalScans     int                `json:"total_scans"`
	TotalFindings  int                `json:"total_findings"`
	TotalVulns     int                `json:"total_vulns"`
	ScansByTool    map[string]int     `json:"scans_by_tool"`
	ScansByTarget  map[string]int     `json:"scans_by_target"`
	ScansByStatus  map[ScanStatus]int `json:"scans_by_status"`
	LastScanTime   *time.Time         `json:"last_scan_time,omitempty"`
	AvgDuration    int64              `json:"avg_duration"` // Average duration in milliseconds
	TotalDuration  int64              `json:"total_duration"`
	SuccessRate    float64            `json:"success_rate"`
}

// Manager handles the scan history operations
type Manager struct {
	historyPath string
	mutex       sync.RWMutex
}

// NewManager creates a new history manager
func NewManager() (*Manager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	historyDir := filepath.Join(homeDir, DefaultHistoryDir)
	if err := os.MkdirAll(historyDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create history directory: %w", err)
	}

	historyPath := filepath.Join(historyDir, HistoryFileName)

	return &Manager{
		historyPath: historyPath,
	}, nil
}

// NewManagerWithPath creates a new history manager with a custom path
func NewManagerWithPath(historyPath string) (*Manager, error) {
	historyDir := filepath.Dir(historyPath)
	if err := os.MkdirAll(historyDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create history directory: %w", err)
	}

	return &Manager{
		historyPath: historyPath,
	}, nil
}

// AddEntry adds a new entry to the history
func (m *Manager) AddEntry(entry *HistoryEntry) error {
	if entry == nil {
		return fmt.Errorf("entry cannot be nil")
	}

	// Validate entry
	if entry.ID == "" {
		return fmt.Errorf("entry ID cannot be empty")
	}
	if entry.Target == "" {
		return fmt.Errorf("entry target cannot be empty")
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if rotation is needed
	if err := m.rotateIfNeeded(); err != nil {
		return fmt.Errorf("failed to rotate history file: %w", err)
	}

	// Read existing entries
	entries, err := m.readEntriesUnsafe()
	if err != nil {
		return fmt.Errorf("failed to read existing entries: %w", err)
	}

	// Append new entry
	entries = append(entries, *entry)

	// Write back to file
	if err := m.writeEntriesUnsafe(entries); err != nil {
		return fmt.Errorf("failed to write entries: %w", err)
	}

	return nil
}

// GetHistory retrieves history entries with pagination
func (m *Manager) GetHistory(limit int, offset int) ([]HistoryEntry, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	entries, err := m.readEntriesUnsafe()
	if err != nil {
		return nil, fmt.Errorf("failed to read entries: %w", err)
	}

	// Sort by timestamp (newest first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})

	// Apply pagination
	start := offset
	if start >= len(entries) {
		return []HistoryEntry{}, nil
	}

	end := start + limit
	if end > len(entries) {
		end = len(entries)
	}

	if limit <= 0 {
		// Return all entries from offset
		return entries[start:], nil
	}

	return entries[start:end], nil
}

// GetHistoryByTarget retrieves all history entries for a specific target
func (m *Manager) GetHistoryByTarget(target string) ([]HistoryEntry, error) {
	if target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	entries, err := m.readEntriesUnsafe()
	if err != nil {
		return nil, fmt.Errorf("failed to read entries: %w", err)
	}

	// Filter by target
	var filtered []HistoryEntry
	for _, entry := range entries {
		if entry.Target == target {
			filtered = append(filtered, entry)
		}
	}

	// Sort by timestamp (newest first)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.After(filtered[j].Timestamp)
	})

	return filtered, nil
}

// GetHistoryByDateRange retrieves history entries within a date range
func (m *Manager) GetHistoryByDateRange(start, end time.Time) ([]HistoryEntry, error) {
	if start.After(end) {
		return nil, fmt.Errorf("start time cannot be after end time")
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	entries, err := m.readEntriesUnsafe()
	if err != nil {
		return nil, fmt.Errorf("failed to read entries: %w", err)
	}

	// Filter by date range
	var filtered []HistoryEntry
	for _, entry := range entries {
		if (entry.Timestamp.Equal(start) || entry.Timestamp.After(start)) &&
			(entry.Timestamp.Equal(end) || entry.Timestamp.Before(end)) {
			filtered = append(filtered, entry)
		}
	}

	// Sort by timestamp (newest first)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.After(filtered[j].Timestamp)
	})

	return filtered, nil
}

// SearchHistory searches history entries by query (searches in target, scan type, tool, tags)
func (m *Manager) SearchHistory(query string) ([]HistoryEntry, error) {
	if query == "" {
		return nil, fmt.Errorf("query cannot be empty")
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	entries, err := m.readEntriesUnsafe()
	if err != nil {
		return nil, fmt.Errorf("failed to read entries: %w", err)
	}

	// Convert query to lowercase for case-insensitive search
	queryLower := strings.ToLower(query)

	// Filter by query
	var filtered []HistoryEntry
	for _, entry := range entries {
		if m.matchesQuery(entry, queryLower) {
			filtered = append(filtered, entry)
		}
	}

	// Sort by timestamp (newest first)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.After(filtered[j].Timestamp)
	})

	return filtered, nil
}

// matchesQuery checks if an entry matches the search query
func (m *Manager) matchesQuery(entry HistoryEntry, queryLower string) bool {
	// Search in target
	if strings.Contains(strings.ToLower(entry.Target), queryLower) {
		return true
	}

	// Search in scan type
	if strings.Contains(strings.ToLower(entry.ScanType), queryLower) {
		return true
	}

	// Search in tool
	if strings.Contains(strings.ToLower(entry.Tool), queryLower) {
		return true
	}

	// Search in tags
	for _, tag := range entry.Tags {
		if strings.Contains(strings.ToLower(tag), queryLower) {
			return true
		}
	}

	// Search in session ID
	if strings.Contains(strings.ToLower(entry.SessionID), queryLower) {
		return true
	}

	// Search in status
	if strings.Contains(strings.ToLower(string(entry.Status)), queryLower) {
		return true
	}

	return false
}

// DeleteEntry deletes a specific entry by ID
func (m *Manager) DeleteEntry(id string) error {
	if id == "" {
		return fmt.Errorf("entry ID cannot be empty")
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	entries, err := m.readEntriesUnsafe()
	if err != nil {
		return fmt.Errorf("failed to read entries: %w", err)
	}

	// Filter out the entry to delete
	var filtered []HistoryEntry
	found := false
	for _, entry := range entries {
		if entry.ID != id {
			filtered = append(filtered, entry)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("entry with ID %s not found", id)
	}

	// Write back to file
	if err := m.writeEntriesUnsafe(filtered); err != nil {
		return fmt.Errorf("failed to write entries: %w", err)
	}

	return nil
}

// ClearHistory removes all history entries
func (m *Manager) ClearHistory() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Write empty array to file
	if err := m.writeEntriesUnsafe([]HistoryEntry{}); err != nil {
		return fmt.Errorf("failed to clear history: %w", err)
	}

	return nil
}

// GetStats computes and returns aggregated statistics
func (m *Manager) GetStats() (*HistoryStats, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	entries, err := m.readEntriesUnsafe()
	if err != nil {
		return nil, fmt.Errorf("failed to read entries: %w", err)
	}

	stats := &HistoryStats{
		ScansByTool:   make(map[string]int),
		ScansByTarget: make(map[string]int),
		ScansByStatus: make(map[ScanStatus]int),
	}

	if len(entries) == 0 {
		return stats, nil
	}

	var totalDuration int64
	var latestTime time.Time

	for _, entry := range entries {
		// Count totals
		stats.TotalScans++
		stats.TotalFindings += entry.FindingsCount
		stats.TotalVulns += entry.VulnCount
		totalDuration += entry.Duration

		// Count by tool
		stats.ScansByTool[entry.Tool]++

		// Count by target
		stats.ScansByTarget[entry.Target]++

		// Count by status
		stats.ScansByStatus[entry.Status]++

		// Track latest scan time
		if entry.Timestamp.After(latestTime) {
			latestTime = entry.Timestamp
		}
	}

	// Set last scan time
	if !latestTime.IsZero() {
		stats.LastScanTime = &latestTime
	}

	// Calculate average duration
	if stats.TotalScans > 0 {
		stats.AvgDuration = totalDuration / int64(stats.TotalScans)
	}
	stats.TotalDuration = totalDuration

	// Calculate success rate
	successCount := stats.ScansByStatus[StatusSuccess]
	if stats.TotalScans > 0 {
		stats.SuccessRate = float64(successCount) / float64(stats.TotalScans) * 100
	}

	return stats, nil
}

// readEntriesUnsafe reads all entries from the history file (not thread-safe, must hold lock)
func (m *Manager) readEntriesUnsafe() ([]HistoryEntry, error) {
	// Check if file exists
	if _, err := os.Stat(m.historyPath); os.IsNotExist(err) {
		return []HistoryEntry{}, nil
	}

	// Read file
	data, err := os.ReadFile(m.historyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read history file: %w", err)
	}

	// Handle empty file
	if len(data) == 0 {
		return []HistoryEntry{}, nil
	}

	// Parse JSON
	var entries []HistoryEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse history file: %w", err)
	}

	return entries, nil
}

// writeEntriesUnsafe writes all entries to the history file (not thread-safe, must hold lock)
func (m *Manager) writeEntriesUnsafe(entries []HistoryEntry) error {
	// Ensure entries is not nil
	if entries == nil {
		entries = []HistoryEntry{}
	}

	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal entries: %w", err)
	}

	// Write to file
	if err := os.WriteFile(m.historyPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write history file: %w", err)
	}

	return nil
}

// rotateIfNeeded rotates the history file if it exceeds the maximum size
func (m *Manager) rotateIfNeeded() error {
	// Check file size
	fileInfo, err := os.Stat(m.historyPath)
	if os.IsNotExist(err) {
		// File doesn't exist yet, no rotation needed
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to stat history file: %w", err)
	}

	// If file is under the limit, no rotation needed
	if fileInfo.Size() < MaxHistoryFileSize {
		return nil
	}

	// Read current entries
	entries, err := m.readEntriesUnsafe()
	if err != nil {
		return fmt.Errorf("failed to read entries for rotation: %w", err)
	}

	// Create backup file with timestamp
	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.%s.bak", m.historyPath, timestamp)

	// Rename current file to backup
	if err := os.Rename(m.historyPath, backupPath); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Keep only the most recent half of entries in the new file
	keepCount := len(entries) / 2
	if keepCount < 100 {
		// Always keep at least 100 entries if available
		keepCount = 100
		if keepCount > len(entries) {
			keepCount = len(entries)
		}
	}

	// Sort entries by timestamp (newest first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})

	// Keep the most recent entries
	recentEntries := entries[:keepCount]

	// Write the recent entries to the new file
	if err := m.writeEntriesUnsafe(recentEntries); err != nil {
		// If writing fails, try to restore the backup
		_ = os.Rename(backupPath, m.historyPath)
		return fmt.Errorf("failed to write rotated entries: %w", err)
	}

	return nil
}

// GetHistoryPath returns the path to the history file
func (m *Manager) GetHistoryPath() string {
	return m.historyPath
}

// ExportHistory exports history entries to a specified file path
func (m *Manager) ExportHistory(exportPath string) error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	entries, err := m.readEntriesUnsafe()
	if err != nil {
		return fmt.Errorf("failed to read entries: %w", err)
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal entries: %w", err)
	}

	// Write to export file
	if err := os.WriteFile(exportPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write export file: %w", err)
	}

	return nil
}

// ImportHistory imports history entries from a specified file path
func (m *Manager) ImportHistory(importPath string, merge bool) error {
	// Read import file
	data, err := os.ReadFile(importPath)
	if err != nil {
		return fmt.Errorf("failed to read import file: %w", err)
	}

	// Parse JSON
	var importedEntries []HistoryEntry
	if err := json.Unmarshal(data, &importedEntries); err != nil {
		return fmt.Errorf("failed to parse import file: %w", err)
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	var finalEntries []HistoryEntry

	if merge {
		// Read existing entries
		existingEntries, err := m.readEntriesUnsafe()
		if err != nil {
			return fmt.Errorf("failed to read existing entries: %w", err)
		}

		// Create a map to track existing IDs
		existingIDs := make(map[string]bool)
		for _, entry := range existingEntries {
			existingIDs[entry.ID] = true
		}

		// Merge: add only new entries
		finalEntries = existingEntries
		for _, entry := range importedEntries {
			if !existingIDs[entry.ID] {
				finalEntries = append(finalEntries, entry)
			}
		}
	} else {
		// Replace: use only imported entries
		finalEntries = importedEntries
	}

	// Write final entries
	if err := m.writeEntriesUnsafe(finalEntries); err != nil {
		return fmt.Errorf("failed to write imported entries: %w", err)
	}

	return nil
}
