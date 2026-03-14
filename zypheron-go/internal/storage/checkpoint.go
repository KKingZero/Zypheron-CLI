package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CheckpointStatus represents the status of a scan checkpoint
type CheckpointStatus string

const (
	CheckpointStatusRunning   CheckpointStatus = "running"
	CheckpointStatusPaused    CheckpointStatus = "paused"
	CheckpointStatusCompleted CheckpointStatus = "completed"
	CheckpointStatusFailed    CheckpointStatus = "failed"
)

// ScanCheckpoint represents the state of an interrupted/resumable scan
type ScanCheckpoint struct {
	ID            string            `json:"id"`
	Target        string            `json:"target"`
	Tool          string            `json:"tool"`
	Ports         string            `json:"ports"`
	Args          []string          `json:"args"`
	StartTime     time.Time         `json:"start_time"`
	LastUpdate    time.Time         `json:"last_update"`
	Status        CheckpointStatus  `json:"status"`
	Progress      float64           `json:"progress"`       // 0-100 percentage
	PartialOutput string            `json:"partial_output"` // Output captured so far
	BytesRead     int64             `json:"bytes_read"`     // For tracking large outputs
	Metadata      map[string]string `json:"metadata"`

	// Tool-specific resume data
	NmapResumeFile string `json:"nmap_resume_file,omitempty"` // Path to nmap's .gnmap file for --resume
}

// CheckpointStorage manages persistent storage of scan checkpoints
type CheckpointStorage struct {
	storageDir string
}

// NewCheckpointStorage creates a new checkpoint storage instance
func NewCheckpointStorage() (*CheckpointStorage, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	storageDir := filepath.Join(homeDir, ".zypheron", "checkpoints")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create checkpoint directory: %w", err)
	}

	return &CheckpointStorage{
		storageDir: storageDir,
	}, nil
}

// SaveCheckpoint saves a checkpoint to disk
func (c *CheckpointStorage) SaveCheckpoint(checkpoint *ScanCheckpoint) error {
	if checkpoint.ID == "" {
		return fmt.Errorf("checkpoint ID cannot be empty")
	}

	// Update last modified time
	checkpoint.LastUpdate = time.Now()

	filename := fmt.Sprintf("%s.json", checkpoint.ID)
	path := filepath.Join(c.storageDir, filename)

	data, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %w", err)
	}

	// Write atomically by writing to temp file first
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write checkpoint file: %w", err)
	}

	// Rename to final location (atomic on most filesystems)
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath) // Clean up temp file
		return fmt.Errorf("failed to finalize checkpoint file: %w", err)
	}

	return nil
}

// LoadCheckpoint loads a checkpoint from disk
func (c *CheckpointStorage) LoadCheckpoint(checkpointID string) (*ScanCheckpoint, error) {
	filename := fmt.Sprintf("%s.json", checkpointID)
	path := filepath.Join(c.storageDir, filename)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("checkpoint not found: %s", checkpointID)
		}
		return nil, fmt.Errorf("failed to read checkpoint file: %w", err)
	}

	var checkpoint ScanCheckpoint
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		return nil, fmt.Errorf("failed to unmarshal checkpoint: %w", err)
	}

	return &checkpoint, nil
}

// ListCheckpoints lists all saved checkpoints, newest first
func (c *CheckpointStorage) ListCheckpoints() ([]ScanCheckpoint, error) {
	files, err := os.ReadDir(c.storageDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []ScanCheckpoint{}, nil
		}
		return nil, fmt.Errorf("failed to read checkpoint directory: %w", err)
	}

	var checkpoints []ScanCheckpoint

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		checkpointID := strings.TrimSuffix(file.Name(), ".json")
		checkpoint, err := c.LoadCheckpoint(checkpointID)
		if err != nil {
			// Skip invalid checkpoint files
			continue
		}

		checkpoints = append(checkpoints, *checkpoint)
	}

	// Sort by last update time, newest first
	sort.Slice(checkpoints, func(i, j int) bool {
		return checkpoints[i].LastUpdate.After(checkpoints[j].LastUpdate)
	})

	return checkpoints, nil
}

// GetResumableCheckpoints returns checkpoints that can be resumed (running or paused)
func (c *CheckpointStorage) GetResumableCheckpoints() ([]ScanCheckpoint, error) {
	all, err := c.ListCheckpoints()
	if err != nil {
		return nil, err
	}

	var resumable []ScanCheckpoint
	for _, cp := range all {
		if cp.Status == CheckpointStatusRunning || cp.Status == CheckpointStatusPaused {
			resumable = append(resumable, cp)
		}
	}

	return resumable, nil
}

// FindCheckpointForTarget finds an existing resumable checkpoint for a target
func (c *CheckpointStorage) FindCheckpointForTarget(target, tool string) (*ScanCheckpoint, error) {
	resumable, err := c.GetResumableCheckpoints()
	if err != nil {
		return nil, err
	}

	for _, cp := range resumable {
		if cp.Target == target && cp.Tool == tool {
			return &cp, nil
		}
	}

	return nil, nil // No matching checkpoint found
}

// DeleteCheckpoint deletes a checkpoint from storage
func (c *CheckpointStorage) DeleteCheckpoint(checkpointID string) error {
	filename := fmt.Sprintf("%s.json", checkpointID)
	path := filepath.Join(c.storageDir, filename)

	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("checkpoint not found: %s", checkpointID)
		}
		return fmt.Errorf("failed to delete checkpoint: %w", err)
	}

	return nil
}

// CleanupOldCheckpoints removes completed/failed checkpoints older than the specified duration
func (c *CheckpointStorage) CleanupOldCheckpoints(maxAge time.Duration) (int, error) {
	checkpoints, err := c.ListCheckpoints()
	if err != nil {
		return 0, err
	}

	cutoff := time.Now().Add(-maxAge)
	cleaned := 0

	for _, cp := range checkpoints {
		// Only clean up completed or failed checkpoints
		if cp.Status != CheckpointStatusCompleted && cp.Status != CheckpointStatusFailed {
			continue
		}

		if cp.LastUpdate.Before(cutoff) {
			if err := c.DeleteCheckpoint(cp.ID); err == nil {
				cleaned++
			}
		}
	}

	return cleaned, nil
}

// GenerateCheckpointID generates a unique checkpoint ID
func GenerateCheckpointID(target, tool string) string {
	timestamp := time.Now().Format("20060102-150405")
	// SECURITY: Sanitize target for filename - prevent path traversal
	sanitized := strings.ReplaceAll(target, "..", "")   // Remove path traversal sequences
	sanitized = strings.ReplaceAll(sanitized, "://", "-")
	sanitized = strings.ReplaceAll(sanitized, "/", "-")
	sanitized = strings.ReplaceAll(sanitized, "\\", "-") // Handle Windows path separators
	sanitized = strings.ReplaceAll(sanitized, ":", "-")
	return fmt.Sprintf("cp-%s-%s-%s", tool, sanitized, timestamp)
}

// CreateCheckpoint creates a new checkpoint with initial state
func CreateCheckpoint(target, tool, ports string, args []string, metadata map[string]string) *ScanCheckpoint {
	if metadata == nil {
		metadata = make(map[string]string)
	}

	return &ScanCheckpoint{
		ID:         GenerateCheckpointID(target, tool),
		Target:     target,
		Tool:       tool,
		Ports:      ports,
		Args:       args,
		StartTime:  time.Now(),
		LastUpdate: time.Now(),
		Status:     CheckpointStatusRunning,
		Progress:   0,
		Metadata:   metadata,
	}
}

// UpdateProgress updates the checkpoint with new progress information
func (cp *ScanCheckpoint) UpdateProgress(progress float64, partialOutput string) {
	cp.Progress = progress
	cp.PartialOutput = partialOutput
	cp.BytesRead = int64(len(partialOutput))
	cp.LastUpdate = time.Now()
}

// MarkCompleted marks the checkpoint as completed
func (cp *ScanCheckpoint) MarkCompleted() {
	cp.Status = CheckpointStatusCompleted
	cp.Progress = 100
	cp.LastUpdate = time.Now()
}

// MarkPaused marks the checkpoint as paused (interrupted)
func (cp *ScanCheckpoint) MarkPaused() {
	cp.Status = CheckpointStatusPaused
	cp.LastUpdate = time.Now()
}

// MarkFailed marks the checkpoint as failed
func (cp *ScanCheckpoint) MarkFailed(errMsg string) {
	cp.Status = CheckpointStatusFailed
	cp.LastUpdate = time.Now()
	if cp.Metadata == nil {
		cp.Metadata = make(map[string]string)
	}
	cp.Metadata["error"] = errMsg
}

// ElapsedTime returns the total elapsed time for this scan
func (cp *ScanCheckpoint) ElapsedTime() time.Duration {
	return cp.LastUpdate.Sub(cp.StartTime)
}

// IsResumable returns true if this checkpoint can be resumed
func (cp *ScanCheckpoint) IsResumable() bool {
	return cp.Status == CheckpointStatusRunning || cp.Status == CheckpointStatusPaused
}
