package storage

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/pkg/types"
)

// ScanStorage manages persistent storage of scan results
type ScanStorage struct {
	storageDir string
}

// NewScanStorage creates a new scan storage instance
func NewScanStorage() (*ScanStorage, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	storageDir := filepath.Join(homeDir, ".zypheron", "scans")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	return &ScanStorage{
		storageDir: storageDir,
	}, nil
}

// SaveScan saves a scan result to disk
func (s *ScanStorage) SaveScan(scan *types.ScanResult) error {
	if scan.ID == "" {
		return fmt.Errorf("scan ID cannot be empty")
	}

	filename := fmt.Sprintf("%s.json", scan.ID)
	filepath := filepath.Join(s.storageDir, filename)

	data, err := json.MarshalIndent(scan, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal scan: %w", err)
	}

	if err := ioutil.WriteFile(filepath, data, 0600); err != nil {
		return fmt.Errorf("failed to write scan file: %w", err)
	}

	return nil
}

// LoadScan loads a scan result from disk
func (s *ScanStorage) LoadScan(scanID string) (*types.ScanResult, error) {
	filename := fmt.Sprintf("%s.json", scanID)
	filepath := filepath.Join(s.storageDir, filename)

	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("scan not found: %s", scanID)
		}
		return nil, fmt.Errorf("failed to read scan file: %w", err)
	}

	var scan types.ScanResult
	if err := json.Unmarshal(data, &scan); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scan: %w", err)
	}

	return &scan, nil
}

// ListScans lists all saved scans, newest first
func (s *ScanStorage) ListScans() ([]types.ScanSummary, error) {
	files, err := ioutil.ReadDir(s.storageDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read storage directory: %w", err)
	}

	var summaries []types.ScanSummary

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		scanID := strings.TrimSuffix(file.Name(), ".json")
		scan, err := s.LoadScan(scanID)
		if err != nil {
			// Skip invalid scan files
			continue
		}

		// Count vulnerabilities by severity
		criticalCount := 0
		highCount := 0
		for _, vuln := range scan.Vulnerabilities {
			if vuln.Severity == "critical" {
				criticalCount++
			} else if vuln.Severity == "high" {
				highCount++
			}
		}

		summary := types.ScanSummary{
			ID:            scan.ID,
			Timestamp:     scan.Timestamp,
			Target:        scan.Target,
			Tool:          scan.Tool,
			Success:       scan.Success,
			VulnCount:     len(scan.Vulnerabilities),
			CriticalCount: criticalCount,
			HighCount:     highCount,
		}

		summaries = append(summaries, summary)
	}

	// Sort by timestamp, newest first
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Timestamp.After(summaries[j].Timestamp)
	})

	return summaries, nil
}

// DeleteScan deletes a scan from storage
func (s *ScanStorage) DeleteScan(scanID string) error {
	filename := fmt.Sprintf("%s.json", scanID)
	filepath := filepath.Join(s.storageDir, filename)

	if err := os.Remove(filepath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("scan not found: %s", scanID)
		}
		return fmt.Errorf("failed to delete scan: %w", err)
	}

	return nil
}

// GenerateScanID generates a unique scan ID
func GenerateScanID(target, tool string) string {
	timestamp := time.Now().Format("20060102-150405")
	// Sanitize target for filename
	sanitized := strings.ReplaceAll(target, "://", "-")
	sanitized = strings.ReplaceAll(sanitized, "/", "-")
	sanitized = strings.ReplaceAll(sanitized, ":", "-")
	return fmt.Sprintf("%s-%s-%s", tool, sanitized, timestamp)
}
