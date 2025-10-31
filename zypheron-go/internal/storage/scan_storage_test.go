package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/pkg/types"
)

func TestGenerateScanID(t *testing.T) {
	tests := []struct {
		name   string
		target string
		tool   string
	}{
		{"simple domain", "example.com", "nmap"},
		{"URL", "https://example.com", "nikto"},
		{"IP address", "192.168.1.1", "masscan"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := GenerateScanID(tt.target, tt.tool)

			// Should not be empty
			if id == "" {
				t.Error("GenerateScanID() returned empty string")
			}

			// Should contain tool name
			if len(id) < len(tt.tool) {
				t.Error("GenerateScanID() too short")
			}

			// Should not contain dangerous characters
			if containsDangerousChars(id) {
				t.Errorf("GenerateScanID() contains dangerous characters: %s", id)
			}
		})
	}
}

func TestSaveScan_LoadScan(t *testing.T) {
	// Create temporary storage
	tmpDir := t.TempDir()
	storage := &ScanStorage{storageDir: tmpDir}

	// Create test scan
	scan := &types.ScanResult{
		ID:        "test-scan-123",
		Timestamp: time.Now(),
		Target:    "example.com",
		Tool:      "nmap",
		Ports:     "1-1000",
		Output:    "test output",
		Duration:  10.5,
		Success:   true,
		Vulnerabilities: []types.Vulnerability{
			{
				ID:          "vuln-1",
				Title:       "Test Vulnerability",
				Description: "Test description",
				Severity:    "high",
			},
		},
		AIAnalysis: "Test AI analysis",
	}

	// Test Save
	err := storage.SaveScan(scan)
	if err != nil {
		t.Fatalf("SaveScan() error = %v", err)
	}

	// Verify file exists
	scanFile := filepath.Join(tmpDir, "test-scan-123.json")
	if _, err := os.Stat(scanFile); os.IsNotExist(err) {
		t.Error("SaveScan() did not create file")
	}

	// Test Load
	loaded, err := storage.LoadScan("test-scan-123")
	if err != nil {
		t.Fatalf("LoadScan() error = %v", err)
	}

	// Verify loaded data
	if loaded.ID != scan.ID {
		t.Errorf("LoadScan() ID = %v, want %v", loaded.ID, scan.ID)
	}
	if loaded.Target != scan.Target {
		t.Errorf("LoadScan() Target = %v, want %v", loaded.Target, scan.Target)
	}
	if loaded.Tool != scan.Tool {
		t.Errorf("LoadScan() Tool = %v, want %v", loaded.Tool, scan.Tool)
	}
	if len(loaded.Vulnerabilities) != len(scan.Vulnerabilities) {
		t.Errorf("LoadScan() Vulnerabilities count = %v, want %v",
			len(loaded.Vulnerabilities), len(scan.Vulnerabilities))
	}
}

func TestSaveScan_EmptyID(t *testing.T) {
	tmpDir := t.TempDir()
	storage := &ScanStorage{storageDir: tmpDir}

	scan := &types.ScanResult{
		ID:     "", // Empty ID
		Target: "example.com",
	}

	err := storage.SaveScan(scan)
	if err == nil {
		t.Error("SaveScan() should error with empty ID")
	}
}

func TestLoadScan_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	storage := &ScanStorage{storageDir: tmpDir}

	_, err := storage.LoadScan("nonexistent-scan")
	if err == nil {
		t.Error("LoadScan() should error for nonexistent scan")
	}
}

func TestListScans(t *testing.T) {
	tmpDir := t.TempDir()
	storage := &ScanStorage{storageDir: tmpDir}

	// Create multiple test scans
	scans := []*types.ScanResult{
		{
			ID:        "scan-1",
			Timestamp: time.Now().Add(-2 * time.Hour),
			Target:    "example1.com",
			Tool:      "nmap",
			Success:   true,
			Vulnerabilities: []types.Vulnerability{
				{Severity: "critical"},
				{Severity: "high"},
			},
		},
		{
			ID:        "scan-2",
			Timestamp: time.Now().Add(-1 * time.Hour),
			Target:    "example2.com",
			Tool:      "nikto",
			Success:   true,
			Vulnerabilities: []types.Vulnerability{
				{Severity: "medium"},
			},
		},
	}

	for _, scan := range scans {
		if err := storage.SaveScan(scan); err != nil {
			t.Fatalf("SaveScan() error = %v", err)
		}
	}

	// Test ListScans
	summaries, err := storage.ListScans()
	if err != nil {
		t.Fatalf("ListScans() error = %v", err)
	}

	if len(summaries) != len(scans) {
		t.Errorf("ListScans() returned %d scans, want %d", len(summaries), len(scans))
	}

	// Verify sorting (newest first)
	if summaries[0].ID != "scan-2" {
		t.Error("ListScans() not sorted correctly (should be newest first)")
	}

	// Verify vulnerability counts
	if summaries[1].CriticalCount != 1 {
		t.Errorf("ListScans() CriticalCount = %d, want 1", summaries[1].CriticalCount)
	}
	if summaries[1].HighCount != 1 {
		t.Errorf("ListScans() HighCount = %d, want 1", summaries[1].HighCount)
	}
}

func TestDeleteScan(t *testing.T) {
	tmpDir := t.TempDir()
	storage := &ScanStorage{storageDir: tmpDir}

	// Create and save a scan
	scan := &types.ScanResult{
		ID:      "test-delete",
		Target:  "example.com",
		Tool:    "nmap",
		Success: true,
	}

	if err := storage.SaveScan(scan); err != nil {
		t.Fatalf("SaveScan() error = %v", err)
	}

	// Delete it
	err := storage.DeleteScan("test-delete")
	if err != nil {
		t.Fatalf("DeleteScan() error = %v", err)
	}

	// Verify it's deleted
	_, err = storage.LoadScan("test-delete")
	if err == nil {
		t.Error("LoadScan() should fail after DeleteScan()")
	}
}

func TestDeleteScan_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	storage := &ScanStorage{storageDir: tmpDir}

	err := storage.DeleteScan("nonexistent")
	if err == nil {
		t.Error("DeleteScan() should error for nonexistent scan")
	}
}

// Helper function
func containsDangerousChars(s string) bool {
	dangerous := []string{";", "&", "|", "`", "$", "(", ")", "\n", "\r", "\\"}
	for _, char := range dangerous {
		if len(s) > 0 && s[0:1] == char {
			return true
		}
	}
	return false
}
