package history

import (
	"os"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	if mgr == nil {
		t.Fatal("Manager is nil")
	}
	if mgr.historyPath == "" {
		t.Fatal("History path is empty")
	}
}

func TestNewManagerWithPath(t *testing.T) {
	testPath := "/tmp/zypheron_test_history.json"
	defer os.Remove(testPath)

	mgr, err := NewManagerWithPath(testPath)
	if err != nil {
		t.Fatalf("Failed to create manager with path: %v", err)
	}
	if mgr == nil {
		t.Fatal("Manager is nil")
	}
	if mgr.historyPath != testPath {
		t.Fatalf("Expected path %s, got %s", testPath, mgr.historyPath)
	}
}

func TestAddAndGetHistory(t *testing.T) {
	testPath := "/tmp/zypheron_test_history_add.json"
	defer os.Remove(testPath)

	mgr, err := NewManagerWithPath(testPath)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	entry := &HistoryEntry{
		ID:            "test-001",
		Timestamp:     time.Now(),
		Target:        "192.168.1.1",
		ScanType:      "port-scan",
		Tool:          "nmap",
		Duration:      1500,
		Status:        StatusSuccess,
		FindingsCount: 10,
		VulnCount:     2,
		SessionID:     "session-001",
		Tags:          []string{"test", "verification"},
	}

	if err := mgr.AddEntry(entry); err != nil {
		t.Fatalf("Failed to add entry: %v", err)
	}

	entries, err := mgr.GetHistory(10, 0)
	if err != nil {
		t.Fatalf("Failed to get history: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(entries))
	}

	if entries[0].ID != entry.ID {
		t.Fatalf("Expected ID %s, got %s", entry.ID, entries[0].ID)
	}
}

func TestGetStats(t *testing.T) {
	testPath := "/tmp/zypheron_test_history_stats.json"
	defer os.Remove(testPath)

	mgr, err := NewManagerWithPath(testPath)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// Add multiple entries
	entries := []*HistoryEntry{
		{
			ID:            "test-001",
			Timestamp:     time.Now(),
			Target:        "192.168.1.1",
			ScanType:      "port-scan",
			Tool:          "nmap",
			Duration:      1500,
			Status:        StatusSuccess,
			FindingsCount: 10,
			VulnCount:     2,
			SessionID:     "session-001",
		},
		{
			ID:            "test-002",
			Timestamp:     time.Now().Add(1 * time.Minute),
			Target:        "192.168.1.2",
			ScanType:      "web-scan",
			Tool:          "nikto",
			Duration:      3000,
			Status:        StatusSuccess,
			FindingsCount: 5,
			VulnCount:     1,
			SessionID:     "session-001",
		},
	}

	for _, entry := range entries {
		if err := mgr.AddEntry(entry); err != nil {
			t.Fatalf("Failed to add entry: %v", err)
		}
	}

	stats, err := mgr.GetStats()
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}

	if stats.TotalScans != 2 {
		t.Fatalf("Expected 2 total scans, got %d", stats.TotalScans)
	}

	if stats.TotalFindings != 15 {
		t.Fatalf("Expected 15 total findings, got %d", stats.TotalFindings)
	}

	if stats.TotalVulns != 3 {
		t.Fatalf("Expected 3 total vulns, got %d", stats.TotalVulns)
	}

	if stats.SuccessRate != 100.0 {
		t.Fatalf("Expected 100%% success rate, got %.2f%%", stats.SuccessRate)
	}
}

func TestSearchHistory(t *testing.T) {
	testPath := "/tmp/zypheron_test_history_search.json"
	defer os.Remove(testPath)

	mgr, err := NewManagerWithPath(testPath)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	entry := &HistoryEntry{
		ID:            "test-001",
		Timestamp:     time.Now(),
		Target:        "example.com",
		ScanType:      "port-scan",
		Tool:          "nmap",
		Duration:      1500,
		Status:        StatusSuccess,
		FindingsCount: 10,
		VulnCount:     2,
		SessionID:     "session-001",
		Tags:          []string{"production", "important"},
	}

	if err := mgr.AddEntry(entry); err != nil {
		t.Fatalf("Failed to add entry: %v", err)
	}

	// Search by target
	results, err := mgr.SearchHistory("example")
	if err != nil {
		t.Fatalf("Failed to search history: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Search by tag
	results, err = mgr.SearchHistory("production")
	if err != nil {
		t.Fatalf("Failed to search by tag: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result for tag search, got %d", len(results))
	}
}

func TestDeleteEntry(t *testing.T) {
	testPath := "/tmp/zypheron_test_history_delete.json"
	defer os.Remove(testPath)

	mgr, err := NewManagerWithPath(testPath)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	entry := &HistoryEntry{
		ID:            "test-delete-001",
		Timestamp:     time.Now(),
		Target:        "192.168.1.1",
		ScanType:      "port-scan",
		Tool:          "nmap",
		Duration:      1500,
		Status:        StatusSuccess,
		FindingsCount: 10,
		VulnCount:     2,
		SessionID:     "session-001",
	}

	if err := mgr.AddEntry(entry); err != nil {
		t.Fatalf("Failed to add entry: %v", err)
	}

	if err := mgr.DeleteEntry(entry.ID); err != nil {
		t.Fatalf("Failed to delete entry: %v", err)
	}

	entries, err := mgr.GetHistory(10, 0)
	if err != nil {
		t.Fatalf("Failed to get history: %v", err)
	}

	if len(entries) != 0 {
		t.Fatalf("Expected 0 entries after deletion, got %d", len(entries))
	}
}

func TestClearHistory(t *testing.T) {
	testPath := "/tmp/zypheron_test_history_clear.json"
	defer os.Remove(testPath)

	mgr, err := NewManagerWithPath(testPath)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// Add some entries
	for i := 0; i < 5; i++ {
		entry := &HistoryEntry{
			ID:            "test-" + string(rune(i)),
			Timestamp:     time.Now(),
			Target:        "192.168.1.1",
			ScanType:      "port-scan",
			Tool:          "nmap",
			Duration:      1500,
			Status:        StatusSuccess,
			FindingsCount: 10,
			VulnCount:     2,
			SessionID:     "session-001",
		}
		if err := mgr.AddEntry(entry); err != nil {
			t.Fatalf("Failed to add entry: %v", err)
		}
	}

	if err := mgr.ClearHistory(); err != nil {
		t.Fatalf("Failed to clear history: %v", err)
	}

	entries, err := mgr.GetHistory(10, 0)
	if err != nil {
		t.Fatalf("Failed to get history: %v", err)
	}

	if len(entries) != 0 {
		t.Fatalf("Expected 0 entries after clear, got %d", len(entries))
	}
}
