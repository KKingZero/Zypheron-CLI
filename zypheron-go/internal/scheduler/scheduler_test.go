package scheduler

import (
	"testing"
	"time"
)

// TestNewScheduler tests creating a new scheduler with in-memory database
func TestNewScheduler(t *testing.T) {
	s, err := NewScheduler(":memory:")
	if err != nil {
		t.Fatalf("Failed to create scheduler: %v", err)
	}
	defer s.Close()

	if s.db == nil {
		t.Fatal("Scheduler database is nil")
	}
}

// TestCreateScan tests creating a scheduled scan
func TestCreateScan(t *testing.T) {
	s, err := NewScheduler(":memory:")
	if err != nil {
		t.Fatalf("Failed to create scheduler: %v", err)
	}
	defer s.Close()

	scan := ScheduledScan{
		ID:       "test-scan-1",
		Name:     "Daily Network Scan",
		Target:   "192.168.1.0/24",
		Tools:    "nmap,nikto",
		CronExpr: "0 2 * * *",
		Enabled:  true,
	}

	err = s.CreateScan(scan)
	if err != nil {
		t.Fatalf("Failed to create scan: %v", err)
	}

	// Verify scan was created
	retrieved, err := s.GetScan(scan.ID)
	if err != nil {
		t.Fatalf("Failed to get scan: %v", err)
	}

	if retrieved.ID != scan.ID {
		t.Errorf("Expected ID %s, got %s", scan.ID, retrieved.ID)
	}
	if retrieved.Name != scan.Name {
		t.Errorf("Expected name %s, got %s", scan.Name, retrieved.Name)
	}
	if retrieved.Target != scan.Target {
		t.Errorf("Expected target %s, got %s", scan.Target, retrieved.Target)
	}
	if retrieved.Tools != scan.Tools {
		t.Errorf("Expected tools %s, got %s", scan.Tools, retrieved.Tools)
	}
	if !retrieved.Enabled {
		t.Error("Expected scan to be enabled")
	}
}

// TestCreateScanValidation tests validation when creating scans
func TestCreateScanValidation(t *testing.T) {
	s, err := NewScheduler(":memory:")
	if err != nil {
		t.Fatalf("Failed to create scheduler: %v", err)
	}
	defer s.Close()

	tests := []struct {
		name    string
		scan    ScheduledScan
		wantErr bool
	}{
		{
			name: "missing ID",
			scan: ScheduledScan{
				Name:     "Test",
				Target:   "example.com",
				Tools:    "nmap",
				CronExpr: "0 0 * * *",
			},
			wantErr: true,
		},
		{
			name: "missing name",
			scan: ScheduledScan{
				ID:       "test-1",
				Target:   "example.com",
				Tools:    "nmap",
				CronExpr: "0 0 * * *",
			},
			wantErr: true,
		},
		{
			name: "missing target",
			scan: ScheduledScan{
				ID:       "test-1",
				Name:     "Test",
				Tools:    "nmap",
				CronExpr: "0 0 * * *",
			},
			wantErr: true,
		},
		{
			name: "missing tools",
			scan: ScheduledScan{
				ID:       "test-1",
				Name:     "Test",
				Target:   "example.com",
				CronExpr: "0 0 * * *",
			},
			wantErr: true,
		},
		{
			name: "invalid cron expression",
			scan: ScheduledScan{
				ID:       "test-1",
				Name:     "Test",
				Target:   "example.com",
				Tools:    "nmap",
				CronExpr: "invalid",
			},
			wantErr: true,
		},
		{
			name: "valid scan",
			scan: ScheduledScan{
				ID:       "test-1",
				Name:     "Test",
				Target:   "example.com",
				Tools:    "nmap",
				CronExpr: "0 0 * * *",
				Enabled:  true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.CreateScan(tt.scan)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateScan() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestListScans tests listing all scans
func TestListScans(t *testing.T) {
	s, err := NewScheduler(":memory:")
	if err != nil {
		t.Fatalf("Failed to create scheduler: %v", err)
	}
	defer s.Close()

	// Create multiple scans
	scans := []ScheduledScan{
		{
			ID:       "scan-1",
			Name:     "Scan 1",
			Target:   "192.168.1.1",
			Tools:    "nmap",
			CronExpr: "0 0 * * *",
			Enabled:  true,
		},
		{
			ID:       "scan-2",
			Name:     "Scan 2",
			Target:   "192.168.1.2",
			Tools:    "nikto",
			CronExpr: "0 1 * * *",
			Enabled:  false,
		},
		{
			ID:       "scan-3",
			Name:     "Scan 3",
			Target:   "192.168.1.3",
			Tools:    "nuclei",
			CronExpr: "0 2 * * *",
			Enabled:  true,
		},
	}

	for _, scan := range scans {
		if err := s.CreateScan(scan); err != nil {
			t.Fatalf("Failed to create scan %s: %v", scan.ID, err)
		}
	}

	// List all scans
	retrieved, err := s.ListScans()
	if err != nil {
		t.Fatalf("Failed to list scans: %v", err)
	}

	if len(retrieved) != len(scans) {
		t.Errorf("Expected %d scans, got %d", len(scans), len(retrieved))
	}
}

// TestGetScan tests retrieving a specific scan
func TestGetScan(t *testing.T) {
	s, err := NewScheduler(":memory:")
	if err != nil {
		t.Fatalf("Failed to create scheduler: %v", err)
	}
	defer s.Close()

	scan := ScheduledScan{
		ID:       "test-scan",
		Name:     "Test Scan",
		Target:   "example.com",
		Tools:    "nmap",
		CronExpr: "0 0 * * *",
		Enabled:  true,
	}

	if err := s.CreateScan(scan); err != nil {
		t.Fatalf("Failed to create scan: %v", err)
	}

	// Test getting existing scan
	retrieved, err := s.GetScan(scan.ID)
	if err != nil {
		t.Fatalf("Failed to get scan: %v", err)
	}
	if retrieved.ID != scan.ID {
		t.Errorf("Expected ID %s, got %s", scan.ID, retrieved.ID)
	}

	// Test getting non-existent scan
	_, err = s.GetScan("non-existent")
	if err == nil {
		t.Error("Expected error when getting non-existent scan")
	}

	// Test empty ID
	_, err = s.GetScan("")
	if err == nil {
		t.Error("Expected error when getting scan with empty ID")
	}
}

// TestUpdateScan tests updating a scheduled scan
func TestUpdateScan(t *testing.T) {
	s, err := NewScheduler(":memory:")
	if err != nil {
		t.Fatalf("Failed to create scheduler: %v", err)
	}
	defer s.Close()

	original := ScheduledScan{
		ID:       "test-scan",
		Name:     "Original Name",
		Target:   "example.com",
		Tools:    "nmap",
		CronExpr: "0 0 * * *",
		Enabled:  true,
	}

	if err := s.CreateScan(original); err != nil {
		t.Fatalf("Failed to create scan: %v", err)
	}

	// Update the scan
	updated := ScheduledScan{
		ID:       "test-scan",
		Name:     "Updated Name",
		Target:   "updated.com",
		Tools:    "nmap,nikto",
		CronExpr: "0 1 * * *",
		Enabled:  false,
	}

	if err := s.UpdateScan(updated); err != nil {
		t.Fatalf("Failed to update scan: %v", err)
	}

	// Verify update
	retrieved, err := s.GetScan(updated.ID)
	if err != nil {
		t.Fatalf("Failed to get updated scan: %v", err)
	}

	if retrieved.Name != updated.Name {
		t.Errorf("Expected name %s, got %s", updated.Name, retrieved.Name)
	}
	if retrieved.Target != updated.Target {
		t.Errorf("Expected target %s, got %s", updated.Target, retrieved.Target)
	}
	if retrieved.Enabled {
		t.Error("Expected scan to be disabled")
	}
}

// TestDeleteScan tests deleting a scheduled scan
func TestDeleteScan(t *testing.T) {
	s, err := NewScheduler(":memory:")
	if err != nil {
		t.Fatalf("Failed to create scheduler: %v", err)
	}
	defer s.Close()

	scan := ScheduledScan{
		ID:       "test-scan",
		Name:     "Test Scan",
		Target:   "example.com",
		Tools:    "nmap",
		CronExpr: "0 0 * * *",
		Enabled:  true,
	}

	if err := s.CreateScan(scan); err != nil {
		t.Fatalf("Failed to create scan: %v", err)
	}

	// Delete the scan
	if err := s.DeleteScan(scan.ID); err != nil {
		t.Fatalf("Failed to delete scan: %v", err)
	}

	// Verify deletion
	_, err = s.GetScan(scan.ID)
	if err == nil {
		t.Error("Expected error when getting deleted scan")
	}

	// Test deleting non-existent scan
	err = s.DeleteScan("non-existent")
	if err == nil {
		t.Error("Expected error when deleting non-existent scan")
	}
}

// TestEnableDisableScan tests enabling and disabling scans
func TestEnableDisableScan(t *testing.T) {
	s, err := NewScheduler(":memory:")
	if err != nil {
		t.Fatalf("Failed to create scheduler: %v", err)
	}
	defer s.Close()

	scan := ScheduledScan{
		ID:       "test-scan",
		Name:     "Test Scan",
		Target:   "example.com",
		Tools:    "nmap",
		CronExpr: "0 0 * * *",
		Enabled:  true,
	}

	if err := s.CreateScan(scan); err != nil {
		t.Fatalf("Failed to create scan: %v", err)
	}

	// Disable the scan
	if err := s.DisableScan(scan.ID); err != nil {
		t.Fatalf("Failed to disable scan: %v", err)
	}

	retrieved, err := s.GetScan(scan.ID)
	if err != nil {
		t.Fatalf("Failed to get scan: %v", err)
	}
	if retrieved.Enabled {
		t.Error("Expected scan to be disabled")
	}

	// Enable the scan
	if err := s.EnableScan(scan.ID); err != nil {
		t.Fatalf("Failed to enable scan: %v", err)
	}

	retrieved, err = s.GetScan(scan.ID)
	if err != nil {
		t.Fatalf("Failed to get scan: %v", err)
	}
	if !retrieved.Enabled {
		t.Error("Expected scan to be enabled")
	}
}

// TestGetDueScans tests retrieving scans that are due to run
func TestGetDueScans(t *testing.T) {
	s, err := NewScheduler(":memory:")
	if err != nil {
		t.Fatalf("Failed to create scheduler: %v", err)
	}
	defer s.Close()

	now := time.Now()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)

	// Create scans with different next run times
	scans := []ScheduledScan{
		{
			ID:       "past-scan",
			Name:     "Past Scan",
			Target:   "example.com",
			Tools:    "nmap",
			CronExpr: "0 0 * * *",
			NextRun:  past,
			Enabled:  true,
		},
		{
			ID:       "future-scan",
			Name:     "Future Scan",
			Target:   "example.com",
			Tools:    "nmap",
			CronExpr: "0 0 * * *",
			NextRun:  future,
			Enabled:  true,
		},
		{
			ID:       "disabled-scan",
			Name:     "Disabled Scan",
			Target:   "example.com",
			Tools:    "nmap",
			CronExpr: "0 0 * * *",
			NextRun:  past,
			Enabled:  false,
		},
	}

	for _, scan := range scans {
		// Use direct database insert to bypass cron parsing
		_, err := s.db.Exec(`
			INSERT INTO scheduled_scans (id, name, target, tools, cron_expr, next_run, enabled, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, scan.ID, scan.Name, scan.Target, scan.Tools, scan.CronExpr, scan.NextRun, boolToInt(scan.Enabled), time.Now())

		if err != nil {
			t.Fatalf("Failed to create scan %s: %v", scan.ID, err)
		}
	}

	// Get due scans
	due, err := s.GetDueScans()
	if err != nil {
		t.Fatalf("Failed to get due scans: %v", err)
	}

	// Should only get the enabled scan that's in the past
	if len(due) != 1 {
		t.Errorf("Expected 1 due scan, got %d", len(due))
	}

	if len(due) > 0 && due[0].ID != "past-scan" {
		t.Errorf("Expected past-scan, got %s", due[0].ID)
	}
}

// TestMarkCompleted tests marking a scan as completed
func TestMarkCompleted(t *testing.T) {
	s, err := NewScheduler(":memory:")
	if err != nil {
		t.Fatalf("Failed to create scheduler: %v", err)
	}
	defer s.Close()

	scan := ScheduledScan{
		ID:       "test-scan",
		Name:     "Test Scan",
		Target:   "example.com",
		Tools:    "nmap",
		CronExpr: "0 0 * * *", // Daily at midnight
		Enabled:  true,
	}

	if err := s.CreateScan(scan); err != nil {
		t.Fatalf("Failed to create scan: %v", err)
	}

	// Mark as completed
	if err := s.MarkCompleted(scan.ID); err != nil {
		t.Fatalf("Failed to mark scan completed: %v", err)
	}

	// Verify last run was set and next run was calculated
	retrieved, err := s.GetScan(scan.ID)
	if err != nil {
		t.Fatalf("Failed to get scan: %v", err)
	}

	if retrieved.LastRun.IsZero() {
		t.Error("Expected last run to be set")
	}

	if !retrieved.NextRun.After(time.Now()) {
		t.Error("Expected next run to be in the future")
	}
}

// TestCronParsing tests cron expression parsing
func TestCronParsing(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{"every minute", "* * * * *", false},
		{"every hour", "0 * * * *", false},
		{"daily at 2am", "0 2 * * *", false},
		{"every 15 minutes", "*/15 * * * *", false},
		{"first day of month", "0 0 1 * *", false},
		{"sundays at midnight", "0 0 * * 0", false},
		{"invalid - too few fields", "0 0 * *", true},
		{"invalid - too many fields", "0 0 * * * *", true},
		{"invalid - bad minute", "60 0 * * *", true},
		{"invalid - bad hour", "0 24 * * *", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCronExpression(tt.expr, time.Now())
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCronExpression() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Benchmark tests

// BenchmarkCreateScan benchmarks creating scans
func BenchmarkCreateScan(b *testing.B) {
	s, err := NewScheduler(":memory:")
	if err != nil {
		b.Fatalf("Failed to create scheduler: %v", err)
	}
	defer s.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scan := ScheduledScan{
			ID:       "bench-scan",
			Name:     "Benchmark Scan",
			Target:   "example.com",
			Tools:    "nmap",
			CronExpr: "0 0 * * *",
			Enabled:  true,
		}
		s.CreateScan(scan)
		s.DeleteScan(scan.ID)
	}
}

// BenchmarkListScans benchmarks listing scans
func BenchmarkListScans(b *testing.B) {
	s, err := NewScheduler(":memory:")
	if err != nil {
		b.Fatalf("Failed to create scheduler: %v", err)
	}
	defer s.Close()

	// Create 100 scans
	for i := 0; i < 100; i++ {
		scan := ScheduledScan{
			ID:       "scan-" + string(rune(i)),
			Name:     "Test Scan",
			Target:   "example.com",
			Tools:    "nmap",
			CronExpr: "0 0 * * *",
			Enabled:  true,
		}
		s.CreateScan(scan)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ListScans()
	}
}

// BenchmarkGetDueScans benchmarks getting due scans
func BenchmarkGetDueScans(b *testing.B) {
	s, err := NewScheduler(":memory:")
	if err != nil {
		b.Fatalf("Failed to create scheduler: %v", err)
	}
	defer s.Close()

	now := time.Now()
	past := now.Add(-1 * time.Hour)

	// Create 100 scans, half due
	for i := 0; i < 100; i++ {
		nextRun := past
		if i%2 == 0 {
			nextRun = now.Add(1 * time.Hour)
		}

		_, err := s.db.Exec(`
			INSERT INTO scheduled_scans (id, name, target, tools, cron_expr, next_run, enabled, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, "scan-"+string(rune(i)), "Test Scan", "example.com", "nmap", "0 0 * * *", nextRun, 1, now)

		if err != nil {
			b.Fatalf("Failed to create scan: %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.GetDueScans()
	}
}

// BenchmarkCronParsing benchmarks cron expression parsing
func BenchmarkCronParsing(b *testing.B) {
	now := time.Now()
	for i := 0; i < b.N; i++ {
		ParseCronExpression("0 2 * * *", now)
	}
}
