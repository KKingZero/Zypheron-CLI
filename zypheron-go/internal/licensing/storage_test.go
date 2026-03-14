package licensing

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// setupTestStorage creates a temporary storage for testing
// This ensures tests don't interfere with production data
func setupTestStorage(t *testing.T) (*Storage, string) {
	// Create temporary directory and database file
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Create database connection
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Create storage with the database
	storage := &Storage{db: db}

	// Initialize schema
	if err := storage.init(); err != nil {
		db.Close()
		t.Fatalf("Failed to initialize test storage: %v", err)
	}

	t.Cleanup(func() {
		storage.Close()
	})

	return storage, dbPath
}

// TestSaveAndLoadSession tests session persistence
func TestSaveAndLoadSession(t *testing.T) {
	storage, _ := setupTestStorage(t)

	// Create test session
	session := &AuthSession{
		AccessToken:  "test-access-token-123",
		RefreshToken: "test-refresh-token-456",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		UserID:       "user-789",
		Email:        "test@example.com",
	}

	// Save session
	err := storage.SaveSession(session)
	if err != nil {
		t.Fatalf("SaveSession failed: %v", err)
	}

	// Load session
	loaded, err := storage.LoadSession()
	if err != nil {
		t.Fatalf("LoadSession failed: %v", err)
	}

	// Verify loaded session
	if loaded.AccessToken != session.AccessToken {
		t.Errorf("Expected access token %s, got %s", session.AccessToken, loaded.AccessToken)
	}
	if loaded.RefreshToken != session.RefreshToken {
		t.Errorf("Expected refresh token %s, got %s", session.RefreshToken, loaded.RefreshToken)
	}
	if loaded.UserID != session.UserID {
		t.Errorf("Expected user ID %s, got %s", session.UserID, loaded.UserID)
	}
	if loaded.Email != session.Email {
		t.Errorf("Expected email %s, got %s", session.Email, loaded.Email)
	}

	// ExpiresAt should be within 1 second (SQLite datetime precision)
	timeDiff := loaded.ExpiresAt.Sub(session.ExpiresAt)
	if timeDiff > time.Second || timeDiff < -time.Second {
		t.Errorf("ExpiresAt mismatch: expected %v, got %v (diff: %v)",
			session.ExpiresAt, loaded.ExpiresAt, timeDiff)
	}
}

// TestSaveAndLoadLicense tests license persistence
func TestSaveAndLoadLicense(t *testing.T) {
	storage, _ := setupTestStorage(t)

	// Create test license
	license := &License{
		UserID:          "user-123",
		Email:           "test@example.com",
		Tier:            TierPro,
		Features:        []Feature{FeatureCloudAI, FeatureAutopent, FeatureExploitation},
		TokensRemaining: 1500000,
		TokensUsed:      500000,
		TokensLimit:     3000000,
		ResetDate:       time.Now().Add(7 * 24 * time.Hour),
		ExpiresAt:       time.Now().Add(30 * 24 * time.Hour),
		IssuedAt:        time.Now().Add(-10 * 24 * time.Hour),
		DeviceID:        "device-abc123",
		TeamID:          "team-xyz",
		TeamRole:        "admin",
		OfflineDays:     30,
		Valid:           true,
		DevicesUsed:     2,
		DevicesLimit:    3,
		OfflineMode:     false,
		LicenseID:       "license-789",
	}

	// Save license
	err := storage.SaveLicense(license)
	if err != nil {
		t.Fatalf("SaveLicense failed: %v", err)
	}

	// Load license
	loaded, err := storage.LoadLicense()
	if err != nil {
		t.Fatalf("LoadLicense failed: %v", err)
	}

	// Verify loaded license
	if loaded.UserID != license.UserID {
		t.Errorf("Expected user ID %s, got %s", license.UserID, loaded.UserID)
	}
	if loaded.Email != license.Email {
		t.Errorf("Expected email %s, got %s", license.Email, loaded.Email)
	}
	if loaded.Tier != license.Tier {
		t.Errorf("Expected tier %v, got %v", license.Tier, loaded.Tier)
	}
	if loaded.TokensRemaining != license.TokensRemaining {
		t.Errorf("Expected tokens remaining %d, got %d", license.TokensRemaining, loaded.TokensRemaining)
	}
	if loaded.TokensUsed != license.TokensUsed {
		t.Errorf("Expected tokens used %d, got %d", license.TokensUsed, loaded.TokensUsed)
	}
	if loaded.DeviceID != license.DeviceID {
		t.Errorf("Expected device ID %s, got %s", license.DeviceID, loaded.DeviceID)
	}
	if loaded.TeamID != license.TeamID {
		t.Errorf("Expected team ID %s, got %s", license.TeamID, loaded.TeamID)
	}
	if loaded.OfflineDays != license.OfflineDays {
		t.Errorf("Expected offline days %d, got %d", license.OfflineDays, loaded.OfflineDays)
	}

	// Verify features
	if len(loaded.Features) != len(license.Features) {
		t.Errorf("Expected %d features, got %d", len(license.Features), len(loaded.Features))
	}
	for i, feature := range license.Features {
		if loaded.Features[i] != feature {
			t.Errorf("Feature mismatch at index %d: expected %v, got %v", i, feature, loaded.Features[i])
		}
	}
}

// TestClearSessionStorage tests session clearing in storage
func TestClearSessionStorage(t *testing.T) {
	storage, _ := setupTestStorage(t)

	// Save session and license
	session := &AuthSession{
		AccessToken: "test-token",
		UserID:      "user-123",
		Email:       "test@example.com",
	}
	license := &License{
		Tier:            TierPro,
		TokensRemaining: 1000000,
	}

	storage.SaveSession(session)
	storage.SaveLicense(license)

	// Verify they exist
	loadedSession, _ := storage.LoadSession()
	if loadedSession == nil {
		t.Fatal("Session should exist before clear")
	}
	loadedLicense, _ := storage.LoadLicense()
	if loadedLicense == nil {
		t.Fatal("License should exist before clear")
	}

	// Clear all
	err := storage.ClearAll()
	if err != nil {
		t.Fatalf("ClearAll failed: %v", err)
	}

	// Verify they're cleared
	loadedSession, _ = storage.LoadSession()
	if loadedSession != nil {
		t.Error("Session should be nil after clear")
	}
	loadedLicense, _ = storage.LoadLicense()
	if loadedLicense != nil {
		t.Error("License should be nil after clear")
	}
}

// TestTokenUsageTracking tests token usage recording and retrieval
func TestTokenUsageTracking(t *testing.T) {
	storage, _ := setupTestStorage(t)

	// Add usage records
	usage1 := TokenUsage{
		Action:    "autopent",
		Tokens:    50000,
		Provider:  "claude",
		Feature:   "exploitation",
		Timestamp: time.Now(),
	}
	usage2 := TokenUsage{
		Action:    "chat",
		Tokens:    10000,
		Provider:  "openai",
		Feature:   "cloud_ai",
		Timestamp: time.Now().Add(1 * time.Hour),
	}
	usage3 := TokenUsage{
		Action:    "scan",
		Tokens:    5000,
		Provider:  "deepseek",
		Feature:   "autopent",
		Timestamp: time.Now().Add(2 * time.Hour),
	}

	// Add all usage records
	if err := storage.AddUsage(usage1); err != nil {
		t.Fatalf("AddUsage failed for usage1: %v", err)
	}
	if err := storage.AddUsage(usage2); err != nil {
		t.Fatalf("AddUsage failed for usage2: %v", err)
	}
	if err := storage.AddUsage(usage3); err != nil {
		t.Fatalf("AddUsage failed for usage3: %v", err)
	}

	// Get unsynced usage
	unsynced, err := storage.GetUnsyncedUsage()
	if err != nil {
		t.Fatalf("GetUnsyncedUsage failed: %v", err)
	}

	if len(unsynced) != 3 {
		t.Errorf("Expected 3 unsynced usage records, got %d", len(unsynced))
	}

	// Verify token amounts
	totalTokens := int64(0)
	for _, u := range unsynced {
		totalTokens += u.Tokens
	}
	expectedTotal := usage1.Tokens + usage2.Tokens + usage3.Tokens
	if totalTokens != expectedTotal {
		t.Errorf("Expected total tokens %d, got %d", expectedTotal, totalTokens)
	}

	// Get total tokens used
	total, err := storage.GetTotalTokensUsed()
	if err != nil {
		t.Fatalf("GetTotalTokensUsed failed: %v", err)
	}
	if total != expectedTotal {
		t.Errorf("Expected total tokens used %d, got %d", expectedTotal, total)
	}
}

// TestMarkUsageSynced tests marking usage as synced
func TestMarkUsageSynced(t *testing.T) {
	storage, _ := setupTestStorage(t)

	// Add usage records
	now := time.Now()
	usage1 := TokenUsage{
		Action:    "test1",
		Tokens:    1000,
		Timestamp: now.Add(-2 * time.Hour),
	}
	usage2 := TokenUsage{
		Action:    "test2",
		Tokens:    2000,
		Timestamp: now.Add(-1 * time.Hour),
	}
	usage3 := TokenUsage{
		Action:    "test3",
		Tokens:    3000,
		Timestamp: now,
	}

	storage.AddUsage(usage1)
	storage.AddUsage(usage2)
	storage.AddUsage(usage3)

	// Verify all are unsynced
	unsynced, _ := storage.GetUnsyncedUsage()
	if len(unsynced) != 3 {
		t.Errorf("Expected 3 unsynced records, got %d", len(unsynced))
	}

	// Mark first two as synced (before current time minus 30 minutes)
	cutoff := now.Add(-30 * time.Minute)
	err := storage.MarkUsageSynced(cutoff)
	if err != nil {
		t.Fatalf("MarkUsageSynced failed: %v", err)
	}

	// Now only one should be unsynced (usage3)
	unsynced, _ = storage.GetUnsyncedUsage()
	if len(unsynced) != 1 {
		t.Errorf("Expected 1 unsynced record after marking, got %d", len(unsynced))
	}
	if unsynced[0].Tokens != 3000 {
		t.Errorf("Expected unsynced record to have 3000 tokens, got %d", unsynced[0].Tokens)
	}
}

// TestGetUsageStats tests usage statistics retrieval
func TestGetUsageStats(t *testing.T) {
	storage, _ := setupTestStorage(t)

	now := time.Now()

	// Add usage records for different actions
	usages := []TokenUsage{
		{Action: "autopent", Tokens: 10000, Timestamp: now.Add(-1 * time.Hour)},
		{Action: "autopent", Tokens: 15000, Timestamp: now.Add(-30 * time.Minute)},
		{Action: "chat", Tokens: 5000, Timestamp: now.Add(-45 * time.Minute)},
		{Action: "scan", Tokens: 2000, Timestamp: now.Add(-15 * time.Minute)},
		{Action: "chat", Tokens: 3000, Timestamp: now.Add(-10 * time.Minute)},
	}

	for _, u := range usages {
		storage.AddUsage(u)
	}

	// Get stats for the last 2 hours
	from := now.Add(-2 * time.Hour)
	to := now
	stats, err := storage.GetUsageStats(from, to)
	if err != nil {
		t.Fatalf("GetUsageStats failed: %v", err)
	}

	// Verify stats
	if stats["autopent"] != 25000 {
		t.Errorf("Expected autopent total 25000, got %d", stats["autopent"])
	}
	if stats["chat"] != 8000 {
		t.Errorf("Expected chat total 8000, got %d", stats["chat"])
	}
	if stats["scan"] != 2000 {
		t.Errorf("Expected scan total 2000, got %d", stats["scan"])
	}
}

// TestSaveDevice tests device registration
func TestSaveDevice(t *testing.T) {
	storage, _ := setupTestStorage(t)

	device := Device{
		DeviceID: "device-abc123",
		Name:     "test-laptop",
		Platform: "linux",
	}

	// Save device
	err := storage.SaveDevice(device)
	if err != nil {
		t.Fatalf("SaveDevice failed: %v", err)
	}

	// Update last seen
	time.Sleep(100 * time.Millisecond)
	err = storage.UpdateDeviceLastSeen(device.DeviceID)
	if err != nil {
		t.Fatalf("UpdateDeviceLastSeen failed: %v", err)
	}
}

// TestGetSetting tests settings storage
func TestGetSetting(t *testing.T) {
	storage, _ := setupTestStorage(t)

	// Set a setting
	err := storage.SetSetting("test_key", "test_value")
	if err != nil {
		t.Fatalf("SetSetting failed: %v", err)
	}

	// Get the setting
	value, err := storage.GetSetting("test_key")
	if err != nil {
		t.Fatalf("GetSetting failed: %v", err)
	}

	if value != "test_value" {
		t.Errorf("Expected value 'test_value', got '%s'", value)
	}

	// Get non-existent setting
	value, err = storage.GetSetting("non_existent")
	if err != nil {
		t.Fatalf("GetSetting for non-existent key failed: %v", err)
	}
	if value != "" {
		t.Errorf("Expected empty string for non-existent key, got '%s'", value)
	}
}

// TestPruneOldUsage tests pruning of old synced usage records
func TestPruneOldUsage(t *testing.T) {
	storage, _ := setupTestStorage(t)

	now := time.Now()

	// Add old usage records (already synced)
	oldUsages := []TokenUsage{
		{Action: "old1", Tokens: 1000, Timestamp: now.Add(-40 * 24 * time.Hour)},
		{Action: "old2", Tokens: 2000, Timestamp: now.Add(-50 * 24 * time.Hour)},
	}
	// Add recent usage
	recentUsages := []TokenUsage{
		{Action: "recent1", Tokens: 3000, Timestamp: now.Add(-10 * 24 * time.Hour)},
		{Action: "recent2", Tokens: 4000, Timestamp: now.Add(-5 * 24 * time.Hour)},
	}

	// Add all usage
	for _, u := range oldUsages {
		storage.AddUsage(u)
	}
	for _, u := range recentUsages {
		storage.AddUsage(u)
	}

	// Mark all as synced
	storage.MarkUsageSynced(now)

	// Get total before pruning
	totalBefore, _ := storage.GetTotalTokensUsed()
	expectedBefore := int64(10000) // 1000 + 2000 + 3000 + 4000
	if totalBefore != expectedBefore {
		t.Errorf("Expected total before pruning %d, got %d", expectedBefore, totalBefore)
	}

	// Prune records older than 30 days
	err := storage.PruneOldUsage(30)
	if err != nil {
		t.Fatalf("PruneOldUsage failed: %v", err)
	}

	// Get total after pruning (should only have recent records)
	totalAfter, _ := storage.GetTotalTokensUsed()
	expectedAfter := int64(7000) // 3000 + 4000
	if totalAfter != expectedAfter {
		t.Errorf("Expected total after pruning %d, got %d", expectedAfter, totalAfter)
	}
}

// TestSessionUpdate tests updating an existing session
func TestSessionUpdate(t *testing.T) {
	storage, _ := setupTestStorage(t)

	// Save initial session
	session1 := &AuthSession{
		AccessToken: "token1",
		UserID:      "user1",
		Email:       "user1@example.com",
	}
	storage.SaveSession(session1)

	// Update with new session
	session2 := &AuthSession{
		AccessToken:  "token2",
		RefreshToken: "refresh2",
		UserID:       "user2",
		Email:        "user2@example.com",
		ExpiresAt:    time.Now().Add(48 * time.Hour),
	}
	storage.SaveSession(session2)

	// Load and verify it was replaced (not appended)
	loaded, _ := storage.LoadSession()
	if loaded.AccessToken != session2.AccessToken {
		t.Errorf("Expected access token %s, got %s", session2.AccessToken, loaded.AccessToken)
	}
	if loaded.UserID != session2.UserID {
		t.Errorf("Expected user ID %s, got %s", session2.UserID, loaded.UserID)
	}
}

// TestLicenseUpdate tests updating an existing license
func TestLicenseUpdate(t *testing.T) {
	storage, _ := setupTestStorage(t)

	// Save initial license
	license1 := &License{
		Tier:            TierFree,
		TokensRemaining: 0,
	}
	storage.SaveLicense(license1)

	// Update with new license
	license2 := &License{
		Tier:            TierPro,
		TokensRemaining: 2000000,
		TokensLimit:     3000000,
		Features:        []Feature{FeatureCloudAI, FeatureAutopent},
	}
	storage.SaveLicense(license2)

	// Load and verify it was replaced
	loaded, _ := storage.LoadLicense()
	if loaded.Tier != license2.Tier {
		t.Errorf("Expected tier %v, got %v", license2.Tier, loaded.Tier)
	}
	if loaded.TokensRemaining != license2.TokensRemaining {
		t.Errorf("Expected tokens %d, got %d", license2.TokensRemaining, loaded.TokensRemaining)
	}
}

// TestStorageInitialization tests database schema initialization
func TestStorageInitialization(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_init.db")

	// Verify database doesn't exist yet
	if _, err := os.Stat(dbPath); err == nil {
		t.Fatal("Database should not exist before setup")
	}

	// Create database directory
	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	// Create storage
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	storage := &Storage{db: db}
	if err := storage.init(); err != nil {
		t.Fatalf("Failed to initialize storage: %v", err)
	}
	defer storage.Close()

	// Verify database was created
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database should exist after initialization")
	}

	// Verify we can interact with it
	session := &AuthSession{
		AccessToken: "test",
		UserID:      "test-user",
	}
	if err := storage.SaveSession(session); err != nil {
		t.Errorf("SaveSession failed after initialization: %v", err)
	}
}

// TestConcurrentAccess tests concurrent reads/writes to storage
func TestConcurrentAccess(t *testing.T) {
	storage, _ := setupTestStorage(t)

	// Perform concurrent operations
	done := make(chan bool)
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			// Add usage
			usage := TokenUsage{
				Action:    "concurrent",
				Tokens:    int64(id * 100),
				Timestamp: time.Now(),
			}
			storage.AddUsage(usage)

			// Read session
			storage.LoadSession()

			// Read license
			storage.LoadLicense()

			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify total usage
	total, err := storage.GetTotalTokensUsed()
	if err != nil {
		t.Fatalf("GetTotalTokensUsed failed: %v", err)
	}

	// Expected: 0 + 100 + 200 + ... + 900 = 4500
	expected := int64(0)
	for i := 0; i < numGoroutines; i++ {
		expected += int64(i * 100)
	}

	if total != expected {
		t.Errorf("Expected total %d, got %d", expected, total)
	}
}
