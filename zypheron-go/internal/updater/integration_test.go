// +build integration

package updater

import (
	"os"
	"testing"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"
)

// Integration tests that require network access
// Run with: go test -tags=integration ./internal/updater/

func TestCheckForUpdatesLive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := config.DefaultConfig()
	cfg.CheckUpdates = true

	// Create temp cache dir
	tempDir, err := os.MkdirTemp("", "zypheron-integration-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	cfg.CacheDir = tempDir

	updater := New(cfg)

	// This will make an actual API call to GitHub
	info, err := updater.checkRemote()
	if err != nil {
		t.Fatalf("checkRemote() error = %v", err)
	}

	if info == nil {
		t.Fatal("checkRemote() returned nil info")
	}

	if info.CurrentVersion == "" {
		t.Error("CurrentVersion is empty")
	}

	if info.LatestVersion == "" {
		t.Error("LatestVersion is empty")
	}

	if info.ReleaseURL == "" {
		t.Error("ReleaseURL is empty")
	}

	if info.LastChecked.IsZero() {
		t.Error("LastChecked is zero")
	}

	t.Logf("Current: %s, Latest: %s, Update Available: %v",
		info.CurrentVersion, info.LatestVersion, info.UpdateAvailable)
}

func TestGetReleaseNotesLive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := config.DefaultConfig()
	updater := New(cfg)

	// Try to get release notes for a known version
	// This makes an actual API call
	notes, err := updater.GetReleaseNotes("1.0.0")

	// We don't fail if the version doesn't exist, just log it
	if err != nil {
		t.Logf("Note: GetReleaseNotes returned error (this is expected if v1.0.0 release doesn't exist): %v", err)
		return
	}

	t.Logf("Release notes length: %d characters", len(notes))
}

func TestCachePerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := config.DefaultConfig()
	cfg.CheckUpdates = true

	tempDir, err := os.MkdirTemp("", "zypheron-cache-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	cfg.CacheDir = tempDir

	updater := New(cfg)

	// First call - should hit API
	start := time.Now()
	info1, err := updater.CheckForUpdates()
	duration1 := time.Since(start)

	if err != nil {
		t.Fatalf("First CheckForUpdates() error = %v", err)
	}

	// Second call - should use cache
	start = time.Now()
	info2, err := updater.CheckForUpdates()
	duration2 := time.Since(start)

	if err != nil {
		t.Fatalf("Second CheckForUpdates() error = %v", err)
	}

	// Cache should be significantly faster
	if duration2 > duration1 {
		t.Errorf("Cached call slower than API call: %v vs %v", duration2, duration1)
	}

	// Results should be identical
	if info1.LatestVersion != info2.LatestVersion {
		t.Errorf("Cache returned different version: %s vs %s",
			info1.LatestVersion, info2.LatestVersion)
	}

	t.Logf("API call: %v, Cached call: %v (%.2fx faster)",
		duration1, duration2, float64(duration1)/float64(duration2))
}

func TestRateLimitHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// This test verifies graceful handling of rate limits
	// In practice, you won't hit the limit unless making many requests
	cfg := config.DefaultConfig()
	updater := New(cfg)

	_, err := updater.checkRemote()
	if err != nil {
		// Check if it's a rate limit error
		if err.Error() == "GitHub API rate limit exceeded, try again later" {
			t.Log("Rate limit error handled correctly")
		} else {
			t.Fatalf("Unexpected error: %v", err)
		}
	}
}
