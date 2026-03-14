package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"
)

func TestGetCurrentVersion(t *testing.T) {
	version := GetCurrentVersion()
	if version == "" {
		t.Error("GetCurrentVersion returned empty string")
	}
	if version != CurrentVersion {
		t.Errorf("GetCurrentVersion() = %s, want %s", version, CurrentVersion)
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		version string
		want    []int
	}{
		{"1.0.0", []int{1, 0, 0}},
		{"2.3.4", []int{2, 3, 4}},
		{"1.0.0-beta.1", []int{1, 0, 0}},
		{"1.0.0+build.123", []int{1, 0, 0}},
		{"v1.2.3", []int{1, 2, 3}},
		{"1.0", []int{1, 0, 0}},
		{"1", []int{1, 0, 0}},
	}

	for _, tt := range tests {
		got := parseVersion(tt.version)
		if len(got) < 3 {
			t.Errorf("parseVersion(%s) returned %d parts, want at least 3", tt.version, len(got))
			continue
		}
		for i := 0; i < 3; i++ {
			if got[i] != tt.want[i] {
				t.Errorf("parseVersion(%s)[%d] = %d, want %d", tt.version, i, got[i], tt.want[i])
			}
		}
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool // true if update available (latest > current)
	}{
		{"1.0.0", "1.0.1", true},
		{"1.0.0", "1.1.0", true},
		{"1.0.0", "2.0.0", true},
		{"1.0.0", "1.0.0", false},
		{"1.0.1", "1.0.0", false},
		{"2.0.0", "1.9.9", false},
		{"v1.0.0", "v1.0.1", true},
		{"1.0.0-beta", "1.0.0", false}, // After stripping suffix, both are 1.0.0
		{"1.0.0", "1.0.0-beta", false}, // After stripping suffix, both are 1.0.0
		{"1.0.0-beta", "1.0.1", true},  // 1.0.0 < 1.0.1
	}

	for _, tt := range tests {
		got := compareVersions(tt.current, tt.latest)
		if got != tt.want {
			t.Errorf("compareVersions(%s, %s) = %v, want %v", tt.current, tt.latest, got, tt.want)
		}
	}
}

func TestUpdaterNew(t *testing.T) {
	cfg := config.DefaultConfig()
	updater := New(cfg)

	if updater == nil {
		t.Fatal("New() returned nil")
	}

	if updater.config != cfg {
		t.Error("Updater config not set correctly")
	}

	if updater.httpClient == nil {
		t.Error("HTTP client not initialized")
	}

	if updater.cachePath == "" {
		t.Error("Cache path not set")
	}

	expectedCache := filepath.Join(cfg.CacheDir, CacheFileName)
	if updater.cachePath != expectedCache {
		t.Errorf("Cache path = %s, want %s", updater.cachePath, expectedCache)
	}
}

func TestSaveAndLoadCache(t *testing.T) {
	// Create temp directory for cache
	tempDir, err := os.MkdirTemp("", "zypheron-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := config.DefaultConfig()
	cfg.CacheDir = tempDir

	updater := New(cfg)

	// Create test update info
	testInfo := &UpdateInfo{
		CurrentVersion:  "1.0.0",
		LatestVersion:   "1.0.1",
		UpdateAvailable: true,
		ReleaseURL:      "https://github.com/test/test",
		ReleaseNotes:    "Test release notes",
		PublishedAt:     time.Now().UTC().Truncate(time.Second),
		LastChecked:     time.Now().UTC().Truncate(time.Second),
	}

	// Save cache
	if err := updater.saveCache(testInfo); err != nil {
		t.Fatalf("saveCache() error = %v", err)
	}

	// Load cache
	loaded, err := updater.loadCache()
	if err != nil {
		t.Fatalf("loadCache() error = %v", err)
	}

	// Verify loaded data
	if loaded.CurrentVersion != testInfo.CurrentVersion {
		t.Errorf("CurrentVersion = %s, want %s", loaded.CurrentVersion, testInfo.CurrentVersion)
	}
	if loaded.LatestVersion != testInfo.LatestVersion {
		t.Errorf("LatestVersion = %s, want %s", loaded.LatestVersion, testInfo.LatestVersion)
	}
	if loaded.UpdateAvailable != testInfo.UpdateAvailable {
		t.Errorf("UpdateAvailable = %v, want %v", loaded.UpdateAvailable, testInfo.UpdateAvailable)
	}
	if loaded.ReleaseURL != testInfo.ReleaseURL {
		t.Errorf("ReleaseURL = %s, want %s", loaded.ReleaseURL, testInfo.ReleaseURL)
	}
}

func TestShouldCheckForUpdates(t *testing.T) {
	// Test with updates disabled
	cfg := config.DefaultConfig()
	cfg.CheckUpdates = false

	if ShouldCheckForUpdates(cfg) {
		t.Error("ShouldCheckForUpdates() = true when updates disabled, want false")
	}

	// Test with updates enabled but no cache
	cfg.CheckUpdates = true
	tempDir, err := os.MkdirTemp("", "zypheron-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	cfg.CacheDir = tempDir

	if !ShouldCheckForUpdates(cfg) {
		t.Error("ShouldCheckForUpdates() = false with no cache, want true")
	}

	// Test with recent cache
	updater := New(cfg)
	testInfo := &UpdateInfo{
		CurrentVersion:  "1.0.0",
		LatestVersion:   "1.0.0",
		UpdateAvailable: false,
		LastChecked:     time.Now(),
	}
	_ = updater.saveCache(testInfo)

	if ShouldCheckForUpdates(cfg) {
		t.Error("ShouldCheckForUpdates() = true with recent cache, want false")
	}

	// Test with expired cache
	testInfo.LastChecked = time.Now().Add(-25 * time.Hour)
	_ = updater.saveCache(testInfo)

	if !ShouldCheckForUpdates(cfg) {
		t.Error("ShouldCheckForUpdates() = false with expired cache, want true")
	}
}

func TestGetAssetName(t *testing.T) {
	cfg := config.DefaultConfig()
	updater := New(cfg)

	ext := "tar.gz"
	if runtime.GOOS == "windows" {
		ext = "zip"
	}
	want := "zypheron-" + runtime.GOOS + "-" + runtime.GOARCH + "." + ext

	got := updater.getAssetName("v2.0.0")
	if got != want {
		t.Errorf("getAssetName() = %s, want %s", got, want)
	}
}

func TestLookupChecksum(t *testing.T) {
	tempDir := t.TempDir()
	checksumFile := filepath.Join(tempDir, "SHA256SUMS")
	content := "abc123  zypheron-linux-amd64.tar.gz\nfff999  zypheron-windows-amd64.zip\n"
	if err := os.WriteFile(checksumFile, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write checksum file: %v", err)
	}

	got, err := lookupChecksum("zypheron-linux-amd64.tar.gz", checksumFile)
	if err != nil {
		t.Fatalf("lookupChecksum() error = %v", err)
	}
	if got != "abc123" {
		t.Errorf("lookupChecksum() = %s, want abc123", got)
	}
}

func TestLookupChecksumMissingEntry(t *testing.T) {
	tempDir := t.TempDir()
	checksumFile := filepath.Join(tempDir, "SHA256SUMS")
	if err := os.WriteFile(checksumFile, []byte("abc123  other-file.tar.gz\n"), 0o600); err != nil {
		t.Fatalf("failed to write checksum file: %v", err)
	}

	if _, err := lookupChecksum("zypheron-linux-amd64.tar.gz", checksumFile); err == nil {
		t.Fatal("lookupChecksum() expected error for missing entry")
	}
}

func TestFindReleaseAssetURL(t *testing.T) {
	release := &GitHubRelease{
		Assets: []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Size               int64  `json:"size"`
		}{
			{Name: "SHA256SUMS", BrowserDownloadURL: "https://example.com/SHA256SUMS"},
			{Name: "zypheron-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.com/zypheron-linux-amd64.tar.gz"},
		},
	}

	got := findReleaseAssetURL(release, "SHA256SUMS")
	if got != "https://example.com/SHA256SUMS" {
		t.Errorf("findReleaseAssetURL() = %s, want checksum URL", got)
	}

	missing := findReleaseAssetURL(release, "missing")
	if missing != "" {
		t.Errorf("findReleaseAssetURL() for missing asset = %s, want empty string", missing)
	}
}

func TestNewUpdateWorkspace(t *testing.T) {
	workspace, err := newUpdateWorkspace("zypheron-linux-amd64.tar.gz")
	if err != nil {
		t.Fatalf("newUpdateWorkspace() error = %v", err)
	}
	defer os.RemoveAll(workspace.rootDir)

	if workspace.rootDir == "" {
		t.Fatal("workspace rootDir is empty")
	}
	if !strings.Contains(filepath.Base(workspace.rootDir), "zypheron-update-") {
		t.Fatalf("workspace rootDir %q does not look like a private temp dir", workspace.rootDir)
	}
	if filepath.Dir(workspace.archivePath) != workspace.rootDir {
		t.Fatalf("archivePath %q is not inside workspace root %q", workspace.archivePath, workspace.rootDir)
	}
	if filepath.Dir(workspace.checksumPath) != workspace.rootDir {
		t.Fatalf("checksumPath %q is not inside workspace root %q", workspace.checksumPath, workspace.rootDir)
	}
	if filepath.Dir(workspace.extractDir) != workspace.rootDir {
		t.Fatalf("extractDir %q is not inside workspace root %q", workspace.extractDir, workspace.rootDir)
	}
	info, err := os.Stat(workspace.extractDir)
	if err != nil {
		t.Fatalf("extractDir stat failed: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("extractDir %q is not a directory", workspace.extractDir)
	}
}

func TestExtractZipArchiveRejectsPathTraversal(t *testing.T) {
	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "malicious.zip")
	createZipArchive(t, archivePath, map[string][]byte{
		"../../evil": []byte("owned"),
		"zypheron":   []byte("#!/bin/sh\necho safe\n"),
	})

	_, err := extractZipArchive(archivePath, filepath.Join(tempDir, "extract"))
	if err == nil {
		t.Fatal("extractZipArchive() expected path traversal error")
	}
	if !strings.Contains(err.Error(), "escapes extraction directory") {
		t.Fatalf("extractZipArchive() error = %v, want path traversal rejection", err)
	}
}

func TestExtractTarGzArchiveRejectsPathTraversal(t *testing.T) {
	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "malicious.tar.gz")
	createTarGzArchive(t, archivePath, map[string][]byte{
		"../../evil": []byte("owned"),
		"zypheron":   []byte("#!/bin/sh\necho safe\n"),
	})

	_, err := extractTarGzArchive(archivePath, filepath.Join(tempDir, "extract"))
	if err == nil {
		t.Fatal("extractTarGzArchive() expected path traversal error")
	}
	if !strings.Contains(err.Error(), "escapes extraction directory") {
		t.Fatalf("extractTarGzArchive() error = %v, want path traversal rejection", err)
	}
}

func TestExtractZipArchiveExtractsBinaryWithinDestination(t *testing.T) {
	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "release.zip")
	createZipArchive(t, archivePath, map[string][]byte{
		"nested/zypheron": []byte("#!/bin/sh\necho release\n"),
	})

	binaryPath, err := extractZipArchive(archivePath, filepath.Join(tempDir, "extract"))
	if err != nil {
		t.Fatalf("extractZipArchive() error = %v", err)
	}
	if !strings.HasPrefix(binaryPath, filepath.Join(tempDir, "extract")+string(os.PathSeparator)) {
		t.Fatalf("binaryPath %q is outside extraction root", binaryPath)
	}
}

func TestExtractTarGzArchiveExtractsBinaryWithinDestination(t *testing.T) {
	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "release.tar.gz")
	createTarGzArchive(t, archivePath, map[string][]byte{
		"nested/zypheron": []byte("#!/bin/sh\necho release\n"),
	})

	binaryPath, err := extractTarGzArchive(archivePath, filepath.Join(tempDir, "extract"))
	if err != nil {
		t.Fatalf("extractTarGzArchive() error = %v", err)
	}
	if !strings.HasPrefix(binaryPath, filepath.Join(tempDir, "extract")+string(os.PathSeparator)) {
		t.Fatalf("binaryPath %q is outside extraction root", binaryPath)
	}
}

func createZipArchive(t *testing.T, archivePath string, files map[string][]byte) {
	t.Helper()

	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("failed to create zip archive: %v", err)
	}
	defer file.Close()

	writer := zip.NewWriter(file)
	for name, data := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatalf("failed to create zip entry %q: %v", name, err)
		}
		if _, err := entry.Write(data); err != nil {
			t.Fatalf("failed to write zip entry %q: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close zip archive: %v", err)
	}
}

func createTarGzArchive(t *testing.T, archivePath string, files map[string][]byte) {
	t.Helper()

	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("failed to create tar.gz archive: %v", err)
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, data := range files {
		header := &tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(data)),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("failed to write tar header %q: %v", name, err)
		}
		if _, err := io.Copy(tarWriter, strings.NewReader(string(data))); err != nil {
			t.Fatalf("failed to write tar entry %q: %v", name, err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}
}

func TestCheckForUpdatesWithDisabledConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.CheckUpdates = false

	updater := New(cfg)
	info, err := updater.CheckForUpdates()

	if err != nil {
		t.Errorf("CheckForUpdates() error = %v, want nil", err)
	}

	if info.UpdateAvailable {
		t.Error("CheckForUpdates() with disabled config returned UpdateAvailable = true, want false")
	}

	if info.CurrentVersion != GetCurrentVersion() {
		t.Errorf("CurrentVersion = %s, want %s", info.CurrentVersion, GetCurrentVersion())
	}
}

// TestCheckForUpdatesAsync tests the async update check function
func TestCheckForUpdatesAsync(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.CheckUpdates = false // Disable to avoid actual API calls

	done := make(chan bool)
	var receivedInfo *UpdateInfo
	var receivedErr error

	callback := func(info *UpdateInfo, err error) {
		receivedInfo = info
		receivedErr = err
		done <- true
	}

	CheckForUpdatesAsync(cfg, callback)

	// Wait for callback with timeout
	select {
	case <-done:
		if receivedErr != nil {
			t.Errorf("Async check returned error: %v", receivedErr)
		}
		if receivedInfo == nil {
			t.Error("Async check returned nil info")
		}
	case <-time.After(2 * time.Second):
		t.Error("Async check timed out")
	}
}
