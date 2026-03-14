package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/errors"
)

const (
	// GitHub API endpoint for latest release
	GitHubReleasesAPI = "https://api.github.com/repos/KKingZero/Cobra-AI/releases/latest"

	// Cache duration for update checks (24 hours)
	CacheDuration = 24 * time.Hour

	// HTTP timeout for API requests
	HTTPTimeout = 10 * time.Second

	// Cache filename
	CacheFileName = "update_check.json"

	// Current version - synced with cmd/zypheron/main.go
	// This should be updated when version changes or can be injected via build flags
	CurrentVersion = "2.0.0"
)

// UpdateInfo contains information about available updates
type UpdateInfo struct {
	CurrentVersion  string    `json:"current_version"`
	LatestVersion   string    `json:"latest_version"`
	UpdateAvailable bool      `json:"update_available"`
	ReleaseURL      string    `json:"release_url"`
	ReleaseNotes    string    `json:"release_notes"`
	PublishedAt     time.Time `json:"published_at"`
	LastChecked     time.Time `json:"last_checked"`
}

// GitHubRelease represents a GitHub release response
type GitHubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`
	Draft       bool      `json:"draft"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

// Updater handles update checking and downloading
type Updater struct {
	config     *config.Config
	httpClient *http.Client
	cachePath  string
}

// New creates a new Updater instance
func New(cfg *config.Config) *Updater {
	if cfg == nil {
		cfg = config.Get()
	}

	cachePath := filepath.Join(cfg.CacheDir, CacheFileName)

	return &Updater{
		config: cfg,
		httpClient: &http.Client{
			Timeout: HTTPTimeout,
		},
		cachePath: cachePath,
	}
}

// GetCurrentVersion returns the current version of the CLI
func GetCurrentVersion() string {
	// In production, this could be injected via build flags:
	// go build -ldflags "-X github.com/KKingZero/Cobra-AI/zypheron-go/internal/updater.CurrentVersion=1.2.3"
	return CurrentVersion
}

// CheckForUpdates checks if a new version is available
// Returns cached result if check was performed within CacheDuration
func (u *Updater) CheckForUpdates() (*UpdateInfo, error) {
	// Check if updates are disabled in config
	if !u.config.CheckUpdates {
		return &UpdateInfo{
			CurrentVersion:  GetCurrentVersion(),
			LatestVersion:   GetCurrentVersion(),
			UpdateAvailable: false,
			LastChecked:     time.Now(),
		}, nil
	}

	// Try to load from cache first
	cached, err := u.loadCache()
	if err == nil && time.Since(cached.LastChecked) < CacheDuration {
		// Cache is valid, return it
		return cached, nil
	}

	// Cache miss or expired, fetch from API
	return u.checkRemote()
}

// IsUpdateAvailable is a convenience method that returns update status
func (u *Updater) IsUpdateAvailable() (bool, string, error) {
	info, err := u.CheckForUpdates()
	if err != nil {
		return false, "", err
	}
	return info.UpdateAvailable, info.LatestVersion, nil
}

// GetReleaseNotes fetches release notes for a specific version
func (u *Updater) GetReleaseNotes(version string) (string, error) {
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	// Construct API URL for specific release
	url := fmt.Sprintf("https://api.github.com/repos/KKingZero/Cobra-AI/releases/tags/%s", version)

	release, err := u.fetchRelease(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch release notes: %w", err)
	}

	return release.Body, nil
}

// DownloadUpdate downloads and installs the update for the current platform.
func (u *Updater) DownloadUpdate(version string) error {
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	// Get release info
	url := fmt.Sprintf("https://api.github.com/repos/KKingZero/Cobra-AI/releases/tags/%s", version)
	release, err := u.fetchRelease(url)
	if err != nil {
		return fmt.Errorf("failed to fetch release info: %w", err)
	}

	// Determine asset name based on platform
	assetName := u.getAssetName(version)

	// Find matching asset
	var downloadURL string
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("no matching asset found for platform %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	workspace, err := newUpdateWorkspace(assetName)
	if err != nil {
		return fmt.Errorf("failed to create update workspace: %w", err)
	}
	defer os.RemoveAll(workspace.rootDir)

	// Download the file
	if err := u.downloadFile(downloadURL, workspace.archivePath); err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}

	checksumURL := findReleaseAssetURL(release, "SHA256SUMS")
	if checksumURL == "" {
		return fmt.Errorf("release is missing SHA256SUMS asset")
	}
	if err := u.downloadFile(checksumURL, workspace.checksumPath); err != nil {
		return fmt.Errorf("failed to download checksums: %w", err)
	}
	if err := verifyDownloadedChecksum(workspace.archivePath, workspace.checksumPath); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	binaryPath, err := extractReleaseArchive(workspace.archivePath, workspace.extractDir)
	if err != nil {
		return fmt.Errorf("failed to extract update archive: %w", err)
	}
	if err := replaceCurrentBinary(binaryPath); err != nil {
		return fmt.Errorf("downloaded and verified update, but failed to replace current binary: %w", err)
	}

	return nil
}

type updateWorkspace struct {
	rootDir      string
	archivePath  string
	checksumPath string
	extractDir   string
}

func newUpdateWorkspace(assetName string) (*updateWorkspace, error) {
	rootDir, err := os.MkdirTemp("", "zypheron-update-*")
	if err != nil {
		return nil, err
	}

	workspace := &updateWorkspace{
		rootDir:      rootDir,
		archivePath:  filepath.Join(rootDir, assetName),
		checksumPath: filepath.Join(rootDir, "SHA256SUMS"),
		extractDir:   filepath.Join(rootDir, "extracted"),
	}

	if err := os.MkdirAll(workspace.extractDir, 0o700); err != nil {
		_ = os.RemoveAll(rootDir)
		return nil, err
	}

	return workspace, nil
}

// checkRemote fetches the latest release from GitHub API
func (u *Updater) checkRemote() (*UpdateInfo, error) {
	release, err := u.fetchRelease(GitHubReleasesAPI)
	if err != nil {
		return nil, err
	}

	// Skip draft and prerelease versions
	if release.Draft || release.Prerelease {
		return &UpdateInfo{
			CurrentVersion:  GetCurrentVersion(),
			LatestVersion:   GetCurrentVersion(),
			UpdateAvailable: false,
			LastChecked:     time.Now(),
		}, nil
	}

	currentVer := GetCurrentVersion()
	latestVer := strings.TrimPrefix(release.TagName, "v")

	updateAvailable := compareVersions(currentVer, latestVer)

	info := &UpdateInfo{
		CurrentVersion:  currentVer,
		LatestVersion:   latestVer,
		UpdateAvailable: updateAvailable,
		ReleaseURL:      release.HTMLURL,
		ReleaseNotes:    release.Body,
		PublishedAt:     release.PublishedAt,
		LastChecked:     time.Now(),
	}

	// Save to cache
	_ = u.saveCache(info)

	return info, nil
}

// fetchRelease fetches a GitHub release from the API
func (u *Updater) fetchRelease(url string) (*GitHubRelease, error) {
	ctx, cancel := context.WithTimeout(context.Background(), HTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set User-Agent (required by GitHub API)
	req.Header.Set("User-Agent", "Zypheron-CLI/"+GetCurrentVersion())
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	// GitHub token if available (to avoid rate limiting)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "token "+token)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch release: %w", err)
	}
	defer resp.Body.Close()

	// Handle rate limiting
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, errors.NetworkError("GitHub API rate limit exceeded, try again later")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(body))
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to decode release info: %w", err)
	}

	return &release, nil
}

// downloadFile downloads a file from a URL to a destination path
func (u *Updater) downloadFile(url, destPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// getAssetName returns the expected asset name for the current platform
func (u *Updater) getAssetName(version string) string {
	ext := "tar.gz"
	if runtime.GOOS == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("zypheron-%s-%s.%s", runtime.GOOS, runtime.GOARCH, ext)
}

func findReleaseAssetURL(release *GitHubRelease, assetName string) string {
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			return asset.BrowserDownloadURL
		}
	}
	return ""
}

func verifyDownloadedChecksum(filePath, checksumPath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open downloaded file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("failed to hash downloaded file: %w", err)
	}
	actual := fmt.Sprintf("%x", hash.Sum(nil))
	expected, err := lookupChecksum(filepath.Base(filePath), checksumPath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("expected %s, got %s", expected, actual)
	}
	return nil
}

func lookupChecksum(fileName, checksumPath string) (string, error) {
	data, err := os.ReadFile(checksumPath)
	if err != nil {
		return "", fmt.Errorf("failed to read checksum file: %w", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == fileName {
			return fields[0], nil
		}
	}

	return "", fmt.Errorf("checksum entry not found for %s", fileName)
}

func extractReleaseArchive(archivePath, destDir string) (string, error) {
	if strings.HasSuffix(archivePath, ".zip") {
		return extractZipArchive(archivePath, destDir)
	}
	if strings.HasSuffix(archivePath, ".tar.gz") {
		return extractTarGzArchive(archivePath, destDir)
	}
	return "", fmt.Errorf("unsupported archive format: %s", archivePath)
}

func extractZipArchive(archivePath, destDir string) (string, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer reader.Close()

	var binaryPath string
	for _, file := range reader.File {
		targetPath, err := secureExtractPath(destDir, file.Name)
		if err != nil {
			return "", err
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return "", err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return "", err
		}
		src, err := file.Open()
		if err != nil {
			return "", err
		}
		dst, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, file.Mode())
		if err != nil {
			src.Close()
			return "", err
		}
		if _, err := io.Copy(dst, src); err != nil {
			src.Close()
			dst.Close()
			return "", err
		}
		src.Close()
		dst.Close()
		if isReleaseBinary(targetPath) {
			binaryPath = targetPath
		}
	}
	if binaryPath == "" {
		return "", fmt.Errorf("binary not found in zip archive")
	}
	return binaryPath, nil
}

func extractTarGzArchive(archivePath, destDir string) (string, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	var binaryPath string
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		targetPath, err := secureExtractPath(destDir, header.Name)
		if err != nil {
			return "", err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return "", err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return "", err
			}
			dst, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return "", err
			}
			if _, err := io.Copy(dst, tr); err != nil {
				dst.Close()
				return "", err
			}
			dst.Close()
			if isReleaseBinary(targetPath) {
				binaryPath = targetPath
			}
		}
	}
	if binaryPath == "" {
		return "", fmt.Errorf("binary not found in tar archive")
	}
	return binaryPath, nil
}

func secureExtractPath(destDir, entryName string) (string, error) {
	cleanedName := filepath.Clean(entryName)
	if cleanedName == "." {
		return "", fmt.Errorf("invalid archive entry %q", entryName)
	}

	destRoot, err := filepath.Abs(destDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve extraction directory: %w", err)
	}

	targetPath := filepath.Join(destRoot, cleanedName)
	targetAbs, err := filepath.Abs(targetPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve archive entry path: %w", err)
	}

	prefix := destRoot + string(os.PathSeparator)
	if targetAbs != destRoot && !strings.HasPrefix(targetAbs, prefix) {
		return "", fmt.Errorf("archive entry %q escapes extraction directory", entryName)
	}

	return targetAbs, nil
}

func isReleaseBinary(path string) bool {
	base := filepath.Base(path)
	if runtime.GOOS == "windows" {
		return base == "zypheron.exe"
	}
	return base == "zypheron"
}

func replaceCurrentBinary(newBinaryPath string) error {
	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to resolve current executable: %w", err)
	}

	newFile, err := os.Open(newBinaryPath)
	if err != nil {
		return fmt.Errorf("failed to open replacement binary: %w", err)
	}
	defer newFile.Close()

	info, err := newFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat replacement binary: %w", err)
	}

	stagedPath := currentBinary + ".new"
	backupPath := currentBinary + ".bak"

	stagedFile, err := os.OpenFile(stagedPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return fmt.Errorf("failed to stage replacement binary: %w", err)
	}
	if _, err := io.Copy(stagedFile, newFile); err != nil {
		stagedFile.Close()
		return fmt.Errorf("failed to stage replacement binary: %w", err)
	}
	if err := stagedFile.Close(); err != nil {
		return fmt.Errorf("failed to finalize staged binary: %w", err)
	}

	_ = os.Remove(backupPath)
	if err := os.Rename(currentBinary, backupPath); err != nil {
		return fmt.Errorf("failed to move current binary aside (try running with elevated permissions): %w", err)
	}
	if err := os.Rename(stagedPath, currentBinary); err != nil {
		_ = os.Rename(backupPath, currentBinary)
		return fmt.Errorf("failed to activate new binary: %w", err)
	}
	_ = os.Remove(backupPath)
	return nil
}

// loadCache loads cached update info from disk
func (u *Updater) loadCache() (*UpdateInfo, error) {
	data, err := os.ReadFile(u.cachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache: %w", err)
	}

	var info UpdateInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("failed to parse cache: %w", err)
	}

	return &info, nil
}

// saveCache saves update info to cache file
func (u *Updater) saveCache(info *UpdateInfo) error {
	// Ensure cache directory exists
	if err := os.MkdirAll(filepath.Dir(u.cachePath), 0o700); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %w", err)
	}

	if err := os.WriteFile(u.cachePath, data, 0o600); err != nil {
		return fmt.Errorf("failed to write cache: %w", err)
	}

	return nil
}

// compareVersions compares two semantic versions
// Returns true if latest > current
func compareVersions(current, latest string) bool {
	// Remove 'v' prefix if present
	current = strings.TrimPrefix(current, "v")
	latest = strings.TrimPrefix(latest, "v")

	// If versions are identical, no update needed
	if current == latest {
		return false
	}

	// Parse versions
	currentParts := parseVersion(current)
	latestParts := parseVersion(latest)

	// Compare major, minor, patch
	for i := 0; i < 3 && i < len(currentParts) && i < len(latestParts); i++ {
		if latestParts[i] > currentParts[i] {
			return true
		}
		if latestParts[i] < currentParts[i] {
			return false
		}
	}

	// If all parts are equal, check if latest has more parts (e.g., 1.0.0.1 > 1.0.0)
	return len(latestParts) > len(currentParts)
}

// parseVersion parses a semantic version string into parts
func parseVersion(version string) []int {
	// Remove 'v' prefix first
	version = strings.TrimPrefix(version, "v")

	// Handle pre-release versions (e.g., 1.0.0-beta.1)
	if idx := strings.IndexAny(version, "-+"); idx != -1 {
		version = version[:idx]
	}

	parts := strings.Split(version, ".")
	result := make([]int, 0, len(parts))

	for _, part := range parts {
		var num int
		fmt.Sscanf(part, "%d", &num)
		result = append(result, num)
	}

	// Ensure at least 3 parts (major, minor, patch)
	for len(result) < 3 {
		result = append(result, 0)
	}

	return result
}

// CheckForUpdatesAsync performs a non-blocking update check
// Useful for checking on startup without blocking the UI
func CheckForUpdatesAsync(cfg *config.Config, callback func(*UpdateInfo, error)) {
	go func() {
		updater := New(cfg)
		info, err := updater.CheckForUpdates()
		if callback != nil {
			callback(info, err)
		}
	}()
}

// ShouldCheckForUpdates determines if an update check should be performed
// based on config settings and last check time
func ShouldCheckForUpdates(cfg *config.Config) bool {
	if !cfg.CheckUpdates {
		return false
	}

	// Check if we have a recent cache
	updater := New(cfg)
	cached, err := updater.loadCache()
	if err == nil && time.Since(cached.LastChecked) < CacheDuration {
		return false // Recent check exists
	}

	return true
}
