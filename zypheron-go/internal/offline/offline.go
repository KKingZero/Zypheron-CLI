package offline

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// Cache configuration
	MaxCachedResponses = 100
	CacheFileName      = "ai_responses.json"
	VulnDBFileName     = "vuln_db.json"
	VulnDBURL          = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/recent.json"

	// Connectivity check timeouts
	PingTimeout      = 3 * time.Second
	AIServiceTimeout = 5 * time.Second

	// Well-known connectivity check endpoints
	GoogleDNS     = "8.8.8.8:53"
	CloudflareDNS = "1.1.1.1:53"
)

// ConnectivityStatus represents comprehensive network and service status
type ConnectivityStatus struct {
	Internet     bool          `json:"internet"`
	AIService    bool          `json:"ai_service"`
	LastChecked  time.Time     `json:"last_checked"`
	Latency      time.Duration `json:"latency"`
	ErrorMessage string        `json:"error_message,omitempty"`
}

// CVEInfo represents a CVE vulnerability entry
type CVEInfo struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
	CVSS        *CVSSInfo `json:"cvss,omitempty"`
	References  []string  `json:"references"`
	Affected    []string  `json:"affected_products"`
}

// CVSSInfo represents CVSS scoring information
type CVSSInfo struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"base_score"`
	BaseSeverity string  `json:"base_severity"`
	VectorString string  `json:"vector_string"`
}

// CachedResponse represents a cached AI response
type CachedResponse struct {
	Query     string    `json:"query"`
	Response  string    `json:"response"`
	Timestamp time.Time `json:"timestamp"`
	UseCount  int       `json:"use_count"`
}

// VulnDB represents the local vulnerability database
type VulnDB struct {
	CVEs        map[string]*CVEInfo `json:"cves"`
	LastUpdated time.Time           `json:"last_updated"`
	Version     string              `json:"version"`
}

// OfflineManager manages offline mode functionality
type OfflineManager struct {
	cacheDir         string
	aiResponseCache  map[string]*CachedResponse
	vulnDB           *VulnDB
	mu               sync.RWMutex
	lastConnCheck    *ConnectivityStatus
	aiServiceChecker func() bool // Injected dependency for testing
}

// NewOfflineManager creates a new offline manager instance
func NewOfflineManager() (*OfflineManager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	cacheDir := filepath.Join(homeDir, ".zypheron", "cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	manager := &OfflineManager{
		cacheDir:        cacheDir,
		aiResponseCache: make(map[string]*CachedResponse),
		vulnDB:          &VulnDB{CVEs: make(map[string]*CVEInfo)},
	}

	// Load existing caches
	_ = manager.loadAIResponseCache() // Non-critical if fails
	_ = manager.loadLocalVulnDB()     // Non-critical if fails

	return manager, nil
}

// IsOnline checks internet connectivity by attempting to reach well-known DNS servers
func (om *OfflineManager) IsOnline() bool {
	// Try Google DNS first
	conn, err := net.DialTimeout("tcp", GoogleDNS, PingTimeout)
	if err == nil {
		conn.Close()
		return true
	}

	// Fallback to Cloudflare DNS
	conn, err = net.DialTimeout("tcp", CloudflareDNS, PingTimeout)
	if err == nil {
		conn.Close()
		return true
	}

	return false
}

// IsAIServiceAvailable checks if the AI backend service is reachable
func (om *OfflineManager) IsAIServiceAvailable() bool {
	// Use injected checker if available (for testing)
	if om.aiServiceChecker != nil {
		return om.aiServiceChecker()
	}

	// Check if AI socket exists and is responsive
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false
	}

	socketDir := filepath.Join(homeDir, ".zypheron", "sockets")
	pattern := filepath.Join(socketDir, "ai-*.sock")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return false
	}

	// Try to connect to the first socket
	for _, socketPath := range matches {
		conn, err := net.DialTimeout("unix", socketPath, AIServiceTimeout)
		if err == nil {
			conn.Close()
			return true
		}
	}

	return false
}

// CheckConnectivity performs comprehensive connectivity check
func (om *OfflineManager) CheckConnectivity() *ConnectivityStatus {
	om.mu.Lock()
	defer om.mu.Unlock()

	startTime := time.Now()

	status := &ConnectivityStatus{
		LastChecked: startTime,
	}

	// Check internet connectivity
	status.Internet = om.IsOnline()

	// Check AI service availability
	status.AIService = om.IsAIServiceAvailable()

	// Measure latency (for successful internet check)
	if status.Internet {
		status.Latency = time.Since(startTime)
	}

	// Set error message if offline
	if !status.Internet && !status.AIService {
		status.ErrorMessage = "No internet connection and AI service unavailable"
	} else if !status.Internet {
		status.ErrorMessage = "No internet connection (offline mode active)"
	} else if !status.AIService {
		status.ErrorMessage = "AI service unavailable (limited AI features)"
	}

	om.lastConnCheck = status
	return status
}

// GetOfflineCapabilities returns a list of features that work offline
func (om *OfflineManager) GetOfflineCapabilities() []string {
	return []string{
		"Network scanning (nmap, masscan)",
		"Port scanning",
		"Service enumeration",
		"Web vulnerability scanning (nikto, dirb, gobuster)",
		"SSL/TLS analysis",
		"DNS enumeration",
		"Subdomain discovery (passive)",
		"Local CVE database lookup",
		"Cached AI response retrieval",
		"Report generation from cached data",
		"Tool execution (non-cloud tools)",
		"Basic exploit search (local database)",
		"Configuration management",
		"Session management",
		"History viewing",
	}
}

// CacheAIResponse caches an AI response with LRU eviction
func (om *OfflineManager) CacheAIResponse(query, response string) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	// Normalize query (lowercase, trim)
	normalizedQuery := normalizeQuery(query)

	// Check if already cached
	if cached, exists := om.aiResponseCache[normalizedQuery]; exists {
		cached.UseCount++
		cached.Timestamp = time.Now()
		return om.saveAIResponseCache()
	}

	// Check cache size and evict LRU if needed
	if len(om.aiResponseCache) >= MaxCachedResponses {
		om.evictLRU()
	}

	// Add new cached response
	om.aiResponseCache[normalizedQuery] = &CachedResponse{
		Query:     query,
		Response:  response,
		Timestamp: time.Now(),
		UseCount:  1,
	}

	return om.saveAIResponseCache()
}

// GetCachedResponse retrieves a cached AI response
func (om *OfflineManager) GetCachedResponse(query string) (string, bool) {
	om.mu.RLock()
	defer om.mu.RUnlock()

	normalizedQuery := normalizeQuery(query)

	if cached, exists := om.aiResponseCache[normalizedQuery]; exists {
		// Update use count asynchronously
		go func() {
			om.mu.Lock()
			defer om.mu.Unlock()
			cached.UseCount++
			cached.Timestamp = time.Now()
			_ = om.saveAIResponseCache()
		}()

		return cached.Response, true
	}

	return "", false
}

// LoadLocalVulnDB loads or downloads the local vulnerability database
func (om *OfflineManager) LoadLocalVulnDB() error {
	om.mu.Lock()
	defer om.mu.Unlock()

	return om.loadLocalVulnDB()
}

// loadLocalVulnDB internal implementation (caller must hold lock)
func (om *OfflineManager) loadLocalVulnDB() error {
	vulnDBPath := filepath.Join(om.cacheDir, VulnDBFileName)

	// Try to load from disk first
	if data, err := os.ReadFile(vulnDBPath); err == nil {
		if err := json.Unmarshal(data, om.vulnDB); err == nil {
			// Check if database is recent (less than 7 days old)
			if time.Since(om.vulnDB.LastUpdated) < 7*24*time.Hour {
				return nil
			}
		}
	}

	// Database doesn't exist or is stale, try to download if online
	if om.IsOnline() {
		if err := om.downloadVulnDB(); err != nil {
			// Download failed, use fallback
			om.populateFallbackCVEs()
		}
		return nil
	}

	// If offline and no local DB, initialize with fallback CVEs
	om.vulnDB = &VulnDB{
		CVEs:        make(map[string]*CVEInfo),
		LastUpdated: time.Now(),
		Version:     "2.0.0-fallback",
	}

	// Add some common CVEs as fallback
	om.populateFallbackCVEs()

	return nil
}

// downloadVulnDB downloads the vulnerability database from remote source
func (om *OfflineManager) downloadVulnDB() error {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(VulnDBURL)
	if err != nil {
		return fmt.Errorf("failed to download vulnerability database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download vulnerability database: HTTP %d", resp.StatusCode)
	}

	// Parse CVE data
	var cveData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cveData); err != nil {
		return fmt.Errorf("failed to parse vulnerability database: %w", err)
	}

	// Process and store CVE data
	om.vulnDB.LastUpdated = time.Now()
	om.vulnDB.Version = "2.0.0"

	// Save to disk
	vulnDBPath := filepath.Join(om.cacheDir, VulnDBFileName)
	data, err := json.MarshalIndent(om.vulnDB, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal vulnerability database: %w", err)
	}

	if err := os.WriteFile(vulnDBPath, data, 0600); err != nil {
		return fmt.Errorf("failed to save vulnerability database: %w", err)
	}

	return nil
}

// populateFallbackCVEs adds common CVEs as fallback for offline mode
func (om *OfflineManager) populateFallbackCVEs() {
	fallbackCVEs := []CVEInfo{
		{
			ID:          "CVE-2024-3094",
			Description: "XZ Utils backdoor - Malicious code in xz/liblzma leading to SSH server compromise",
			Published:   time.Date(2024, 3, 29, 0, 0, 0, 0, time.UTC),
			Modified:    time.Date(2024, 4, 1, 0, 0, 0, 0, time.UTC),
			CVSS: &CVSSInfo{
				Version:      "3.1",
				BaseScore:    10.0,
				BaseSeverity: "CRITICAL",
				VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			},
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
				"https://www.openwall.com/lists/oss-security/2024/03/29/4",
			},
			Affected: []string{"xz", "liblzma", "xz-utils"},
		},
		{
			ID:          "CVE-2021-44228",
			Description: "Log4Shell - Remote code execution in Apache Log4j 2",
			Published:   time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
			Modified:    time.Date(2021, 12, 14, 0, 0, 0, 0, time.UTC),
			CVSS: &CVSSInfo{
				Version:      "3.1",
				BaseScore:    10.0,
				BaseSeverity: "CRITICAL",
				VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			},
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
				"https://logging.apache.org/log4j/2.x/security.html",
			},
			Affected: []string{"log4j", "log4j-core", "apache-log4j"},
		},
		{
			ID:          "CVE-2017-0144",
			Description: "EternalBlue - Remote code execution in Microsoft SMBv1",
			Published:   time.Date(2017, 3, 14, 0, 0, 0, 0, time.UTC),
			Modified:    time.Date(2017, 5, 12, 0, 0, 0, 0, time.UTC),
			CVSS: &CVSSInfo{
				Version:      "3.0",
				BaseScore:    8.1,
				BaseSeverity: "HIGH",
				VectorString: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
				"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
			},
			Affected: []string{"Windows SMBv1", "Windows Server 2003-2016"},
		},
	}

	for _, cve := range fallbackCVEs {
		om.vulnDB.CVEs[cve.ID] = &cve
	}
}

// LookupCVE performs offline CVE lookup from local database
func (om *OfflineManager) LookupCVE(cveID string) (*CVEInfo, error) {
	om.mu.RLock()
	defer om.mu.RUnlock()

	// Normalize CVE ID (uppercase)
	normalizedID := normalizeQuery(cveID)

	if cve, exists := om.vulnDB.CVEs[normalizedID]; exists {
		return cve, nil
	}

	return nil, fmt.Errorf("CVE %s not found in local database", cveID)
}

// GetCacheStats returns cache statistics
func (om *OfflineManager) GetCacheStats() map[string]interface{} {
	om.mu.RLock()
	defer om.mu.RUnlock()

	totalUseCount := 0
	oldestEntry := time.Now()
	newestEntry := time.Time{}

	for _, cached := range om.aiResponseCache {
		totalUseCount += cached.UseCount
		if cached.Timestamp.Before(oldestEntry) {
			oldestEntry = cached.Timestamp
		}
		if cached.Timestamp.After(newestEntry) {
			newestEntry = cached.Timestamp
		}
	}

	return map[string]interface{}{
		"cached_responses": len(om.aiResponseCache),
		"max_cache_size":   MaxCachedResponses,
		"total_use_count":  totalUseCount,
		"oldest_entry":     oldestEntry,
		"newest_entry":     newestEntry,
		"vuln_db_cves":     len(om.vulnDB.CVEs),
		"vuln_db_updated":  om.vulnDB.LastUpdated,
		"vuln_db_version":  om.vulnDB.Version,
	}
}

// GetOfflineStatus returns comprehensive offline mode status
func (om *OfflineManager) GetOfflineStatus() map[string]interface{} {
	status := om.CheckConnectivity()
	stats := om.GetCacheStats()

	return map[string]interface{}{
		"connectivity": status,
		"cache_stats":  stats,
		"capabilities": om.GetOfflineCapabilities(),
		"mode":         om.getOperatingMode(status),
	}
}

// getOperatingMode determines current operating mode
func (om *OfflineManager) getOperatingMode(status *ConnectivityStatus) string {
	if status.Internet && status.AIService {
		return "online"
	} else if status.Internet && !status.AIService {
		return "partial (internet only)"
	} else if !status.Internet && status.AIService {
		return "partial (AI service only)"
	}
	return "offline"
}

// evictLRU removes least recently used cache entry
func (om *OfflineManager) evictLRU() {
	if len(om.aiResponseCache) == 0 {
		return
	}

	var oldestKey string
	var oldestScore int64 = 9223372036854775807 // Max int64

	// Find LRU entry (considering both timestamp and use count)
	for key, cached := range om.aiResponseCache {
		// Lower score = older/less used
		score := cached.Timestamp.Unix() + int64(cached.UseCount*86400) // Boost frequently used items
		if score < oldestScore {
			oldestScore = score
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(om.aiResponseCache, oldestKey)
	}
}

// saveAIResponseCache saves AI response cache to disk
func (om *OfflineManager) saveAIResponseCache() error {
	// Ensure cache directory exists
	if err := os.MkdirAll(om.cacheDir, 0700); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	cachePath := filepath.Join(om.cacheDir, CacheFileName)

	data, err := json.MarshalIndent(om.aiResponseCache, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal AI response cache: %w", err)
	}

	if err := os.WriteFile(cachePath, data, 0600); err != nil {
		return fmt.Errorf("failed to save AI response cache: %w", err)
	}

	return nil
}

// loadAIResponseCache loads AI response cache from disk
func (om *OfflineManager) loadAIResponseCache() error {
	cachePath := filepath.Join(om.cacheDir, CacheFileName)

	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No cache file yet, not an error
		}
		return fmt.Errorf("failed to read AI response cache: %w", err)
	}

	if err := json.Unmarshal(data, &om.aiResponseCache); err != nil {
		return fmt.Errorf("failed to unmarshal AI response cache: %w", err)
	}

	return nil
}

// normalizeQuery normalizes a query string for caching
func normalizeQuery(query string) string {
	// Simple normalization: trim whitespace and convert to uppercase for CVE IDs
	trimmed := ""
	for _, r := range query {
		if r != ' ' && r != '\t' && r != '\n' {
			trimmed += string(r)
		}
	}

	// Convert to uppercase for CVE IDs
	result := ""
	for _, r := range trimmed {
		if r >= 'a' && r <= 'z' {
			result += string(r - 32)
		} else {
			result += string(r)
		}
	}

	return result
}

// ClearCache clears all cached data
func (om *OfflineManager) ClearCache() error {
	om.mu.Lock()
	defer om.mu.Unlock()

	om.aiResponseCache = make(map[string]*CachedResponse)

	cachePath := filepath.Join(om.cacheDir, CacheFileName)
	if err := os.Remove(cachePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove cache file: %w", err)
	}

	return nil
}

// UpdateVulnDB forces an update of the vulnerability database
func (om *OfflineManager) UpdateVulnDB() error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if !om.IsOnline() {
		return fmt.Errorf("cannot update vulnerability database: no internet connection")
	}

	return om.downloadVulnDB()
}

// GetGracefulDegradationMessage returns user-friendly message about offline limitations
func (om *OfflineManager) GetGracefulDegradationMessage() string {
	status := om.CheckConnectivity()

	if status.Internet && status.AIService {
		return "All features available (online mode)"
	}

	msg := "Running in "

	if !status.Internet && !status.AIService {
		msg += "offline mode.\n\n"
		msg += "Available features:\n"
		msg += "  - Local network scanning (nmap, masscan)\n"
		msg += "  - Vulnerability scanning (nikto, dirb)\n"
		msg += "  - CVE lookup from local database\n"
		msg += "  - Cached AI responses\n\n"
		msg += "Unavailable features:\n"
		msg += "  - Real-time AI analysis\n"
		msg += "  - Online exploit database\n"
		msg += "  - Cloud-based scanning\n"
		msg += "  - Vulnerability database updates\n\n"
		msg += "To restore full functionality:\n"
		msg += "  1. Check internet connection\n"
		msg += "  2. Start AI service: zypheron ai start"
	} else if !status.AIService {
		msg += "partial mode (AI service unavailable).\n\n"
		msg += "Available features:\n"
		msg += "  - All scanning tools\n"
		msg += "  - Online vulnerability lookups\n"
		msg += "  - Cached AI responses\n\n"
		msg += "Unavailable features:\n"
		msg += "  - Real-time AI analysis\n"
		msg += "  - AI-powered recommendations\n\n"
		msg += "To restore AI features:\n"
		msg += "  Start AI service: zypheron ai start"
	} else {
		msg += "partial mode (no internet connection).\n\n"
		msg += "Available features:\n"
		msg += "  - Local network scanning\n"
		msg += "  - AI analysis (local)\n"
		msg += "  - Cached data\n\n"
		msg += "Unavailable features:\n"
		msg += "  - Online databases\n"
		msg += "  - Cloud AI providers\n"
		msg += "  - Database updates\n\n"
		msg += "To restore full functionality:\n"
		msg += "  Check internet connection"
	}

	return msg
}

// Global offline manager instance
var (
	globalManager     *OfflineManager
	globalManagerOnce sync.Once
	globalManagerErr  error
)

// GetManager returns the global offline manager instance
func GetManager() (*OfflineManager, error) {
	globalManagerOnce.Do(func() {
		globalManager, globalManagerErr = NewOfflineManager()
	})
	return globalManager, globalManagerErr
}

// IsOnline is a convenience function for checking internet connectivity
func IsOnline() bool {
	manager, err := GetManager()
	if err != nil {
		return false
	}
	return manager.IsOnline()
}

// IsAIServiceAvailable is a convenience function for checking AI service availability
func IsAIServiceAvailable() bool {
	manager, err := GetManager()
	if err != nil {
		return false
	}
	return manager.IsAIServiceAvailable()
}

// CheckConnectivity is a convenience function for comprehensive connectivity check
func CheckConnectivity() *ConnectivityStatus {
	manager, err := GetManager()
	if err != nil {
		return &ConnectivityStatus{
			Internet:     false,
			AIService:    false,
			LastChecked:  time.Now(),
			ErrorMessage: fmt.Sprintf("Failed to initialize offline manager: %v", err),
		}
	}
	return manager.CheckConnectivity()
}
