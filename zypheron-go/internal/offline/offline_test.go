package offline

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNewOfflineManager(t *testing.T) {
	manager, err := NewOfflineManager()
	if err != nil {
		t.Fatalf("Failed to create offline manager: %v", err)
	}

	if manager == nil {
		t.Fatal("Expected non-nil manager")
	}

	if manager.cacheDir == "" {
		t.Error("Expected non-empty cache directory")
	}

	if manager.aiResponseCache == nil {
		t.Error("Expected initialized response cache")
	}

	if manager.vulnDB == nil {
		t.Error("Expected initialized vulnerability database")
	}
}

func TestIsOnline(t *testing.T) {
	manager, err := NewOfflineManager()
	if err != nil {
		t.Fatalf("Failed to create offline manager: %v", err)
	}

	// This will actually check connectivity
	online := manager.IsOnline()
	t.Logf("Internet connectivity: %v", online)

	// No assertion since it depends on actual network state
	// Just verify it doesn't crash
}

func TestIsAIServiceAvailable(t *testing.T) {
	manager, err := NewOfflineManager()
	if err != nil {
		t.Fatalf("Failed to create offline manager: %v", err)
	}

	// Test with custom checker
	manager.aiServiceChecker = func() bool {
		return true
	}

	if !manager.IsAIServiceAvailable() {
		t.Error("Expected AI service to be available with custom checker")
	}

	manager.aiServiceChecker = func() bool {
		return false
	}

	if manager.IsAIServiceAvailable() {
		t.Error("Expected AI service to be unavailable with custom checker")
	}
}

func TestCheckConnectivity(t *testing.T) {
	manager, err := NewOfflineManager()
	if err != nil {
		t.Fatalf("Failed to create offline manager: %v", err)
	}

	// Mock AI service checker
	manager.aiServiceChecker = func() bool {
		return false
	}

	status := manager.CheckConnectivity()

	if status == nil {
		t.Fatal("Expected non-nil connectivity status")
	}

	if status.LastChecked.IsZero() {
		t.Error("Expected non-zero last checked time")
	}

	t.Logf("Connectivity status: Internet=%v, AI=%v, Latency=%v",
		status.Internet, status.AIService, status.Latency)
}

func TestGetOfflineCapabilities(t *testing.T) {
	manager, err := NewOfflineManager()
	if err != nil {
		t.Fatalf("Failed to create offline manager: %v", err)
	}

	capabilities := manager.GetOfflineCapabilities()

	if len(capabilities) == 0 {
		t.Error("Expected non-empty capabilities list")
	}

	// Verify some expected capabilities
	expectedCapabilities := map[string]bool{
		"Network scanning (nmap, masscan)": false,
		"Local CVE database lookup":         false,
		"Cached AI response retrieval":      false,
	}

	for _, cap := range capabilities {
		if _, exists := expectedCapabilities[cap]; exists {
			expectedCapabilities[cap] = true
		}
	}

	for cap, found := range expectedCapabilities {
		if !found {
			t.Errorf("Expected capability not found: %s", cap)
		}
	}

	t.Logf("Available offline capabilities: %d", len(capabilities))
}

func TestCacheAIResponse(t *testing.T) {
	// Create temp directory for testing
	tmpDir := t.TempDir()

	manager := &OfflineManager{
		cacheDir:        tmpDir,
		aiResponseCache: make(map[string]*CachedResponse),
		vulnDB:          &VulnDB{CVEs: make(map[string]*CVEInfo)},
	}

	query := "What is SQL injection?"
	response := "SQL injection is a code injection technique..."

	err := manager.CacheAIResponse(query, response)
	if err != nil {
		t.Fatalf("Failed to cache AI response: %v", err)
	}

	// Verify cache contains the response
	normalizedQuery := normalizeQuery(query)
	if _, exists := manager.aiResponseCache[normalizedQuery]; !exists {
		t.Error("Expected query to be cached")
	}

	// Test cache retrieval
	retrieved, found := manager.GetCachedResponse(query)
	if !found {
		t.Error("Expected to find cached response")
	}

	if retrieved != response {
		t.Errorf("Expected response '%s', got '%s'", response, retrieved)
	}
}

func TestGetCachedResponse(t *testing.T) {
	manager := &OfflineManager{
		cacheDir:        t.TempDir(),
		aiResponseCache: make(map[string]*CachedResponse),
		vulnDB:          &VulnDB{CVEs: make(map[string]*CVEInfo)},
	}

	// Test non-existent cache
	_, found := manager.GetCachedResponse("non-existent query")
	if found {
		t.Error("Expected not to find non-existent query")
	}

	// Add and retrieve
	query := "test query"
	response := "test response"
	manager.CacheAIResponse(query, response)

	retrieved, found := manager.GetCachedResponse(query)
	if !found {
		t.Error("Expected to find cached response")
	}

	if retrieved != response {
		t.Errorf("Expected '%s', got '%s'", response, retrieved)
	}

	// Test case-insensitive retrieval
	retrieved, found = manager.GetCachedResponse("TEST QUERY")
	if !found {
		t.Error("Expected case-insensitive cache lookup to succeed")
	}
}

func TestLRUEviction(t *testing.T) {
	manager := &OfflineManager{
		cacheDir:        t.TempDir(),
		aiResponseCache: make(map[string]*CachedResponse),
		vulnDB:          &VulnDB{CVEs: make(map[string]*CVEInfo)},
	}

	// Fill cache to max capacity with unique normalized queries
	for i := 0; i < MaxCachedResponses; i++ {
		// Use format that won't normalize to same value
		query := "query number " + fmt.Sprintf("%d", i)
		response := "response number " + fmt.Sprintf("%d", i)
		manager.CacheAIResponse(query, response)
	}

	// Account for normalization (spaces removed, uppercase)
	actualSize := len(manager.aiResponseCache)
	t.Logf("Cache size after filling: %d (expected: %d)", actualSize, MaxCachedResponses)

	if actualSize > MaxCachedResponses {
		t.Errorf("Cache size %d exceeds max %d", actualSize, MaxCachedResponses)
	}

	// Add one more to trigger eviction
	manager.CacheAIResponse("overflow query test", "overflow response")

	newSize := len(manager.aiResponseCache)
	t.Logf("Cache size after overflow: %d", newSize)

	if newSize > MaxCachedResponses {
		t.Errorf("Expected cache size <= %d after eviction, got %d",
			MaxCachedResponses, newSize)
	}
}

func TestLoadLocalVulnDB(t *testing.T) {
	manager, err := NewOfflineManager()
	if err != nil {
		t.Fatalf("Failed to create offline manager: %v", err)
	}

	err = manager.LoadLocalVulnDB()
	if err != nil {
		t.Logf("Failed to load vuln DB (expected if offline): %v", err)
	}

	// Should have fallback CVEs even if download fails
	if len(manager.vulnDB.CVEs) == 0 {
		t.Error("Expected fallback CVEs to be populated")
	}

	t.Logf("Loaded %d CVEs", len(manager.vulnDB.CVEs))
}

func TestLookupCVE(t *testing.T) {
	manager := &OfflineManager{
		cacheDir:        t.TempDir(),
		aiResponseCache: make(map[string]*CachedResponse),
		vulnDB: &VulnDB{
			CVEs: map[string]*CVEInfo{
				"CVE-2024-1234": {
					ID:          "CVE-2024-1234",
					Description: "Test vulnerability",
					Published:   time.Now(),
					Modified:    time.Now(),
				},
			},
			LastUpdated: time.Now(),
			Version:     "1.0.0-test",
		},
	}

	// Test successful lookup
	cve, err := manager.LookupCVE("CVE-2024-1234")
	if err != nil {
		t.Fatalf("Failed to lookup CVE: %v", err)
	}

	if cve.ID != "CVE-2024-1234" {
		t.Errorf("Expected CVE-2024-1234, got %s", cve.ID)
	}

	// Test case-insensitive lookup
	cve, err = manager.LookupCVE("cve-2024-1234")
	if err != nil {
		t.Fatalf("Failed case-insensitive lookup: %v", err)
	}

	// Test non-existent CVE
	_, err = manager.LookupCVE("CVE-9999-9999")
	if err == nil {
		t.Error("Expected error for non-existent CVE")
	}
}

func TestGetCacheStats(t *testing.T) {
	manager := &OfflineManager{
		cacheDir:        t.TempDir(),
		aiResponseCache: make(map[string]*CachedResponse),
		vulnDB: &VulnDB{
			CVEs:        make(map[string]*CVEInfo),
			LastUpdated: time.Now(),
			Version:     "1.0.0-test",
		},
	}

	// Add some cached responses
	manager.CacheAIResponse("query1", "response1")
	manager.CacheAIResponse("query2", "response2")

	stats := manager.GetCacheStats()

	if stats["cached_responses"] != 2 {
		t.Errorf("Expected 2 cached responses, got %v", stats["cached_responses"])
	}

	if stats["max_cache_size"] != MaxCachedResponses {
		t.Errorf("Expected max cache size %d, got %v", MaxCachedResponses, stats["max_cache_size"])
	}

	if stats["vuln_db_version"] != "1.0.0-test" {
		t.Errorf("Expected version '1.0.0-test', got %v", stats["vuln_db_version"])
	}

	t.Logf("Cache stats: %+v", stats)
}

func TestGetOfflineStatus(t *testing.T) {
	manager := &OfflineManager{
		cacheDir:        t.TempDir(),
		aiResponseCache: make(map[string]*CachedResponse),
		vulnDB:          &VulnDB{CVEs: make(map[string]*CVEInfo)},
	}

	manager.aiServiceChecker = func() bool { return false }

	status := manager.GetOfflineStatus()

	if status == nil {
		t.Fatal("Expected non-nil status")
	}

	if _, ok := status["connectivity"]; !ok {
		t.Error("Expected connectivity in status")
	}

	if _, ok := status["cache_stats"]; !ok {
		t.Error("Expected cache_stats in status")
	}

	if _, ok := status["capabilities"]; !ok {
		t.Error("Expected capabilities in status")
	}

	if _, ok := status["mode"]; !ok {
		t.Error("Expected mode in status")
	}

	t.Logf("Offline status: %+v", status)
}

func TestGetGracefulDegradationMessage(t *testing.T) {
	manager := &OfflineManager{
		cacheDir:        t.TempDir(),
		aiResponseCache: make(map[string]*CachedResponse),
		vulnDB:          &VulnDB{CVEs: make(map[string]*CVEInfo)},
	}

	manager.aiServiceChecker = func() bool { return false }

	msg := manager.GetGracefulDegradationMessage()

	if msg == "" {
		t.Error("Expected non-empty degradation message")
	}

	t.Logf("Degradation message:\n%s", msg)
}

func TestClearCache(t *testing.T) {
	tmpDir := t.TempDir()

	manager := &OfflineManager{
		cacheDir:        tmpDir,
		aiResponseCache: make(map[string]*CachedResponse),
		vulnDB:          &VulnDB{CVEs: make(map[string]*CVEInfo)},
	}

	// Add some cached responses
	manager.CacheAIResponse("query1", "response1")
	manager.CacheAIResponse("query2", "response2")

	if len(manager.aiResponseCache) != 2 {
		t.Errorf("Expected 2 cached responses, got %d", len(manager.aiResponseCache))
	}

	// Clear cache
	err := manager.ClearCache()
	if err != nil {
		t.Fatalf("Failed to clear cache: %v", err)
	}

	if len(manager.aiResponseCache) != 0 {
		t.Errorf("Expected empty cache after clear, got %d entries", len(manager.aiResponseCache))
	}

	// Verify cache file is deleted
	cachePath := filepath.Join(tmpDir, CacheFileName)
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Error("Expected cache file to be deleted")
	}
}

func TestNormalizeQuery(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CVE-2024-1234", "CVE-2024-1234"},
		{"cve-2024-1234", "CVE-2024-1234"},
		{"  CVE-2024-1234  ", "CVE-2024-1234"},
		{"what is sql injection?", "WHATISSQLINJECTION?"},
		{"What Is SQL Injection?", "WHATISSQLINJECTION?"},
	}

	for _, test := range tests {
		result := normalizeQuery(test.input)
		if result != test.expected {
			t.Errorf("normalizeQuery(%q) = %q, expected %q", test.input, result, test.expected)
		}
	}
}

func TestGlobalManagerSingleton(t *testing.T) {
	// Reset global manager for testing
	globalManagerOnce = sync.Once{}
	globalManager = nil
	globalManagerErr = nil

	manager1, err1 := GetManager()
	if err1 != nil {
		t.Fatalf("Failed to get first manager instance: %v", err1)
	}

	manager2, err2 := GetManager()
	if err2 != nil {
		t.Fatalf("Failed to get second manager instance: %v", err2)
	}

	// Should be the same instance
	if manager1 != manager2 {
		t.Error("Expected singleton pattern - same manager instance")
	}
}

func TestConvenienceFunctions(t *testing.T) {
	// Reset global manager
	globalManagerOnce = sync.Once{}
	globalManager = nil
	globalManagerErr = nil

	// Test IsOnline
	online := IsOnline()
	t.Logf("IsOnline: %v", online)

	// Test IsAIServiceAvailable
	aiAvailable := IsAIServiceAvailable()
	t.Logf("IsAIServiceAvailable: %v", aiAvailable)

	// Test CheckConnectivity
	status := CheckConnectivity()
	if status == nil {
		t.Fatal("Expected non-nil connectivity status")
	}
	t.Logf("Connectivity: Internet=%v, AI=%v", status.Internet, status.AIService)
}

func TestPopulateFallbackCVEs(t *testing.T) {
	manager := &OfflineManager{
		cacheDir:        t.TempDir(),
		aiResponseCache: make(map[string]*CachedResponse),
		vulnDB:          &VulnDB{CVEs: make(map[string]*CVEInfo)},
	}

	manager.populateFallbackCVEs()

	if len(manager.vulnDB.CVEs) == 0 {
		t.Error("Expected fallback CVEs to be populated")
	}

	// Check for specific well-known CVEs
	expectedCVEs := []string{"CVE-2024-3094", "CVE-2021-44228", "CVE-2017-0144"}
	for _, cveID := range expectedCVEs {
		if _, exists := manager.vulnDB.CVEs[cveID]; !exists {
			t.Errorf("Expected fallback CVE %s to be present", cveID)
		}
	}

	t.Logf("Populated %d fallback CVEs", len(manager.vulnDB.CVEs))
}

func BenchmarkCacheAIResponse(b *testing.B) {
	manager := &OfflineManager{
		cacheDir:        b.TempDir(),
		aiResponseCache: make(map[string]*CachedResponse),
		vulnDB:          &VulnDB{CVEs: make(map[string]*CVEInfo)},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := "benchmark query " + string(rune(i%100))
		response := "benchmark response " + string(rune(i%100))
		manager.CacheAIResponse(query, response)
	}
}

func BenchmarkGetCachedResponse(b *testing.B) {
	manager := &OfflineManager{
		cacheDir:        b.TempDir(),
		aiResponseCache: make(map[string]*CachedResponse),
		vulnDB:          &VulnDB{CVEs: make(map[string]*CVEInfo)},
	}

	// Pre-populate cache
	for i := 0; i < 100; i++ {
		query := "query " + string(rune(i))
		response := "response " + string(rune(i))
		manager.CacheAIResponse(query, response)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := "query " + string(rune(i%100))
		manager.GetCachedResponse(query)
	}
}

func BenchmarkLookupCVE(b *testing.B) {
	manager := &OfflineManager{
		cacheDir:        b.TempDir(),
		aiResponseCache: make(map[string]*CachedResponse),
		vulnDB:          &VulnDB{CVEs: make(map[string]*CVEInfo)},
	}

	manager.populateFallbackCVEs()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.LookupCVE("CVE-2021-44228")
	}
}
