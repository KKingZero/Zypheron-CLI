package browser

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	// DefaultCacheTTL is the default time-to-live for cached results (7 days)
	DefaultCacheTTL = 7 * 24 * time.Hour
)

// DorkCache manages SQLite-based caching for dork query results
type DorkCache struct {
	db      *sql.DB
	dbPath  string
}

// NewDorkCache creates a new dork cache instance
func NewDorkCache() (*DorkCache, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	cacheDir := filepath.Join(homeDir, ".zypheron", "cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	dbPath := filepath.Join(cacheDir, "dorks.db")

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open cache database: %w", err)
	}

	cache := &DorkCache{
		db:     db,
		dbPath: dbPath,
	}

	if err := cache.init(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize cache: %w", err)
	}

	return cache, nil
}

// init creates the cache table if it doesn't exist
func (c *DorkCache) init() error {
	schema := `
	CREATE TABLE IF NOT EXISTS dork_cache (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		query_hash TEXT NOT NULL,
		engine TEXT NOT NULL,
		results_json TEXT NOT NULL,
		result_count INTEGER NOT NULL DEFAULT 0,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMP NOT NULL,
		UNIQUE(query_hash, engine)
	);
	CREATE INDEX IF NOT EXISTS idx_cache_lookup ON dork_cache(query_hash, engine);
	CREATE INDEX IF NOT EXISTS idx_cache_expires ON dork_cache(expires_at);
	`

	_, err := c.db.Exec(schema)
	return err
}

// hashQuery creates a SHA256 hash of the query for storage
func hashQuery(query string) string {
	hash := sha256.Sum256([]byte(query))
	return hex.EncodeToString(hash[:])
}

// Get retrieves cached results for a query and engine
// Returns the results and a boolean indicating if the cache hit was successful
func (c *DorkCache) Get(query, engine string) ([]SearchResult, bool) {
	queryHash := hashQuery(query)

	var resultsJSON string
	var expiresAt time.Time

	err := c.db.QueryRow(`
		SELECT results_json, expires_at
		FROM dork_cache
		WHERE query_hash = ? AND engine = ?
	`, queryHash, engine).Scan(&resultsJSON, &expiresAt)

	if err != nil {
		return nil, false
	}

	// Check if expired
	if time.Now().After(expiresAt) {
		// Delete expired entry
		c.Delete(query, engine)
		return nil, false
	}

	var results []SearchResult
	if err := json.Unmarshal([]byte(resultsJSON), &results); err != nil {
		return nil, false
	}

	return results, true
}

// Set stores results for a query and engine with the specified TTL
func (c *DorkCache) Set(query, engine string, results []SearchResult, ttl time.Duration) error {
	if ttl == 0 {
		ttl = DefaultCacheTTL
	}

	queryHash := hashQuery(query)
	expiresAt := time.Now().Add(ttl)

	resultsJSON, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	// Use REPLACE to handle both insert and update
	_, err = c.db.Exec(`
		REPLACE INTO dork_cache (query_hash, engine, results_json, result_count, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, queryHash, engine, string(resultsJSON), len(results), expiresAt)

	if err != nil {
		return fmt.Errorf("failed to cache results: %w", err)
	}

	return nil
}

// Delete removes a specific cache entry
func (c *DorkCache) Delete(query, engine string) error {
	queryHash := hashQuery(query)

	_, err := c.db.Exec(`
		DELETE FROM dork_cache
		WHERE query_hash = ? AND engine = ?
	`, queryHash, engine)

	return err
}

// Cleanup removes all expired entries from the cache
func (c *DorkCache) Cleanup() error {
	result, err := c.db.Exec(`
		DELETE FROM dork_cache
		WHERE expires_at < ?
	`, time.Now())

	if err != nil {
		return fmt.Errorf("failed to cleanup cache: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		// Vacuum to reclaim space
		_, _ = c.db.Exec("VACUUM")
	}

	return nil
}

// Clear removes all entries from the cache
func (c *DorkCache) Clear() error {
	_, err := c.db.Exec("DELETE FROM dork_cache")
	if err != nil {
		return fmt.Errorf("failed to clear cache: %w", err)
	}

	_, _ = c.db.Exec("VACUUM")
	return nil
}

// Stats returns cache statistics
func (c *DorkCache) Stats() (*CacheStats, error) {
	var stats CacheStats

	// Total entries
	err := c.db.QueryRow("SELECT COUNT(*) FROM dork_cache").Scan(&stats.TotalEntries)
	if err != nil {
		return nil, err
	}

	// Expired entries
	err = c.db.QueryRow("SELECT COUNT(*) FROM dork_cache WHERE expires_at < ?", time.Now()).Scan(&stats.ExpiredEntries)
	if err != nil {
		return nil, err
	}

	// Valid entries
	stats.ValidEntries = stats.TotalEntries - stats.ExpiredEntries

	// Total results cached
	var totalResults sql.NullInt64
	err = c.db.QueryRow("SELECT SUM(result_count) FROM dork_cache WHERE expires_at >= ?", time.Now()).Scan(&totalResults)
	if err != nil {
		return nil, err
	}
	if totalResults.Valid {
		stats.TotalResults = int(totalResults.Int64)
	}

	// Oldest entry
	var oldestCreated sql.NullTime
	err = c.db.QueryRow("SELECT MIN(created_at) FROM dork_cache").Scan(&oldestCreated)
	if err == nil && oldestCreated.Valid {
		stats.OldestEntry = oldestCreated.Time
	}

	// Newest entry
	var newestCreated sql.NullTime
	err = c.db.QueryRow("SELECT MAX(created_at) FROM dork_cache").Scan(&newestCreated)
	if err == nil && newestCreated.Valid {
		stats.NewestEntry = newestCreated.Time
	}

	// Entries by engine
	stats.EntriesByEngine = make(map[string]int)
	rows, err := c.db.Query("SELECT engine, COUNT(*) FROM dork_cache GROUP BY engine")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var engine string
			var count int
			if rows.Scan(&engine, &count) == nil {
				stats.EntriesByEngine[engine] = count
			}
		}
	}

	return &stats, nil
}

// CacheStats contains statistics about the cache
type CacheStats struct {
	TotalEntries    int
	ValidEntries    int
	ExpiredEntries  int
	TotalResults    int
	OldestEntry     time.Time
	NewestEntry     time.Time
	EntriesByEngine map[string]int
}

// Close closes the database connection
func (c *DorkCache) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// GetOrFetch tries to get from cache, otherwise calls the fetch function and caches the result
func (c *DorkCache) GetOrFetch(query, engine string, ttl time.Duration, fetch func() ([]SearchResult, error)) ([]SearchResult, bool, error) {
	// Try cache first
	if results, ok := c.Get(query, engine); ok {
		return results, true, nil
	}

	// Fetch fresh results
	results, err := fetch()
	if err != nil {
		return nil, false, err
	}

	// Cache the results
	if cacheErr := c.Set(query, engine, results, ttl); cacheErr != nil {
		// Log but don't fail - caching is optional
		fmt.Printf("Warning: failed to cache results: %v\n", cacheErr)
	}

	return results, false, nil
}
