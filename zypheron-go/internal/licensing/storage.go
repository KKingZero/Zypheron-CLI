package licensing

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Storage handles persistent license and session storage using SQLite
// This database is shared between CLI and Electron app
type Storage struct {
	db *sql.DB
}

// NewStorage creates a new storage instance
func NewStorage() (*Storage, error) {
	dbPath, err := getDBPath()
	if err != nil {
		return nil, err
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	s := &Storage{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}

	return s, nil
}

var overrideDBPath string

// getDBPath returns the path to the shared SQLite database
func getDBPath() (string, error) {
	if overrideDBPath != "" {
		return overrideDBPath, nil
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".zypheron", "zypheron.db"), nil
}

// init creates the database schema
func (s *Storage) init() error {
	schema := `
	CREATE TABLE IF NOT EXISTS auth_session (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		access_token TEXT NOT NULL,
		refresh_token TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		user_id TEXT NOT NULL,
		email TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS license_cache (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		license_json TEXT NOT NULL,
		cached_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS token_usage (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		action TEXT NOT NULL,
		tokens INTEGER NOT NULL,
		provider TEXT,
		feature TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		synced INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id TEXT UNIQUE NOT NULL,
		name TEXT,
		platform TEXT,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_usage_synced ON token_usage(synced);
	CREATE INDEX IF NOT EXISTS idx_usage_timestamp ON token_usage(timestamp);
	`

	_, err := s.db.Exec(schema)
	return err
}

// SaveSession stores the auth session
func (s *Storage) SaveSession(session *AuthSession) error {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO auth_session (id, access_token, refresh_token, expires_at, user_id, email, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`, session.AccessToken, session.RefreshToken, session.ExpiresAt, session.UserID, session.Email)
	return err
}

// LoadSession retrieves the stored auth session
func (s *Storage) LoadSession() (*AuthSession, error) {
	var session AuthSession
	err := s.db.QueryRow(`
		SELECT access_token, refresh_token, expires_at, user_id, email
		FROM auth_session WHERE id = 1
	`).Scan(&session.AccessToken, &session.RefreshToken, &session.ExpiresAt, &session.UserID, &session.Email)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// SaveLicense stores the license in cache
func (s *Storage) SaveLicense(license *License) error {
	data, err := json.Marshal(license)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`
		INSERT OR REPLACE INTO license_cache (id, license_json, cached_at)
		VALUES (1, ?, CURRENT_TIMESTAMP)
	`, string(data))
	return err
}

// LoadLicense retrieves the cached license
func (s *Storage) LoadLicense() (*License, error) {
	var jsonData string
	err := s.db.QueryRow(`SELECT license_json FROM license_cache WHERE id = 1`).Scan(&jsonData)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var license License
	if err := json.Unmarshal([]byte(jsonData), &license); err != nil {
		return nil, err
	}
	return &license, nil
}

// AddUsage records a token usage event
func (s *Storage) AddUsage(usage TokenUsage) error {
	_, err := s.db.Exec(`
		INSERT INTO token_usage (action, tokens, provider, feature, timestamp)
		VALUES (?, ?, ?, ?, ?)
	`, usage.Action, usage.Tokens, usage.Provider, usage.Feature, usage.Timestamp)
	return err
}

// GetUnsyncedUsage returns usage records not yet synced to server
func (s *Storage) GetUnsyncedUsage() ([]TokenUsage, error) {
	rows, err := s.db.Query(`
		SELECT action, tokens, provider, feature, timestamp
		FROM token_usage WHERE synced = 0 ORDER BY timestamp
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var usages []TokenUsage
	for rows.Next() {
		var u TokenUsage
		if err := rows.Scan(&u.Action, &u.Tokens, &u.Provider, &u.Feature, &u.Timestamp); err != nil {
			return nil, err
		}
		usages = append(usages, u)
	}
	return usages, nil
}

// MarkUsageSynced marks usage records as synced
func (s *Storage) MarkUsageSynced(before time.Time) error {
	_, err := s.db.Exec(`UPDATE token_usage SET synced = 1 WHERE timestamp <= ?`, before)
	return err
}

// GetUsageStats returns usage statistics for a time period
func (s *Storage) GetUsageStats(from, to time.Time) (map[string]int64, error) {
	rows, err := s.db.Query(`
		SELECT action, SUM(tokens) as total
		FROM token_usage
		WHERE timestamp BETWEEN ? AND ?
		GROUP BY action
	`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := make(map[string]int64)
	for rows.Next() {
		var action string
		var total int64
		if err := rows.Scan(&action, &total); err != nil {
			return nil, err
		}
		stats[action] = total
	}
	return stats, nil
}

// SaveDevice registers this device
func (s *Storage) SaveDevice(device Device) error {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO devices (device_id, name, platform, last_seen)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
	`, device.DeviceID, device.Name, device.Platform)
	return err
}

// UpdateDeviceLastSeen updates the last seen timestamp
func (s *Storage) UpdateDeviceLastSeen(deviceID string) error {
	_, err := s.db.Exec(`UPDATE devices SET last_seen = CURRENT_TIMESTAMP WHERE device_id = ?`, deviceID)
	return err
}

// GetSetting retrieves a setting value
func (s *Storage) GetSetting(key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// SetSetting stores a setting value
func (s *Storage) SetSetting(key, value string) error {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO settings (key, value, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
	`, key, value)
	return err
}

// ClearAll removes all cached data (used on logout)
func (s *Storage) ClearAll() error {
	tables := []string{"auth_session", "license_cache"}
	for _, table := range tables {
		if _, err := s.db.Exec("DELETE FROM " + table); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database connection
func (s *Storage) Close() error {
	return s.db.Close()
}

// GetTotalTokensUsed returns total tokens used (synced or not)
func (s *Storage) GetTotalTokensUsed() (int64, error) {
	var total sql.NullInt64
	err := s.db.QueryRow(`SELECT SUM(tokens) FROM token_usage`).Scan(&total)
	if err != nil {
		return 0, err
	}
	if !total.Valid {
		return 0, nil
	}
	return total.Int64, nil
}

// PruneOldUsage removes usage records older than specified days
func (s *Storage) PruneOldUsage(daysOld int) error {
	_, err := s.db.Exec(`
		DELETE FROM token_usage
		WHERE synced = 1 AND timestamp < datetime('now', '-' || ? || ' days')
	`, daysOld)
	return err
}
