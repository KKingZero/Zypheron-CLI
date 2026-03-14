package scheduler

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ScheduledScan represents a scheduled security scan
type ScheduledScan struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Target    string    `json:"target"`
	Tools     string    `json:"tools"` // Comma-separated list of tools
	CronExpr  string    `json:"cron_expr"`
	NextRun   time.Time `json:"next_run"`
	LastRun   time.Time `json:"last_run,omitempty"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// Scheduler manages scheduled scans with SQLite backend
type Scheduler struct {
	db *sql.DB
}

const (
	// Schema version for migrations
	schemaVersion = 1

	// Default database path
	DefaultDBPath = "~/.zypheron/scheduler.db"
)

// NewScheduler creates a new Scheduler instance with SQLite backend
func NewScheduler(dbPath string) (*Scheduler, error) {
	// Expand home directory if present
	if strings.HasPrefix(dbPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		dbPath = strings.Replace(dbPath, "~", home, 1)
	}

	// Ensure the directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Open database connection
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(1) // SQLite works best with single connection
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	// Enable foreign keys and WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	s := &Scheduler{db: db}

	// Run migrations
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return s, nil
}

// migrate runs database migrations
func (s *Scheduler) migrate() error {
	// Create schema_version table if not exists
	createVersionTable := `
	CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY,
		applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`

	if _, err := s.db.Exec(createVersionTable); err != nil {
		return fmt.Errorf("failed to create schema_version table: %w", err)
	}

	// Check current version
	var currentVersion int
	err := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("failed to get current schema version: %w", err)
	}

	// Apply migrations
	if currentVersion < 1 {
		if err := s.migrationV1(); err != nil {
			return fmt.Errorf("migration v1 failed: %w", err)
		}
		if _, err := s.db.Exec("INSERT INTO schema_version (version) VALUES (1)"); err != nil {
			return fmt.Errorf("failed to update schema version: %w", err)
		}
	}

	return nil
}

// migrationV1 creates the initial schema
func (s *Scheduler) migrationV1() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scheduled_scans (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		target TEXT NOT NULL,
		tools TEXT NOT NULL,
		cron_expr TEXT NOT NULL,
		next_run TIMESTAMP NOT NULL,
		last_run TIMESTAMP,
		enabled INTEGER NOT NULL DEFAULT 1,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_scheduled_scans_enabled ON scheduled_scans(enabled);
	CREATE INDEX IF NOT EXISTS idx_scheduled_scans_next_run ON scheduled_scans(next_run);
	CREATE INDEX IF NOT EXISTS idx_scheduled_scans_enabled_next_run ON scheduled_scans(enabled, next_run);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

// CreateScan creates a new scheduled scan
func (s *Scheduler) CreateScan(scan ScheduledScan) error {
	if scan.ID == "" {
		return fmt.Errorf("scan ID is required")
	}
	if scan.Name == "" {
		return fmt.Errorf("scan name is required")
	}
	if scan.Target == "" {
		return fmt.Errorf("scan target is required")
	}
	if scan.Tools == "" {
		return fmt.Errorf("scan tools are required")
	}
	if scan.CronExpr == "" {
		return fmt.Errorf("cron expression is required")
	}

	// Validate and parse cron expression
	nextRun, err := ParseCronExpression(scan.CronExpr, time.Now())
	if err != nil {
		return fmt.Errorf("invalid cron expression: %w", err)
	}

	// Set defaults
	if scan.CreatedAt.IsZero() {
		scan.CreatedAt = time.Now()
	}
	scan.NextRun = nextRun

	query := `
	INSERT INTO scheduled_scans (id, name, target, tools, cron_expr, next_run, last_run, enabled, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	var lastRun interface{}
	if !scan.LastRun.IsZero() {
		lastRun = scan.LastRun
	}

	_, err = s.db.Exec(query,
		scan.ID,
		scan.Name,
		scan.Target,
		scan.Tools,
		scan.CronExpr,
		scan.NextRun,
		lastRun,
		boolToInt(scan.Enabled),
		scan.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create scheduled scan: %w", err)
	}

	return nil
}

// ListScans returns all scheduled scans
func (s *Scheduler) ListScans() ([]ScheduledScan, error) {
	query := `
	SELECT id, name, target, tools, cron_expr, next_run, last_run, enabled, created_at
	FROM scheduled_scans
	ORDER BY created_at DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list scans: %w", err)
	}
	defer rows.Close()

	var scans []ScheduledScan
	for rows.Next() {
		var scan ScheduledScan
		var enabled int
		var lastRun sql.NullTime

		err := rows.Scan(
			&scan.ID,
			&scan.Name,
			&scan.Target,
			&scan.Tools,
			&scan.CronExpr,
			&scan.NextRun,
			&lastRun,
			&enabled,
			&scan.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		scan.Enabled = intToBool(enabled)
		if lastRun.Valid {
			scan.LastRun = lastRun.Time
		}

		scans = append(scans, scan)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return scans, nil
}

// GetScan retrieves a scheduled scan by ID
func (s *Scheduler) GetScan(id string) (*ScheduledScan, error) {
	if id == "" {
		return nil, fmt.Errorf("scan ID is required")
	}

	query := `
	SELECT id, name, target, tools, cron_expr, next_run, last_run, enabled, created_at
	FROM scheduled_scans
	WHERE id = ?
	`

	var scan ScheduledScan
	var enabled int
	var lastRun sql.NullTime

	err := s.db.QueryRow(query, id).Scan(
		&scan.ID,
		&scan.Name,
		&scan.Target,
		&scan.Tools,
		&scan.CronExpr,
		&scan.NextRun,
		&lastRun,
		&enabled,
		&scan.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("scan not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get scan: %w", err)
	}

	scan.Enabled = intToBool(enabled)
	if lastRun.Valid {
		scan.LastRun = lastRun.Time
	}

	return &scan, nil
}

// UpdateScan updates an existing scheduled scan
func (s *Scheduler) UpdateScan(scan ScheduledScan) error {
	if scan.ID == "" {
		return fmt.Errorf("scan ID is required")
	}

	// Validate cron expression if it's being updated
	if scan.CronExpr != "" {
		nextRun, err := ParseCronExpression(scan.CronExpr, time.Now())
		if err != nil {
			return fmt.Errorf("invalid cron expression: %w", err)
		}
		scan.NextRun = nextRun
	}

	query := `
	UPDATE scheduled_scans
	SET name = ?, target = ?, tools = ?, cron_expr = ?, next_run = ?, enabled = ?
	WHERE id = ?
	`

	result, err := s.db.Exec(query,
		scan.Name,
		scan.Target,
		scan.Tools,
		scan.CronExpr,
		scan.NextRun,
		boolToInt(scan.Enabled),
		scan.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update scan: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("scan not found: %s", scan.ID)
	}

	return nil
}

// DeleteScan deletes a scheduled scan by ID
func (s *Scheduler) DeleteScan(id string) error {
	if id == "" {
		return fmt.Errorf("scan ID is required")
	}

	query := "DELETE FROM scheduled_scans WHERE id = ?"
	result, err := s.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete scan: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("scan not found: %s", id)
	}

	return nil
}

// EnableScan enables a scheduled scan
func (s *Scheduler) EnableScan(id string) error {
	return s.setEnabled(id, true)
}

// DisableScan disables a scheduled scan
func (s *Scheduler) DisableScan(id string) error {
	return s.setEnabled(id, false)
}

// setEnabled sets the enabled status of a scan
func (s *Scheduler) setEnabled(id string, enabled bool) error {
	if id == "" {
		return fmt.Errorf("scan ID is required")
	}

	query := "UPDATE scheduled_scans SET enabled = ? WHERE id = ?"
	result, err := s.db.Exec(query, boolToInt(enabled), id)
	if err != nil {
		return fmt.Errorf("failed to update scan status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("scan not found: %s", id)
	}

	return nil
}

// GetDueScans returns all scans that should run now
func (s *Scheduler) GetDueScans() ([]ScheduledScan, error) {
	query := `
	SELECT id, name, target, tools, cron_expr, next_run, last_run, enabled, created_at
	FROM scheduled_scans
	WHERE enabled = 1 AND next_run <= ?
	ORDER BY next_run ASC
	`

	rows, err := s.db.Query(query, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to get due scans: %w", err)
	}
	defer rows.Close()

	var scans []ScheduledScan
	for rows.Next() {
		var scan ScheduledScan
		var enabled int
		var lastRun sql.NullTime

		err := rows.Scan(
			&scan.ID,
			&scan.Name,
			&scan.Target,
			&scan.Tools,
			&scan.CronExpr,
			&scan.NextRun,
			&lastRun,
			&enabled,
			&scan.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		scan.Enabled = intToBool(enabled)
		if lastRun.Valid {
			scan.LastRun = lastRun.Time
		}

		scans = append(scans, scan)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return scans, nil
}

// MarkCompleted marks a scan as completed and calculates next run time
func (s *Scheduler) MarkCompleted(id string) error {
	if id == "" {
		return fmt.Errorf("scan ID is required")
	}

	// Get the scan to retrieve cron expression
	scan, err := s.GetScan(id)
	if err != nil {
		return fmt.Errorf("failed to get scan: %w", err)
	}

	// Calculate next run time
	nextRun, err := ParseCronExpression(scan.CronExpr, time.Now())
	if err != nil {
		return fmt.Errorf("failed to calculate next run: %w", err)
	}

	query := `
	UPDATE scheduled_scans
	SET last_run = ?, next_run = ?
	WHERE id = ?
	`

	result, err := s.db.Exec(query, time.Now(), nextRun, id)
	if err != nil {
		return fmt.Errorf("failed to mark scan completed: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("scan not found: %s", id)
	}

	return nil
}

// Close closes the database connection
func (s *Scheduler) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Helper functions

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func intToBool(i int) bool {
	return i != 0
}
