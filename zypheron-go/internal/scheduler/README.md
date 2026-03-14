# Scheduler Package

A production-ready scan scheduling system with SQLite backend for the Zypheron CLI.

## Features

- **Cron-based Scheduling**: Schedule scans using familiar cron expression syntax
- **SQLite Backend**: Lightweight, embedded database with no external dependencies
- **CRUD Operations**: Full create, read, update, delete support for scheduled scans
- **Enable/Disable**: Easily enable or disable scans without deleting them
- **Due Scan Detection**: Automatically identify scans that need to run
- **Automatic Next Run Calculation**: Cron parser calculates next execution time
- **Migration Support**: Database schema versioning for safe upgrades
- **Thread-Safe**: Uses SQLite WAL mode for better concurrency
- **Comprehensive Tests**: Full test coverage with benchmarks

## Architecture

### Components

1. **scheduler.go**: Core scheduler implementation with SQLite backend
   - `Scheduler` struct: Main scheduler interface
   - `ScheduledScan` struct: Represents a scheduled scan
   - CRUD methods for managing scans
   - Database connection management and migrations

2. **cron.go**: Cron expression parser
   - Parse standard 5-field cron expressions
   - Support for wildcards, ranges, steps, and lists
   - Calculate next run time from cron expression
   - Human-readable cron descriptions

3. **scheduler_test.go**: Comprehensive test suite
   - Unit tests for all operations
   - Integration tests with in-memory SQLite
   - Benchmarks for performance testing

## Usage

### Creating a Scheduler

```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/scheduler"

// Create scheduler with default path
s, err := scheduler.NewScheduler(scheduler.DefaultDBPath)
if err != nil {
    log.Fatal(err)
}
defer s.Close()

// Or use in-memory database for testing
s, err := scheduler.NewScheduler(":memory:")
```

### Creating a Scheduled Scan

```go
scan := scheduler.ScheduledScan{
    ID:       "daily-scan-1",
    Name:     "Daily Network Scan",
    Target:   "192.168.1.0/24",
    Tools:    "nmap,nikto",
    CronExpr: "0 2 * * *", // Daily at 2:00 AM
    Enabled:  true,
}

err := s.CreateScan(scan)
```

### Listing Scans

```go
scans, err := s.ListScans()
if err != nil {
    log.Fatal(err)
}

for _, scan := range scans {
    fmt.Printf("Scan: %s (Next run: %s)\n", scan.Name, scan.NextRun)
}
```

### Getting Due Scans

```go
dueScans, err := s.GetDueScans()
if err != nil {
    log.Fatal(err)
}

for _, scan := range dueScans {
    // Execute the scan
    fmt.Printf("Running: %s\n", scan.Name)

    // Mark as completed (updates last_run and calculates next_run)
    s.MarkCompleted(scan.ID)
}
```

### Enabling/Disabling Scans

```go
// Disable a scan
err := s.DisableScan("daily-scan-1")

// Enable a scan
err := s.EnableScan("daily-scan-1")
```

### Deleting Scans

```go
err := s.DeleteScan("daily-scan-1")
```

## Cron Expression Format

The scheduler uses standard 5-field cron expressions:

```
* * * * *
│ │ │ │ │
│ │ │ │ └─── Day of week (0-6, Sunday=0)
│ │ │ └───── Month (1-12)
│ │ └─────── Day of month (1-31)
│ └───────── Hour (0-23)
└─────────── Minute (0-59)
```

### Supported Syntax

- **Wildcards**: `*` matches any value
- **Ranges**: `1-5` matches 1, 2, 3, 4, 5
- **Steps**: `*/15` every 15 units, `1-10/2` every 2 units from 1 to 10
- **Lists**: `1,3,5` matches 1, 3, and 5
- **Combinations**: `1-5,10,*/2` complex expressions

### Common Patterns

```
"0 2 * * *"      - Every day at 2:00 AM
"*/15 * * * *"   - Every 15 minutes
"0 0 * * 0"      - Every Sunday at midnight
"30 3 1 * *"     - First day of month at 3:30 AM
"0 */6 * * *"    - Every 6 hours
"0 9-17 * * 1-5" - Every hour from 9 AM to 5 PM on weekdays
```

## CLI Commands

### Create a Scheduled Scan

```bash
zypheron schedule create \
  --name "Daily Network Scan" \
  --target 192.168.1.0/24 \
  --cron "0 2 * * *" \
  --tools nmap,nikto
```

### List All Scheduled Scans

```bash
zypheron schedule list
zypheron schedule list --json  # JSON output
```

### Show Scan Details

```bash
zypheron schedule show <scan-id>
```

### Delete a Scan

```bash
zypheron schedule delete <scan-id>
```

### Enable/Disable Scans

```bash
zypheron schedule enable <scan-id>
zypheron schedule disable <scan-id>
```

### Run Due Scans

```bash
zypheron schedule run              # Execute all due scans
zypheron schedule run --dry-run    # Show what would run
```

## Database Schema

### scheduled_scans Table

```sql
CREATE TABLE scheduled_scans (
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

CREATE INDEX idx_scheduled_scans_enabled ON scheduled_scans(enabled);
CREATE INDEX idx_scheduled_scans_next_run ON scheduled_scans(next_run);
CREATE INDEX idx_scheduled_scans_enabled_next_run ON scheduled_scans(enabled, next_run);
```

### Indexes

- `idx_scheduled_scans_enabled`: Fast filtering by enabled status
- `idx_scheduled_scans_next_run`: Fast retrieval of upcoming scans
- `idx_scheduled_scans_enabled_next_run`: Composite index for due scan queries

## Testing

### Run Tests

```bash
cd internal/scheduler
go test -v                    # Run all tests
go test -v -run TestCreate    # Run specific test
go test -bench=.              # Run benchmarks
go test -cover                # Show coverage
```

### Test Coverage

- CRUD operations
- Cron expression parsing
- Due scan detection
- Enable/disable functionality
- Error handling
- Edge cases

### Benchmarks

```bash
BenchmarkCreateScan      - Test scan creation performance
BenchmarkListScans       - Test listing performance with 100 scans
BenchmarkGetDueScans     - Test due scan detection with 100 scans
BenchmarkCronParsing     - Test cron expression parsing performance
```

## Error Handling

The package uses Go's standard error handling with descriptive error messages:

```go
// Validation errors
if err := s.CreateScan(scan); err != nil {
    // Returns: "scan name is required"
    // Returns: "invalid cron expression: ..."
}

// Not found errors
if scan, err := s.GetScan("invalid-id"); err != nil {
    // Returns: "scan not found: invalid-id"
}

// Database errors
// All errors are wrapped with context using fmt.Errorf
```

## Best Practices

1. **Always Close the Scheduler**: Use `defer s.Close()` to ensure database connections are closed

2. **Use Unique IDs**: Generate unique scan IDs to avoid conflicts

3. **Validate Before Creating**: Validate targets and tools before creating scans

4. **Handle Errors**: Always check error returns from scheduler methods

5. **Use Transactions**: For bulk operations, consider wrapping in transactions

6. **Regular Cleanup**: Periodically clean up old/completed scans

7. **Monitor Due Scans**: Set up a cron job or systemd timer to run `zypheron schedule run`

## Production Deployment

### Setting Up Automatic Execution

#### Using systemd (Linux)

Create `/etc/systemd/system/zypheron-scheduler.service`:

```ini
[Unit]
Description=Zypheron Scheduled Scan Runner
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/zypheron schedule run
User=zypheron
Group=zypheron

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/zypheron-scheduler.timer`:

```ini
[Unit]
Description=Run Zypheron scheduled scans every minute
Requires=zypheron-scheduler.service

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=1s

[Install]
WantedBy=timers.target
```

Enable and start:

```bash
sudo systemctl enable zypheron-scheduler.timer
sudo systemctl start zypheron-scheduler.timer
```

#### Using Cron

Add to crontab (`crontab -e`):

```
* * * * * /usr/local/bin/zypheron schedule run >> /var/log/zypheron-scheduler.log 2>&1
```

### Database Location

Default: `~/.zypheron/scheduler.db`

For production, consider:
- `/var/lib/zypheron/scheduler.db` (system-wide)
- Custom path via environment variable
- Regular backups of the database file

### Security Considerations

1. **File Permissions**: Restrict database file to owner-only (600)
2. **Input Validation**: All targets and tools are validated
3. **SQL Injection**: Uses parameterized queries throughout
4. **Resource Limits**: Set timeouts on scan execution
5. **Logging**: Log all scan executions for audit trail

## Performance

### Benchmarks (approximate)

- **CreateScan**: ~1-2ms per operation
- **ListScans**: ~0.1ms for 100 scans
- **GetDueScans**: ~0.05ms with proper indexes
- **CronParsing**: ~0.01ms per expression

### Optimization Tips

1. **Batch Operations**: Use transactions for multiple creates/updates
2. **Index Usage**: Queries are optimized to use indexes
3. **WAL Mode**: Enabled for better concurrent read/write performance
4. **Connection Pool**: Single connection for SQLite (optimal)

## Migration Guide

The scheduler includes automatic migration support. When upgrading:

1. Backup your database file
2. Update the Zypheron binary
3. Run any command - migrations run automatically
4. Verify with `zypheron schedule list`

Schema version is tracked in the `schema_version` table.

## Troubleshooting

### Database Locked

If you see "database is locked" errors:
- Ensure no other Zypheron processes are accessing the database
- Check for stale lock files
- WAL mode should prevent most locking issues

### Scans Not Running

1. Check if scan is enabled: `zypheron schedule show <id>`
2. Verify next run time is in the past
3. Check cron expression: Use `zypheron schedule show <id>` to see description
4. Ensure scheduler timer/cron is running
5. Check logs for execution errors

### Invalid Cron Expression

Use the cron description feature to verify:
```bash
zypheron schedule show <id>  # Shows human-readable description
```

Common mistakes:
- Using 6 fields (seconds not supported)
- Invalid ranges (e.g., 25/60 for hours)
- Month/weekday starting at 0 vs 1

## Future Enhancements

Potential additions:
- [ ] Support for @yearly, @monthly, @weekly, @daily, @hourly shortcuts
- [ ] Email/webhook notifications on scan completion
- [ ] Retry logic for failed scans
- [ ] Scan execution history
- [ ] Concurrent scan limits
- [ ] Time zone support
- [ ] Scan templates
- [ ] Web dashboard for management

## License

Part of the Zypheron project. See main repository for license details.
