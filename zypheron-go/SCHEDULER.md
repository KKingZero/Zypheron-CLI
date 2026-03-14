# Zypheron Scheduled Scan System

A production-ready scan scheduling system for automating security scans with cron-like scheduling.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [CLI Commands](#cli-commands)
- [Cron Expression Guide](#cron-expression-guide)
- [Programmatic Usage](#programmatic-usage)
- [Production Deployment](#production-deployment)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

## Overview

The Zypheron Scheduler allows you to automate security scans by scheduling them to run at specific times using cron expressions. It provides:

- **Automated Scanning**: Schedule scans to run automatically without manual intervention
- **Flexible Scheduling**: Use cron expressions for complex scheduling patterns
- **Multi-Tool Support**: Run multiple security tools (nmap, nikto, nuclei, etc.) in a single scheduled scan
- **SQLite Backend**: Lightweight, embedded database with no external dependencies
- **Enable/Disable**: Temporarily disable scans without deleting them
- **Due Scan Detection**: Automatically identifies scans that need to run
- **Production Ready**: Built with error handling, validation, and best practices

## Quick Start

### 1. Create a Scheduled Scan

Schedule a daily network scan at 2:00 AM:

```bash
zypheron schedule create \
  --name "Daily Network Scan" \
  --target 192.168.1.0/24 \
  --cron "0 2 * * *" \
  --tools nmap,nikto
```

### 2. List Scheduled Scans

View all your scheduled scans:

```bash
zypheron schedule list
```

### 3. View Scan Details

See detailed information about a specific scan:

```bash
zypheron schedule show daily-network-scan-1234567890
```

### 4. Run Due Scans

Execute all scans that are due to run:

```bash
zypheron schedule run
```

### 5. Enable/Disable Scans

Temporarily disable a scan:

```bash
zypheron schedule disable daily-network-scan-1234567890
```

Re-enable it later:

```bash
zypheron schedule enable daily-network-scan-1234567890
```

### 6. Delete a Scan

Permanently remove a scheduled scan:

```bash
zypheron schedule delete daily-network-scan-1234567890
```

## Architecture

### Components

```
internal/scheduler/
├── scheduler.go        # Core scheduler implementation
├── cron.go            # Cron expression parser
├── scheduler_test.go  # Comprehensive tests
├── example_test.go    # Usage examples
└── README.md          # Package documentation

internal/commands/
└── schedule.go        # CLI commands

cmd/zypheron/
└── main.go           # Command registration
```

### Database Schema

```sql
CREATE TABLE scheduled_scans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    tools TEXT NOT NULL,              -- Comma-separated tool list
    cron_expr TEXT NOT NULL,
    next_run TIMESTAMP NOT NULL,
    last_run TIMESTAMP,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_scheduled_scans_enabled ON scheduled_scans(enabled);
CREATE INDEX idx_scheduled_scans_next_run ON scheduled_scans(next_run);
CREATE INDEX idx_scheduled_scans_enabled_next_run ON scheduled_scans(enabled, next_run);
```

### Data Flow

```
1. User creates scan via CLI
   ↓
2. Cron expression parsed and validated
   ↓
3. Next run time calculated
   ↓
4. Scan stored in SQLite database
   ↓
5. Scheduler daemon/cron checks for due scans
   ↓
6. Due scans executed with specified tools
   ↓
7. Scan marked completed, next run calculated
   ↓
8. Repeat from step 5
```

## CLI Commands

### `zypheron schedule create`

Create a new scheduled scan.

**Syntax:**
```bash
zypheron schedule create --name <name> --target <target> --cron <expr> --tools <tools>
```

**Options:**
- `--name, -n`: Scan name (required)
- `--target, -t`: Target to scan - IP, hostname, URL, or CIDR (required)
- `--cron`: Cron expression defining schedule (required)
- `--tools`: Comma-separated list of tools to run (required)

**Examples:**

Daily network scan:
```bash
zypheron schedule create \
  --name "Daily Network Scan" \
  --target 192.168.1.0/24 \
  --cron "0 2 * * *" \
  --tools nmap
```

Hourly web application scan:
```bash
zypheron schedule create \
  --name "Hourly Web Scan" \
  --target https://example.com \
  --cron "0 * * * *" \
  --tools nikto,nuclei
```

Weekly comprehensive scan:
```bash
zypheron schedule create \
  --name "Weekly Full Scan" \
  --target example.com \
  --cron "0 0 * * 0" \
  --tools nmap,nikto,nuclei,masscan
```

### `zypheron schedule list`

List all scheduled scans.

**Syntax:**
```bash
zypheron schedule list [--json]
```

**Options:**
- `--json`: Output as JSON (optional)

**Output:**
```
Scheduled Scans
════════════════════════════════════════════════════════════════════════════════

ID                          Name                Target              Tools           Schedule      Next Run           Status
daily-scan-1234567890      Daily Network Scan  192.168.1.0/24      nmap,nikto      0 2 * * *     2025-12-25 02:00   Enabled
weekly-scan-1234567891     Weekly Full Scan    example.com         nmap,nuclei     0 0 * * 0     2025-12-29 00:00   Enabled

Total: 2 scans
```

### `zypheron schedule show`

Show detailed information about a specific scan.

**Syntax:**
```bash
zypheron schedule show <id>
```

**Example:**
```bash
zypheron schedule show daily-scan-1234567890
```

**Output:**
```
Scheduled Scan Details
════════════════════════════════════════════════════════════════════════════════

  ID:          daily-scan-1234567890
  Name:        Daily Network Scan
  Target:      192.168.1.0/24
  Tools:       nmap,nikto
  Schedule:    0 2 * * *
  Description: Every day at 2:00 AM

  Status:      Enabled
  Created:     2025-12-24 10:00:00
  Next Run:    2025-12-25 02:00:00
  Last Run:    2025-12-24 02:00:00
```

### `zypheron schedule delete`

Delete a scheduled scan.

**Syntax:**
```bash
zypheron schedule delete <id>
```

**Aliases:** `del`, `rm`

**Example:**
```bash
zypheron schedule delete daily-scan-1234567890
```

### `zypheron schedule enable`

Enable a disabled scan.

**Syntax:**
```bash
zypheron schedule enable <id>
```

**Example:**
```bash
zypheron schedule enable daily-scan-1234567890
```

### `zypheron schedule disable`

Disable a scan without deleting it.

**Syntax:**
```bash
zypheron schedule disable <id>
```

**Example:**
```bash
zypheron schedule disable daily-scan-1234567890
```

### `zypheron schedule run`

Execute all scans that are due to run.

**Syntax:**
```bash
zypheron schedule run [--dry-run]
```

**Options:**
- `--dry-run`: Show what would run without executing

**Example:**
```bash
zypheron schedule run
```

**Output:**
```
Found 2 due scan(s)

[1/2] Running: Daily Network Scan
        Target: 192.168.1.0/24
        Tools:  nmap,nikto

        Executing nmap...
        ✓ nmap completed in 45.23s
        Executing nikto...
        ✓ nikto completed in 123.45s
        Next run: 2025-12-26 02:00:00

[2/2] Running: Hourly Web Scan
        Target: https://example.com
        Tools:  nuclei

        Executing nuclei...
        ✓ nuclei completed in 23.45s
        Next run: 2025-12-25 11:00:00

════════════════════════════════════════════════════════════════════════════════
Completed: 2  Failed: 0
```

## Cron Expression Guide

### Format

Zypheron uses the standard 5-field cron expression format:

```
* * * * *
│ │ │ │ │
│ │ │ │ └─── Day of week (0-6, Sunday=0)
│ │ │ └───── Month (1-12)
│ │ └─────── Day of month (1-31)
│ └───────── Hour (0-23)
└─────────── Minute (0-59)
```

### Syntax Elements

- **`*`** (wildcard): Matches any value
  - Example: `* * * * *` = Every minute

- **`,`** (list): Specify multiple values
  - Example: `0 9,12,15,18 * * *` = At 9 AM, 12 PM, 3 PM, and 6 PM

- **`-`** (range): Specify a range of values
  - Example: `0 9-17 * * *` = Every hour from 9 AM to 5 PM

- **`/`** (step): Specify step values
  - Example: `*/15 * * * *` = Every 15 minutes
  - Example: `0 */6 * * *` = Every 6 hours

### Common Patterns

| Pattern | Description | Example Use Case |
|---------|-------------|------------------|
| `* * * * *` | Every minute | High-frequency monitoring |
| `*/5 * * * *` | Every 5 minutes | Frequent web checks |
| `0 * * * *` | Every hour | Hourly vulnerability scans |
| `0 0 * * *` | Every day at midnight | Daily comprehensive scans |
| `0 2 * * *` | Every day at 2 AM | Off-hours network scans |
| `0 */6 * * *` | Every 6 hours | Regular interval checks |
| `0 0 * * 0` | Every Sunday at midnight | Weekly full assessments |
| `0 0 1 * *` | First day of month | Monthly compliance scans |
| `30 3 1 * *` | 1st of month at 3:30 AM | Monthly reports |
| `0 9-17 * * 1-5` | 9 AM-5 PM on weekdays | Business hours monitoring |
| `0 0 * * 1,3,5` | Mon, Wed, Fri at midnight | Alternate day scans |

### Validation

The scheduler validates cron expressions when creating or updating scans:

```bash
# Valid expression
zypheron schedule create --name "Test" --target example.com --cron "0 2 * * *" --tools nmap

# Invalid - too few fields
zypheron schedule create --name "Test" --target example.com --cron "0 2 * *" --tools nmap
# Error: invalid cron expression: expected 5 fields, got 4

# Invalid - bad hour value
zypheron schedule create --name "Test" --target example.com --cron "0 25 * * *" --tools nmap
# Error: invalid hour field: value must be between 0 and 23
```

## Programmatic Usage

### Basic Example

```go
package main

import (
    "log"
    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/scheduler"
)

func main() {
    // Create scheduler
    s, err := scheduler.NewScheduler(scheduler.DefaultDBPath)
    if err != nil {
        log.Fatal(err)
    }
    defer s.Close()

    // Create a scheduled scan
    scan := scheduler.ScheduledScan{
        ID:       "daily-scan-1",
        Name:     "Daily Network Scan",
        Target:   "192.168.1.0/24",
        Tools:    "nmap,nikto",
        CronExpr: "0 2 * * *",
        Enabled:  true,
    }

    if err := s.CreateScan(scan); err != nil {
        log.Fatal(err)
    }

    log.Println("Scan created successfully")
}
```

### Checking for Due Scans

```go
// Get scans that need to run
dueScans, err := s.GetDueScans()
if err != nil {
    log.Fatal(err)
}

for _, scan := range dueScans {
    log.Printf("Executing: %s", scan.Name)

    // Execute the scan
    executeScan(scan)

    // Mark as completed (calculates next run time)
    if err := s.MarkCompleted(scan.ID); err != nil {
        log.Printf("Failed to mark completed: %v", err)
    }
}
```

See `internal/scheduler/example_test.go` for more examples.

## Production Deployment

### Automatic Execution Options

#### Option 1: systemd Timer (Recommended for Linux)

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
StandardOutput=journal
StandardError=journal

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
sudo systemctl status zypheron-scheduler.timer
```

Check logs:

```bash
journalctl -u zypheron-scheduler.service -f
```

#### Option 2: Cron (Cross-platform)

Add to crontab (`crontab -e`):

```
# Run every minute
* * * * * /usr/local/bin/zypheron schedule run >> /var/log/zypheron-scheduler.log 2>&1

# Or every 5 minutes (less frequent checking)
*/5 * * * * /usr/local/bin/zypheron schedule run >> /var/log/zypheron-scheduler.log 2>&1
```

#### Option 3: Standalone Daemon

Create a simple daemon in Go:

```go
package main

import (
    "log"
    "time"
    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/scheduler"
)

func main() {
    s, err := scheduler.NewScheduler(scheduler.DefaultDBPath)
    if err != nil {
        log.Fatal(err)
    }
    defer s.Close()

    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        scans, err := s.GetDueScans()
        if err != nil {
            log.Printf("Error getting due scans: %v", err)
            continue
        }

        for _, scan := range scans {
            go func(scan scheduler.ScheduledScan) {
                log.Printf("Executing: %s", scan.Name)
                executeScan(scan)
                s.MarkCompleted(scan.ID)
            }(scan)
        }
    }
}
```

### Database Location

**Default:** `~/.zypheron/scheduler.db`

**Production Options:**

1. **System-wide installation:**
   ```bash
   /var/lib/zypheron/scheduler.db
   ```

2. **User-specific:**
   ```bash
   ~/.zypheron/scheduler.db
   ```

3. **Custom path via environment variable:**
   ```bash
   export ZYPHERON_SCHEDULER_DB=/path/to/scheduler.db
   ```

### Backup Strategy

Regular backups of the SQLite database:

```bash
#!/bin/bash
# /usr/local/bin/zypheron-backup.sh

BACKUP_DIR="/var/backups/zypheron"
DB_PATH="/var/lib/zypheron/scheduler.db"
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p "$BACKUP_DIR"
sqlite3 "$DB_PATH" ".backup '$BACKUP_DIR/scheduler-$DATE.db'"

# Keep only last 30 days of backups
find "$BACKUP_DIR" -name "scheduler-*.db" -mtime +30 -delete
```

Add to crontab:
```
0 3 * * * /usr/local/bin/zypheron-backup.sh
```

### Security Considerations

1. **File Permissions:**
   ```bash
   chmod 600 /var/lib/zypheron/scheduler.db
   chown zypheron:zypheron /var/lib/zypheron/scheduler.db
   ```

2. **Run as Dedicated User:**
   ```bash
   sudo useradd -r -s /bin/false zypheron
   ```

3. **Restrict Network Access:**
   - Use firewall rules to limit scan targets
   - Run in isolated network segment for testing

4. **Audit Logging:**
   - All executions logged via systemd journal or syslog
   - Store scan results for compliance

## Testing

### Run Unit Tests

```bash
cd /home/zero/Downloads/Zypheron\ project/Zypheron-CLI-Production/zypheron-go
go test -v ./internal/scheduler/
```

### Run Specific Tests

```bash
go test -v -run TestCreateScan ./internal/scheduler/
go test -v -run TestCron ./internal/scheduler/
```

### Run with Coverage

```bash
go test -cover ./internal/scheduler/
go test -coverprofile=coverage.out ./internal/scheduler/
go tool cover -html=coverage.out
```

### Run Benchmarks

```bash
go test -bench=. ./internal/scheduler/
go test -bench=. -benchmem ./internal/scheduler/
```

### Integration Testing

```bash
# Create test scan
zypheron schedule create \
  --name "Test Scan" \
  --target example.com \
  --cron "* * * * *" \
  --tools nmap

# List to verify
zypheron schedule list

# Run immediately
zypheron schedule run --dry-run

# Clean up
zypheron schedule delete test-scan-<id>
```

## Troubleshooting

### Common Issues

#### 1. Database Locked

**Symptom:** `database is locked` error

**Solution:**
```bash
# Check for other Zypheron processes
ps aux | grep zypheron

# Kill stale processes
pkill -f zypheron

# Remove WAL files if corrupted
rm ~/.zypheron/scheduler.db-wal ~/.zypheron/scheduler.db-shm
```

#### 2. Scans Not Running

**Diagnosis:**

1. Check if scan is enabled:
   ```bash
   zypheron schedule show <id>
   ```

2. Verify next run time is in the past

3. Check scheduler is running:
   ```bash
   systemctl status zypheron-scheduler.timer
   ```

4. Check logs:
   ```bash
   journalctl -u zypheron-scheduler.service -n 50
   ```

#### 3. Invalid Cron Expression

**Symptom:** Error creating scan with cron validation error

**Solution:**
- Verify expression has exactly 5 fields
- Check value ranges (minute: 0-59, hour: 0-23, etc.)
- Use `zypheron schedule show` to see human-readable description
- Test with simpler expression first: `0 0 * * *`

#### 4. Permission Denied

**Symptom:** Cannot write to database directory

**Solution:**
```bash
# Create directory with proper permissions
mkdir -p ~/.zypheron
chmod 700 ~/.zypheron

# Or for system-wide installation
sudo mkdir -p /var/lib/zypheron
sudo chown zypheron:zypheron /var/lib/zypheron
```

### Debug Mode

Enable debug logging:

```bash
export ZYPHERON_DEBUG=1
zypheron schedule run
```

### Getting Help

For more help:

```bash
zypheron schedule --help
zypheron schedule create --help
zypheron schedule run --help
```

## Summary

The Zypheron Scheduler provides a robust, production-ready solution for automating security scans. Key features:

- ✅ Simple cron-based scheduling
- ✅ SQLite backend with no external dependencies
- ✅ Multi-tool scan support
- ✅ Enable/disable without deletion
- ✅ Comprehensive CLI interface
- ✅ Full test coverage
- ✅ Production deployment examples
- ✅ Error handling and validation

Start automating your security scans today with `zypheron schedule create`!
