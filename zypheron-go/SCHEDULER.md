# Zypheron Scheduled Scan System

Automate security scans with cron-based scheduling, backed by SQLite.

## Quick Start

```bash
# Create a daily scan at 2 AM
zypheron schedule create \
  --name "Daily Network Scan" \
  --target 192.168.1.0/24 \
  --cron "0 2 * * *" \
  --tools nmap,nikto

# List all scheduled scans
zypheron schedule list

# Run all due scans
zypheron schedule run

# Enable/disable without deleting
zypheron schedule disable <id>
zypheron schedule enable <id>

# Delete a scan
zypheron schedule delete <id>
```

## CLI Commands

### `zypheron schedule create`

```bash
zypheron schedule create --name <name> --target <target> --cron <expr> --tools <tools>
```

| Flag | Short | Description |
|------|-------|-------------|
| `--name` | `-n` | Scan name (required) |
| `--target` | `-t` | Target IP, hostname, URL, or CIDR (required) |
| `--cron` | | Cron expression (required) |
| `--tools` | | Comma-separated tool list (required) |

Examples:

```bash
# Hourly web scan
zypheron schedule create -n "Hourly Web Scan" -t https://example.com --cron "0 * * * *" --tools nikto,nuclei

# Weekly comprehensive scan
zypheron schedule create -n "Weekly Full Scan" -t example.com --cron "0 0 * * 0" --tools nmap,nikto,nuclei,masscan
```

### `zypheron schedule list`

```bash
zypheron schedule list [--json]
```

### `zypheron schedule show`

```bash
zypheron schedule show <id>
```

### `zypheron schedule run`

```bash
zypheron schedule run [--dry-run]
```

Executes all scans whose next run time is in the past. Use `--dry-run` to preview without executing.

### `zypheron schedule delete`

```bash
zypheron schedule delete <id>
```

Aliases: `del`, `rm`

### `zypheron schedule enable` / `disable`

```bash
zypheron schedule enable <id>
zypheron schedule disable <id>
```

## Cron Expression Reference

Standard 5-field format:

```
* * * * *
| | | | +-- Day of week (0-6, Sun=0)
| | | +---- Month (1-12)
| | +------ Day of month (1-31)
| +-------- Hour (0-23)
+---------- Minute (0-59)
```

### Syntax

- `*` -- any value
- `,` -- list (`0 9,12,18 * * *` = 9 AM, noon, 6 PM)
- `-` -- range (`0 9-17 * * *` = every hour 9 AM-5 PM)
- `/` -- step (`*/15 * * * *` = every 15 minutes)

### Common Patterns

| Pattern | Description |
|---------|-------------|
| `*/5 * * * *` | Every 5 minutes |
| `0 * * * *` | Every hour |
| `0 2 * * *` | Daily at 2 AM |
| `0 0 * * 0` | Weekly on Sunday |
| `0 0 1 * *` | First of each month |
| `0 9-17 * * 1-5` | Hourly, weekdays 9-5 |

## Database Schema

SQLite database at `~/.zypheron/scheduler.db` (configurable via `ZYPHERON_SCHEDULER_DB`).

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
```

## Programmatic Usage

```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/scheduler"

s, err := scheduler.NewScheduler(scheduler.DefaultDBPath)
if err != nil {
    log.Fatal(err)
}
defer s.Close()

// Create a scan
scan := scheduler.ScheduledScan{
    ID:       "daily-scan-1",
    Name:     "Daily Network Scan",
    Target:   "192.168.1.0/24",
    Tools:    "nmap,nikto",
    CronExpr: "0 2 * * *",
    Enabled:  true,
}
s.CreateScan(scan)

// Get and execute due scans
dueScans, _ := s.GetDueScans()
for _, scan := range dueScans {
    executeScan(scan)
    s.MarkCompleted(scan.ID)
}
```

## Production Deployment

### systemd Timer (Linux)

`/etc/systemd/system/zypheron-scheduler.service`:
```ini
[Unit]
Description=Zypheron Scheduled Scan Runner
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/zypheron schedule run
User=zypheron
```

`/etc/systemd/system/zypheron-scheduler.timer`:
```ini
[Unit]
Description=Run Zypheron scheduled scans every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now zypheron-scheduler.timer
```

### Cron

```
* * * * * /usr/local/bin/zypheron schedule run >> /var/log/zypheron-scheduler.log 2>&1
```

### Security

```bash
# Dedicated user
sudo useradd -r -s /bin/false zypheron

# Database permissions
chmod 600 /var/lib/zypheron/scheduler.db
chown zypheron:zypheron /var/lib/zypheron/scheduler.db
```

## Troubleshooting

**Database locked**: Check for stale processes (`ps aux | grep zypheron`). Remove WAL files if corrupted:
```bash
rm ~/.zypheron/scheduler.db-wal ~/.zypheron/scheduler.db-shm
```

**Scans not running**: Verify the scan is enabled (`zypheron schedule show <id>`), confirm `next_run` is in the past, and check the scheduler timer is active.

**Invalid cron expression**: Ensure exactly 5 fields with valid ranges (minute 0-59, hour 0-23, day 1-31, month 1-12, weekday 0-6).

**Permission denied**: Create the database directory with proper permissions:
```bash
mkdir -p ~/.zypheron && chmod 700 ~/.zypheron
```

**Debug mode**:
```bash
ZYPHERON_DEBUG=1 zypheron schedule run
```

**Help**:
```bash
zypheron schedule --help
zypheron schedule create --help
```
