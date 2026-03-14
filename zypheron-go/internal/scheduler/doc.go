// Package scheduler provides a production-ready scan scheduling system with SQLite backend.
//
// The scheduler allows you to automate security scans by scheduling them to run at specific
// times using cron expressions. It provides a complete CRUD interface for managing scheduled
// scans, along with automatic next run time calculation and due scan detection.
//
// # Features
//
//   - Cron-based scheduling with standard 5-field expressions
//   - SQLite backend with automatic migrations
//   - CRUD operations for scheduled scans
//   - Enable/disable functionality
//   - Due scan detection
//   - Automatic next run calculation
//   - Comprehensive validation
//   - Production-ready error handling
//
// # Quick Start
//
// Creating a scheduler:
//
//	s, err := scheduler.NewScheduler(scheduler.DefaultDBPath)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer s.Close()
//
// Creating a scheduled scan:
//
//	scan := scheduler.ScheduledScan{
//	    ID:       "daily-scan-1",
//	    Name:     "Daily Network Scan",
//	    Target:   "192.168.1.0/24",
//	    Tools:    "nmap,nikto",
//	    CronExpr: "0 2 * * *", // Daily at 2:00 AM
//	    Enabled:  true,
//	}
//	err := s.CreateScan(scan)
//
// Getting scans that are due to run:
//
//	dueScans, err := s.GetDueScans()
//	for _, scan := range dueScans {
//	    // Execute the scan
//	    executeScan(scan)
//	    s.MarkCompleted(scan.ID) // Updates last_run and calculates next_run
//	}
//
// # Cron Expression Format
//
// The scheduler uses standard 5-field cron expressions:
//
//	* * * * *
//	│ │ │ │ │
//	│ │ │ │ └─── Day of week (0-6, Sunday=0)
//	│ │ │ └───── Month (1-12)
//	│ │ └─────── Day of month (1-31)
//	│ └───────── Hour (0-23)
//	└─────────── Minute (0-59)
//
// Supported syntax:
//   - Wildcards: * (any value)
//   - Ranges: 1-5 (range of values)
//   - Steps: */15 (step values)
//   - Lists: 1,3,5 (specific values)
//   - Combinations: 1-5,10,*/2 (complex expressions)
//
// # Common Cron Patterns
//
//	"0 2 * * *"      - Every day at 2:00 AM
//	"*/15 * * * *"   - Every 15 minutes
//	"0 0 * * 0"      - Every Sunday at midnight
//	"30 3 1 * *"     - First day of month at 3:30 AM
//	"0 */6 * * *"    - Every 6 hours
//
// # Database Schema
//
// The scheduler uses SQLite with the following schema:
//
//	CREATE TABLE scheduled_scans (
//	    id TEXT PRIMARY KEY,
//	    name TEXT NOT NULL,
//	    target TEXT NOT NULL,
//	    tools TEXT NOT NULL,
//	    cron_expr TEXT NOT NULL,
//	    next_run TIMESTAMP NOT NULL,
//	    last_run TIMESTAMP,
//	    enabled INTEGER NOT NULL DEFAULT 1,
//	    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
//	);
//
// # CLI Usage
//
// The scheduler integrates with the Zypheron CLI:
//
//	# Create a scheduled scan
//	zypheron schedule create --name "Daily Scan" --target 192.168.1.0/24 --cron "0 2 * * *" --tools nmap
//
//	# List all scheduled scans
//	zypheron schedule list
//
//	# Show scan details
//	zypheron schedule show <id>
//
//	# Run all due scans
//	zypheron schedule run
//
//	# Enable/disable scans
//	zypheron schedule enable <id>
//	zypheron schedule disable <id>
//
//	# Delete a scan
//	zypheron schedule delete <id>
//
// # Production Deployment
//
// For production use, set up a systemd timer or cron job to run:
//
//	zypheron schedule run
//
// This command checks for due scans and executes them automatically.
//
// See SCHEDULER.md for complete documentation including:
//   - Production deployment guides (systemd, cron, standalone daemon)
//   - Security considerations
//   - Backup strategies
//   - Troubleshooting guide
//
// See README.md in this package for developer documentation including:
//   - Architecture details
//   - Testing guide
//   - Performance benchmarks
//   - Future enhancements
package scheduler
