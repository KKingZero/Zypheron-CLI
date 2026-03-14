package scheduler_test

import (
	"fmt"
	"log"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/scheduler"
)

// Example_basic demonstrates basic scheduler usage
func Example_basic() {
	// Create scheduler with in-memory database (for testing)
	s, err := scheduler.NewScheduler(":memory:")
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	// Create a scheduled scan
	scan := scheduler.ScheduledScan{
		ID:       "example-scan-1",
		Name:     "Daily Security Scan",
		Target:   "192.168.1.0/24",
		Tools:    "nmap,nikto",
		CronExpr: "0 2 * * *", // Every day at 2:00 AM
		Enabled:  true,
	}

	if err := s.CreateScan(scan); err != nil {
		log.Fatal(err)
	}

	// List all scans
	scans, err := s.ListScans()
	if err != nil {
		log.Fatal(err)
	}

	for _, scan := range scans {
		fmt.Printf("Scan: %s\n", scan.Name)
		fmt.Printf("  Target: %s\n", scan.Target)
		fmt.Printf("  Schedule: %s\n", scheduler.GetCronDescription(scan.CronExpr))
		fmt.Printf("  Next run: %s\n", scan.NextRun.Format("2006-01-02 15:04:05"))
	}
}

// Example_dueScans demonstrates how to check and execute due scans
func Example_dueScans() {
	s, err := scheduler.NewScheduler(":memory:")
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	// Create a scan that should run now
	scan := scheduler.ScheduledScan{
		ID:       "immediate-scan",
		Name:     "Immediate Scan",
		Target:   "example.com",
		Tools:    "nmap",
		CronExpr: "* * * * *", // Every minute
		Enabled:  true,
	}

	if err := s.CreateScan(scan); err != nil {
		log.Fatal(err)
	}

	// Wait a bit to ensure it's due
	time.Sleep(100 * time.Millisecond)

	// Get due scans
	dueScans, err := s.GetDueScans()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d due scan(s)\n", len(dueScans))

	for _, scan := range dueScans {
		fmt.Printf("Executing: %s\n", scan.Name)

		// Here you would execute the actual scan
		// For example: executeScan(scan)

		// Mark as completed (updates last_run and calculates next_run)
		if err := s.MarkCompleted(scan.ID); err != nil {
			log.Printf("Failed to mark completed: %v", err)
			continue
		}

		// Get updated scan to see next run time
		updated, err := s.GetScan(scan.ID)
		if err != nil {
			log.Printf("Failed to get updated scan: %v", err)
			continue
		}

		fmt.Printf("  Completed. Next run: %s\n", updated.NextRun.Format("2006-01-02 15:04:05"))
	}
}

// Example_cronExpressions demonstrates various cron expression patterns
func Example_cronExpressions() {
	expressions := []string{
		"* * * * *",      // Every minute
		"0 * * * *",      // Every hour
		"0 0 * * *",      // Every day at midnight
		"0 2 * * *",      // Every day at 2:00 AM
		"*/15 * * * *",   // Every 15 minutes
		"0 */6 * * *",    // Every 6 hours
		"0 0 * * 0",      // Every Sunday at midnight
		"0 0 1 * *",      // First day of month at midnight
		"30 3 1 * *",     // First day of month at 3:30 AM
		"0 9-17 * * 1-5", // Every hour from 9 AM to 5 PM on weekdays
	}

	now := time.Now()

	for _, expr := range expressions {
		nextRun, err := scheduler.ParseCronExpression(expr, now)
		if err != nil {
			fmt.Printf("Invalid: %s (%v)\n", expr, err)
			continue
		}

		description := scheduler.GetCronDescription(expr)
		fmt.Printf("%-20s -> %s (Next: %s)\n",
			expr,
			description,
			nextRun.Format("2006-01-02 15:04"),
		)
	}
}

// Example_enableDisable demonstrates enabling and disabling scans
func Example_enableDisable() {
	s, err := scheduler.NewScheduler(":memory:")
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	// Create a scan
	scan := scheduler.ScheduledScan{
		ID:       "toggle-scan",
		Name:     "Toggleable Scan",
		Target:   "example.com",
		Tools:    "nmap",
		CronExpr: "0 0 * * *",
		Enabled:  true,
	}

	if err := s.CreateScan(scan); err != nil {
		log.Fatal(err)
	}

	// Disable the scan
	if err := s.DisableScan(scan.ID); err != nil {
		log.Fatal(err)
	}

	retrieved, _ := s.GetScan(scan.ID)
	fmt.Printf("After disable: enabled=%t\n", retrieved.Enabled)

	// Enable the scan
	if err := s.EnableScan(scan.ID); err != nil {
		log.Fatal(err)
	}

	retrieved, _ = s.GetScan(scan.ID)
	fmt.Printf("After enable: enabled=%t\n", retrieved.Enabled)
}

// Example_update demonstrates updating a scheduled scan
func Example_update() {
	s, err := scheduler.NewScheduler(":memory:")
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	// Create initial scan
	scan := scheduler.ScheduledScan{
		ID:       "update-scan",
		Name:     "Original Name",
		Target:   "example.com",
		Tools:    "nmap",
		CronExpr: "0 0 * * *",
		Enabled:  true,
	}

	if err := s.CreateScan(scan); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Original: %s (target: %s)\n", scan.Name, scan.Target)

	// Update the scan
	scan.Name = "Updated Name"
	scan.Target = "updated.example.com"
	scan.Tools = "nmap,nikto,nuclei"
	scan.CronExpr = "0 2 * * *" // Change to 2 AM

	if err := s.UpdateScan(scan); err != nil {
		log.Fatal(err)
	}

	// Retrieve updated scan
	updated, err := s.GetScan(scan.ID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Updated: %s (target: %s)\n", updated.Name, updated.Target)
	fmt.Printf("Tools: %s\n", updated.Tools)
	fmt.Printf("Schedule: %s\n", updated.CronExpr)
}

// Example_validation demonstrates validation errors
func Example_validation() {
	s, err := scheduler.NewScheduler(":memory:")
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	// Try to create scan without ID
	scan := scheduler.ScheduledScan{
		Name:     "No ID Scan",
		Target:   "example.com",
		Tools:    "nmap",
		CronExpr: "0 0 * * *",
	}

	if err := s.CreateScan(scan); err != nil {
		fmt.Printf("Validation error: %v\n", err)
	}

	// Try invalid cron expression
	scan.ID = "test-scan"
	scan.CronExpr = "invalid cron"

	if err := s.CreateScan(scan); err != nil {
		fmt.Printf("Cron validation error: %v\n", err)
	}

	// Valid scan
	scan.CronExpr = "0 0 * * *"
	if err := s.CreateScan(scan); err != nil {
		fmt.Printf("Unexpected error: %v\n", err)
	} else {
		fmt.Println("Scan created successfully")
	}
}

// Example_multipleTools demonstrates scheduling with multiple tools
func Example_multipleTools() {
	s, err := scheduler.NewScheduler(":memory:")
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	// Create scan with multiple tools
	scan := scheduler.ScheduledScan{
		ID:       "multi-tool-scan",
		Name:     "Comprehensive Security Scan",
		Target:   "192.168.1.0/24",
		Tools:    "nmap,nikto,nuclei,masscan", // Multiple tools
		CronExpr: "0 2 * * *",
		Enabled:  true,
	}

	if err := s.CreateScan(scan); err != nil {
		log.Fatal(err)
	}

	retrieved, _ := s.GetScan(scan.ID)
	fmt.Printf("Scan: %s\n", retrieved.Name)
	fmt.Printf("Tools: %s\n", retrieved.Tools)
	fmt.Printf("Schedule: %s\n", scheduler.GetCronDescription(retrieved.CronExpr))
}
