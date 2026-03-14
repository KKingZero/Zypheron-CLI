package history

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Example demonstrates how to use the history manager in the Zypheron CLI

// ExampleAddingScanToHistory shows how to add a scan to the history
func ExampleAddingScanToHistory() {
	// Create a history manager
	manager, err := NewManager()
	if err != nil {
		fmt.Printf("Failed to create history manager: %v\n", err)
		return
	}

	// Create a new history entry for a scan
	entry := &HistoryEntry{
		ID:            uuid.New().String(),
		Timestamp:     time.Now(),
		Target:        "example.com",
		ScanType:      "port-scan",
		Tool:          "nmap",
		Duration:      45000, // 45 seconds in milliseconds
		Status:        StatusSuccess,
		FindingsCount: 15,
		VulnCount:     3,
		SessionID:     "session-" + uuid.New().String(),
		Tags:          []string{"production", "web-server"},
	}

	// Add the entry to history
	if err := manager.AddEntry(entry); err != nil {
		fmt.Printf("Failed to add entry to history: %v\n", err)
		return
	}

	fmt.Println("Scan added to history successfully")
}

// ExampleRetrievingHistory shows how to retrieve and display history
func ExampleRetrievingHistory() {
	manager, err := NewManager()
	if err != nil {
		fmt.Printf("Failed to create history manager: %v\n", err)
		return
	}

	// Get the last 10 scans
	entries, err := manager.GetHistory(10, 0)
	if err != nil {
		fmt.Printf("Failed to get history: %v\n", err)
		return
	}

	// Display the history
	fmt.Printf("Last %d scans:\n", len(entries))
	for i, entry := range entries {
		fmt.Printf("%d. [%s] %s - %s (%s) - %d findings\n",
			i+1,
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			entry.Target,
			entry.Tool,
			entry.Status,
			entry.FindingsCount,
		)
	}
}

// ExampleSearchingHistory shows how to search through history
func ExampleSearchingHistory() {
	manager, err := NewManager()
	if err != nil {
		fmt.Printf("Failed to create history manager: %v\n", err)
		return
	}

	// Search for all scans related to "example.com"
	entries, err := manager.SearchHistory("example.com")
	if err != nil {
		fmt.Printf("Failed to search history: %v\n", err)
		return
	}

	fmt.Printf("Found %d scans for 'example.com':\n", len(entries))
	for _, entry := range entries {
		fmt.Printf("- %s: %s with %s\n",
			entry.Timestamp.Format("2006-01-02 15:04"),
			entry.ScanType,
			entry.Tool,
		)
	}
}

// ExampleGettingStats shows how to get aggregated statistics
func ExampleGettingStats() {
	manager, err := NewManager()
	if err != nil {
		fmt.Printf("Failed to create history manager: %v\n", err)
		return
	}

	// Get statistics
	stats, err := manager.GetStats()
	if err != nil {
		fmt.Printf("Failed to get stats: %v\n", err)
		return
	}

	// Display statistics
	fmt.Println("Scan History Statistics:")
	fmt.Printf("  Total Scans: %d\n", stats.TotalScans)
	fmt.Printf("  Total Findings: %d\n", stats.TotalFindings)
	fmt.Printf("  Total Vulnerabilities: %d\n", stats.TotalVulns)
	fmt.Printf("  Success Rate: %.2f%%\n", stats.SuccessRate)
	fmt.Printf("  Average Duration: %.2f seconds\n", float64(stats.AvgDuration)/1000)

	if stats.LastScanTime != nil {
		fmt.Printf("  Last Scan: %s\n", stats.LastScanTime.Format("2006-01-02 15:04:05"))
	}

	fmt.Println("\nScans by Tool:")
	for tool, count := range stats.ScansByTool {
		fmt.Printf("  %s: %d\n", tool, count)
	}

	fmt.Println("\nScans by Target:")
	for target, count := range stats.ScansByTarget {
		fmt.Printf("  %s: %d\n", target, count)
	}

	fmt.Println("\nScans by Status:")
	for status, count := range stats.ScansByStatus {
		fmt.Printf("  %s: %d\n", status, count)
	}
}

// ExampleFilteringByDateRange shows how to filter history by date range
func ExampleFilteringByDateRange() {
	manager, err := NewManager()
	if err != nil {
		fmt.Printf("Failed to create history manager: %v\n", err)
		return
	}

	// Get all scans from the last 7 days
	now := time.Now()
	start := now.Add(-7 * 24 * time.Hour)
	end := now

	entries, err := manager.GetHistoryByDateRange(start, end)
	if err != nil {
		fmt.Printf("Failed to get history by date range: %v\n", err)
		return
	}

	fmt.Printf("Scans in the last 7 days: %d\n", len(entries))
	for _, entry := range entries {
		fmt.Printf("- %s: %s on %s\n",
			entry.Timestamp.Format("2006-01-02"),
			entry.Tool,
			entry.Target,
		)
	}
}

// ExampleExportingHistory shows how to export history to a file
func ExampleExportingHistory() {
	manager, err := NewManager()
	if err != nil {
		fmt.Printf("Failed to create history manager: %v\n", err)
		return
	}

	// Export history to a JSON file
	exportPath := "/tmp/zypheron_history_export.json"
	if err := manager.ExportHistory(exportPath); err != nil {
		fmt.Printf("Failed to export history: %v\n", err)
		return
	}

	fmt.Printf("History exported to: %s\n", exportPath)
}

// ExampleIntegrationWithScanCommand shows how to integrate history with a scan command
func ExampleIntegrationWithScanCommand() {
	// This is a pseudo-code example showing integration

	// 1. Initialize history manager at application start
	manager, err := NewManager()
	if err != nil {
		fmt.Printf("Failed to create history manager: %v\n", err)
		return
	}

	// 2. When starting a scan
	scanID := uuid.New().String()
	sessionID := uuid.New().String()
	startTime := time.Now()
	target := "example.com"
	tool := "nmap"

	fmt.Printf("Starting scan with ID: %s\n", scanID)

	// 3. Execute the scan (pseudo-code)
	// scanResult, scanErr := executeScan(target, tool)

	// 4. Calculate duration
	duration := time.Since(startTime).Milliseconds()

	// 5. Create history entry based on scan result
	entry := &HistoryEntry{
		ID:        scanID,
		Timestamp: startTime,
		Target:    target,
		ScanType:  "port-scan",
		Tool:      tool,
		Duration:  duration,
		Status:    StatusSuccess, // or StatusFailed based on scanErr
		// FindingsCount: len(scanResult.Findings),
		// VulnCount:     countVulnerabilities(scanResult),
		SessionID: sessionID,
		Tags:      []string{"automated"},
	}

	// 6. Add to history
	if err := manager.AddEntry(entry); err != nil {
		fmt.Printf("Warning: Failed to add scan to history: %v\n", err)
		// Don't fail the scan just because history failed
	}

	fmt.Println("Scan completed and added to history")
}

// ExampleRecoveringFromFailedScan shows how to track failed scans
func ExampleRecoveringFromFailedScan() {
	manager, err := NewManager()
	if err != nil {
		fmt.Printf("Failed to create history manager: %v\n", err)
		return
	}

	// Create entry for a failed scan
	entry := &HistoryEntry{
		ID:            uuid.New().String(),
		Timestamp:     time.Now(),
		Target:        "unreachable.example.com",
		ScanType:      "vulnerability-scan",
		Tool:          "nikto",
		Duration:      5000,
		Status:        StatusFailed,
		FindingsCount: 0,
		VulnCount:     0,
		SessionID:     "session-" + uuid.New().String(),
		Tags:          []string{"failed", "timeout"},
	}

	manager.AddEntry(entry)

	// Later, user wants to see all failed scans to retry
	failedScans, err := manager.SearchHistory("failed")
	if err != nil {
		fmt.Printf("Failed to search history: %v\n", err)
		return
	}

	fmt.Printf("Found %d failed scans that might need retry:\n", len(failedScans))
	for _, scan := range failedScans {
		fmt.Printf("- %s: %s with %s\n",
			scan.Target,
			scan.ScanType,
			scan.Tool,
		)
	}
}

// ExampleTrackingAutoPentSession shows how to track an autopent session
func ExampleTrackingAutoPentSession() {
	manager, err := NewManager()
	if err != nil {
		fmt.Printf("Failed to create history manager: %v\n", err)
		return
	}

	// AutoPent session consists of multiple scans
	sessionID := uuid.New().String()
	target := "testlab.example.com"

	// Track each phase of the autopent
	phases := []struct {
		tool     string
		scanType string
		duration int64
		findings int
		vulns    int
	}{
		{"nmap", "port-scan", 45000, 20, 0},
		{"nikto", "web-scan", 120000, 15, 3},
		{"sqlmap", "sql-injection", 300000, 5, 2},
	}

	for i, phase := range phases {
		entry := &HistoryEntry{
			ID:            fmt.Sprintf("%s-phase-%d", sessionID, i+1),
			Timestamp:     time.Now().Add(time.Duration(i) * time.Minute),
			Target:        target,
			ScanType:      phase.scanType,
			Tool:          phase.tool,
			Duration:      phase.duration,
			Status:        StatusSuccess,
			FindingsCount: phase.findings,
			VulnCount:     phase.vulns,
			SessionID:     sessionID,
			Tags:          []string{"autopent", fmt.Sprintf("phase-%d", i+1)},
		}

		if err := manager.AddEntry(entry); err != nil {
			fmt.Printf("Failed to add phase %d to history: %v\n", i+1, err)
		}
	}

	// Later, retrieve all scans from this autopent session
	sessionScans, err := manager.SearchHistory(sessionID)
	if err != nil {
		fmt.Printf("Failed to search session: %v\n", err)
		return
	}

	fmt.Printf("AutoPent session %s completed %d phases:\n", sessionID[:8], len(sessionScans))
	totalVulns := 0
	for _, scan := range sessionScans {
		totalVulns += scan.VulnCount
		fmt.Printf("  Phase: %s (%s) - %d vulnerabilities\n",
			scan.ScanType,
			scan.Tool,
			scan.VulnCount,
		)
	}
	fmt.Printf("Total vulnerabilities found: %d\n", totalVulns)
}
