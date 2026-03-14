package offline

// Example usage of the offline mode functionality
// This file demonstrates how to integrate offline mode into commands

/*
EXAMPLE 1: Check connectivity before executing a command

func ExecuteScanCommand(target string) error {
    // Check connectivity status
    status := offline.CheckConnectivity()

    if !status.Internet && !status.AIService {
        fmt.Println(offline.GetManager().GetGracefulDegradationMessage())
        fmt.Println("\nProceeding with offline scan (no AI analysis)...")
    } else if !status.AIService {
        fmt.Println("Warning: AI service unavailable. Analysis will be limited.")
    }

    // Execute scan with appropriate flags
    useAI := status.AIService
    return executeScan(target, useAI)
}

EXAMPLE 2: Use cached AI responses when offline

func GetAIAnalysis(query string) (string, error) {
    manager, err := offline.GetManager()
    if err != nil {
        return "", err
    }

    // Check if AI service is available
    if !manager.IsAIServiceAvailable() {
        // Try to get cached response
        if cached, found := manager.GetCachedResponse(query); found {
            return fmt.Sprintf("[CACHED] %s", cached), nil
        }
        return "", fmt.Errorf("AI service unavailable and no cached response found")
    }

    // Get fresh response from AI
    response := callAIService(query)

    // Cache the response for offline use
    manager.CacheAIResponse(query, response)

    return response, nil
}

EXAMPLE 3: CVE lookup with offline fallback

func LookupCVE(cveID string) (*offline.CVEInfo, error) {
    manager, err := offline.GetManager()
    if err != nil {
        return nil, err
    }

    // Check if online
    if manager.IsOnline() {
        // Try online lookup first
        if cve, err := fetchCVEOnline(cveID); err == nil {
            return cve, nil
        }
    }

    // Fallback to local database
    return manager.LookupCVE(cveID)
}

EXAMPLE 4: Display offline mode status

func ShowSystemStatus() {
    manager, err := offline.GetManager()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    status := manager.GetOfflineStatus()

    fmt.Println("=== Zypheron System Status ===")
    fmt.Printf("Mode: %s\n", status["mode"])

    if connectivity, ok := status["connectivity"].(*offline.ConnectivityStatus); ok {
        fmt.Printf("Internet: %v\n", connectivity.Internet)
        fmt.Printf("AI Service: %v\n", connectivity.AIService)
        if connectivity.Latency > 0 {
            fmt.Printf("Latency: %v\n", connectivity.Latency)
        }
    }

    if cacheStats, ok := status["cache_stats"].(map[string]interface{}); ok {
        fmt.Printf("\nCache Statistics:\n")
        fmt.Printf("  Cached Responses: %v/%v\n",
            cacheStats["cached_responses"],
            cacheStats["max_cache_size"])
        fmt.Printf("  CVE Database: %v entries\n", cacheStats["vuln_db_cves"])
    }

    fmt.Println("\nOffline Capabilities:")
    if caps, ok := status["capabilities"].([]string); ok {
        for _, cap := range caps {
            fmt.Printf("  - %s\n", cap)
        }
    }
}

EXAMPLE 5: Command with automatic offline detection

func AutoScanCommand(target string) error {
    manager, err := offline.GetManager()
    if err != nil {
        return err
    }

    // Check what features are available
    capabilities := manager.GetOfflineCapabilities()

    // Determine scan strategy based on connectivity
    status := manager.CheckConnectivity()

    scanConfig := ScanConfig{
        Target:         target,
        UseAI:          status.AIService,
        UseOnlineDB:    status.Internet,
        UseCachedData:  true,
    }

    fmt.Printf("Scan Mode: %s\n", getOperatingMode(status))

    if !status.Internet || !status.AIService {
        fmt.Println("\nNote: Running in degraded mode")
        fmt.Println(manager.GetGracefulDegradationMessage())
        fmt.Println()
    }

    return executeScanWithConfig(scanConfig)
}

EXAMPLE 6: Periodic connectivity check in long-running process

func MonitorConnectivity(ctx context.Context, interval time.Duration) {
    manager, _ := offline.GetManager()
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    var lastStatus *offline.ConnectivityStatus

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            status := manager.CheckConnectivity()

            // Detect status changes
            if lastStatus == nil ||
               lastStatus.Internet != status.Internet ||
               lastStatus.AIService != status.AIService {

                if status.Internet && status.AIService {
                    fmt.Println("✓ System back online - all features available")
                } else if lastStatus != nil {
                    fmt.Printf("⚠ Connectivity changed: %s\n", status.ErrorMessage)
                }

                lastStatus = status
            }
        }
    }
}

EXAMPLE 7: Update vulnerability database

func UpdateVulnDatabase() error {
    manager, err := offline.GetManager()
    if err != nil {
        return err
    }

    if !manager.IsOnline() {
        return fmt.Errorf("cannot update vulnerability database: no internet connection")
    }

    fmt.Println("Updating vulnerability database...")
    if err := manager.UpdateVulnDB(); err != nil {
        return fmt.Errorf("update failed: %w", err)
    }

    fmt.Println("Vulnerability database updated successfully")

    // Show stats
    stats := manager.GetCacheStats()
    fmt.Printf("Database now contains %v CVEs\n", stats["vuln_db_cves"])

    return nil
}

EXAMPLE 8: Integration in main command router

func RouterCommand(cmd string, args []string) error {
    // Check connectivity at startup
    manager, _ := offline.GetManager()
    status := manager.CheckConnectivity()

    // Store in context for all commands
    ctx := context.WithValue(context.Background(), "connectivity", status)
    ctx = context.WithValue(ctx, "offline_manager", manager)

    // Route to appropriate command
    switch cmd {
    case "scan":
        return ScanCommandWithContext(ctx, args)
    case "analyze":
        return AnalyzeCommandWithContext(ctx, args)
    case "status":
        ShowSystemStatus()
        return nil
    default:
        return fmt.Errorf("unknown command: %s", cmd)
    }
}

EXAMPLE 9: Graceful AI fallback

func AnalyzeWithAI(data string) (string, error) {
    manager, err := offline.GetManager()
    if err != nil {
        return "", err
    }

    // Try AI service
    if manager.IsAIServiceAvailable() {
        return callAIService(data)
    }

    // Fallback 1: Check cache
    if cached, found := manager.GetCachedResponse(data); found {
        return fmt.Sprintf("[FROM CACHE]\n%s", cached), nil
    }

    // Fallback 2: Basic pattern matching (no AI)
    return performBasicAnalysis(data), nil
}

EXAMPLE 10: Cache management command

func CacheClearCommand() error {
    manager, err := offline.GetManager()
    if err != nil {
        return err
    }

    // Show stats before clearing
    stats := manager.GetCacheStats()
    fmt.Printf("Clearing cache...\n")
    fmt.Printf("  Cached responses: %v\n", stats["cached_responses"])

    if err := manager.ClearCache(); err != nil {
        return fmt.Errorf("failed to clear cache: %w", err)
    }

    fmt.Println("Cache cleared successfully")
    return nil
}
*/
