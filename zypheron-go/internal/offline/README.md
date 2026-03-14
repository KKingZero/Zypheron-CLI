# Zypheron Offline Mode System

## Overview

The offline mode system provides graceful degradation of Zypheron CLI functionality when network connectivity or AI services are unavailable. This ensures that core penetration testing tools remain functional even in air-gapped or restricted network environments.

## Features

### 1. Network Connectivity Detection
- **Internet Connectivity**: Checks connection to well-known DNS servers (Google DNS 8.8.8.8, Cloudflare DNS 1.1.1.1)
- **AI Service Availability**: Verifies if local AI backend is running and responsive
- **Latency Measurement**: Tracks connection quality for diagnostics

### 2. Intelligent Caching
- **AI Response Cache**: Stores up to 100 most recent/frequently used AI responses
- **LRU Eviction**: Automatically manages cache size using Least Recently Used algorithm
- **Query Normalization**: Case-insensitive, whitespace-agnostic cache lookup
- **Persistent Storage**: Cache survives application restarts

### 3. Local Vulnerability Database
- **CVE Lookup**: Offline CVE information lookup from local database
- **Automatic Updates**: Downloads latest CVE data when online
- **Fallback Data**: Includes critical CVEs (Log4Shell, EternalBlue, XZ backdoor) by default
- **7-Day Refresh**: Automatically checks for updates weekly

### 4. Graceful Degradation
- **Feature Detection**: Automatically determines available capabilities
- **User Notifications**: Clear messaging about limited functionality
- **Transparent Fallbacks**: Seamlessly switches between online and offline modes

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Zypheron CLI                       │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌──────────────────────────────────────────────┐  │
│  │         Offline Manager                      │  │
│  │  ┌────────────────┐  ┌────────────────────┐ │  │
│  │  │ Connectivity   │  │  Cache Manager     │ │  │
│  │  │   Checker      │  │  - AI Responses    │ │  │
│  │  │  - Internet    │  │  - LRU Eviction    │ │  │
│  │  │  - AI Service  │  │  - Persistence     │ │  │
│  │  └────────────────┘  └────────────────────┘ │  │
│  │                                              │  │
│  │  ┌────────────────────────────────────────┐ │  │
│  │  │     Local Vulnerability Database       │ │  │
│  │  │  - CVE Lookup                          │ │  │
│  │  │  - Auto-update                         │ │  │
│  │  │  - Fallback Data                       │ │  │
│  │  └────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────┘  │
│                                                      │
└─────────────────────────────────────────────────────┘
         │                    │                │
         v                    v                v
   ┌──────────┐        ┌───────────┐    ┌─────────┐
   │ Internet │        │ AI Service│    │  Cache  │
   │  Check   │        │  Socket   │    │  Files  │
   └──────────┘        └───────────┘    └─────────┘
```

## Cache Storage

Caches are stored in: `~/.zypheron/cache/`

- **ai_responses.json**: Cached AI responses (max 100 entries, LRU eviction)
- **vuln_db.json**: Local vulnerability database (CVE data)

### Cache File Format

**AI Responses Cache:**
```json
{
  "WHATISSQLINJECTION?": {
    "query": "What is SQL injection?",
    "response": "SQL injection is a code injection technique...",
    "timestamp": "2026-01-18T10:00:00Z",
    "use_count": 5
  }
}
```

**Vulnerability Database:**
```json
{
  "cves": {
    "CVE-2024-3094": {
      "id": "CVE-2024-3094",
      "description": "XZ Utils backdoor - Malicious code...",
      "published": "2024-03-29T00:00:00Z",
      "modified": "2024-04-01T00:00:00Z",
      "cvss": {
        "version": "3.1",
        "base_score": 10.0,
        "base_severity": "CRITICAL",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
      },
      "references": ["..."],
      "affected_products": ["xz", "liblzma"]
    }
  },
  "last_updated": "2026-01-18T10:00:00Z",
  "version": "1.0.0"
}
```

## API Reference

### Core Functions

#### `NewOfflineManager() (*OfflineManager, error)`
Creates a new offline manager instance. Automatically loads existing caches.

#### `IsOnline() bool`
Checks internet connectivity by pinging well-known DNS servers.

#### `IsAIServiceAvailable() bool`
Checks if the AI backend service is running and responsive.

#### `CheckConnectivity() *ConnectivityStatus`
Performs comprehensive connectivity check, returning detailed status.

**ConnectivityStatus:**
```go
type ConnectivityStatus struct {
    Internet     bool
    AIService    bool
    LastChecked  time.Time
    Latency      time.Duration
    ErrorMessage string
}
```

### Cache Management

#### `CacheAIResponse(query, response string) error`
Caches an AI response. Automatically evicts LRU entry if cache is full.

#### `GetCachedResponse(query string) (string, bool)`
Retrieves a cached AI response. Returns (response, true) if found, ("", false) otherwise.

#### `ClearCache() error`
Clears all cached AI responses.

### Vulnerability Database

#### `LoadLocalVulnDB() error`
Loads or downloads the vulnerability database. Falls back to embedded CVEs if offline.

#### `LookupCVE(cveID string) (*CVEInfo, error)`
Looks up CVE information from local database.

#### `UpdateVulnDB() error`
Forces an update of the vulnerability database from remote source.

### Status & Capabilities

#### `GetOfflineCapabilities() []string`
Returns list of features available in offline mode.

#### `GetOfflineStatus() map[string]interface{}`
Returns comprehensive status including connectivity, cache stats, and capabilities.

#### `GetGracefulDegradationMessage() string`
Returns user-friendly message explaining current limitations.

### Convenience Functions

```go
// Global singleton access
offline.IsOnline()              // Quick internet check
offline.IsAIServiceAvailable()  // Quick AI service check
offline.CheckConnectivity()     // Full status check
offline.GetManager()            // Get manager instance
```

## Offline Capabilities

When running in offline mode, the following features remain functional:

### ✅ Available Offline
- Network scanning (nmap, masscan)
- Port scanning
- Service enumeration
- Web vulnerability scanning (nikto, dirb, gobuster)
- SSL/TLS analysis
- DNS enumeration (local)
- Subdomain discovery (passive)
- Local CVE database lookup
- Cached AI response retrieval
- Report generation from cached data
- Tool execution (non-cloud tools)
- Basic exploit search (local database)
- Configuration management
- Session management
- History viewing

### ❌ Unavailable Offline
- Real-time AI analysis (new queries)
- Online exploit database queries
- Cloud-based scanning services
- Vulnerability database updates
- Remote API calls
- Cloud AI providers (OpenAI, Anthropic, DeepSeek)
- Online CVE lookup (uses local database instead)

## Usage Examples

### Example 1: Basic Connectivity Check
```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/offline"

func main() {
    if offline.IsOnline() {
        fmt.Println("Internet connection available")
    } else {
        fmt.Println("Running in offline mode")
    }
}
```

### Example 2: Detailed Status Check
```go
status := offline.CheckConnectivity()

fmt.Printf("Internet: %v\n", status.Internet)
fmt.Printf("AI Service: %v\n", status.AIService)
fmt.Printf("Latency: %v\n", status.Latency)

if status.ErrorMessage != "" {
    fmt.Printf("Warning: %s\n", status.ErrorMessage)
}
```

### Example 3: Caching AI Responses
```go
manager, _ := offline.GetManager()

// Cache a response
query := "What is SQL injection?"
response := "SQL injection is a code injection technique..."
manager.CacheAIResponse(query, response)

// Later, retrieve from cache
if cached, found := manager.GetCachedResponse(query); found {
    fmt.Printf("Cached response: %s\n", cached)
}
```

### Example 4: CVE Lookup
```go
manager, _ := offline.GetManager()

// Load CVE database
manager.LoadLocalVulnDB()

// Lookup CVE
if cve, err := manager.LookupCVE("CVE-2021-44228"); err == nil {
    fmt.Printf("CVE: %s\n", cve.ID)
    fmt.Printf("Description: %s\n", cve.Description)
    fmt.Printf("Severity: %s (%.1f)\n",
        cve.CVSS.BaseSeverity, cve.CVSS.BaseScore)
}
```

### Example 5: Graceful Degradation
```go
manager, _ := offline.GetManager()

if !manager.IsAIServiceAvailable() {
    fmt.Println(manager.GetGracefulDegradationMessage())
}

// Continue with available functionality
executeOfflineTools()
```

## Integration Guide

### Step 1: Import the Package
```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/offline"
```

### Step 2: Check Connectivity at Startup
```go
func main() {
    status := offline.CheckConnectivity()

    if !status.Internet || !status.AIService {
        fmt.Println("Warning: Running in degraded mode")
        fmt.Println(offline.GetManager().GetGracefulDegradationMessage())
    }

    // Continue with application
}
```

### Step 3: Add Caching to AI Calls
```go
func analyzeWithAI(data string) (string, error) {
    manager, _ := offline.GetManager()

    // Check if AI is available
    if !manager.IsAIServiceAvailable() {
        // Try cache first
        if cached, found := manager.GetCachedResponse(data); found {
            return "[CACHED] " + cached, nil
        }
        return "", errors.New("AI unavailable and no cached response")
    }

    // Get fresh response
    response := callAIService(data)

    // Cache for offline use
    manager.CacheAIResponse(data, response)

    return response, nil
}
```

### Step 4: Add Fallback Logic
```go
func scanWithAnalysis(target string) error {
    manager, _ := offline.GetManager()

    // Execute scan (works offline)
    scanResults := executeScan(target)

    // Try AI analysis
    if manager.IsAIServiceAvailable() {
        analysis := analyzeWithAI(scanResults)
        displayResults(scanResults, analysis)
    } else {
        // Fallback to basic analysis
        fmt.Println("AI unavailable - showing raw results")
        displayResults(scanResults, nil)
    }

    return nil
}
```

## Best Practices

1. **Check Connectivity Early**: Verify connectivity at application startup to set user expectations
2. **Cache Aggressively**: Cache all AI responses for offline availability
3. **Provide Clear Feedback**: Use `GetGracefulDegradationMessage()` to inform users about limitations
4. **Fallback Gracefully**: Always provide alternative functionality when services are unavailable
5. **Update Regularly**: Keep vulnerability database updated when online
6. **Test Offline**: Verify your application works properly in offline mode
7. **Monitor Changes**: Watch for connectivity state changes in long-running processes

## Performance Considerations

- **Connectivity Checks**: Cached for 3-second timeout
- **Cache Lookups**: O(1) hash map lookup, very fast
- **CVE Lookups**: O(1) hash map lookup, instant
- **Cache Eviction**: O(n) where n=cache size, only on overflow
- **Disk I/O**: Async for cache updates, non-blocking

## Security Considerations

- **Cache Storage**: Files stored with 0600 permissions (owner read/write only)
- **Directory Security**: Cache directory created with 0700 permissions
- **No Sensitive Data**: Avoid caching sensitive queries or responses
- **Local-Only**: All cached data stored locally, never transmitted

## Troubleshooting

### Issue: "No cached responses available"
- **Cause**: Cache is empty or queries don't match
- **Solution**: Use AI online first to build cache, ensure query normalization

### Issue: "CVE not found in local database"
- **Cause**: CVE not in database or database not loaded
- **Solution**: Run `UpdateVulnDB()` when online, or use fallback CVEs

### Issue: "Cache directory permission denied"
- **Cause**: Insufficient permissions on `~/.zypheron/cache/`
- **Solution**: Check directory permissions, run with appropriate user

### Issue: "AI service detection fails"
- **Cause**: Socket not found or not owned by current user
- **Solution**: Start AI service with `zypheron ai start`, check socket permissions

## Future Enhancements

- [ ] Encrypted cache storage
- [ ] Cache compression for large responses
- [ ] Distributed cache synchronization
- [ ] Smart pre-caching of common queries
- [ ] Offline exploit database
- [ ] Peer-to-peer cache sharing
- [ ] Differential vulnerability database updates
- [ ] Cache analytics and insights

## License

Part of Zypheron CLI - Professional Penetration Testing Platform
