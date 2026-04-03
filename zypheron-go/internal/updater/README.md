# Updater Package

Automatic update checker for Zypheron CLI that checks GitHub releases for new versions.

## Features

- **Semantic Version Comparison**: Properly compares versions following SemVer specification
- **24-Hour Cache**: Results cached for 24 hours in `~/.zypheron/cache/update_check.json`
- **Non-blocking**: Async checks don't slow down startup
- **Config Respecting**: Honors `config.CheckUpdates` setting
- **Rate Limit Handling**: Gracefully handles GitHub API rate limits
- **Timeout Protection**: 10-second timeout prevents hanging
- **Release Notes**: Fetch detailed release information
- **Platform-Aware**: Knows which binary to download for current OS/arch

## API

### Core Functions

```go
// Create updater instance
updater := updater.New(cfg)

// Check for updates (uses cache if recent)
info, err := updater.CheckForUpdates()

// Get current version
version := updater.GetCurrentVersion()

// Simple check
available, newVersion, err := updater.IsUpdateAvailable()

// Get release notes
notes, err := updater.GetReleaseNotes("1.0.1")

// Download update (stub implementation)
err := updater.DownloadUpdate("1.0.1")
```

### Helper Functions

```go
// Non-blocking async check
updater.CheckForUpdatesAsync(cfg, func(info *UpdateInfo, err error) {
    if info.UpdateAvailable {
        fmt.Printf("Update available: %s\n", info.LatestVersion)
    }
})

// Should we check now?
if updater.ShouldCheckForUpdates(cfg) {
    // Perform check
}
```

## Data Structures

### UpdateInfo

```go
type UpdateInfo struct {
    CurrentVersion  string    // e.g., "1.0.0"
    LatestVersion   string    // e.g., "1.0.1"
    UpdateAvailable bool      // true if latest > current
    ReleaseURL      string    // GitHub release page URL
    ReleaseNotes    string    // Markdown release notes
    PublishedAt     time.Time // When released
    LastChecked     time.Time // When we checked
}
```

## Configuration

The updater respects the following config settings:

- `CheckUpdates` (bool): Enable/disable update checks
- `LastUpdateCheck` (string): Timestamp of last check
- `CacheDir` (string): Where to store cache file

## Environment Variables

- `GITHUB_TOKEN`: Optional GitHub token to increase API rate limit from 60/hr to 5000/hr

## Cache Behavior

- Cache stored at: `~/.zypheron/cache/update_check.json`
- Cache valid for: 24 hours
- Cache format: JSON with UpdateInfo structure
- Cache automatically refreshed when expired

## Testing

### Unit Tests
```bash
go test ./internal/updater/
```

### Integration Tests (requires network)
```bash
go test -tags=integration ./internal/updater/
```

### Skip Integration Tests
```bash
go test -short ./internal/updater/
```

## Example Usage

### 1. Startup Check (Non-blocking)

```go
func main() {
    cfg := config.Get()

    if updater.ShouldCheckForUpdates(cfg) {
        updater.CheckForUpdatesAsync(cfg, func(info *updater.UpdateInfo, err error) {
            if err == nil && info.UpdateAvailable {
                log.Printf("Update available: %s -> %s",
                    info.CurrentVersion, info.LatestVersion)
            }
        })
    }

    // Continue with startup...
}
```

### 2. Update Command

```go
func updateCmd() *cobra.Command {
    return &cobra.Command{
        Use:   "update",
        Short: "Check for updates",
        RunE: func(cmd *cobra.Command, args []string) error {
            u := updater.New(config.Get())
            info, err := u.CheckForUpdates()
            if err != nil {
                return err
            }

            if info.UpdateAvailable {
                fmt.Printf("New version available: %s\n", info.LatestVersion)
                fmt.Printf("Download: %s\n", info.ReleaseURL)
            } else {
                fmt.Println("You're up to date!")
            }
            return nil
        },
    }
}
```

### 3. TUI Integration

```go
type Model struct {
    updateInfo *updater.UpdateInfo
}

func (m Model) Init() tea.Cmd {
    return checkForUpdatesCmd()
}

func checkForUpdatesCmd() tea.Cmd {
    return func() tea.Msg {
        u := updater.New(config.Get())
        info, err := u.CheckForUpdates()
        return UpdateCheckMsg{Info: info, Err: err}
    }
}

func (m Model) View() string {
    if m.updateInfo != nil && m.updateInfo.UpdateAvailable {
        return fmt.Sprintf("Update available: %s", m.updateInfo.LatestVersion)
    }
    return ""
}
```

## Version Comparison

The updater uses semantic versioning comparison:

```
1.0.0 < 1.0.1   ✓
1.0.0 < 1.1.0   ✓
1.0.0 < 2.0.0   ✓
1.0.0 = 1.0.0   ✓
1.0.1 > 1.0.0   ✓
```

Pre-release versions are handled by stripping the suffix:
```
1.0.0-beta -> 1.0.0
1.0.0-rc.1 -> 1.0.0
```

## Error Handling

The updater handles various error conditions:

- **Network errors**: Returns error, app continues
- **Rate limiting**: Returns specific error message
- **Invalid JSON**: Returns parse error
- **Timeout**: Returns after 10 seconds
- **Missing release**: Returns error for GetReleaseNotes

All errors are non-fatal - the app continues if update check fails.

## GitHub API

The updater uses GitHub's REST API v3:

- Endpoint: `https://api.github.com/repos/KKingZero/Zypheron-CLI/releases/latest`
- Auth: Optional via `GITHUB_TOKEN` environment variable
- Rate limit: 60/hour (unauthenticated), 5000/hour (authenticated)
- Timeout: 10 seconds
- User-Agent: `Zypheron-CLI/1.0.0`

## Download Feature

The `DownloadUpdate()` function is currently a stub that:
1. Fetches release information
2. Determines correct asset for platform
3. Downloads to temp directory
4. Returns error (automatic installation not implemented)

Future enhancements could include:
- Checksum verification
- Archive extraction
- Binary replacement (requires elevated permissions)
- Rollback capability

## Security Considerations

- API calls use HTTPS only
- No credentials stored (GITHUB_TOKEN from env only)
- Cache files have 0600 permissions (owner read/write only)
- User-Agent header identifies the client
- Timeout prevents indefinite hangs
- No automatic code execution

## Performance

- **First check**: ~200-500ms (network latency dependent)
- **Cached check**: <1ms (local file read)
- **Cache size**: ~1KB
- **Memory footprint**: Minimal (only during check)

## Troubleshooting

### Update Check Fails

```bash
# Check if updates are enabled
zypheron config get check_updates

# Clear cache and retry
rm ~/.zypheron/cache/update_check.json
```

### Rate Limited

```bash
# Set GitHub token to increase limit
export GITHUB_TOKEN=ghp_your_token_here
```

### Network Timeout

The updater will timeout after 10 seconds. This is normal if:
- No internet connection
- GitHub is down
- Firewall blocking HTTPS
- DNS issues

The app will continue normally - update checks are not critical.

## Future Enhancements

- [ ] Automatic download and install
- [ ] Update channels (stable/beta/nightly)
- [ ] Changelog viewer
- [ ] Version pinning
- [ ] Update notifications via desktop notification
- [ ] Automatic background updates
- [ ] Delta updates (download only changed files)
- [ ] GPG signature verification
