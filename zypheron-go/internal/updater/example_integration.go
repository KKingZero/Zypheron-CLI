package updater

// Example integration code for Zypheron CLI
// This file shows how to integrate the updater into your commands

/*

INTEGRATION EXAMPLES:

1. Check for updates on startup (non-blocking):

```go
import (
	"fmt"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/updater"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
)

func main() {
	cfg := config.Get()

	// Check for updates asynchronously on startup
	if updater.ShouldCheckForUpdates(cfg) {
		updater.CheckForUpdatesAsync(cfg, func(info *updater.UpdateInfo, err error) {
			if err != nil {
				// Silently fail - don't block startup for update check failures
				return
			}

			if info.UpdateAvailable {
				fmt.Fprintf(os.Stderr, "\n%s\n", ui.Warning(
					fmt.Sprintf("A new version of Zypheron is available: %s -> %s",
						info.CurrentVersion, info.LatestVersion)))
				fmt.Fprintf(os.Stderr, "%s\n\n", ui.Muted(
					fmt.Sprintf("Visit %s to download", info.ReleaseURL)))
			}
		})
	}

	// Rest of your application...
}
```

2. Create an "update" command:

```go
import (
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/updater"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
)

func updateCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Check for Zypheron updates",
		Long:  "Check if a new version of Zypheron CLI is available",
		Example: `  zypheron update              # Check for updates
  zypheron update --json       # Output as JSON`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.Get()
			u := updater.New(cfg)

			info, err := u.CheckForUpdates()
			if err != nil {
				return fmt.Errorf("failed to check for updates: %w", err)
			}

			if jsonOutput {
				data, _ := json.MarshalIndent(info, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			fmt.Printf("  %s %s\n", ui.Muted("Current Version:"), ui.Accent.Sprint(info.CurrentVersion))
			fmt.Printf("  %s %s\n", ui.Muted("Latest Version: "), ui.Accent.Sprint(info.LatestVersion))

			if info.UpdateAvailable {
				fmt.Printf("\n  %s\n\n", ui.Success("A new version is available!"))
				fmt.Printf("  %s %s\n", ui.Muted("Release URL:"), info.ReleaseURL)
				fmt.Printf("  %s %s\n\n", ui.Muted("Published:  "), info.PublishedAt.Format("2006-01-02"))

				if info.ReleaseNotes != "" {
					fmt.Printf("  %s\n", ui.Header("Release Notes:"))
					// Truncate release notes if too long
					notes := info.ReleaseNotes
					if len(notes) > 500 {
						notes = notes[:500] + "..."
					}
					fmt.Printf("%s\n", notes)
				}
			} else {
				fmt.Printf("\n  %s\n", ui.Success("You're running the latest version!"))
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")
	return cmd
}
```

3. Show update notification in TUI:

```go
import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/updater"
)

type UpdateCheckMsg struct {
	Info *updater.UpdateInfo
	Err  error
}

type Model struct {
	// ... other fields
	updateInfo *updater.UpdateInfo
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		// ... other init commands
		checkForUpdatesCmd(),
	)
}

func checkForUpdatesCmd() tea.Cmd {
	return func() tea.Msg {
		cfg := config.Get()
		if !updater.ShouldCheckForUpdates(cfg) {
			return nil
		}

		u := updater.New(cfg)
		info, err := u.CheckForUpdates()
		return UpdateCheckMsg{Info: info, Err: err}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case UpdateCheckMsg:
		if msg.Err == nil && msg.Info != nil {
			m.updateInfo = msg.Info
		}
		return m, nil
	// ... handle other messages
	}
	return m, nil
}

func (m Model) View() string {
	var s string

	// Show update banner if available
	if m.updateInfo != nil && m.updateInfo.UpdateAvailable {
		banner := lipgloss.NewStyle().
			Background(lipgloss.Color("33")).
			Foreground(lipgloss.Color("0")).
			Padding(0, 1).
			Render(fmt.Sprintf(" Update available: %s -> %s ",
				m.updateInfo.CurrentVersion, m.updateInfo.LatestVersion))
		s += banner + "\n\n"
	}

	// ... rest of your view
	return s
}
```

4. Manual update check in config command:

```go
// In your config command or settings interface
func checkUpdatesNow() error {
	cfg := config.Get()
	u := updater.New(cfg)

	fmt.Println(ui.Info("Checking for updates..."))

	info, err := u.CheckForUpdates()
	if err != nil {
		return fmt.Errorf("update check failed: %w", err)
	}

	if info.UpdateAvailable {
		fmt.Printf("\n%s\n", ui.Success(
			fmt.Sprintf("Version %s is available (you have %s)",
				info.LatestVersion, info.CurrentVersion)))
		fmt.Printf("%s\n", ui.Muted(info.ReleaseURL))
		return nil
	}

	fmt.Printf("\n%s\n", ui.Success("You're up to date!"))
	return nil
}
```

5. Disable update checks:

```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"

func disableUpdateChecks() error {
	return config.SetValue("check_updates", false)
}

func enableUpdateChecks() error {
	return config.SetValue("check_updates", true)
}
```

6. Get release notes for specific version:

```go
func showReleaseNotes(version string) error {
	cfg := config.Get()
	u := updater.New(cfg)

	notes, err := u.GetReleaseNotes(version)
	if err != nil {
		return fmt.Errorf("failed to fetch release notes: %w", err)
	}

	fmt.Printf("\n%s\n\n", ui.Header(fmt.Sprintf("Release Notes for v%s", version)))
	fmt.Println(notes)
	return nil
}
```

CACHE MANAGEMENT:

The update checker automatically caches results for 24 hours in:
~/.zypheron/cache/update_check.json

To manually clear the cache:

```go
import "os"
import "path/filepath"

func clearUpdateCache() error {
	cfg := config.Get()
	cachePath := filepath.Join(cfg.CacheDir, updater.CacheFileName)
	return os.Remove(cachePath)
}
```

CONFIGURATION:

The updater respects the following config settings:
- config.CheckUpdates (bool) - Enable/disable update checks
- config.LastUpdateCheck (string) - Timestamp of last check

ENVIRONMENT VARIABLES:

- GITHUB_TOKEN: Optional GitHub personal access token to avoid API rate limiting
  (useful for CI/CD environments with many builds)

RATE LIMITING:

The GitHub API allows 60 requests/hour for unauthenticated requests.
With GITHUB_TOKEN, this increases to 5000 requests/hour.
The updater handles rate limit errors gracefully.

TIMEOUT:

All HTTP requests timeout after 10 seconds to prevent hanging on startup.

*/
