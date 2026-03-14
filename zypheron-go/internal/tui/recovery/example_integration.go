package recovery

// This file demonstrates how to integrate the recovery module with the Zypheron TUI
// It provides examples for common integration patterns

import (
	"fmt"
	"log"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Example 1: Basic integration - Replace standard Run() with RecoverableRun()
//
// Before:
//
//	func Run() error {
//	    p := tea.NewProgram(NewModel(), tea.WithAltScreen(), tea.WithMouseCellMotion())
//	    if _, err := p.Run(); err != nil {
//	        return fmt.Errorf("error running TUI: %w", err)
//	    }
//	    return nil
//	}
//
// After:
//
//	func Run() error {
//	    p := tea.NewProgram(NewModel(), tea.WithAltScreen(), tea.WithMouseCellMotion())
//	    if err := recovery.RecoverableRun(p); err != nil {
//	        return fmt.Errorf("error running TUI: %w", err)
//	    }
//	    return nil
//	}

// Example 2: Integration with automatic retry on crash
//
// This pattern is useful for production deployments where you want
// the TUI to automatically recover from transient issues
//
// Usage in app.go:
//
//	func RunWithAutoRecovery() error {
//	    p := tea.NewProgram(NewModel(), tea.WithAltScreen(), tea.WithMouseCellMotion())
//	    // Retry up to 3 times with 2-second delay between attempts
//	    return recovery.RecoverableRunWithRetry(p, 3, 2*time.Second)
//	}

// Example 3: Custom crash log directory for multi-user systems
//
// Useful when deploying to shared systems or containers
//
// Usage in main.go or init():
//
//	func init() {
//	    // Use system-wide log directory
//	    recovery.SetLogDirectory("/var/log/zypheron/crashes")
//	    // Or use user-specific directory
//	    homeDir, _ := os.UserHomeDir()
//	    recovery.SetLogDirectory(filepath.Join(homeDir, ".local/share/zypheron/crashes"))
//	}

// Example 4: Error reporting integration
//
// Send crash reports to monitoring service or log aggregator
//
// Usage after TUI exit:
//
//	func main() {
//	    if err := tui.Run(); err != nil {
//	        // Check if this was a crash
//	        if crashLog, logErr := recovery.GetLastCrashLog(); logErr == nil {
//	            // Send to error tracking service
//	            reportCrashToSentry(err, crashLog)
//	            // Or log to file
//	            log.Printf("TUI crashed: %v\nCrash log:\n%s", err, crashLog)
//	        }
//	        os.Exit(1)
//	    }
//	}

// Example 5: Complete integration in app.go

// ExampleRun shows a complete integration with the Zypheron TUI
// This replaces the existing Run() function in internal/tui/app.go
func ExampleRun(model tea.Model) error {
	// Create Bubble Tea program with default options
	p := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	// Run with panic recovery
	if err := RecoverableRun(p); err != nil {
		// Log the error
		log.Printf("TUI error: %v", err)

		// Attempt to retrieve crash log for diagnostics
		if crashLog, logErr := GetLastCrashLog(); logErr == nil {
			log.Printf("Crash details:\n%s", crashLog)
		}

		return fmt.Errorf("error running TUI: %w", err)
	}

	return nil
}

// ExampleRunWithOptions shows integration with custom Bubble Tea options
// This replaces the existing RunWithOptions() function in internal/tui/app.go
func ExampleRunWithOptions(model tea.Model, opts ...tea.ProgramOption) error {
	// Start with default options
	defaultOpts := []tea.ProgramOption{
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	}

	// Append custom options
	allOpts := append(defaultOpts, opts...)

	// Create and run program with combined options
	p := tea.NewProgram(model, allOpts...)

	// Run with panic recovery
	return RecoverableRun(p)
}

// ExampleProductionRun shows a production-ready integration with retries
// This provides maximum resilience for production deployments
func ExampleProductionRun(model tea.Model) error {
	// Create Bubble Tea program
	p := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	// Run with automatic retry on crash
	// - Up to 3 retry attempts
	// - 1 second delay between retries
	if err := RecoverableRunWithRetry(p, 3, time.Second); err != nil {
		// All retries exhausted - log and report
		log.Printf("TUI failed after retries: %v", err)

		// Retrieve crash log for bug report
		if crashLog, logErr := GetLastCrashLog(); logErr == nil {
			// In production, send to error tracking service
			// For example: Sentry, Rollbar, CloudWatch, etc.
			log.Printf("Final crash log:\n%s", crashLog)
		}

		return fmt.Errorf("TUI failed after multiple attempts: %w", err)
	}

	return nil
}

// ExampleDiagnosticMode shows how to enable enhanced diagnostics
// Useful for debugging and development
func ExampleDiagnosticMode(model tea.Model, enableDiagnostics bool) error {
	if enableDiagnostics {
		// Use verbose logging directory
		SetLogDirectory("/tmp/zypheron-diagnostics")
		log.Println("Enhanced diagnostics enabled - crash logs in /tmp/zypheron-diagnostics")
	}

	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())

	if err := RecoverableRun(p); err != nil {
		if enableDiagnostics {
			// Print crash log to stderr for immediate debugging
			if crashLog, logErr := GetLastCrashLog(); logErr == nil {
				fmt.Fprintf(log.Writer(), "\n=== CRASH DIAGNOSTICS ===\n%s\n", crashLog)
			}
		}
		return err
	}

	return nil
}

// Example 6: Integration pattern for the existing Zypheron CLI
//
// Modify cmd/root.go or the TUI command to use recovery:
//
//	var tuiCmd = &cobra.Command{
//	    Use:   "tui",
//	    Short: "Launch Zypheron TUI",
//	    RunE: func(cmd *cobra.Command, args []string) error {
//	        // Initialize recovery module
//	        recovery.SetLogDirectory(filepath.Join(homeDir, ".zypheron/logs"))
//
//	        // Run TUI with recovery
//	        if err := tui.Run(); err != nil {
//	            // Check if crash log is available
//	            if crashLog, logErr := recovery.GetLastCrashLog(); logErr == nil {
//	                fmt.Fprintf(os.Stderr, "\nThe TUI encountered an error.\n")
//	                fmt.Fprintf(os.Stderr, "Crash log saved to: %s\n", crashLog)
//	                fmt.Fprintf(os.Stderr, "Please report this issue with the crash log.\n")
//	            }
//	            return err
//	        }
//	        return nil
//	    },
//	}

// Example 7: Health check integration
//
// Monitor crash frequency and disable TUI if too many crashes occur
//
// Usage:
//
//	type CrashMonitor struct {
//	    crashes []time.Time
//	    mu      sync.Mutex
//	}
//
//	func (m *CrashMonitor) RecordCrash() {
//	    m.mu.Lock()
//	    defer m.mu.Unlock()
//	    m.crashes = append(m.crashes, time.Now())
//	}
//
//	func (m *CrashMonitor) ShouldDisableTUI() bool {
//	    m.mu.Lock()
//	    defer m.mu.Unlock()
//	    // Disable TUI if 5+ crashes in last 5 minutes
//	    recent := 0
//	    cutoff := time.Now().Add(-5 * time.Minute)
//	    for _, t := range m.crashes {
//	        if t.After(cutoff) {
//	            recent++
//	        }
//	    }
//	    return recent >= 5
//	}
//
//	func RunWithHealthCheck(monitor *CrashMonitor) error {
//	    if monitor.ShouldDisableTUI() {
//	        return fmt.Errorf("TUI disabled due to frequent crashes")
//	    }
//
//	    p := tea.NewProgram(NewModel(), tea.WithAltScreen())
//	    if err := recovery.RecoverableRun(p); err != nil {
//	        monitor.RecordCrash()
//	        return err
//	    }
//	    return nil
//	}
