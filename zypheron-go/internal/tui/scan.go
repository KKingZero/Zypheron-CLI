package tui

import (
	"context"
	"sync"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tools"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/components"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/uuid"
)

// ScanRequest contains parameters for a scan
type ScanRequest struct {
	Target  string
	Tool    string
	Args    []string
	Timeout time.Duration
}

// SECURITY FIX: Added mutex to protect global channel from race conditions
var (
	scanMsgChan   chan tea.Msg
	scanChanMutex sync.Mutex
	scanActive    bool // Track if a scan is in progress
)

// safeSend sends a message to the scan channel with panic recovery
// Returns true if the message was sent successfully
func safeSend(msg tea.Msg) bool {
	scanChanMutex.Lock()
	ch := scanMsgChan
	scanChanMutex.Unlock()

	if ch == nil {
		return false
	}

	// Use recover to handle send on closed channel
	defer func() {
		recover() // Silently recover from send on closed channel
	}()

	select {
	case ch <- msg:
		return true
	default:
		return false
	}
}

// StartScan initiates a scan and returns the start message
func StartScan(req ScanRequest) tea.Cmd {
	return func() tea.Msg {
		scanChanMutex.Lock()
		// Check if a scan is already running
		if scanActive {
			scanChanMutex.Unlock()
			return components.ScanCompleteMsg{
				ScanID:  "",
				Success: false,
				Error:   "another scan is already in progress",
			}
		}

		scanID := uuid.New().String()[:8]

		// Create message channel
		scanMsgChan = make(chan tea.Msg, 100)
		scanActive = true
		scanChanMutex.Unlock()

		// Start scan in background
		go runScanInBackground(scanID, req)

		// Return start message immediately
		return components.ScanStartMsg{
			ScanID: scanID,
			Target: req.Target,
			Tool:   req.Tool,
		}
	}
}

// runScanInBackground executes the scan and sends messages to channel
func runScanInBackground(scanID string, req ScanRequest) {
	// SECURITY FIX: Use mutex when closing channel to prevent races
	defer func() {
		scanChanMutex.Lock()
		if scanMsgChan != nil {
			close(scanMsgChan)
			scanMsgChan = nil
		}
		scanActive = false
		scanChanMutex.Unlock()
	}()

	opts := tools.TUIExecutionOptions{
		ExecutionOptions: tools.ExecutionOptions{
			Tool:    req.Tool,
			Target:  req.Target,
			Args:    req.Args,
			Stream:  true,
			Timeout: req.Timeout,
		},
		ScanID: scanID,
		OnProgress: func(scanID string, percent float64, status string) {
			safeSend(components.ScanProgressMsg{
				ScanID:  scanID,
				Percent: percent,
				Status:  status,
			})
		},
		OnFinding: func(scanID, findingType, value, severity string) {
			safeSend(components.ScanFindingMsg{
				ScanID: scanID,
				Finding: components.Finding{
					Type:      findingType,
					Value:     value,
					Severity:  severity,
					Timestamp: time.Now(),
				},
			})
		},
		OnOutput: func(scanID, line string) {
			safeSend(components.ScanOutputMsg{
				ScanID: scanID,
				Line:   line,
			})
		},
		OnComplete: func(scanID string, success bool, duration time.Duration, errMsg string) {
			safeSend(components.ScanCompleteMsg{
				ScanID:   scanID,
				Success:  success,
				Duration: duration,
				Error:    errMsg,
			})
		},
	}

	ctx := context.Background()
	tools.ExecuteForTUI(ctx, opts)
}

// WaitForScanUpdate returns a cmd that waits for the next scan message
func WaitForScanUpdate() tea.Cmd {
	return func() tea.Msg {
		// SECURITY FIX: Get channel reference under lock to prevent race
		scanChanMutex.Lock()
		ch := scanMsgChan
		scanChanMutex.Unlock()

		if ch == nil {
			return nil
		}

		// Read from channel without holding the lock (blocking operation)
		msg, ok := <-ch
		if !ok {
			// Channel was closed, cleanup already handled by runScanInBackground
			return nil
		}
		return msg
	}
}

// ScanUpdateTick is used to poll for scan updates
type ScanUpdateTick struct{}

// TickForScanUpdate creates a ticker command to poll for scan updates
func TickForScanUpdate() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return ScanUpdateTick{}
	})
}
