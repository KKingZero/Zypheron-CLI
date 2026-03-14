package aibridge

import (
	"fmt"
	"sync"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
)

var (
	sharedBridge *AIBridge
	bridgeOnce   sync.Once
)

// GetSharedBridge returns the singleton AIBridge instance.
// The bridge is created once and reused across all callers.
func GetSharedBridge() *AIBridge {
	bridgeOnce.Do(func() {
		sharedBridge = NewAIBridge()
		sharedBridge.EnsureReadyAsync(5 * time.Second)
		sharedBridge.ensurePersistentEngine()
	})
	return sharedBridge
}

func (b *AIBridge) ensurePersistentEngine() {
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if !b.IsRunning() {
				_ = b.Start()
			}
		}
	}()
}

// EnsureReady blocks until the AI engine is reachable or the timeout expires.
// Returns nil if already connected, or an error if the engine cannot be reached.
func (b *AIBridge) EnsureReady(timeout time.Duration) error {
	if b.connected || b.IsRunning() {
		b.connected = true
		return nil
	}

	deadline := time.Now().Add(timeout)
	interval := 250 * time.Millisecond

	for time.Now().Before(deadline) {
		if b.IsRunning() {
			b.connected = true
			// Reload auth token if missing
			if b.authToken == "" {
				if token, err := loadAuthToken(); err == nil {
					b.authToken = token
				}
			}
			// Initialize connection pool only for Unix transport.
			if b.connPool == nil && b.transport == transportUnix && b.socketPath != "" {
				b.connPool = NewConnectionPool(b.socketPath, DefaultPoolSize)
			}
			return nil
		}
		time.Sleep(interval)
	}

	return fmt.Errorf("AI engine not ready after %s", timeout)
}

// EnsureReadyAsync starts a background goroutine that waits for the AI engine
// to become ready. Logs status but never blocks the caller.
func (b *AIBridge) EnsureReadyAsync(timeout time.Duration) {
	go func() {
		if err := b.EnsureReady(timeout); err != nil {
			fmt.Println(ui.Muted.Sprint("AI engine not available (will connect on demand)"))
		}
	}()
}
