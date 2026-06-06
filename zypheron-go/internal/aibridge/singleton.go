package aibridge

import (
	"fmt"
	"sync"
	"time"
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
	})
	return sharedBridge
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
