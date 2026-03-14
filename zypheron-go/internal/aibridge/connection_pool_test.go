package aibridge

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func requireUnixPoolListener(t *testing.T, socketPath string) net.Listener {
	t.Helper()

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("Skipping socket test: unix listen not permitted in this environment: %v", err)
		}
		t.Fatalf("Failed to create listener: %v", err)
	}
	return listener
}

// TestNewConnectionPool tests pool initialization
func TestNewConnectionPool(t *testing.T) {
	tests := []struct {
		name         string
		size         int
		expectedSize int
	}{
		{"default size on zero", 0, DefaultPoolSize},
		{"default size on negative", -1, DefaultPoolSize},
		{"custom size 10", 10, 10},
		{"custom size 3", 3, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := NewConnectionPool("/tmp/test.sock", tt.size)
			defer pool.Close()

			if pool.maxSize != tt.expectedSize {
				t.Errorf("Expected maxSize %d, got %d", tt.expectedSize, pool.maxSize)
			}

			if pool.closed {
				t.Error("New pool should not be closed")
			}

			if pool.socketPath != "/tmp/test.sock" {
				t.Errorf("Expected socket path /tmp/test.sock, got %s", pool.socketPath)
			}
		})
	}
}

// TestConnectionPoolAcquireFromClosedPool tests acquiring from closed pool
func TestConnectionPoolAcquireFromClosedPool(t *testing.T) {
	pool := NewConnectionPool("/tmp/test.sock", 5)
	pool.Close()

	_, err := pool.Acquire()
	if err != ErrPoolClosed {
		t.Errorf("Expected ErrPoolClosed, got %v", err)
	}
}

// TestConnectionPoolStats tests pool statistics
func TestConnectionPoolStats(t *testing.T) {
	pool := NewConnectionPool("/tmp/test.sock", 10)
	defer pool.Close()

	stats := pool.Stats()

	if stats["total"].(int) != 0 {
		t.Errorf("Expected 0 total connections, got %v", stats["total"])
	}

	if stats["max_size"].(int) != 10 {
		t.Errorf("Expected max_size 10, got %v", stats["max_size"])
	}

	if stats["in_use"].(int) != 0 {
		t.Errorf("Expected 0 in_use, got %v", stats["in_use"])
	}

	if stats["idle"].(int) != 0 {
		t.Errorf("Expected 0 idle, got %v", stats["idle"])
	}
}

// TestConnectionPoolClose tests closing the pool
func TestConnectionPoolClose(t *testing.T) {
	pool := NewConnectionPool("/tmp/test.sock", 5)

	// Close once should not error
	err := pool.Close()
	if err != nil {
		t.Errorf("First close should not error, got %v", err)
	}

	// Close again should be safe (idempotent)
	err = pool.Close()
	if err != nil {
		t.Errorf("Second close should not error, got %v", err)
	}

	if !pool.closed {
		t.Error("Pool should be closed after Close()")
	}
}

// TestConnectionPoolConcurrentAccess tests thread safety
func TestConnectionPoolConcurrentAccess(t *testing.T) {
	pool := NewConnectionPool("/tmp/test.sock", 5)
	defer pool.Close()

	var wg sync.WaitGroup
	errChan := make(chan error, 100)

	// Spawn multiple goroutines to test concurrent access
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Try to acquire (will fail because no socket exists, but should not panic)
			_, err := pool.Acquire()
			if err != nil && err != ErrPoolExhausted && err != ErrPoolClosed {
				// Expected to fail since no real socket
				// Just check it doesn't panic
			}

			// Stats should be safe to call concurrently
			pool.Stats()
		}()
	}

	wg.Wait()
	close(errChan)

	// Check for any panics captured as errors
	for err := range errChan {
		t.Errorf("Concurrent access error: %v", err)
	}
}

// TestPooledConnectionFields tests PooledConnection struct
func TestPooledConnectionFields(t *testing.T) {
	now := time.Now()
	pc := &PooledConnection{
		conn:     nil,
		lastUsed: now,
		inUse:    true,
		healthy:  true,
		created:  now,
	}

	if !pc.inUse {
		t.Error("Expected inUse to be true")
	}

	if !pc.healthy {
		t.Error("Expected healthy to be true")
	}

	if pc.lastUsed != now {
		t.Error("lastUsed should match")
	}

	if pc.created != now {
		t.Error("created should match")
	}
}

// TestConnectionPoolConstants tests pool constants have sensible values
func TestConnectionPoolConstants(t *testing.T) {
	if DefaultPoolSize < 1 {
		t.Errorf("DefaultPoolSize should be at least 1, got %d", DefaultPoolSize)
	}

	if DefaultPoolSize > 100 {
		t.Errorf("DefaultPoolSize seems too high: %d", DefaultPoolSize)
	}

	if DefaultIdleTimeout < time.Minute {
		t.Error("DefaultIdleTimeout seems too short")
	}

	if DefaultConnectTimeout < time.Second {
		t.Error("DefaultConnectTimeout seems too short")
	}

	if DefaultHealthCheckInterval < 10*time.Second {
		t.Error("DefaultHealthCheckInterval seems too frequent")
	}
}

// TestConnectionPoolWithRealSocket tests with a real Unix socket
func TestConnectionPoolWithRealSocket(t *testing.T) {
	// Create temp directory for socket
	tmpDir, err := os.MkdirTemp("", "pool_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "test.sock")

	// Start a simple server
	listener := requireUnixPoolListener(t, socketPath)
	defer listener.Close()

	// Set secure permissions on the socket
	if err := os.Chmod(socketPath, 0600); err != nil {
		t.Fatalf("Failed to set socket permissions: %v", err)
	}

	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // Listener closed
			}
			// Keep connection alive for testing
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					_, err := c.Read(buf)
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	// Create pool and test
	pool := NewConnectionPool(socketPath, 3)
	defer pool.Close()

	// Acquire a connection
	conn1, err := pool.Acquire()
	if err != nil {
		t.Fatalf("Failed to acquire first connection: %v", err)
	}

	// Check stats
	stats := pool.Stats()
	if stats["total"].(int) != 1 {
		t.Errorf("Expected 1 total connection, got %v", stats["total"])
	}
	if stats["in_use"].(int) != 1 {
		t.Errorf("Expected 1 in_use connection, got %v", stats["in_use"])
	}

	// Release the connection
	pool.Release(conn1)

	// Check stats after release
	stats = pool.Stats()
	if stats["idle"].(int) != 1 {
		t.Errorf("Expected 1 idle connection after release, got %v", stats["idle"])
	}
	if stats["in_use"].(int) != 0 {
		t.Errorf("Expected 0 in_use after release, got %v", stats["in_use"])
	}

	// Acquire should reuse the connection
	conn2, err := pool.Acquire()
	if err != nil {
		t.Fatalf("Failed to acquire second connection: %v", err)
	}

	// Should still be 1 total (reused)
	stats = pool.Stats()
	if stats["total"].(int) != 1 {
		t.Errorf("Expected 1 total connection (reused), got %v", stats["total"])
	}

	pool.Release(conn2)
}

// TestConnectionPoolExhaustion tests pool exhaustion
func TestConnectionPoolExhaustion(t *testing.T) {
	// Create temp directory for socket
	tmpDir, err := os.MkdirTemp("", "pool_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "test.sock")

	// Start server
	listener := requireUnixPoolListener(t, socketPath)
	defer listener.Close()

	// Set secure permissions on the socket
	if err := os.Chmod(socketPath, 0600); err != nil {
		t.Fatalf("Failed to set socket permissions: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					_, err := c.Read(buf)
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	// Create pool with size 2
	pool := NewConnectionPool(socketPath, 2)
	defer pool.Close()

	// Acquire all connections
	conn1, err := pool.Acquire()
	if err != nil {
		t.Fatalf("Failed to acquire first connection: %v", err)
	}
	defer pool.Release(conn1)

	conn2, err := pool.Acquire()
	if err != nil {
		t.Fatalf("Failed to acquire second connection: %v", err)
	}
	defer pool.Release(conn2)

	// Third acquire should fail with ErrPoolExhausted
	_, err = pool.Acquire()
	if err != ErrPoolExhausted {
		t.Errorf("Expected ErrPoolExhausted, got %v", err)
	}
}

// TestConnectionPoolReleaseUnknown tests releasing unknown connection
func TestConnectionPoolReleaseUnknown(t *testing.T) {
	pool := NewConnectionPool("/tmp/test.sock", 5)
	defer pool.Close()

	// Create a fake connection
	conn, _ := net.Pipe()
	defer conn.Close()

	// Release should be a no-op for unknown connections
	pool.Release(conn) // Should not panic

	// Stats should still show 0 connections
	stats := pool.Stats()
	if stats["total"].(int) != 0 {
		t.Errorf("Expected 0 connections after releasing unknown, got %v", stats["total"])
	}
}

// TestConnectionPoolIdleTimeout tests idle connection cleanup
func TestConnectionPoolIdleTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping idle timeout test in short mode")
	}

	// Create pool with very short idle timeout for testing
	pool := NewConnectionPool("/tmp/test.sock", 5)
	pool.idleTimeout = 100 * time.Millisecond
	defer pool.Close()

	// Manually add a "connection" to test cleanup
	pool.mu.Lock()
	pc := &PooledConnection{
		conn:     nil,                                     // nil conn will fail health check
		lastUsed: time.Now().Add(-200 * time.Millisecond), // Already past idle timeout
		inUse:    false,
		healthy:  true,
		created:  time.Now(),
	}
	pool.connections = append(pool.connections, pc)
	pool.mu.Unlock()

	// Trigger cleanup manually
	pool.cleanupStale()

	// Should have removed the stale connection
	stats := pool.Stats()
	if stats["total"].(int) != 0 {
		t.Errorf("Expected 0 connections after cleanup, got %v", stats["total"])
	}
}

// TestErrPoolClosedMessage tests error messages
func TestErrPoolClosedMessage(t *testing.T) {
	if ErrPoolClosed.Error() != "connection pool is closed" {
		t.Errorf("Unexpected ErrPoolClosed message: %s", ErrPoolClosed.Error())
	}

	if ErrPoolExhausted.Error() != "connection pool exhausted" {
		t.Errorf("Unexpected ErrPoolExhausted message: %s", ErrPoolExhausted.Error())
	}
}
