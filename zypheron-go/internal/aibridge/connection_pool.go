package aibridge

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	// Pool configuration
	DefaultPoolSize      = 5
	DefaultIdleTimeout   = 5 * time.Minute
	DefaultHealthCheckInterval = 30 * time.Second
	DefaultConnectTimeout = 5 * time.Second
)

var (
	ErrPoolClosed    = errors.New("connection pool is closed")
	ErrPoolExhausted = errors.New("connection pool exhausted")
)

// PooledConnection wraps a Unix socket connection with metadata
type PooledConnection struct {
	conn       net.Conn
	lastUsed   time.Time
	inUse      bool
	healthy    bool
	created    time.Time
}

// ConnectionPool manages a pool of reusable Unix socket connections
type ConnectionPool struct {
	socketPath   string
	connections  []*PooledConnection
	maxSize      int
	idleTimeout  time.Duration
	mu           sync.Mutex
	closed       bool
	healthTicker *time.Ticker
	stopHealth   chan struct{}
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(socketPath string, size int) *ConnectionPool {
	if size <= 0 {
		size = DefaultPoolSize
	}

	pool := &ConnectionPool{
		socketPath:   socketPath,
		connections:  make([]*PooledConnection, 0, size),
		maxSize:      size,
		idleTimeout:  DefaultIdleTimeout,
		closed:       false,
		stopHealth:   make(chan struct{}),
	}

	// Start health check goroutine
	pool.startHealthChecks()

	return pool
}

// Acquire gets a connection from the pool (creates new if needed)
func (p *ConnectionPool) Acquire() (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrPoolClosed
	}

	// Try to find an idle, healthy connection
	for _, pc := range p.connections {
		if !pc.inUse && pc.healthy {
			pc.inUse = true
			pc.lastUsed = time.Now()
			return pc.conn, nil
		}
	}

	// No idle connection found, create new if under limit
	if len(p.connections) < p.maxSize {
		conn, err := p.createConnection()
		if err != nil {
			return nil, fmt.Errorf("failed to create connection: %w", err)
		}

		pc := &PooledConnection{
			conn:     conn,
			lastUsed: time.Now(),
			inUse:    true,
			healthy:  true,
			created:  time.Now(),
		}

		p.connections = append(p.connections, pc)
		return conn, nil
	}

	// Pool exhausted - wait and retry (simple backoff)
	// In production, this should use a channel-based waiting mechanism
	return nil, ErrPoolExhausted
}

// Release returns a connection to the pool
func (p *ConnectionPool) Release(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, pc := range p.connections {
		if pc.conn == conn {
			pc.inUse = false
			pc.lastUsed = time.Now()
			return
		}
	}
}

// createConnection creates a new Unix socket connection with security validation
func (p *ConnectionPool) createConnection() (net.Conn, error) {
	// Validate socket ownership before connecting
	if err := validateSocketOwnership(p.socketPath); err != nil {
		return nil, fmt.Errorf("socket security validation failed: %w", err)
	}

	// Connect with timeout
	conn, err := net.DialTimeout("unix", p.socketPath, DefaultConnectTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to dial socket: %w", err)
	}

	return conn, nil
}

// healthCheck verifies a connection is still usable
func (p *ConnectionPool) healthCheck(pc *PooledConnection) bool {
	if pc.conn == nil {
		return false
	}

	// Set a short deadline for health check
	pc.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	defer pc.conn.SetReadDeadline(time.Time{}) // Clear deadline

	// Try to read 0 bytes (will error if connection is closed)
	one := make([]byte, 1)
	pc.conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	
	// If we can't peek, connection might be dead
	_, err := pc.conn.Read(one[:0])
	
	// No error or timeout means connection is alive
	if err == nil {
		return true
	}
	
	// Check for temporary network errors
	if netErr, ok := err.(net.Error); ok {
		return netErr.Temporary() || netErr.Timeout()
	}

	return false
}

// startHealthChecks starts a background goroutine to clean up stale connections
func (p *ConnectionPool) startHealthChecks() {
	p.healthTicker = time.NewTicker(DefaultHealthCheckInterval)

	go func() {
		for {
			select {
			case <-p.healthTicker.C:
				p.cleanupStale()
			case <-p.stopHealth:
				return
			}
		}
	}()
}

// cleanupStale removes unhealthy and idle connections
func (p *ConnectionPool) cleanupStale() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	now := time.Now()
	newConnections := make([]*PooledConnection, 0, len(p.connections))

	for _, pc := range p.connections {
		shouldKeep := true

		// Remove connections that have been idle too long
		if !pc.inUse && now.Sub(pc.lastUsed) > p.idleTimeout {
			pc.conn.Close()
			shouldKeep = false
		} else if !pc.inUse {
			// Health check idle connections
			pc.healthy = p.healthCheck(pc)
			if !pc.healthy {
				pc.conn.Close()
				shouldKeep = false
			}
		}

		if shouldKeep {
			newConnections = append(newConnections, pc)
		}
	}

	p.connections = newConnections
}

// Close closes all connections in the pool
func (p *ConnectionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true

	// Stop health checks
	if p.healthTicker != nil {
		p.healthTicker.Stop()
	}
	close(p.stopHealth)

	// Close all connections
	var errs []error
	for _, pc := range p.connections {
		if err := pc.conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	p.connections = nil

	if len(errs) > 0 {
		return fmt.Errorf("errors closing pool connections: %v", errs)
	}

	return nil
}

// Stats returns pool statistics
func (p *ConnectionPool) Stats() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	inUse := 0
	idle := 0
	unhealthy := 0

	for _, pc := range p.connections {
		if pc.inUse {
			inUse++
		} else {
			idle++
		}
		if !pc.healthy {
			unhealthy++
		}
	}

	return map[string]interface{}{
		"total":     len(p.connections),
		"in_use":    inUse,
		"idle":      idle,
		"unhealthy": unhealthy,
		"max_size":  p.maxSize,
	}
}

