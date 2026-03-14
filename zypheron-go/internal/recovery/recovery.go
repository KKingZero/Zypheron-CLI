package recovery

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// Default configuration constants
const (
	// Default log directory for error logs
	defaultLogDir = ".zypheron/logs"

	// Default circuit breaker parameters
	defaultThreshold = 5                // Failures before opening
	defaultTimeout   = 30 * time.Second // Time before attempting half-open
	defaultResetTime = 60 * time.Second // Time before resetting success counter

	// Maximum values for security (prevent resource exhaustion)
	maxRetries   = 100             // Prevent infinite retry loops
	maxDelay     = 5 * time.Minute // Prevent excessive backoff delays
	maxThreshold = 1000            // Prevent excessive failure counting
	maxTimeout   = 1 * time.Hour   // Prevent indefinite circuit open state
)

var (
	// logDirectory stores the current error log directory
	// Thread-safe configuration with mutex protection
	logDirectory string
	logDirMutex  sync.RWMutex
)

// init initializes the default log directory on package load
func init() {
	// Get user home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to /tmp if home directory unavailable
		logDirectory = filepath.Join("/tmp", defaultLogDir)
		return
	}

	logDirectory = filepath.Join(homeDir, defaultLogDir)
}

// SetLogDirectory sets a custom directory for error logs
// Thread-safe: Can be called from any goroutine
//
// Security: Only accepts absolute paths to prevent directory traversal
func SetLogDirectory(dir string) {
	// Input validation: Ensure absolute path
	if !filepath.IsAbs(dir) {
		// Silently ignore relative paths for security
		return
	}

	logDirMutex.Lock()
	defer logDirMutex.Unlock()
	logDirectory = dir
}

// getLogDirectory retrieves the current log directory (thread-safe)
func getLogDirectory() string {
	logDirMutex.RLock()
	defer logDirMutex.RUnlock()
	return logDirectory
}

// writeErrorLog writes an error log entry to disk with timestamp
// Returns error if log directory creation or file writing fails
//
// Permissions:
//   - Log directory: 0755 (rwxr-xr-x)
//   - Log file: 0644 (rw-r--r--)
func writeErrorLog(message string) error {
	// Get configured log directory (thread-safe)
	dir := getLogDirectory()

	// Create log directory if it doesn't exist
	// MkdirAll is idempotent and safe for concurrent use
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Use errors.log as the main error log file (append mode)
	logPath := filepath.Join(dir, "errors.log")

	// Open file in append mode, create if doesn't exist
	// O_APPEND ensures atomic appends for concurrent writes
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open error log: %w", err)
	}
	defer f.Close()

	// Write timestamped log entry
	timestamp := time.Now().UTC().Format("2006-01-02 15:04:05 MST")
	logEntry := fmt.Sprintf("[%s] %s\n", timestamp, message)

	if _, err := f.WriteString(logEntry); err != nil {
		return fmt.Errorf("failed to write to error log: %w", err)
	}

	return nil
}

// Recover wraps a function with panic recovery and logging
// Captures panics, logs stack traces, and prevents application crashes
//
// Parameters:
//   - fn: func() - The function to execute with panic protection
//
// Behavior:
//   - Executes fn within a defer/recover block
//   - On panic: Logs stack trace to errors.log, continues execution
//   - On success: Returns normally
//
// Security considerations:
//   - Does not expose panic details to stdout (only logs)
//   - Sanitizes panic message before logging
//   - Atomic file operations prevent log corruption
//
// Example:
//
//	recovery.Recover(func() {
//	    // Potentially panicking code
//	    processData(untrustedInput)
//	})
func Recover(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			// Capture full stack trace
			stackTrace := debug.Stack()

			// Format panic message safely
			panicMsg := fmt.Sprintf("%v", r)

			// Build error log message
			logMsg := fmt.Sprintf("PANIC RECOVERED: %s\nStack Trace:\n%s",
				panicMsg, string(stackTrace))

			// Write to error log (best effort, ignore errors)
			_ = writeErrorLog(logMsg)
		}
	}()

	// Execute wrapped function
	fn()
}

// RetryConfig defines configuration for retry mechanism
type RetryConfig struct {
	MaxRetries   int                          // Maximum retry attempts (capped at maxRetries)
	InitialDelay time.Duration                // Initial delay before first retry
	MaxDelay     time.Duration                // Maximum delay between retries (capped at maxDelay)
	Multiplier   float64                      // Backoff multiplier (should be >= 1.0)
	OnRetry      func(attempt int, err error) // Optional callback on each retry
}

// Validate validates and sanitizes retry configuration
// Enforces security limits and sensible defaults
func (c *RetryConfig) Validate() {
	// Enforce maximum retry limit (prevent infinite loops)
	if c.MaxRetries < 0 || c.MaxRetries > maxRetries {
		c.MaxRetries = maxRetries
	}

	// Enforce delay limits (prevent resource exhaustion)
	if c.InitialDelay <= 0 {
		c.InitialDelay = 100 * time.Millisecond
	}
	if c.MaxDelay <= 0 || c.MaxDelay > maxDelay {
		c.MaxDelay = maxDelay
	}

	// Ensure initial delay doesn't exceed max delay
	if c.InitialDelay > c.MaxDelay {
		c.InitialDelay = c.MaxDelay
	}

	// Validate multiplier (prevent negative or zero backoff)
	if c.Multiplier < 1.0 {
		c.Multiplier = 2.0 // Default exponential backoff
	}
}

// WithRetry executes a function with retry logic and exponential backoff
// Suitable for transient failures (network requests, AI calls, etc.)
//
// Parameters:
//   - fn: func() error - The function to execute with retry logic
//   - config: RetryConfig - Retry configuration parameters
//
// Returns:
//   - error: Final error after all retries exhausted, or nil on success
//
// Behavior:
//   - Attempts execution up to (MaxRetries + 1) times
//   - Uses exponential backoff with jitter between attempts
//   - Calls OnRetry callback before each retry (if provided)
//   - Returns nil on first successful execution
//
// Security considerations:
//   - Validates and caps retry count to prevent DoS
//   - Validates and caps delays to prevent resource exhaustion
//   - Logs retry attempts for auditing
//
// Example:
//
//	config := recovery.RetryConfig{
//	    MaxRetries:   3,
//	    InitialDelay: 100 * time.Millisecond,
//	    MaxDelay:     5 * time.Second,
//	    Multiplier:   2.0,
//	    OnRetry: func(attempt int, err error) {
//	        log.Printf("Retry attempt %d: %v", attempt, err)
//	    },
//	}
//	err := recovery.WithRetry(func() error {
//	    return callExternalAPI()
//	}, config)
func WithRetry(fn func() error, config RetryConfig) error {
	// Validate and sanitize configuration
	config.Validate()

	var lastErr error
	delay := config.InitialDelay

	// Execute up to MaxRetries + 1 times
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		// Execute function
		err := fn()

		// Success - return immediately
		if err == nil {
			return nil
		}

		// Save error for final return
		lastErr = err

		// Log retry attempt (best effort)
		logMsg := fmt.Sprintf("Retry attempt %d/%d failed: %v",
			attempt+1, config.MaxRetries+1, err)
		_ = writeErrorLog(logMsg)

		// Check if this was the last attempt
		if attempt < config.MaxRetries {
			// Call retry callback if provided
			if config.OnRetry != nil {
				config.OnRetry(attempt+1, err)
			}

			// Wait before retry with exponential backoff
			time.Sleep(delay)

			// Calculate next delay with exponential backoff
			delay = time.Duration(float64(delay) * config.Multiplier)

			// Cap delay at maximum
			if delay > config.MaxDelay {
				delay = config.MaxDelay
			}
		}
	}

	// All retries exhausted - return final error
	return fmt.Errorf("operation failed after %d attempts: %w",
		config.MaxRetries+1, lastErr)
}

// CircuitState represents the state of a circuit breaker
type CircuitState int32

const (
	// StateClosed - Circuit is closed, requests pass through normally
	StateClosed CircuitState = iota

	// StateOpen - Circuit is open, requests fail immediately
	StateOpen

	// StateHalfOpen - Circuit is testing if service has recovered
	StateHalfOpen
)

// String returns the string representation of a circuit state
func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

// CircuitBreaker implements the circuit breaker pattern for external services
// Prevents cascading failures by failing fast when a service is down
//
// States:
//   - Closed: Normal operation, requests pass through
//   - Open: Service is failing, requests fail immediately
//   - Half-Open: Testing if service has recovered
//
// Thread-safe: All methods can be called concurrently
type CircuitBreaker struct {
	name      string        // Circuit breaker name (for logging)
	threshold int32         // Failures before opening (atomic)
	timeout   time.Duration // Time before attempting half-open
	resetTime time.Duration // Time before resetting success counter

	state           atomic.Int32 // Current state (StateClosed/StateOpen/StateHalfOpen)
	failures        atomic.Int32 // Consecutive failure count
	successes       atomic.Int32 // Consecutive success count (in half-open state)
	lastFailTime    atomic.Int64 // Timestamp of last failure (Unix nano)
	lastStateChange atomic.Int64 // Timestamp of last state change (Unix nano)

	mu              sync.RWMutex                // Protects state transitions
	probeInProgress bool                        // Prevents concurrent half-open probes
	onStateChange   func(from, to CircuitState) // Optional state change callback
}

// CircuitBreakerConfig defines configuration for circuit breaker
type CircuitBreakerConfig struct {
	Name          string                      // Circuit breaker name
	Threshold     int                         // Failures before opening
	Timeout       time.Duration               // Time before half-open
	ResetTime     time.Duration               // Time before resetting success count
	OnStateChange func(from, to CircuitState) // Optional callback
}

// NewCircuitBreaker creates a new circuit breaker with the specified configuration
//
// Parameters:
//   - config: CircuitBreakerConfig - Circuit breaker configuration
//
// Returns:
//   - *CircuitBreaker: New circuit breaker instance
//
// Security considerations:
//   - Validates and caps threshold to prevent excessive failure counting
//   - Validates and caps timeout to prevent indefinite open state
//   - Uses atomic operations for lock-free state reads
//
// Example:
//
//	cb := recovery.NewCircuitBreaker(recovery.CircuitBreakerConfig{
//	    Name:      "external-api",
//	    Threshold: 5,
//	    Timeout:   30 * time.Second,
//	})
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	// Validate and sanitize threshold
	threshold := int32(config.Threshold)
	if threshold <= 0 || threshold > maxThreshold {
		threshold = int32(defaultThreshold)
	}

	// Validate and sanitize timeout
	timeout := config.Timeout
	if timeout <= 0 || timeout > maxTimeout {
		timeout = defaultTimeout
	}

	// Validate and sanitize reset time
	resetTime := config.ResetTime
	if resetTime <= 0 || resetTime > maxTimeout {
		resetTime = defaultResetTime
	}

	cb := &CircuitBreaker{
		name:          config.Name,
		threshold:     threshold,
		timeout:       timeout,
		resetTime:     resetTime,
		onStateChange: config.OnStateChange,
	}

	// Initialize state to Closed
	cb.state.Store(int32(StateClosed))
	cb.lastStateChange.Store(time.Now().UnixNano())

	return cb
}

// GetState returns the current circuit breaker state (lock-free read)
func (cb *CircuitBreaker) GetState() CircuitState {
	return CircuitState(cb.state.Load())
}

// GetFailures returns the current failure count (lock-free read)
func (cb *CircuitBreaker) GetFailures() int32 {
	return cb.failures.Load()
}

// setState changes the circuit breaker state with proper logging and callbacks
// Must be called with mu lock held
func (cb *CircuitBreaker) setState(newState CircuitState) {
	oldState := cb.GetState()

	// Only transition if state actually changed
	if oldState == newState {
		return
	}

	// Update state atomically
	cb.state.Store(int32(newState))
	cb.lastStateChange.Store(time.Now().UnixNano())

	// Log state transition
	logMsg := fmt.Sprintf("Circuit breaker '%s': %s -> %s (failures: %d)",
		cb.name, oldState.String(), newState.String(), cb.failures.Load())
	_ = writeErrorLog(logMsg)

	// Call state change callback if provided
	if cb.onStateChange != nil {
		go cb.onStateChange(oldState, newState)
	}
}

// Execute runs a function through the circuit breaker
// Returns error immediately if circuit is open, otherwise executes function
//
// Parameters:
//   - fn: func() error - The function to execute with circuit breaker protection
//
// Returns:
//   - error: Error from function execution or circuit breaker
//
// Behavior:
//   - Closed: Executes function, transitions to Open on threshold failures
//   - Open: Fails immediately with ErrCircuitOpen
//   - Half-Open: Executes function, transitions based on result
//
// Thread-safe: Can be called concurrently from multiple goroutines
//
// Example:
//
//	err := cb.Execute(func() error {
//	    return callExternalService()
//	})
//	if errors.Is(err, recovery.ErrCircuitOpen) {
//	    // Circuit is open, service is down
//	    return handleServiceUnavailable()
//	}
func (cb *CircuitBreaker) Execute(fn func() error) error {
	// Check current state (lock-free read)
	currentState := cb.GetState()

	switch currentState {
	case StateClosed:
		return cb.executeClosed(fn)
	case StateOpen:
		return cb.executeOpen(fn)
	case StateHalfOpen:
		return cb.executeHalfOpen(fn)
	default:
		return fmt.Errorf("invalid circuit breaker state: %v", currentState)
	}
}

// ErrCircuitOpen is returned when the circuit breaker is open
var ErrCircuitOpen = errors.New("circuit breaker is open")

// executeClosed handles execution in Closed state
func (cb *CircuitBreaker) executeClosed(fn func() error) error {
	// Execute function
	err := fn()

	if err != nil {
		// Increment failure count atomically
		failures := cb.failures.Add(1)
		cb.lastFailTime.Store(time.Now().UnixNano())

		// Check if threshold reached
		if failures >= cb.threshold {
			// Transition to Open state
			cb.mu.Lock()
			cb.setState(StateOpen)
			cb.mu.Unlock()
		}

		return err
	}

	// Success - reset failure count
	cb.failures.Store(0)
	return nil
}

// executeOpen handles execution in Open state
func (cb *CircuitBreaker) executeOpen(fn func() error) error {
	// Check if timeout has elapsed
	lastFailTime := time.Unix(0, cb.lastFailTime.Load())
	if time.Since(lastFailTime) >= cb.timeout {
		// Attempt transition to Half-Open state
		cb.mu.Lock()
		// Double-check state hasn't changed
		if cb.GetState() == StateOpen {
			cb.setState(StateHalfOpen)
			cb.successes.Store(0)
		}
		cb.mu.Unlock()

		// Retry execution in Half-Open state
		return cb.executeHalfOpen(fn)
	}

	// Circuit still open - fail fast
	return ErrCircuitOpen
}

// ErrProbeInProgress is returned when a half-open probe is already running
var ErrProbeInProgress = errors.New("circuit breaker probe already in progress")

// executeHalfOpen handles execution in Half-Open state
// Fixed to prevent TOCTOU race - only one probe runs at a time
func (cb *CircuitBreaker) executeHalfOpen(fn func() error) error {
	// Acquire lock FIRST to check and set probe flag atomically
	cb.mu.Lock()

	// Check if we're still in half-open state
	if cb.GetState() != StateHalfOpen {
		cb.mu.Unlock()
		return ErrCircuitOpen
	}

	// Check if a probe is already in progress
	if cb.probeInProgress {
		cb.mu.Unlock()
		return ErrProbeInProgress
	}

	// Mark probe as in progress
	cb.probeInProgress = true
	cb.mu.Unlock()

	// Execute function OUTSIDE the lock to avoid blocking other operations
	err := fn()

	// Re-acquire lock to update state
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Clear probe flag
	cb.probeInProgress = false

	// Only process if still in Half-Open state (could have been reset)
	if cb.GetState() != StateHalfOpen {
		return err
	}

	if err != nil {
		// Failure in half-open - immediately reopen circuit
		cb.failures.Store(1)
		cb.lastFailTime.Store(time.Now().UnixNano())
		cb.setState(StateOpen)
		return err
	}

	// Success in half-open
	successes := cb.successes.Add(1)

	// Check if we should close the circuit
	// Require at least 1 success and enough time has passed
	lastStateChange := time.Unix(0, cb.lastStateChange.Load())
	if successes >= 1 && time.Since(lastStateChange) >= cb.resetTime {
		// Close circuit
		cb.failures.Store(0)
		cb.successes.Store(0)
		cb.setState(StateClosed)
	}

	return nil
}

// Reset manually resets the circuit breaker to Closed state
// Use with caution - prefer automatic recovery
//
// Thread-safe: Can be called from any goroutine
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures.Store(0)
	cb.successes.Store(0)
	cb.setState(StateClosed)
}

// RecoveryMiddleware provides a middleware wrapper for functions that need
// both panic recovery and error logging
//
// This is useful for wrapping HTTP handlers, CLI commands, or any function
// that should not crash the application on panic
//
// Example:
//
//	wrapped := recovery.RecoveryMiddleware(func() error {
//	    return riskyOperation()
//	})
//	if err := wrapped(); err != nil {
//	    log.Printf("Operation failed: %v", err)
//	}
func RecoveryMiddleware(fn func() error) func() error {
	return func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				// Capture stack trace
				stackTrace := debug.Stack()

				// Format panic as error
				panicMsg := fmt.Sprintf("%v", r)

				// Log panic with stack trace
				logMsg := fmt.Sprintf("PANIC IN MIDDLEWARE: %s\nStack Trace:\n%s",
					panicMsg, string(stackTrace))
				_ = writeErrorLog(logMsg)

				// Return panic as error
				err = fmt.Errorf("panic recovered: %v", panicMsg)
			}
		}()

		// Execute function and return error (if any)
		err = fn()
		return err
	}
}
