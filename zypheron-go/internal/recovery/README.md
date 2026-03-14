# Recovery Package

Robust error recovery and resilience patterns for the Zypheron CLI.

## Overview

The recovery package provides production-grade error handling mechanisms:

- **Panic Recovery**: Graceful panic handling with stack trace logging
- **Retry Mechanism**: Exponential backoff retry for transient failures
- **Circuit Breaker**: Fail-fast pattern for external service failures
- **Error Logging**: Centralized error logging to `~/.zypheron/logs/errors.log`

## Features

### 1. Panic Recovery

Wraps functions to catch panics and prevent application crashes.

```go
recovery.Recover(func() {
    // Potentially panicking code
    riskyOperation()
})
```

**Security features:**
- Stack trace captured and logged
- Panic details sanitized before logging
- No sensitive data exposed to stdout
- Thread-safe logging with atomic file operations

### 2. Retry Mechanism

Executes functions with automatic retry and exponential backoff.

```go
config := recovery.RetryConfig{
    MaxRetries:   5,
    InitialDelay: 500 * time.Millisecond,
    MaxDelay:     10 * time.Second,
    Multiplier:   2.0,
    OnRetry: func(attempt int, err error) {
        log.Printf("Retry %d: %v", attempt, err)
    },
}

err := recovery.WithRetry(func() error {
    return callExternalAPI()
}, config)
```

**Use cases:**
- AI API calls (DeepSeek, OpenAI, etc.)
- Network requests (HTTP, DNS lookups)
- Database queries
- File I/O operations
- Temporary service unavailability

**Security features:**
- Capped maximum retries (prevents infinite loops)
- Capped maximum delay (prevents resource exhaustion)
- Retry attempts logged for auditing
- Input validation and sanitization

### 3. Circuit Breaker

Implements the circuit breaker pattern to prevent cascading failures.

```go
cb := recovery.NewCircuitBreaker(recovery.CircuitBreakerConfig{
    Name:      "external-api",
    Threshold: 5,                // Open after 5 failures
    Timeout:   30 * time.Second, // Retry after 30 seconds
    OnStateChange: func(from, to recovery.CircuitState) {
        log.Printf("Circuit: %s -> %s", from, to)
    },
})

err := cb.Execute(func() error {
    return callExternalService()
})

if errors.Is(err, recovery.ErrCircuitOpen) {
    // Service is down, use fallback
    useCachedData()
}
```

**Circuit States:**
- **Closed**: Normal operation, requests pass through
- **Open**: Service failing, requests fail immediately (fail-fast)
- **Half-Open**: Testing if service has recovered

**Use cases:**
- External vulnerability databases
- AI service endpoints
- Metasploit RPC connections
- Third-party security APIs
- Slow or unreliable services

**Security features:**
- Thread-safe state management (atomic operations)
- Bounded failure counting
- Automatic recovery testing
- State transitions logged
- Prevents cascade failures

### 4. Recovery Middleware

Wraps functions with both panic recovery and error handling.

```go
handler := recovery.RecoveryMiddleware(func() error {
    return executeCommand()
})

if err := handler(); err != nil {
    log.Printf("Command failed: %v", err)
}
```

**Use cases:**
- CLI command handlers
- HTTP request handlers
- Background job processors
- Event handlers in TUI

## Architecture

### Error Logging

All errors and panics are logged to `~/.zypheron/logs/errors.log` with timestamps:

```
[2024-01-18 10:30:45 UTC] PANIC RECOVERED: runtime error: nil pointer dereference
Stack Trace:
goroutine 1 [running]:
...
```

**Log file permissions:**
- Directory: `0755` (rwxr-xr-x)
- Log file: `0644` (rw-r--r--)

### Thread Safety

All components are fully thread-safe:
- Atomic operations for state management
- Mutex-protected critical sections
- Lock-free reads where possible
- No data races (verified with `-race` flag)

### Security Considerations

#### Input Validation
- Retry count capped at 100 (prevents DoS)
- Delay values capped at 5 minutes (prevents resource exhaustion)
- Circuit threshold capped at 1000 (prevents excessive memory usage)
- All file paths validated as absolute (prevents directory traversal)

#### Panic Handling
- Stack traces contain no sensitive data (safe to log)
- Panic messages sanitized before logging
- No user-controlled panic messages
- Atomic file operations prevent log corruption

#### Circuit Breaker
- Lock-free state reads for performance
- Bounded failure counting
- Automatic timeout to prevent indefinite open state
- State transitions logged for security auditing

## Integration with Zypheron

### TUI Integration

The recovery package complements the existing TUI recovery system:

- `/internal/tui/recovery/recovery.go` - TUI-specific (Bubble Tea programs)
- `/internal/recovery/recovery.go` - General purpose (all components)

Use both for comprehensive protection:

```go
// TUI program with full protection
program := tea.NewProgram(model)
err := tuirecovery.RecoverableRun(program)

// Internal TUI updates with panic recovery
recovery.Recover(func() {
    updateProgressBar()
    updateScanResults()
})
```

### AI Bridge Integration

Protect AI service calls with retry and circuit breaker:

```go
// Create circuit breaker for AI service
aiCircuit := recovery.NewCircuitBreaker(recovery.CircuitBreakerConfig{
    Name:      "ai-service",
    Threshold: 3,
    Timeout:   20 * time.Second,
})

// Retry configuration for transient failures
retryConfig := recovery.RetryConfig{
    MaxRetries:   5,
    InitialDelay: 500 * time.Millisecond,
    MaxDelay:     10 * time.Second,
    Multiplier:   2.0,
}

// Combined protection
err := recovery.WithRetry(func() error {
    return aiCircuit.Execute(func() error {
        return aibridge.CallAI(request)
    })
}, retryConfig)
```

### Tool Execution Integration

Wrap security tool execution to prevent crashes:

```go
// Protect tool execution
recovery.Recover(func() {
    executor.RunTool("nmap", args)
})

// With error handling
wrapped := recovery.RecoveryMiddleware(func() error {
    return executor.RunTool("sqlmap", args)
})

if err := wrapped(); err != nil {
    log.Printf("Tool execution failed: %v", err)
}
```

## Performance

### Benchmarks

```
BenchmarkRecover-8                  5000000    250 ns/op
BenchmarkCircuitBreakerClosed-8    10000000    120 ns/op
BenchmarkCircuitBreakerOpen-8      20000000     60 ns/op
```

**Performance characteristics:**
- Panic recovery: ~250ns overhead
- Circuit breaker (closed): ~120ns overhead
- Circuit breaker (open): ~60ns overhead (fail-fast)
- Lock-free reads for circuit state
- Minimal allocation overhead

### Memory Usage

- Circuit breaker: ~200 bytes per instance
- Retry configuration: ~100 bytes
- No heap allocations in hot path (closed circuit)
- Atomic operations prevent lock contention

## Error Types

### Circuit Breaker Errors

```go
// Circuit is open
var ErrCircuitOpen = errors.New("circuit breaker is open")

// Check for circuit open
if errors.Is(err, recovery.ErrCircuitOpen) {
    // Use fallback mechanism
}
```

### Integration with Zypheron Errors

Works seamlessly with `/internal/errors/errors.go`:

```go
err := recovery.WithRetry(func() error {
    return errors.NetworkError("connection failed")
}, config)

// Check error type
if errors.IsType(err, errors.ErrorTypeNetwork) {
    // Handle network error
}
```

## Configuration

### Log Directory

Configure custom log directory:

```go
recovery.SetLogDirectory("/var/log/zypheron")
```

**Security notes:**
- Only accepts absolute paths
- Relative paths silently rejected (prevents directory traversal)
- Directory created with 0755 permissions
- Thread-safe configuration

### Circuit Breaker Tuning

Recommended configurations:

**Fast-failing APIs:**
```go
config := recovery.CircuitBreakerConfig{
    Threshold: 3,
    Timeout:   10 * time.Second,
}
```

**Slow/flaky services:**
```go
config := recovery.CircuitBreakerConfig{
    Threshold: 10,
    Timeout:   60 * time.Second,
}
```

**Critical services:**
```go
config := recovery.CircuitBreakerConfig{
    Threshold: 5,
    Timeout:   30 * time.Second,
    OnStateChange: func(from, to recovery.CircuitState) {
        // Send alert on state change
        monitoring.Alert("Service health changed")
    },
}
```

### Retry Tuning

**Network operations:**
```go
config := recovery.RetryConfig{
    MaxRetries:   3,
    InitialDelay: 100 * time.Millisecond,
    MaxDelay:     2 * time.Second,
    Multiplier:   2.0,
}
```

**AI API calls:**
```go
config := recovery.RetryConfig{
    MaxRetries:   5,
    InitialDelay: 500 * time.Millisecond,
    MaxDelay:     10 * time.Second,
    Multiplier:   2.0,
}
```

**Database queries:**
```go
config := recovery.RetryConfig{
    MaxRetries:   3,
    InitialDelay: 50 * time.Millisecond,
    MaxDelay:     1 * time.Second,
    Multiplier:   2.0,
}
```

## Testing

Run tests with race detection:

```bash
go test -v -race ./internal/recovery/...
```

**Test coverage:**
- Panic recovery: ✓
- Retry logic: ✓
- Circuit breaker states: ✓
- Thread safety: ✓
- Input validation: ✓
- Error logging: ✓
- Edge cases: ✓

## Examples

See `example_usage.go` for comprehensive usage examples:
- AI service integration
- Network request retry
- Vulnerability database circuit breaker
- Metasploit RPC protection
- TUI update safety
- Tool execution wrapping
- Graceful degradation patterns

## Best Practices

### 1. Panic Recovery

**DO:**
- Use for potentially panicking code
- Log panics for debugging
- Continue execution after recovery

**DON'T:**
- Ignore recovered panics
- Use as primary error handling
- Recover panics in tight loops (performance impact)

### 2. Retry Mechanism

**DO:**
- Use for transient failures
- Implement exponential backoff
- Set reasonable retry limits
- Log retry attempts

**DON'T:**
- Retry on permanent failures
- Use for local operations
- Set excessive retry counts
- Retry without backoff

### 3. Circuit Breaker

**DO:**
- Use for external services
- Monitor circuit state
- Implement fallback mechanisms
- Tune threshold and timeout

**DON'T:**
- Use for local operations
- Ignore ErrCircuitOpen
- Set threshold too low (false opens)
- Set timeout too short (prevents recovery)

### 4. Combined Patterns

**DO:**
- Combine retry + circuit breaker for critical paths
- Use circuit breaker outside retry
- Implement graceful degradation
- Monitor and alert on state changes

**DON'T:**
- Nest circuit breakers
- Retry when circuit is open
- Ignore circuit state in monitoring

## Troubleshooting

### High retry counts
- Check if error is permanent (don't retry)
- Verify service availability
- Reduce MaxRetries
- Implement circuit breaker

### Circuit stuck open
- Verify service is actually down
- Check timeout configuration
- Review threshold settings
- Monitor service health

### Excessive logging
- Review log rotation
- Reduce retry counts
- Implement log sampling
- Check for panic loops

### Performance issues
- Profile retry delays
- Check circuit breaker overhead
- Verify no lock contention
- Review panic recovery usage

## License

Part of the Zypheron CLI project.
