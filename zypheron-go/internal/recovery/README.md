# Recovery Package

Production-grade error recovery and resilience patterns for the Zypheron CLI.

## Features

- **Panic Recovery**: Graceful panic handling with stack trace logging
- **Retry Mechanism**: Exponential backoff retry for transient failures
- **Circuit Breaker**: Fail-fast pattern for external service failures
- **Error Logging**: Centralized logging to `~/.zypheron/logs/errors.log`
- **Thread-Safe**: All operations safe for concurrent use

## Quick Start

### Panic Recovery

```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/recovery"

// Simple recovery
recovery.Recover(func() {
    riskyOperation()
})

// Middleware pattern (returns error instead of panicking)
wrapped := recovery.RecoveryMiddleware(func() error {
    return riskyOperation()
})
if err := wrapped(); err != nil {
    log.Printf("Operation failed: %v", err)
}
```

### Retry with Exponential Backoff

```go
config := recovery.RetryConfig{
    MaxRetries:   3,
    InitialDelay: 100 * time.Millisecond,
    MaxDelay:     5 * time.Second,
    Multiplier:   2.0,
    OnRetry: func(attempt int, err error) {
        log.Printf("Retry %d: %v", attempt, err)
    },
}

err := recovery.WithRetry(func() error {
    return callExternalAPI()
}, config)
```

### Circuit Breaker

```go
cb := recovery.NewCircuitBreaker(recovery.CircuitBreakerConfig{
    Name:      "external-api",
    Threshold: 5,                // Open after 5 failures
    Timeout:   30 * time.Second, // Retry after 30s
    OnStateChange: func(from, to recovery.CircuitState) {
        log.Printf("Circuit: %s -> %s", from, to)
    },
})

err := cb.Execute(func() error {
    return callExternalService()
})

if errors.Is(err, recovery.ErrCircuitOpen) {
    useCachedData() // Fallback
}
```

**Circuit states:**
- **Closed** -- normal operation, requests pass through
- **Open** -- service failing, requests fail immediately
- **Half-Open** -- testing if service has recovered

### Combined: Retry + Circuit Breaker

```go
cb := recovery.NewCircuitBreaker(recovery.CircuitBreakerConfig{
    Name: "ai-api", Threshold: 3, Timeout: 30 * time.Second,
})

retryConfig := recovery.RetryConfig{
    MaxRetries: 2, InitialDelay: 200 * time.Millisecond,
    MaxDelay: 2 * time.Second, Multiplier: 2.0,
}

err := cb.Execute(func() error {
    return recovery.WithRetry(func() error {
        return callAIService()
    }, retryConfig)
})
```

## Use Cases in Zypheron

### Tool Execution

```go
recovery.Recover(func() {
    executor.RunTool("nmap", args)
})
```

### AI Service Calls

```go
aiCircuit := recovery.NewCircuitBreaker(recovery.CircuitBreakerConfig{
    Name: "deepseek-api", Threshold: 5, Timeout: 60 * time.Second,
})

err := aiCircuit.Execute(func() error {
    return recovery.WithRetry(func() error {
        return aibridge.Query(prompt)
    }, recovery.RetryConfig{
        MaxRetries: 3, InitialDelay: 500 * time.Millisecond,
        MaxDelay: 10 * time.Second, Multiplier: 2.0,
    })
})
```

### Database Operations

```go
err := recovery.WithRetry(func() error {
    return db.SaveScanResults(results)
}, recovery.RetryConfig{
    MaxRetries: 5, InitialDelay: 100 * time.Millisecond,
    MaxDelay: 2 * time.Second, Multiplier: 2.0,
})
```

## Configuration

### Log Directory

```go
recovery.SetLogDirectory("/var/log/zypheron")  // Must be absolute path
```

Default: `~/.zypheron/logs/errors.log`

### Recommended Retry Configs

| Use Case | MaxRetries | InitialDelay | MaxDelay |
|----------|-----------|--------------|----------|
| Network operations | 3 | 100ms | 2s |
| AI API calls | 5 | 500ms | 10s |
| Database queries | 3 | 50ms | 1s |

### Circuit Breaker Tuning

| Use Case | Threshold | Timeout |
|----------|-----------|---------|
| Fast-failing APIs | 3 | 10s |
| Slow/flaky services | 10 | 60s |
| Critical services | 5 | 30s |

## Circuit Breaker API

```go
state := cb.GetState()       // StateClosed, StateOpen, StateHalfOpen
failures := cb.GetFailures() // Current failure count
cb.Reset()                   // Manual reset
```

## Security Properties

### Resource Limits
- Max retries capped at 100
- Max delay capped at 5 minutes
- Circuit threshold capped at 1000
- Log directory must be absolute path (prevents directory traversal)

### Panic Handling
- Stack traces logged but sanitized
- No sensitive data in panic messages
- Atomic file operations prevent log corruption

### Thread Safety
- Atomic operations for state management
- Mutex-protected critical sections
- No data races (verified with `-race` flag)

### File Permissions
- Log directories: `0755`
- Log files: `0644`

## Error Types

```go
// Circuit breaker open
var ErrCircuitOpen = errors.New("circuit breaker is open")

if errors.Is(err, recovery.ErrCircuitOpen) {
    // Use fallback
}
```

Compatible with Zypheron's error types (`internal/errors/errors.go`):

```go
if errors.IsType(err, errors.ErrorTypeNetwork) {
    // Handle network error
}
```

## TUI Integration

The general-purpose recovery package complements the TUI-specific recovery:

- `internal/tui/recovery/recovery.go` -- Bubble Tea programs
- `internal/recovery/recovery.go` -- general purpose (this package)

## Best Practices

**Panic Recovery**: Use for potentially panicking code. Do not use in tight loops (performance). Do not use as primary error handling.

**Retry**: Use for transient failures only. Always use exponential backoff. Set reasonable limits. Do not retry permanent failures.

**Circuit Breaker**: Use for external services. Always implement fallbacks. Monitor state changes. Do not nest circuit breakers.

**Combined**: Place circuit breaker outside retry. Implement graceful degradation.

## Performance

| Operation | Overhead |
|-----------|----------|
| Panic recovery | ~250ns |
| Circuit breaker (closed) | ~120ns |
| Circuit breaker (open) | ~60ns |

Circuit breaker instance: ~200 bytes. No heap allocations in hot path.

## Testing

```bash
go test -v -race ./internal/recovery/...
```

See `example_usage.go` and `integration_example.go` for comprehensive examples.

## Troubleshooting

**High retry counts**: Check if error is permanent (do not retry). Reduce MaxRetries. Add a circuit breaker.

**Circuit stuck open**: Verify service availability. Check timeout configuration. Review threshold settings.

**Excessive logging**: Review log rotation. Reduce retry counts. Check for panic loops.
