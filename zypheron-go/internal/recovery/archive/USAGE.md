# Recovery Package Usage Guide

The recovery package provides production-ready error recovery mechanisms for the Zypheron CLI, including panic recovery, retry logic with exponential backoff, and circuit breaker pattern implementation.

## Features

1. **Panic Recovery**: Safely handle panics without crashing the application
2. **Retry Mechanism**: Automatic retry with exponential backoff for transient failures
3. **Circuit Breaker**: Prevent cascading failures by failing fast when services are down
4. **Thread-Safe**: All operations are safe for concurrent use

## Quick Start

### 1. Panic Recovery

Wrap potentially panicking code to prevent application crashes:

```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/recovery"

// Simple panic recovery
recovery.Recover(func() {
    // Code that might panic
    processUntrustedInput(data)
})

// Middleware pattern for functions returning errors
wrappedFunc := recovery.RecoveryMiddleware(func() error {
    return riskyOperation()
})

if err := wrappedFunc(); err != nil {
    log.Printf("Operation failed: %v", err)
}
```

### 2. Retry Mechanism

Automatically retry operations that may fail transiently (network calls, API requests, etc.):

```go
import (
    "time"
    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/recovery"
)

// Configure retry behavior
config := recovery.RetryConfig{
    MaxRetries:   3,                        // Retry up to 3 times
    InitialDelay: 100 * time.Millisecond,   // Start with 100ms delay
    MaxDelay:     5 * time.Second,          // Cap delays at 5 seconds
    Multiplier:   2.0,                      // Double delay each retry (exponential backoff)
    OnRetry: func(attempt int, err error) {
        log.Printf("Retry attempt %d: %v", attempt, err)
    },
}

// Execute with retry
err := recovery.WithRetry(func() error {
    return callExternalAPI()
}, config)

if err != nil {
    log.Printf("Operation failed after retries: %v", err)
}
```

### 3. Circuit Breaker

Protect external service calls from cascading failures:

```go
import (
    "time"
    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/recovery"
)

// Create circuit breaker
cb := recovery.NewCircuitBreaker(recovery.CircuitBreakerConfig{
    Name:      "external-api",              // Name for logging
    Threshold: 5,                           // Open after 5 consecutive failures
    Timeout:   30 * time.Second,            // Try again after 30 seconds
    ResetTime: 60 * time.Second,            // Fully reset after 60 seconds of success
    OnStateChange: func(from, to recovery.CircuitState) {
        log.Printf("Circuit %s: %s -> %s", cb.name, from, to)
    },
})

// Use circuit breaker
err := cb.Execute(func() error {
    return callExternalService()
})

if errors.Is(err, recovery.ErrCircuitOpen) {
    // Circuit is open - service is down
    log.Println("Service unavailable, circuit breaker is open")
    return handleServiceUnavailable()
}
```

## Advanced Examples

### Combining Retry and Circuit Breaker

For maximum resilience, combine retry logic with circuit breaker:

```go
cb := recovery.NewCircuitBreaker(recovery.CircuitBreakerConfig{
    Name:      "ai-api",
    Threshold: 3,
    Timeout:   30 * time.Second,
})

retryConfig := recovery.RetryConfig{
    MaxRetries:   2,
    InitialDelay: 200 * time.Millisecond,
    MaxDelay:     2 * time.Second,
    Multiplier:   2.0,
}

err := cb.Execute(func() error {
    return recovery.WithRetry(func() error {
        return callAIService()
    }, retryConfig)
})
```

### Custom Log Directory

Change where error logs are written:

```go
// Use custom log directory (must be absolute path)
recovery.SetLogDirectory("/var/log/zypheron")
```

### Circuit Breaker States

Monitor circuit breaker state:

```go
state := cb.GetState()
switch state {
case recovery.StateClosed:
    // Normal operation
case recovery.StateOpen:
    // Service is failing, requests fail fast
case recovery.StateHalfOpen:
    // Testing if service has recovered
}

// Check failure count
failures := cb.GetFailures()
if failures > 0 {
    log.Printf("Current failure count: %d", failures)
}

// Manual reset (use sparingly)
cb.Reset()
```

## Security Considerations

The recovery package includes built-in security protections:

1. **Resource Exhaustion Prevention**:
   - Max retries capped at 100
   - Max delay capped at 5 minutes
   - Circuit breaker thresholds capped at 1000
   - Circuit breaker timeout capped at 1 hour

2. **Input Validation**:
   - Log directory must be absolute path (prevents directory traversal)
   - All numeric parameters validated and sanitized

3. **Thread Safety**:
   - All operations use atomic operations or proper locking
   - Safe for concurrent use across goroutines

4. **Logging**:
   - Errors logged to `~/.zypheron/logs/errors.log` by default
   - Log files: 0644 permissions (rw-r--r--)
   - Log directories: 0755 permissions (rwxr-xr-x)
   - Stack traces included for debugging

## Use Cases in Zypheron

### 1. Tool Execution

Wrap external security tool execution with panic recovery:

```go
recovery.Recover(func() {
    executor.RunTool(toolName, args)
})
```

### 2. AI Service Calls

Use retry + circuit breaker for AI API calls:

```go
aiCircuit := recovery.NewCircuitBreaker(recovery.CircuitBreakerConfig{
    Name:      "deepseek-api",
    Threshold: 5,
    Timeout:   60 * time.Second,
})

err := aiCircuit.Execute(func() error {
    return recovery.WithRetry(func() error {
        return aibridge.Query(prompt)
    }, recovery.RetryConfig{
        MaxRetries:   3,
        InitialDelay: 500 * time.Millisecond,
        MaxDelay:     10 * time.Second,
        Multiplier:   2.0,
    })
})
```

### 3. Browser Automation

Recover from browser crashes during CVE lookup:

```go
wrapped := recovery.RecoveryMiddleware(func() error {
    return browser.LookupCVE(cveID)
})

if err := wrapped(); err != nil {
    log.Printf("CVE lookup failed: %v", err)
}
```

### 4. Database Operations

Retry transient database errors:

```go
err := recovery.WithRetry(func() error {
    return db.SaveScanResults(results)
}, recovery.RetryConfig{
    MaxRetries:   5,
    InitialDelay: 100 * time.Millisecond,
    MaxDelay:     2 * time.Second,
    Multiplier:   2.0,
})
```

## Best Practices

1. **Use Panic Recovery Sparingly**: Only wrap code that might actually panic
2. **Configure Retries Based on Operation Type**:
   - Network operations: 3-5 retries, longer delays
   - Database operations: 2-3 retries, shorter delays
   - Local operations: Don't retry unless necessary
3. **Circuit Breaker Thresholds**: Set based on expected failure rates
   - Critical services: Lower threshold (3-5 failures)
   - Less critical: Higher threshold (10+ failures)
4. **Monitor Circuit State**: Log state changes to track service health
5. **Combine Patterns**: Use retry inside circuit breaker for maximum resilience

## Error Handling

All functions follow Go conventions:

```go
// Check for circuit open error
if errors.Is(err, recovery.ErrCircuitOpen) {
    // Handle circuit open state
}

// Retry exhaustion returns wrapped error
if err != nil {
    // Error contains attempt count and final error
    log.Printf("Failed: %v", err)
}
```

## Performance Considerations

- **Atomic Operations**: State reads are lock-free
- **Minimal Overhead**: Panic recovery adds negligible overhead
- **Concurrent Safe**: All operations thread-safe
- **Log File I/O**: Async logging recommended for high-frequency errors

## Testing

The package includes comprehensive tests:

```bash
go test -v ./internal/recovery/
```

Test coverage includes:
- Panic recovery scenarios
- Retry exhaustion and success
- Circuit state transitions
- Thread safety validation
- Configuration validation
