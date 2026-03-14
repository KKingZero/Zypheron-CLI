# Scanner Interface - Secure Scanner Abstraction

## Overview

The scanner interface provides a secure, sandboxed abstraction for executing security scanning tools in the Zypheron TUI. It enforces strict security constraints, resource limits, and provides real-time output streaming.

## Security Features

### Input Validation
- **Target Validation**: All targets validated against shell metacharacters, null bytes, and length limits
- **Argument Sanitization**: Scanner arguments checked for injection attempts
- **Tool Name Allowlist**: Only whitelisted tools can be executed
- **Path Traversal Prevention**: Working directory paths validated

### Execution Sandboxing
- **Timeout Enforcement**: Hard timeout via context cancellation (SIGKILL after grace period)
- **Output Limits**: Process killed if output exceeds configured maximum
- **Resource Isolation**: Minimal environment, no inherited sensitive variables
- **Signal Handling**: Graceful SIGTERM → SIGKILL escalation

### Output Sanitization
- **Control Character Filtering**: Removes null bytes, ANSI escapes, and control chars
- **Line Length Limits**: Prevents memory exhaustion from infinite lines
- **Buffer Management**: Fixed-size buffers with overflow protection
- **UTF-8 Safety**: Handles multi-byte sequences without breaking

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Scanner Interface                       │
│  - Name() string                                            │
│  - Validate(target) error                                   │
│  - Execute(ctx, opts) <-chan OutputLine                     │
│  - ParseResult(output) (interface{}, error)                 │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ implements
                         │
          ┌──────────────┴──────────────┐
          │                             │
┌─────────▼──────────┐      ┌──────────▼──────────┐
│  NmapScanner       │      │  NiktoScanner       │
│  (tool-specific)   │      │  (tool-specific)    │
└─────────┬──────────┘      └──────────┬──────────┘
          │                             │
          └──────────────┬──────────────┘
                         │
                         │ uses
                         │
          ┌──────────────▼──────────────┐
          │   SandboxedExecutor         │
          │  - Execute(ctx, name, opts) │
          │  - Enforces security limits │
          │  - Streams output           │
          │  - Handles cleanup          │
          └─────────────────────────────┘
```

## Usage Example

### Basic Scanner Implementation

```go
package scanner

import (
    "context"
    "fmt"
    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/validation"
)

type NmapScanner struct {
    executor *SandboxedExecutor
}

func NewNmapScanner() *NmapScanner {
    return &NmapScanner{
        executor: NewSandboxedExecutor(DefaultExecutorConfig()),
    }
}

func (n *NmapScanner) Name() string {
    return "nmap"
}

func (n *NmapScanner) Validate(target string) error {
    // Use existing validation infrastructure
    return validation.ValidateTarget(target)
}

func (n *NmapScanner) Execute(ctx context.Context, opts ScanOptions) (<-chan OutputLine, error) {
    // Build nmap-specific arguments
    args := []string{"-sV", "-sC", opts.Target}
    args = append(args, opts.Args...)

    opts.Args = args

    // Execute via sandboxed executor
    return n.executor.Execute(ctx, n.Name(), opts)
}

func (n *NmapScanner) ParseResult(output string) (interface{}, error) {
    // Parse nmap output into structured data
    // Use existing tools.ParseNmapOutput or implement custom parser
    return tools.ParseNmapOutput(output), nil
}
```

### Using the Scanner

```go
// Create scanner
scanner := NewNmapScanner()

// Configure scan options
opts := ScanOptions{
    Target:       "example.com",
    Timeout:      5 * time.Minute,
    Args:         []string{"-p", "80,443"},
    MaxOutputMB:  10,
    StreamOutput: true,
}

// Validate target
if err := scanner.Validate(opts.Target); err != nil {
    return fmt.Errorf("invalid target: %w", err)
}

// Execute scan
ctx := context.Background()
outputChan, err := scanner.Execute(ctx, opts)
if err != nil {
    return fmt.Errorf("execution failed: %w", err)
}

// Stream output
start := time.Now()
for line := range outputChan {
    if line.IsError {
        fmt.Printf("[ERROR] %s\n", line.Content)
    } else {
        fmt.Printf("[%s] %s\n", line.Timestamp.Format("15:04:05"), line.Content)
    }
}

// Or collect all output
result := CollectOutput(ctx, outputChan, start)
if result.Error != nil {
    fmt.Printf("Scan failed: %v\n", result.Error)
}

// Parse results
parsed, err := scanner.ParseResult(result.Output)
if err != nil {
    fmt.Printf("Parse failed: %v\n", err)
}
```

## Security Constraints

### Hard Limits

| Constraint | Default | Maximum | Purpose |
|------------|---------|---------|---------|
| Output Size | 10MB | 100MB | Prevent memory exhaustion |
| Timeout | 5 min | 1 hour | Prevent runaway processes |
| Target Length | - | 512 bytes | Prevent buffer overflow |
| Args Count | - | 100 | Prevent resource exhaustion |
| Arg Length | - | 4KB | Prevent buffer overflow |
| Line Length | - | 8KB | Prevent memory DoS |

### Validation Rules

1. **Tool Names**: Must be in `validation.AllowedTools` whitelist
2. **Targets**: Validated via `validation.ValidateTarget()`
   - No shell metacharacters: `; & | \` $ ( ) < >`
   - No null bytes
   - Valid IP, domain, CIDR, or URL
3. **Arguments**:
   - No null bytes
   - Length limits enforced
   - Passed verbatim (no shell expansion)
4. **Environment**:
   - Minimal safe environment by default
   - Custom vars checked for shell metacharacters
   - No inherited sensitive variables

## Error Handling

All errors are wrapped with context:

```go
var (
    ErrInvalidTarget     = errors.New("invalid target specification")
    ErrExecutionTimeout  = errors.New("scanner execution timed out")
    ErrOutputExceeded    = errors.New("scanner output exceeded maximum size")
    ErrScannerNotFound   = errors.New("scanner binary not found in PATH")
    ErrInvalidOptions    = errors.New("invalid scanner options")
    ErrContextCanceled   = errors.New("scanner execution canceled")
)
```

Check for specific errors:

```go
if errors.Is(err, ErrExecutionTimeout) {
    // Handle timeout
}
if errors.Is(err, ErrOutputExceeded) {
    // Handle output limit
}
```

## Thread Safety

- **SandboxedExecutor**: Thread-safe, can run multiple scans concurrently
- **OutputLine channel**: Each execution gets its own channel
- **Atomic counters**: Output byte tracking uses atomic operations
- **No shared state**: Each scan is isolated

## Integration with Existing Code

The scanner interface integrates seamlessly with existing Zypheron infrastructure:

1. **Validation**: Uses `internal/validation/validator.go`
2. **Tool Execution**: Compatible with `internal/tools/executor.go` patterns
3. **Parsing**: Can use existing `tools.ParseNmapOutput()` etc.
4. **UI**: Output channels work with bubble tea TUI

## Performance Considerations

### Memory Usage
- **Streaming**: Output is streamed, not buffered entirely in memory
- **Line buffering**: Fixed 8KB max line length prevents unbounded growth
- **Channel buffering**: Default 100 lines, tune via `ExecutorConfig.BufferSize`

### CPU Usage
- **Minimal overhead**: Single pass sanitization
- **Atomic operations**: Lock-free byte counter
- **Efficient copying**: Pre-allocated buffers where possible

### I/O
- **Non-blocking reads**: Uses bufio.Scanner for efficient reading
- **Immediate streaming**: Lines sent as soon as received
- **Graceful shutdown**: SIGTERM before SIGKILL reduces I/O disruption

## Testing

Example test structure:

```go
func TestNmapScanner_Execute(t *testing.T) {
    scanner := NewNmapScanner()

    tests := []struct {
        name    string
        opts    ScanOptions
        wantErr bool
    }{
        {
            name: "valid scan",
            opts: ScanOptions{
                Target:  "127.0.0.1",
                Timeout: 30 * time.Second,
                Args:    []string{"-p", "80"},
            },
            wantErr: false,
        },
        {
            name: "invalid target",
            opts: ScanOptions{
                Target:  "; rm -rf /",
                Timeout: 30 * time.Second,
            },
            wantErr: true,
        },
        // More test cases...
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            ctx := context.Background()
            _, err := scanner.Execute(ctx, tt.opts)
            if (err != nil) != tt.wantErr {
                t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

## Best Practices

1. **Always validate before execute**: Call `Validate()` even though `Execute()` validates
2. **Set reasonable timeouts**: Don't use MaxTimeout unless necessary
3. **Limit output size**: Set `MaxOutputMB` based on expected tool output
4. **Handle context cancellation**: Respect context cancellation for clean shutdown
5. **Parse errors gracefully**: `ParseResult()` should never panic
6. **Log security events**: Log validation failures and limit violations
7. **Use streaming for UX**: Real-time output improves user experience
8. **Clean up resources**: Always consume the output channel completely

## Security Checklist

Before deploying a new scanner implementation:

- [ ] Validates all inputs (target, args, options)
- [ ] Uses SandboxedExecutor (not raw exec.Command)
- [ ] Sets appropriate timeout
- [ ] Sets output limit
- [ ] Handles context cancellation
- [ ] Sanitizes output in ParseResult
- [ ] No shell expansion or subprocess spawning
- [ ] No hardcoded credentials or sensitive data
- [ ] Error messages don't leak sensitive info
- [ ] Thread-safe implementation
- [ ] Tested with malicious inputs

## Future Enhancements

Potential improvements for future versions:

1. **OS-level sandboxing**: seccomp, AppArmor, SELinux integration
2. **Network isolation**: Network namespaces on Linux
3. **Resource limits**: CPU, memory limits via cgroups
4. **Audit logging**: Structured logging of all executions
5. **Rate limiting**: Prevent scanner abuse
6. **Result caching**: Cache scan results with TTL
7. **Progress reporting**: Enhanced progress callbacks
8. **Distributed scanning**: Execute scans on remote workers
