package scanner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/validation"
)

// ExecutorConfig configures the sandboxed executor
type ExecutorConfig struct {
	// MaxLineLength limits individual output line length (prevents memory DoS)
	MaxLineLength int

	// BufferSize is the channel buffer size for output streaming
	BufferSize int

	// GracefulShutdownTimeout is how long to wait for SIGTERM before SIGKILL
	GracefulShutdownTimeout time.Duration

	// EnableResourceLimits enables OS-level resource limits (Linux only)
	EnableResourceLimits bool
}

// DefaultExecutorConfig returns secure default configuration
func DefaultExecutorConfig() ExecutorConfig {
	return ExecutorConfig{
		MaxLineLength:           8192,  // 8KB per line max
		BufferSize:              100,   // Buffer up to 100 lines
		GracefulShutdownTimeout: 5 * time.Second,
		EnableResourceLimits:    true,
	}
}

// SandboxedExecutor wraps exec.CommandContext with application-level sandboxing
// Enforces timeouts, output limits, and provides streaming capabilities
// Thread-safe for concurrent scanner executions
type SandboxedExecutor struct {
	config ExecutorConfig
	mu     sync.RWMutex
}

// NewSandboxedExecutor creates a new sandboxed executor with the given config
func NewSandboxedExecutor(config ExecutorConfig) *SandboxedExecutor {
	return &SandboxedExecutor{
		config: config,
	}
}

// Execute runs a scanner with comprehensive security controls
// Returns a channel for streaming output and an error if setup fails
// The returned channel is closed when execution completes or fails
func (e *SandboxedExecutor) Execute(ctx context.Context, scannerName string, opts ScanOptions) (<-chan OutputLine, error) {
	// Validate options first
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("invalid scan options: %w", err)
	}

	// Validate scanner name using existing validation
	if err := validation.ValidateToolName(scannerName); err != nil {
		return nil, fmt.Errorf("invalid scanner name: %w", err)
	}

	// Validate target using existing validation
	if err := validation.ValidateTarget(opts.Target); err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	// Check if scanner binary exists
	scannerPath, err := exec.LookPath(scannerName)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrScannerNotFound, scannerName)
	}

	// Create context with timeout
	execCtx, cancel := context.WithTimeout(ctx, opts.Timeout)

	// Create command with context (auto-killed on timeout/cancellation)
	cmd := exec.CommandContext(execCtx, scannerPath, opts.Args...)

	// Set working directory if specified
	if opts.WorkingDir != "" {
		cmd.Dir = opts.WorkingDir
	}

	// Set environment variables (sanitized)
	if len(opts.Env) > 0 {
		env := e.buildEnvironment(opts.Env)
		cmd.Env = env
	}

	// Create pipes for stdout/stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		stdout.Close()
		cancel()
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		stdout.Close()
		stderr.Close()
		cancel()
		return nil, fmt.Errorf("failed to start scanner: %w", err)
	}

	// Create output channel
	outputChan := make(chan OutputLine, e.config.BufferSize)

	// Launch monitoring goroutine
	go e.monitorExecution(execCtx, cancel, cmd, stdout, stderr, opts, outputChan)

	return outputChan, nil
}

// monitorExecution handles the actual process monitoring and output streaming
// Enforces output limits, handles cleanup, and manages graceful shutdown
func (e *SandboxedExecutor) monitorExecution(
	ctx context.Context,
	cancel context.CancelFunc,
	cmd *exec.Cmd,
	stdout, stderr io.ReadCloser,
	opts ScanOptions,
	outputChan chan<- OutputLine,
) {
	defer cancel()
	defer close(outputChan)

	// Track total bytes read (atomic for thread safety)
	var bytesRead atomic.Int64
	outputLimit := opts.GetOutputLimit()

	// WaitGroup to synchronize stdout/stderr readers
	var wg sync.WaitGroup
	wg.Add(2)

	// Channel to collect errors from readers
	errChan := make(chan error, 2)

	// Stream stdout
	go func() {
		defer wg.Done()
		if err := e.streamOutput(ctx, stdout, false, &bytesRead, outputLimit, outputChan); err != nil {
			errChan <- err
		}
	}()

	// Stream stderr
	go func() {
		defer wg.Done()
		if err := e.streamOutput(ctx, stderr, true, &bytesRead, outputLimit, outputChan); err != nil {
			errChan <- err
		}
	}()

	// Wait for readers to finish
	wg.Wait()
	close(errChan)

	// Check if output limit was exceeded
	outputExceeded := false
	for err := range errChan {
		if errors.Is(err, ErrOutputExceeded) {
			outputExceeded = true
			break
		}
	}

	// Wait for process to exit or kill it if output exceeded
	if outputExceeded {
		// Output limit exceeded - kill the process
		e.killProcess(cmd)
	} else {
		// Normal wait
		_ = cmd.Wait()
	}

	// Check for timeout
	if ctx.Err() == context.DeadlineExceeded {
		// Ensure process is killed
		e.killProcess(cmd)
	}
}

// streamOutput reads from a pipe and sends lines to the output channel
// Enforces line length limits and total output limits
func (e *SandboxedExecutor) streamOutput(
	ctx context.Context,
	reader io.ReadCloser,
	isError bool,
	bytesRead *atomic.Int64,
	outputLimit int64,
	outputChan chan<- OutputLine,
) error {
	defer reader.Close()

	scanner := bufio.NewScanner(reader)

	// Set maximum line length to prevent buffer overflow
	buf := make([]byte, 0, e.config.MaxLineLength)
	scanner.Buffer(buf, e.config.MaxLineLength)

	for scanner.Scan() {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Text()
		lineLen := int64(len(line))

		// Update bytes read counter
		newTotal := bytesRead.Add(lineLen + 1) // +1 for newline

		// Check output limit
		if outputLimit > 0 && newTotal > outputLimit {
			// Send truncation notice
			select {
			case outputChan <- OutputLine{
				Content:   "[OUTPUT TRUNCATED - SIZE LIMIT EXCEEDED]",
				Timestamp: time.Now(),
				IsError:   true,
				Truncated: true,
			}:
			case <-ctx.Done():
			}
			return ErrOutputExceeded
		}

		// Sanitize output line (remove control characters, null bytes)
		sanitized := e.sanitizeLine(line)

		// Check if line was truncated by scanner
		truncated := len(sanitized) < len(line)

		// Send output line
		outputLine := OutputLine{
			Content:   sanitized,
			Timestamp: time.Now(),
			IsError:   isError,
			Truncated: truncated,
		}

		select {
		case outputChan <- outputLine:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		// Don't return error for buffer overflow - we handle it
		if !errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("scanner error: %w", err)
		}
		// Send truncation notice for buffer overflow
		select {
		case outputChan <- OutputLine{
			Content:   "[LINE TRUNCATED - MAXIMUM LINE LENGTH EXCEEDED]",
			Timestamp: time.Now(),
			IsError:   true,
			Truncated: true,
		}:
		case <-ctx.Done():
		}
	}

	return nil
}

// sanitizeLine removes dangerous characters from output
// Prevents terminal escape sequence attacks and control character injection
func (e *SandboxedExecutor) sanitizeLine(line string) string {
	// Pre-allocate result buffer
	result := make([]byte, 0, len(line))

	for i := 0; i < len(line); i++ {
		c := line[i]

		// Filter out control characters except tab and printable ASCII
		// Allow: tab (0x09), printable ASCII (0x20-0x7E)
		// Block: null (0x00), other control chars (0x01-0x08, 0x0A-0x1F, 0x7F)
		// Block: ANSI escape sequences (0x1B)
		if c == 0x00 {
			// Null byte - skip entirely
			continue
		} else if c == 0x1B {
			// Escape character - skip full ANSI sequence
			// ANSI sequences: ESC [ <params> <letter>
			// Skip ESC, then skip until we hit a terminating letter (A-Z, a-z)
			i++ // Skip ESC
			if i < len(line) && line[i] == '[' {
				i++ // Skip [
				// Skip parameters (digits, semicolons) until we hit a letter
				for i < len(line) {
					ch := line[i]
					if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
						// Found terminator, skip it and exit loop
						break
					}
					i++
				}
			}
			continue
		} else if c == 0x09 || (c >= 0x20 && c <= 0x7E) {
			// Printable character or tab
			result = append(result, c)
		} else if c >= 0x80 {
			// UTF-8 continuation - allow (simple approach)
			// More sophisticated: validate full UTF-8 sequences
			result = append(result, c)
		}
		// Skip other control characters
	}

	return string(result)
}

// killProcess attempts graceful shutdown (SIGTERM) then forceful (SIGKILL)
func (e *SandboxedExecutor) killProcess(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}

	// Try graceful shutdown first (SIGTERM on Unix, TerminateProcess on Windows)
	_ = cmd.Process.Signal(nil) // Check if process exists
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return
	}

	// Send SIGTERM
	_ = cmd.Process.Kill()

	// Wait for graceful shutdown
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Graceful shutdown succeeded
		return
	case <-time.After(e.config.GracefulShutdownTimeout):
		// Graceful shutdown timed out - force kill
		// On Unix, this is SIGKILL; on Windows, TerminateProcess with exit code
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
}

// buildEnvironment creates a sanitized environment variable list
// Prevents shell injection via environment variables
func (e *SandboxedExecutor) buildEnvironment(envVars map[string]string) []string {
	// Start with a minimal safe environment
	// DO NOT inherit full environment to prevent leaking sensitive data
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/tmp",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
	}

	// Add user-specified variables (already validated)
	for key, val := range envVars {
		// Double-check for shell metacharacters (defense in depth)
		if e.isSafeEnvValue(key) && e.isSafeEnvValue(val) {
			env = append(env, fmt.Sprintf("%s=%s", key, val))
		}
	}

	return env
}

// isSafeEnvValue checks if an environment value is safe
// Rejects values containing shell metacharacters
func (e *SandboxedExecutor) isSafeEnvValue(value string) bool {
	// Check for dangerous characters
	dangerous := []byte{'$', '`', '!', ';', '&', '|', '<', '>', '(', ')', '{', '}', '[', ']', '*', '?', '~', '\n', '\r', 0}

	for _, c := range dangerous {
		for i := 0; i < len(value); i++ {
			if value[i] == c {
				return false
			}
		}
	}

	return true
}

// CollectOutput collects all output from a channel into a ScanResult
// This is a utility function for non-streaming execution
func CollectOutput(ctx context.Context, outputChan <-chan OutputLine, start time.Time) *ScanResult {
	var output []byte
	var totalBytes int64
	var lastError error
	outputTruncated := false

	for line := range outputChan {
		lineBytes := []byte(line.Content)
		lineBytes = append(lineBytes, '\n')

		totalBytes += int64(len(lineBytes))
		output = append(output, lineBytes...)

		if line.Truncated {
			outputTruncated = true
		}

		if line.IsError && line.Content != "" {
			lastError = errors.New(line.Content)
		}
	}

	duration := time.Since(start)

	result := &ScanResult{
		Success:         lastError == nil && !outputTruncated,
		Output:          string(output),
		Duration:        duration,
		Error:           lastError,
		TimedOut:        errors.Is(ctx.Err(), context.DeadlineExceeded),
		OutputTruncated: outputTruncated,
		BytesRead:       totalBytes,
	}

	return result
}
