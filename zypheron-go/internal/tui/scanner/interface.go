package scanner

import (
	"context"
	"errors"
	"time"
)

// Security constraints for scanner execution
const (
	// MaxOutputBytes is the absolute maximum output size (100MB default)
	MaxOutputBytes = 100 * 1024 * 1024

	// DefaultTimeout is the default execution timeout
	DefaultTimeout = 5 * time.Minute

	// MaxTimeout is the maximum allowed timeout
	MaxTimeout = 1 * time.Hour

	// MaxTargetLength prevents buffer overflow attacks via oversized targets
	MaxTargetLength = 512

	// MaxArgsCount limits the number of arguments to prevent resource exhaustion
	MaxArgsCount = 100

	// MaxArgLength limits individual argument length
	MaxArgLength = 4096
)

var (
	// ErrInvalidTarget indicates target validation failed
	ErrInvalidTarget = errors.New("invalid target specification")

	// ErrExecutionTimeout indicates the scanner timed out
	ErrExecutionTimeout = errors.New("scanner execution timed out")

	// ErrOutputExceeded indicates output size limit was exceeded
	ErrOutputExceeded = errors.New("scanner output exceeded maximum size")

	// ErrScannerNotFound indicates the scanner binary is not available
	ErrScannerNotFound = errors.New("scanner binary not found in PATH")

	// ErrInvalidOptions indicates scanner options are invalid
	ErrInvalidOptions = errors.New("invalid scanner options")

	// ErrContextCanceled indicates the context was canceled
	ErrContextCanceled = errors.New("scanner execution canceled")
)

// OutputLine represents a single line of scanner output with metadata
// This allows streaming output with proper categorization
type OutputLine struct {
	// Content is the actual output line (sanitized)
	Content string

	// Timestamp records when this line was produced
	Timestamp time.Time

	// IsError indicates if this line came from stderr
	IsError bool

	// Truncated indicates if this line was truncated due to length limits
	Truncated bool
}

// ScanOptions configures scanner execution with security constraints
type ScanOptions struct {
	// Target is the scan target (validated before execution)
	Target string

	// Timeout limits execution time (0 = use DefaultTimeout)
	// Must not exceed MaxTimeout
	Timeout time.Duration

	// Args are additional scanner-specific arguments (validated)
	// Each arg is checked for shell metacharacters
	Args []string

	// MaxOutputMB kills process if output exceeds this (0 = unlimited, up to MaxOutputBytes)
	// This prevents memory exhaustion from runaway scanners
	MaxOutputMB int

	// StreamOutput enables real-time output streaming via channels
	StreamOutput bool

	// WorkingDir specifies the working directory (optional, validated)
	WorkingDir string

	// Environment variables to set (validated, no shell expansion)
	Env map[string]string
}

// Validate performs comprehensive validation of scan options
// Returns detailed error messages for security violations
func (o *ScanOptions) Validate() error {
	if o == nil {
		return ErrInvalidOptions
	}

	// Target validation
	if len(o.Target) == 0 {
		return errors.New("target cannot be empty")
	}
	if len(o.Target) > MaxTargetLength {
		return errors.New("target exceeds maximum length")
	}

	// Timeout validation
	if o.Timeout < 0 {
		return errors.New("timeout cannot be negative")
	}
	if o.Timeout > MaxTimeout {
		return errors.New("timeout exceeds maximum allowed duration")
	}
	if o.Timeout == 0 {
		o.Timeout = DefaultTimeout
	}

	// Arguments validation
	if len(o.Args) > MaxArgsCount {
		return errors.New("too many arguments")
	}
	for i, arg := range o.Args {
		if len(arg) > MaxArgLength {
			return errors.New("argument exceeds maximum length")
		}
		// Prevent null byte injection
		for j := 0; j < len(arg); j++ {
			if arg[j] == 0 {
				return errors.New("null byte detected in argument")
			}
		}
		// Sanitize argument (stored back)
		o.Args[i] = arg
	}

	// Output limit validation
	if o.MaxOutputMB < 0 {
		return errors.New("MaxOutputMB cannot be negative")
	}
	maxMB := MaxOutputBytes / (1024 * 1024)
	if o.MaxOutputMB > maxMB {
		return errors.New("MaxOutputMB exceeds system maximum")
	}

	// Environment validation (prevent shell injection)
	for key, val := range o.Env {
		if len(key) == 0 || len(key) > 256 {
			return errors.New("invalid environment variable key length")
		}
		if len(val) > MaxArgLength {
			return errors.New("environment variable value too long")
		}
		// Check for null bytes
		for i := 0; i < len(key); i++ {
			if key[i] == 0 {
				return errors.New("null byte in environment key")
			}
		}
		for i := 0; i < len(val); i++ {
			if val[i] == 0 {
				return errors.New("null byte in environment value")
			}
		}
	}

	return nil
}

// GetOutputLimit returns the output limit in bytes (0 = unlimited)
func (o *ScanOptions) GetOutputLimit() int64 {
	if o.MaxOutputMB == 0 {
		return 0
	}
	return int64(o.MaxOutputMB) * 1024 * 1024
}

// ScanResult contains parsed scan results with error details
type ScanResult struct {
	// Success indicates if the scan completed without errors
	Success bool

	// Output contains the complete scanner output (sanitized)
	Output string

	// ExitCode is the scanner process exit code
	ExitCode int

	// Duration is the actual execution time
	Duration time.Duration

	// Parsed contains tool-specific parsed data (nil if parsing failed)
	// Type depends on the scanner implementation
	Parsed interface{}

	// Error contains any error that occurred during execution
	Error error

	// TimedOut indicates if the scan was terminated due to timeout
	TimedOut bool

	// OutputTruncated indicates if output was truncated due to size limits
	OutputTruncated bool

	// BytesRead is the total number of bytes read from the scanner
	BytesRead int64
}

// Scanner interface defines the contract for all security scanning tools
// Implementations must be thread-safe and enforce security constraints
type Scanner interface {
	// Name returns the scanner's identifier (e.g., "nmap", "nikto")
	// Used for logging and tool selection
	Name() string

	// Validate performs scanner-specific target validation
	// Must check for scanner-specific security requirements
	// Returns detailed error message on validation failure
	Validate(target string) error

	// Execute runs the scanner with the provided options
	// Returns a channel for streaming output lines (if StreamOutput enabled)
	// The channel is closed when execution completes or fails
	// Context cancellation immediately terminates the scanner process
	// Implementations MUST:
	//   - Validate all inputs before execution
	//   - Enforce timeout via context
	//   - Monitor output size and kill if exceeded
	//   - Sanitize all output before sending
	//   - Close the output channel when done
	//   - Handle SIGKILL if process doesn't respond to SIGTERM
	Execute(ctx context.Context, opts ScanOptions) (<-chan OutputLine, error)

	// ParseResult extracts structured data from scanner output
	// Returns scanner-specific parsed data or nil if parsing fails
	// Must handle malformed output gracefully without panicking
	// The parsed data type is scanner-specific
	ParseResult(output string) (interface{}, error)
}

// ScannerFactory creates scanner instances
// Used for dependency injection and testing
type ScannerFactory interface {
	// CreateScanner returns a scanner instance for the given tool
	// Returns ErrScannerNotFound if tool is not supported
	CreateScanner(toolName string) (Scanner, error)

	// ListScanners returns all available scanner names
	ListScanners() []string

	// IsAvailable checks if a scanner binary is installed and executable
	IsAvailable(toolName string) bool
}
