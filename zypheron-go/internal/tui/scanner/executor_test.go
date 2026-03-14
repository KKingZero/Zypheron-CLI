package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestScanOptions_Validate tests comprehensive option validation
func TestScanOptions_Validate(t *testing.T) {
	tests := []struct {
		name    string
		opts    ScanOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid options",
			opts: ScanOptions{
				Target:      "example.com",
				Timeout:     30 * time.Second,
				Args:        []string{"-p", "80"},
				MaxOutputMB: 10,
			},
			wantErr: false,
		},
		{
			name: "empty target",
			opts: ScanOptions{
				Target:  "",
				Timeout: 30 * time.Second,
			},
			wantErr: true,
			errMsg:  "target cannot be empty",
		},
		{
			name: "oversized target",
			opts: ScanOptions{
				Target:  strings.Repeat("a", MaxTargetLength+1),
				Timeout: 30 * time.Second,
			},
			wantErr: true,
			errMsg:  "target exceeds maximum length",
		},
		{
			name: "negative timeout",
			opts: ScanOptions{
				Target:  "example.com",
				Timeout: -1 * time.Second,
			},
			wantErr: true,
			errMsg:  "timeout cannot be negative",
		},
		{
			name: "excessive timeout",
			opts: ScanOptions{
				Target:  "example.com",
				Timeout: MaxTimeout + 1*time.Second,
			},
			wantErr: true,
			errMsg:  "timeout exceeds maximum",
		},
		{
			name: "too many arguments",
			opts: ScanOptions{
				Target:  "example.com",
				Timeout: 30 * time.Second,
				Args:    make([]string, MaxArgsCount+1),
			},
			wantErr: true,
			errMsg:  "too many arguments",
		},
		{
			name: "oversized argument",
			opts: ScanOptions{
				Target:  "example.com",
				Timeout: 30 * time.Second,
				Args:    []string{strings.Repeat("a", MaxArgLength+1)},
			},
			wantErr: true,
			errMsg:  "argument exceeds maximum length",
		},
		{
			name: "null byte in argument",
			opts: ScanOptions{
				Target:  "example.com",
				Timeout: 30 * time.Second,
				Args:    []string{"test\x00injection"},
			},
			wantErr: true,
			errMsg:  "null byte",
		},
		{
			name: "negative output limit",
			opts: ScanOptions{
				Target:      "example.com",
				Timeout:     30 * time.Second,
				MaxOutputMB: -1,
			},
			wantErr: true,
			errMsg:  "MaxOutputMB cannot be negative",
		},
		{
			name: "excessive output limit",
			opts: ScanOptions{
				Target:      "example.com",
				Timeout:     30 * time.Second,
				MaxOutputMB: (MaxOutputBytes / (1024 * 1024)) + 1,
			},
			wantErr: true,
			errMsg:  "MaxOutputMB exceeds system maximum",
		},
		{
			name: "null byte in env key",
			opts: ScanOptions{
				Target:  "example.com",
				Timeout: 30 * time.Second,
				Env: map[string]string{
					"TEST\x00": "value",
				},
			},
			wantErr: true,
			errMsg:  "null byte",
		},
		{
			name: "null byte in env value",
			opts: ScanOptions{
				Target:  "example.com",
				Timeout: 30 * time.Second,
				Env: map[string]string{
					"TEST": "value\x00",
				},
			},
			wantErr: true,
			errMsg:  "null byte",
		},
		{
			name: "zero timeout gets default",
			opts: ScanOptions{
				Target:  "example.com",
				Timeout: 0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

// TestScanOptions_GetOutputLimit tests output limit calculation
func TestScanOptions_GetOutputLimit(t *testing.T) {
	tests := []struct {
		name        string
		maxOutputMB int
		want        int64
	}{
		{
			name:        "zero means unlimited",
			maxOutputMB: 0,
			want:        0,
		},
		{
			name:        "10MB",
			maxOutputMB: 10,
			want:        10 * 1024 * 1024,
		},
		{
			name:        "100MB",
			maxOutputMB: 100,
			want:        100 * 1024 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := ScanOptions{MaxOutputMB: tt.maxOutputMB}
			got := opts.GetOutputLimit()
			if got != tt.want {
				t.Errorf("GetOutputLimit() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSandboxedExecutor_sanitizeLine tests output sanitization
func TestSandboxedExecutor_sanitizeLine(t *testing.T) {
	executor := NewSandboxedExecutor(DefaultExecutorConfig())

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "normal text",
			input: "Hello World",
			want:  "Hello World",
		},
		{
			name:  "remove null bytes",
			input: "Hello\x00World",
			want:  "HelloWorld",
		},
		{
			name:  "remove ANSI escape sequences",
			input: "\x1b[31mRed Text\x1b[0m",
			want:  "Red Text",
		},
		{
			name:  "allow tabs",
			input: "Col1\tCol2\tCol3",
			want:  "Col1\tCol2\tCol3",
		},
		{
			name:  "remove control characters",
			input: "Test\x01\x02\x03String",
			want:  "TestString",
		},
		{
			name:  "preserve printable ASCII",
			input: "Test!@#$%^&*()_+-=[]{}|;:',.<>?",
			want:  "Test!@#$%^&*()_+-=[]{}|;:',.<>?",
		},
		{
			name:  "remove bell character",
			input: "Alert\x07",
			want:  "Alert",
		},
		{
			name:  "complex mixed content",
			input: "\x1b[1;31mError:\x1b[0m File\x00not\x07found",
			want:  "Error: Filenotfound",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := executor.sanitizeLine(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeLine() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSandboxedExecutor_isSafeEnvValue tests environment value validation
func TestSandboxedExecutor_isSafeEnvValue(t *testing.T) {
	executor := NewSandboxedExecutor(DefaultExecutorConfig())

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{
			name:  "safe alphanumeric",
			value: "value123",
			want:  true,
		},
		{
			name:  "safe with underscores",
			value: "test_value_123",
			want:  true,
		},
		{
			name:  "safe with dots and dashes",
			value: "test.value-123",
			want:  true,
		},
		{
			name:  "unsafe dollar sign",
			value: "$PATH",
			want:  false,
		},
		{
			name:  "unsafe backtick",
			value: "`whoami`",
			want:  false,
		},
		{
			name:  "unsafe semicolon",
			value: "value;rm -rf /",
			want:  false,
		},
		{
			name:  "unsafe ampersand",
			value: "value&& rm -rf /",
			want:  false,
		},
		{
			name:  "unsafe pipe",
			value: "value | cat",
			want:  false,
		},
		{
			name:  "unsafe redirect",
			value: "value > /etc/passwd",
			want:  false,
		},
		{
			name:  "unsafe newline",
			value: "value\nrm -rf /",
			want:  false,
		},
		{
			name:  "unsafe null byte",
			value: "value\x00",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := executor.isSafeEnvValue(tt.value)
			if got != tt.want {
				t.Errorf("isSafeEnvValue() = %v, want %v for value %q", got, tt.want, tt.value)
			}
		})
	}
}

// TestSandboxedExecutor_buildEnvironment tests environment building
func TestSandboxedExecutor_buildEnvironment(t *testing.T) {
	executor := NewSandboxedExecutor(DefaultExecutorConfig())

	tests := []struct {
		name     string
		envVars  map[string]string
		contains []string
		excludes []string
	}{
		{
			name:    "empty environment",
			envVars: map[string]string{},
			contains: []string{
				"PATH=",
				"HOME=/tmp",
				"LANG=C.UTF-8",
			},
			excludes: []string{},
		},
		{
			name: "safe custom variables",
			envVars: map[string]string{
				"CUSTOM_VAR": "safe_value",
				"TIMEOUT":    "300",
			},
			contains: []string{
				"PATH=",
				"CUSTOM_VAR=safe_value",
				"TIMEOUT=300",
			},
			excludes: []string{},
		},
		{
			name: "unsafe variables filtered",
			envVars: map[string]string{
				"SAFE":   "value",
				"UNSAFE": "$PATH",
			},
			contains: []string{
				"SAFE=value",
			},
			excludes: []string{
				"UNSAFE=",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := executor.buildEnvironment(tt.envVars)

			// Check that required variables are present
			for _, required := range tt.contains {
				found := false
				for _, e := range env {
					if strings.Contains(e, required) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("buildEnvironment() missing %q in %v", required, env)
				}
			}

			// Check that excluded variables are not present
			for _, excluded := range tt.excludes {
				for _, e := range env {
					if strings.Contains(e, excluded) {
						t.Errorf("buildEnvironment() should not contain %q but found in %v", excluded, env)
					}
				}
			}
		})
	}
}

// TestCollectOutput tests output collection utility
func TestCollectOutput(t *testing.T) {
	tests := []struct {
		name          string
		lines         []OutputLine
		wantSuccess   bool
		wantTruncated bool
		wantOutputLen int
		wantBytesRead int64
	}{
		{
			name: "successful output",
			lines: []OutputLine{
				{Content: "Line 1", IsError: false, Truncated: false},
				{Content: "Line 2", IsError: false, Truncated: false},
			},
			wantSuccess:   true,
			wantTruncated: false,
			wantOutputLen: 14, // "Line 1\nLine 2\n"
			wantBytesRead: 14,
		},
		{
			name: "error output",
			lines: []OutputLine{
				{Content: "Error occurred", IsError: true, Truncated: false},
			},
			wantSuccess:   false,
			wantTruncated: false,
			wantOutputLen: 15, // "Error occurred\n"
			wantBytesRead: 15,
		},
		{
			name: "truncated output",
			lines: []OutputLine{
				{Content: "Line 1", IsError: false, Truncated: false},
				{Content: "[TRUNCATED]", IsError: false, Truncated: true},
			},
			wantSuccess:   false,
			wantTruncated: true,
			wantOutputLen: 19, // "Line 1\n[TRUNCATED]\n" = 6+1+11+1 = 19 bytes
			wantBytesRead: 19,
		},
		{
			name:          "empty output",
			lines:         []OutputLine{},
			wantSuccess:   true,
			wantTruncated: false,
			wantOutputLen: 0,
			wantBytesRead: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create channel and send lines
			outputChan := make(chan OutputLine, len(tt.lines))
			for _, line := range tt.lines {
				outputChan <- line
			}
			close(outputChan)

			ctx := context.Background()
			start := time.Now()

			result := CollectOutput(ctx, outputChan, start)

			if result.Success != tt.wantSuccess {
				t.Errorf("CollectOutput() Success = %v, want %v", result.Success, tt.wantSuccess)
			}
			if result.OutputTruncated != tt.wantTruncated {
				t.Errorf("CollectOutput() OutputTruncated = %v, want %v", result.OutputTruncated, tt.wantTruncated)
			}
			if len(result.Output) != tt.wantOutputLen {
				t.Errorf("CollectOutput() output length = %v, want %v", len(result.Output), tt.wantOutputLen)
			}
			if result.BytesRead != tt.wantBytesRead {
				t.Errorf("CollectOutput() BytesRead = %v, want %v", result.BytesRead, tt.wantBytesRead)
			}
			if result.Duration <= 0 {
				t.Error("CollectOutput() Duration should be positive")
			}
		})
	}
}

// TestDefaultExecutorConfig tests default configuration
func TestDefaultExecutorConfig(t *testing.T) {
	config := DefaultExecutorConfig()

	if config.MaxLineLength <= 0 {
		t.Error("DefaultExecutorConfig() MaxLineLength should be positive")
	}
	if config.BufferSize <= 0 {
		t.Error("DefaultExecutorConfig() BufferSize should be positive")
	}
	if config.GracefulShutdownTimeout <= 0 {
		t.Error("DefaultExecutorConfig() GracefulShutdownTimeout should be positive")
	}
}

// TestErrorConstants tests that error constants are properly defined
func TestErrorConstants(t *testing.T) {
	errorTests := []struct {
		name string
		err  error
	}{
		{"ErrInvalidTarget", ErrInvalidTarget},
		{"ErrExecutionTimeout", ErrExecutionTimeout},
		{"ErrOutputExceeded", ErrOutputExceeded},
		{"ErrScannerNotFound", ErrScannerNotFound},
		{"ErrInvalidOptions", ErrInvalidOptions},
		{"ErrContextCanceled", ErrContextCanceled},
	}

	for _, tt := range errorTests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s should not be nil", tt.name)
			}
			if tt.err.Error() == "" {
				t.Errorf("%s should have error message", tt.name)
			}
		})
	}
}

// TestErrorWrapping tests error wrapping and unwrapping
func TestErrorWrapping(t *testing.T) {
	wrappedErr := errors.New("scanner nmap not found")

	if !errors.Is(wrappedErr, wrappedErr) {
		t.Error("errors.Is should work with wrapped errors")
	}
}

// TestOutputLineStructure tests OutputLine structure
func TestOutputLineStructure(t *testing.T) {
	now := time.Now()
	line := OutputLine{
		Content:   "test content",
		Timestamp: now,
		IsError:   false,
		Truncated: false,
	}

	if line.Content != "test content" {
		t.Errorf("OutputLine.Content = %q, want %q", line.Content, "test content")
	}
	if !line.Timestamp.Equal(now) {
		t.Error("OutputLine.Timestamp not preserved")
	}
	if line.IsError {
		t.Error("OutputLine.IsError should be false")
	}
	if line.Truncated {
		t.Error("OutputLine.Truncated should be false")
	}
}
