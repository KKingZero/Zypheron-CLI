package ui

import (
	"errors"
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestGetDocsURL(t *testing.T) {
	tests := []struct {
		name     string
		topic    string
		expected string
	}{
		{"setup topic", "setup", "https://docs.zypheron.io/getting-started/setup"},
		{"python topic", "python", "https://docs.zypheron.io/setup/python"},
		{"api-keys topic", "api-keys", "https://docs.zypheron.io/configuration/api-keys"},
		{"ai-engine topic", "ai-engine", "https://docs.zypheron.io/ai/engine"},
		{"tools topic", "tools", "https://docs.zypheron.io/tools/installation"},
		{"unknown topic", "nonexistent", "https://docs.zypheron.io/troubleshooting"},
		{"empty topic", "", "https://docs.zypheron.io/troubleshooting"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetDocsURL(tt.topic)
			if result != tt.expected {
				t.Errorf("GetDocsURL(%q) = %q, want %q", tt.topic, result, tt.expected)
			}
		})
	}
}

func TestErrorWithSuggestion(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name           string
		message        string
		suggestion     string
		wantMessage    string
		wantSuggestion string
	}{
		{
			name:           "with suggestion",
			message:        "Connection failed",
			suggestion:     "Check your network connection",
			wantMessage:    "Connection failed",
			wantSuggestion: "Check your network connection",
		},
		{
			name:           "empty suggestion",
			message:        "Error occurred",
			suggestion:     "",
			wantMessage:    "Error occurred",
			wantSuggestion: "",
		},
		{
			name:           "long suggestion",
			message:        "Build failed",
			suggestion:     "Try running 'go mod tidy' and then rebuild the project",
			wantMessage:    "Build failed",
			wantSuggestion: "go mod tidy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ErrorWithSuggestion(tt.message, tt.suggestion)

			if !strings.Contains(result, tt.wantMessage) {
				t.Errorf("ErrorWithSuggestion() = %q, want to contain %q", result, tt.wantMessage)
			}

			if tt.suggestion != "" {
				if !strings.Contains(result, "Tip:") {
					t.Errorf("ErrorWithSuggestion() = %q, want to contain 'Tip:'", result)
				}
				if !strings.Contains(result, tt.wantSuggestion) {
					t.Errorf("ErrorWithSuggestion() = %q, want to contain %q", result, tt.wantSuggestion)
				}
			} else {
				if strings.Contains(result, "Tip:") {
					t.Errorf("ErrorWithSuggestion() with empty suggestion should not contain 'Tip:'")
				}
			}
		})
	}
}

func TestErrorWithCommand(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name        string
		message     string
		command     string
		wantCommand string
	}{
		{
			name:        "simple command",
			message:     "Tool not found",
			command:     "zypheron tools install nmap",
			wantCommand: "zypheron tools install nmap",
		},
		{
			name:        "command with flags",
			message:     "Configuration missing",
			command:     "zypheron config --reset",
			wantCommand: "zypheron config --reset",
		},
		{
			name:        "empty command",
			message:     "Error",
			command:     "",
			wantCommand: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ErrorWithCommand(tt.message, tt.command)

			if !strings.Contains(result, tt.message) {
				t.Errorf("ErrorWithCommand() = %q, want to contain %q", result, tt.message)
			}

			if tt.command != "" {
				if !strings.Contains(result, "Try:") {
					t.Errorf("ErrorWithCommand() = %q, want to contain 'Try:'", result)
				}
				if !strings.Contains(result, tt.wantCommand) {
					t.Errorf("ErrorWithCommand() = %q, want to contain %q", result, tt.wantCommand)
				}
			}
		})
	}
}

func TestErrorWithDocs(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name        string
		message     string
		topic       string
		wantDocsURL string
	}{
		{
			name:        "setup docs",
			message:     "Setup failed",
			topic:       "setup",
			wantDocsURL: "https://docs.zypheron.io/getting-started/setup",
		},
		{
			name:        "api-keys docs",
			message:     "API key missing",
			topic:       "api-keys",
			wantDocsURL: "https://docs.zypheron.io/configuration/api-keys",
		},
		{
			name:        "unknown topic defaults to troubleshooting",
			message:     "Unknown error",
			topic:       "invalid-topic",
			wantDocsURL: "https://docs.zypheron.io/troubleshooting",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ErrorWithDocs(tt.message, tt.topic)

			if !strings.Contains(result, tt.message) {
				t.Errorf("ErrorWithDocs() = %q, want to contain %q", result, tt.message)
			}

			if !strings.Contains(result, "Documentation:") {
				t.Errorf("ErrorWithDocs() = %q, want to contain 'Documentation:'", result)
			}

			if !strings.Contains(result, tt.wantDocsURL) {
				t.Errorf("ErrorWithDocs() = %q, want to contain %q", result, tt.wantDocsURL)
			}
		})
	}
}

func TestErrorWithCommandAndDocs(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name        string
		message     string
		command     string
		topic       string
		wantCommand string
		wantDocsURL string
	}{
		{
			name:        "complete error",
			message:     "Installation failed",
			command:     "zypheron setup",
			topic:       "setup",
			wantCommand: "zypheron setup",
			wantDocsURL: "https://docs.zypheron.io/getting-started/setup",
		},
		{
			name:        "with multiple flags",
			message:     "Scan error",
			command:     "zypheron scan --target 192.168.1.1 --verbose",
			topic:       "scan",
			wantCommand: "zypheron scan",
			wantDocsURL: "https://docs.zypheron.io/commands/scan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ErrorWithCommandAndDocs(tt.message, tt.command, tt.topic)

			if !strings.Contains(result, tt.message) {
				t.Errorf("ErrorWithCommandAndDocs() = %q, want to contain %q", result, tt.message)
			}

			if !strings.Contains(result, "Try:") {
				t.Errorf("ErrorWithCommandAndDocs() = %q, want to contain 'Try:'", result)
			}

			if !strings.Contains(result, tt.wantCommand) {
				t.Errorf("ErrorWithCommandAndDocs() = %q, want to contain %q", result, tt.wantCommand)
			}

			if !strings.Contains(result, "Docs:") {
				t.Errorf("ErrorWithCommandAndDocs() = %q, want to contain 'Docs:'", result)
			}

			if !strings.Contains(result, tt.wantDocsURL) {
				t.Errorf("ErrorWithCommandAndDocs() = %q, want to contain %q", result, tt.wantDocsURL)
			}
		})
	}
}

func TestValidationError(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name     string
		field    string
		reason   string
		examples []string
	}{
		{
			name:     "no examples",
			field:    "email",
			reason:   "invalid format",
			examples: nil,
		},
		{
			name:     "single example",
			field:    "port",
			reason:   "must be between 1-65535",
			examples: []string{"80"},
		},
		{
			name:   "multiple examples",
			field:  "target",
			reason: "invalid target format",
			examples: []string{
				"192.168.1.1",
				"example.com",
				"https://example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidationError(tt.field, tt.reason, tt.examples...)

			if !strings.Contains(result, tt.field) {
				t.Errorf("ValidationError() = %q, want to contain field %q", result, tt.field)
			}

			if !strings.Contains(result, tt.reason) {
				t.Errorf("ValidationError() = %q, want to contain reason %q", result, tt.reason)
			}

			if len(tt.examples) > 0 {
				if !strings.Contains(result, "Examples:") {
					t.Errorf("ValidationError() = %q, want to contain 'Examples:'", result)
				}

				for _, ex := range tt.examples {
					if !strings.Contains(result, ex) {
						t.Errorf("ValidationError() = %q, want to contain example %q", result, ex)
					}
				}
			}
		})
	}
}

func TestValidationErrorWithDocs(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name     string
		field    string
		reason   string
		topic    string
		examples []string
		wantURL  string
	}{
		{
			name:     "with docs link",
			field:    "API key",
			reason:   "invalid format",
			topic:    "api-keys",
			examples: []string{"sk-1234567890abcdef"},
			wantURL:  "https://docs.zypheron.io/configuration/api-keys",
		},
		{
			name:     "no examples",
			field:    "config",
			reason:   "missing required field",
			topic:    "configuration",
			examples: nil,
			wantURL:  "https://docs.zypheron.io/configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidationErrorWithDocs(tt.field, tt.reason, tt.topic, tt.examples...)

			if !strings.Contains(result, tt.field) {
				t.Errorf("ValidationErrorWithDocs() = %q, want to contain field %q", result, tt.field)
			}

			if !strings.Contains(result, tt.reason) {
				t.Errorf("ValidationErrorWithDocs() = %q, want to contain reason %q", result, tt.reason)
			}

			if !strings.Contains(result, "Docs:") {
				t.Errorf("ValidationErrorWithDocs() = %q, want to contain 'Docs:'", result)
			}

			if !strings.Contains(result, tt.wantURL) {
				t.Errorf("ValidationErrorWithDocs() = %q, want to contain URL %q", result, tt.wantURL)
			}
		})
	}
}

func TestErrorWithHelp(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name        string
		message     string
		helpCommand string
	}{
		{
			name:        "scan help",
			message:     "Invalid scan options",
			helpCommand: "zypheron scan --help",
		},
		{
			name:        "config help",
			message:     "Configuration error",
			helpCommand: "zypheron config --help",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ErrorWithHelp(tt.message, tt.helpCommand)

			if !strings.Contains(result, tt.message) {
				t.Errorf("ErrorWithHelp() = %q, want to contain %q", result, tt.message)
			}

			if !strings.Contains(result, "For more information, run:") {
				t.Errorf("ErrorWithHelp() = %q, want to contain help prompt", result)
			}

			if !strings.Contains(result, tt.helpCommand) {
				t.Errorf("ErrorWithHelp() = %q, want to contain %q", result, tt.helpCommand)
			}
		})
	}
}

func TestWrapError(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name        string
		context     string
		err         error
		wantContext string
		wantErr     string
	}{
		{
			name:        "with error",
			context:     "Failed to connect",
			err:         errors.New("connection timeout"),
			wantContext: "Failed to connect",
			wantErr:     "connection timeout",
		},
		{
			name:        "nil error",
			context:     "Operation failed",
			err:         nil,
			wantContext: "Operation failed",
			wantErr:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WrapError(tt.context, tt.err)

			if !strings.Contains(result, tt.wantContext) {
				t.Errorf("WrapError() = %q, want to contain %q", result, tt.wantContext)
			}

			if tt.err != nil && !strings.Contains(result, tt.wantErr) {
				t.Errorf("WrapError() = %q, want to contain %q", result, tt.wantErr)
			}
		})
	}
}

func TestWrapErrorWithDocs(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name        string
		context     string
		err         error
		topic       string
		wantContext string
		wantURL     string
	}{
		{
			name:        "network error with docs",
			context:     "Network request failed",
			err:         errors.New("timeout"),
			topic:       "network",
			wantContext: "Network request failed",
			wantURL:     "https://docs.zypheron.io/troubleshooting/network",
		},
		{
			name:        "nil error with docs",
			context:     "Configuration issue",
			err:         nil,
			topic:       "configuration",
			wantContext: "Configuration issue",
			wantURL:     "https://docs.zypheron.io/configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WrapErrorWithDocs(tt.context, tt.err, tt.topic)

			if !strings.Contains(result, tt.wantContext) {
				t.Errorf("WrapErrorWithDocs() = %q, want to contain %q", result, tt.wantContext)
			}

			if !strings.Contains(result, "Docs:") {
				t.Errorf("WrapErrorWithDocs() = %q, want to contain 'Docs:'", result)
			}

			if !strings.Contains(result, tt.wantURL) {
				t.Errorf("WrapErrorWithDocs() = %q, want to contain %q", result, tt.wantURL)
			}
		})
	}
}

func TestErrorWithRecovery(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name        string
		message     string
		steps       []string
		wantMessage string
		wantSteps   []string
	}{
		{
			name:        "no steps",
			message:     "Installation failed",
			steps:       nil,
			wantMessage: "Installation failed",
			wantSteps:   nil,
		},
		{
			name:        "single step",
			message:     "Permission denied",
			steps:       []string{"Run with sudo"},
			wantMessage: "Permission denied",
			wantSteps:   []string{"Run with sudo"},
		},
		{
			name:    "multiple steps",
			message: "Build failed",
			steps: []string{
				"Clear build cache",
				"Update dependencies",
				"Rebuild project",
			},
			wantMessage: "Build failed",
			wantSteps: []string{
				"Clear build cache",
				"Update dependencies",
				"Rebuild project",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ErrorWithRecovery(tt.message, tt.steps...)

			if !strings.Contains(result, tt.wantMessage) {
				t.Errorf("ErrorWithRecovery() = %q, want to contain %q", result, tt.wantMessage)
			}

			if len(tt.steps) > 0 {
				if !strings.Contains(result, "To resolve:") {
					t.Errorf("ErrorWithRecovery() = %q, want to contain 'To resolve:'", result)
				}

				for i, step := range tt.wantSteps {
					if !strings.Contains(result, step) {
						t.Errorf("ErrorWithRecovery() = %q, want to contain step %q", result, step)
					}
					// Check for step numbering
					stepNum := string(rune('0' + i + 1))
					if !strings.Contains(result, stepNum+".") {
						t.Errorf("ErrorWithRecovery() = %q, want to contain step number %s", result, stepNum)
					}
				}
			}
		})
	}
}

func TestErrorWithRecoveryAndDocs(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name    string
		message string
		topic   string
		steps   []string
		wantURL string
	}{
		{
			name:    "with recovery and docs",
			message: "Python not found",
			topic:   "python",
			steps: []string{
				"Install Python 3.8+",
				"Add Python to PATH",
			},
			wantURL: "https://docs.zypheron.io/setup/python",
		},
		{
			name:    "no steps with docs",
			message: "Setup incomplete",
			topic:   "setup",
			steps:   nil,
			wantURL: "https://docs.zypheron.io/getting-started/setup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ErrorWithRecoveryAndDocs(tt.message, tt.topic, tt.steps...)

			if !strings.Contains(result, tt.message) {
				t.Errorf("ErrorWithRecoveryAndDocs() = %q, want to contain %q", result, tt.message)
			}

			if !strings.Contains(result, "Documentation:") {
				t.Errorf("ErrorWithRecoveryAndDocs() = %q, want to contain 'Documentation:'", result)
			}

			if !strings.Contains(result, tt.wantURL) {
				t.Errorf("ErrorWithRecoveryAndDocs() = %q, want to contain %q", result, tt.wantURL)
			}

			if len(tt.steps) > 0 {
				if !strings.Contains(result, "To resolve:") {
					t.Errorf("ErrorWithRecoveryAndDocs() = %q, want to contain 'To resolve:'", result)
				}
			}
		})
	}
}

func TestToolNotFoundError(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name     string
		toolName string
	}{
		{"nmap", "nmap"},
		{"nikto", "nikto"},
		{"metasploit", "metasploit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToolNotFoundError(tt.toolName)

			if !strings.Contains(result, tt.toolName) {
				t.Errorf("ToolNotFoundError(%q) = %q, want to contain %q", tt.toolName, result, tt.toolName)
			}

			if !strings.Contains(result, "not installed") {
				t.Errorf("ToolNotFoundError(%q) = %q, want to contain 'not installed'", tt.toolName, result)
			}

			if !strings.Contains(result, "To resolve:") {
				t.Errorf("ToolNotFoundError(%q) = %q, want to contain 'To resolve:'", tt.toolName, result)
			}

			if !strings.Contains(result, "zypheron tools install") {
				t.Errorf("ToolNotFoundError(%q) = %q, want to contain install command", tt.toolName, result)
			}

			if !strings.Contains(result, "Documentation:") {
				t.Errorf("ToolNotFoundError(%q) = %q, want to contain 'Documentation:'", tt.toolName, result)
			}

			if !strings.Contains(result, "https://docs.zypheron.io/tools/installation") {
				t.Errorf("ToolNotFoundError(%q) = %q, want to contain tools docs URL", tt.toolName, result)
			}
		})
	}
}

func TestAIEngineError(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name    string
		details string
	}{
		{"connection failed", "connection timeout"},
		{"service unavailable", "service is not running"},
		{"model error", "model not loaded"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AIEngineError(tt.details)

			if !strings.Contains(result, "AI Engine error") {
				t.Errorf("AIEngineError(%q) = %q, want to contain 'AI Engine error'", tt.details, result)
			}

			if !strings.Contains(result, tt.details) {
				t.Errorf("AIEngineError(%q) = %q, want to contain %q", tt.details, result, tt.details)
			}

			if !strings.Contains(result, "To resolve:") {
				t.Errorf("AIEngineError(%q) = %q, want to contain 'To resolve:'", tt.details, result)
			}

			if !strings.Contains(result, "zypheron ai start") {
				t.Errorf("AIEngineError(%q) = %q, want to contain start command", tt.details, result)
			}

			if !strings.Contains(result, "Documentation:") {
				t.Errorf("AIEngineError(%q) = %q, want to contain 'Documentation:'", tt.details, result)
			}

			if !strings.Contains(result, "https://docs.zypheron.io/ai/engine") {
				t.Errorf("AIEngineError(%q) = %q, want to contain AI engine docs URL", tt.details, result)
			}
		})
	}
}

func TestConfigError(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name    string
		details string
	}{
		{"missing file", "config file not found"},
		{"parse error", "invalid JSON format"},
		{"validation error", "required field missing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConfigError(tt.details)

			if !strings.Contains(result, "Configuration error") {
				t.Errorf("ConfigError(%q) = %q, want to contain 'Configuration error'", tt.details, result)
			}

			if !strings.Contains(result, tt.details) {
				t.Errorf("ConfigError(%q) = %q, want to contain %q", tt.details, result, tt.details)
			}

			if !strings.Contains(result, "To resolve:") {
				t.Errorf("ConfigError(%q) = %q, want to contain 'To resolve:'", tt.details, result)
			}

			if !strings.Contains(result, "zypheron setup") {
				t.Errorf("ConfigError(%q) = %q, want to contain setup command", tt.details, result)
			}

			if !strings.Contains(result, "Documentation:") {
				t.Errorf("ConfigError(%q) = %q, want to contain 'Documentation:'", tt.details, result)
			}

			if !strings.Contains(result, "https://docs.zypheron.io/configuration") {
				t.Errorf("ConfigError(%q) = %q, want to contain configuration docs URL", tt.details, result)
			}
		})
	}
}

func TestAPIKeyError(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	tests := []struct {
		name     string
		provider string
	}{
		{"openai", "openai"},
		{"anthropic", "anthropic"},
		{"google", "google"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := APIKeyError(tt.provider)

			if !strings.Contains(result, "API key not configured") {
				t.Errorf("APIKeyError(%q) = %q, want to contain 'API key not configured'", tt.provider, result)
			}

			if !strings.Contains(result, tt.provider) {
				t.Errorf("APIKeyError(%q) = %q, want to contain %q", tt.provider, result, tt.provider)
			}

			if !strings.Contains(result, "To resolve:") {
				t.Errorf("APIKeyError(%q) = %q, want to contain 'To resolve:'", tt.provider, result)
			}

			if !strings.Contains(result, "zypheron config set-key") {
				t.Errorf("APIKeyError(%q) = %q, want to contain set-key command", tt.provider, result)
			}

			if !strings.Contains(result, "Documentation:") {
				t.Errorf("APIKeyError(%q) = %q, want to contain 'Documentation:'", tt.provider, result)
			}

			if !strings.Contains(result, "https://docs.zypheron.io/configuration/api-keys") {
				t.Errorf("APIKeyError(%q) = %q, want to contain API keys docs URL", tt.provider, result)
			}
		})
	}
}

// Edge case tests

func TestErrorFunctionsWithEmptyStrings(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	t.Run("ErrorWithSuggestion empty message", func(t *testing.T) {
		result := ErrorWithSuggestion("", "suggestion")
		if result == "" {
			t.Error("ErrorWithSuggestion with empty message returned empty string")
		}
	})

	t.Run("ErrorWithCommand empty message", func(t *testing.T) {
		result := ErrorWithCommand("", "command")
		if result == "" {
			t.Error("ErrorWithCommand with empty message returned empty string")
		}
	})

	t.Run("ValidationError empty field", func(t *testing.T) {
		result := ValidationError("", "reason")
		if result == "" {
			t.Error("ValidationError with empty field returned empty string")
		}
	})

	t.Run("ToolNotFoundError empty tool", func(t *testing.T) {
		result := ToolNotFoundError("")
		if result == "" {
			t.Error("ToolNotFoundError with empty tool returned empty string")
		}
	})
}

func TestErrorFunctionsWithSpecialCharacters(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	specialChars := "Test\nwith\ttabs\rand\nnewlines"

	t.Run("ErrorWithSuggestion with special chars", func(t *testing.T) {
		result := ErrorWithSuggestion(specialChars, "suggestion")
		if !strings.Contains(result, "Test") {
			t.Error("ErrorWithSuggestion lost content with special characters")
		}
	})

	t.Run("ValidationError with special chars in examples", func(t *testing.T) {
		result := ValidationError("field", "reason", specialChars)
		if !strings.Contains(result, "Examples:") {
			t.Error("ValidationError lost examples with special characters")
		}
	})
}

// Benchmark tests for error formatting functions

func BenchmarkErrorWithSuggestion(b *testing.B) {
	msg := "Connection failed"
	suggestion := "Check your network connection"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ErrorWithSuggestion(msg, suggestion)
	}
}

func BenchmarkErrorWithCommand(b *testing.B) {
	msg := "Tool not found"
	cmd := "zypheron tools install nmap"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ErrorWithCommand(msg, cmd)
	}
}

func BenchmarkErrorWithDocs(b *testing.B) {
	msg := "Setup failed"
	topic := "setup"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ErrorWithDocs(msg, topic)
	}
}

func BenchmarkErrorWithCommandAndDocs(b *testing.B) {
	msg := "Installation failed"
	cmd := "zypheron setup"
	topic := "setup"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ErrorWithCommandAndDocs(msg, cmd, topic)
	}
}

func BenchmarkValidationError(b *testing.B) {
	field := "email"
	reason := "invalid format"
	examples := []string{"user@example.com", "test@test.org"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidationError(field, reason, examples...)
	}
}

func BenchmarkErrorWithRecovery(b *testing.B) {
	msg := "Build failed"
	steps := []string{
		"Clear build cache",
		"Update dependencies",
		"Rebuild project",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ErrorWithRecovery(msg, steps...)
	}
}

func BenchmarkToolNotFoundError(b *testing.B) {
	toolName := "nmap"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ToolNotFoundError(toolName)
	}
}

func BenchmarkAIEngineError(b *testing.B) {
	details := "connection timeout"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AIEngineError(details)
	}
}

func BenchmarkConfigError(b *testing.B) {
	details := "config file not found"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ConfigError(details)
	}
}

func BenchmarkAPIKeyError(b *testing.B) {
	provider := "openai"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = APIKeyError(provider)
	}
}

func BenchmarkWrapError(b *testing.B) {
	context := "Failed to connect"
	err := errors.New("connection timeout")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = WrapError(context, err)
	}
}

func BenchmarkGetDocsURL(b *testing.B) {
	topic := "setup"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetDocsURL(topic)
	}
}
