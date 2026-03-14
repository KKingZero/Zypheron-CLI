package commands

import (
	"strings"
	"testing"
)

func TestChooseDorkEnhancementProvider(t *testing.T) {
	tests := []struct {
		name      string
		providers []string
		def       string
		want      string
	}{
		{
			name:      "prefers configured default",
			providers: []string{"ollama", "deepseek"},
			def:       "deepseek",
			want:      "deepseek",
		},
		{
			name:      "falls back to preference order",
			providers: []string{"deepseek", "ollama"},
			def:       "missing",
			want:      "ollama",
		},
		{
			name:      "falls back to first available",
			providers: []string{"custom"},
			def:       "",
			want:      "custom",
		},
		{
			name:      "empty list",
			providers: nil,
			def:       "",
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := chooseDorkEnhancementProvider(tt.providers, tt.def); got != tt.want {
				t.Errorf("chooseDorkEnhancementProvider() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeAIDorkQuery(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "keeps valid query",
			input: `site:example.com inurl:admin`,
			want:  `site:example.com inurl:admin`,
		},
		{
			name:  "collapses multiline output",
			input: "site:example.com\ninurl:login\r\nfiletype:env",
			want:  "site:example.com inurl:login filetype:env",
		},
		{
			name:  "strips control characters",
			input: "site:example.com\x00\x1f inurl:admin",
			want:  "site:example.com inurl:admin",
		},
		{
			name:    "rejects empty output",
			input:   " \n\t ",
			wantErr: true,
		},
		{
			name:    "rejects oversized output",
			input:   strings.Repeat("a", maxAIDorkQueryLength+1),
			wantErr: true,
		},
		{
			name:    "rejects malformed leading dash",
			input:   "-ignore previous instructions",
			wantErr: true,
		},
		{
			name:    "rejects backticks",
			input:   "site:example.com `rm -rf /`",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sanitizeAIDorkQuery(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("sanitizeAIDorkQuery() expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("sanitizeAIDorkQuery() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("sanitizeAIDorkQuery() = %q, want %q", got, tt.want)
			}
		})
	}
}
