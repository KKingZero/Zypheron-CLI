package validation

import (
	"strings"
	"testing"
)

func TestValidateToolName(t *testing.T) {
	tests := []struct {
		name    string
		tool    string
		wantErr bool
	}{
		{"valid nmap", "nmap", false},
		{"valid nikto", "nikto", false},
		{"valid uppercase", "NMAP", false},
		{"invalid tool", "malicious", true},
		{"empty string", "", true},
		{"shell command", "nmap; rm -rf /", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateToolName(tt.tool)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateToolName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTarget(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"valid IP", "192.168.1.1", false},
		{"valid domain", "example.com", false},
		{"valid subdomain", "sub.example.com", false},
		{"valid URL", "https://example.com", false},
		{"valid CIDR", "192.168.1.0/24", false},
		{"command injection semicolon", "example.com; rm -rf /", true},
		{"command injection pipe", "example.com | cat /etc/passwd", true},
		{"command injection backtick", "example.com`whoami`", true},
		{"command injection dollar", "example.com$(whoami)", true},
		{"empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTarget(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTarget() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePorts(t *testing.T) {
	tests := []struct {
		name    string
		ports   string
		wantErr bool
	}{
		{"single port", "80", false},
		{"port range", "1-1000", false},
		{"multiple ports", "80,443,8080", false},
		{"multiple ranges", "1-100,200-300", false},
		{"max port", "65535", false},
		{"invalid port too high", "65536", true},
		{"invalid port zero", "0", true},
		{"invalid port negative", "-1", true},
		{"invalid range reversed", "1000-1", true},
		{"command injection", "80; rm -rf /", true},
		{"empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePorts(tt.ports)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePorts() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"clean input", "example.com", "example.com"},
		{"remove semicolon", "test;command", "testcommand"},
		{"remove pipe", "test|command", "testcommand"},
		{"remove backtick", "test`command`", "testcommand"},
		{"remove dollar", "test$command", "testcommand"},
		{"remove multiple", "test;rm|cat`whoami`", "testrmcatwhoami"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeInput(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeInput() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestValidateFilePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid relative path", "report.txt", false},
		{"valid absolute path", "/tmp/report.txt", false},
		{"path traversal", "../../../etc/passwd", true},
		{"null byte", "report\x00.txt", true},
		{"empty path", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFilePath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestContainsShellMetachars(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"clean input", "example.com", false},
		{"has semicolon", "test;command", true},
		{"has pipe", "test|command", true},
		{"has backtick", "test`command`", true},
		{"has ampersand", "test&command", true},
		{"has dollar", "test$VAR", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsShellMetachars(tt.input)
			if result != tt.expected {
				t.Errorf("containsShellMetachars() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsValidDomainOrURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"simple domain", "example.com", true},
		{"subdomain", "sub.example.com", true},
		{"http URL", "http://example.com", true},
		{"https URL", "https://example.com", true},
		{"URL with path", "https://example.com/path", true},
		{"URL with port", "example.com:8080", true},
		{"too long", strings.Repeat("a", 255), false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidDomainOrURL(tt.input)
			if result != tt.expected {
				t.Errorf("isValidDomainOrURL() = %v, want %v", result, tt.expected)
			}
		})
	}
}
