package commands

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ===== COMMAND CREATION TESTS =====

func TestDoctorCmd(t *testing.T) {
	cmd := DoctorCmd()

	if cmd == nil {
		t.Fatal("DoctorCmd() returned nil")
	}

	if cmd.Use != "doctor" {
		t.Errorf("Expected Use to be 'doctor', got '%s'", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Short description should not be empty")
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if cmd.RunE == nil {
		t.Error("RunE function should be set")
	}
}

func TestDoctorCmd_Flags(t *testing.T) {
	cmd := DoctorCmd()

	// Test JSON flag
	jsonFlag := cmd.Flags().Lookup("json")
	if jsonFlag == nil {
		t.Error("--json flag should be defined")
	}
	if jsonFlag.DefValue != "false" {
		t.Errorf("--json flag default should be false, got %s", jsonFlag.DefValue)
	}

	// Test verbose flag
	verboseFlag := cmd.Flags().Lookup("verbose")
	if verboseFlag == nil {
		t.Error("--verbose flag should be defined")
	}
	if verboseFlag.Shorthand != "v" {
		t.Errorf("--verbose shorthand should be 'v', got '%s'", verboseFlag.Shorthand)
	}
}

// ===== HEALTH CHECK TESTS =====

func TestCheckPython(t *testing.T) {
	tests := []struct {
		name        string
		verbose     bool
		wantStatus  string // Can be "ok", "warning", or "error"
		checkFields bool
	}{
		{
			name:        "check python non-verbose",
			verbose:     false,
			checkFields: true,
		},
		{
			name:        "check python verbose",
			verbose:     true,
			checkFields: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkPython(tt.verbose)

			// Verify required fields
			if result.Name != "Python" {
				t.Errorf("Expected Name to be 'Python', got '%s'", result.Name)
			}

			if result.Status == "" {
				t.Error("Status should not be empty")
			}

			validStatuses := map[string]bool{"ok": true, "warning": true, "error": true}
			if !validStatuses[result.Status] {
				t.Errorf("Invalid status: %s", result.Status)
			}

			if result.Message == "" {
				t.Error("Message should not be empty")
			}

			if result.DocURL == "" {
				t.Error("DocURL should not be empty")
			}

			// If verbose, details should be populated for successful checks
			if tt.verbose && result.Status == "ok" && result.Details == "" {
				t.Error("Details should be populated in verbose mode for successful checks")
			}
		})
	}
}

func TestCheckPythonDeps(t *testing.T) {
	tests := []struct {
		name    string
		verbose bool
	}{
		{"non-verbose", false},
		{"verbose", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkPythonDeps(tt.verbose)

			if result.Name != "Python Dependencies" {
				t.Errorf("Expected Name to be 'Python Dependencies', got '%s'", result.Name)
			}

			if result.Status == "" {
				t.Error("Status should not be empty")
			}

			if result.Message == "" {
				t.Error("Message should not be empty")
			}

			// If status is not ok, should have suggestion in details
			if result.Status != "ok" && result.Details == "" {
				t.Error("Non-OK status should include details with suggestions")
			}
		})
	}
}

func TestCheckAIEngine(t *testing.T) {
	tests := []struct {
		name    string
		verbose bool
	}{
		{"non-verbose", false},
		{"verbose", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkAIEngine(tt.verbose)

			if result.Name != "AI Engine" {
				t.Errorf("Expected Name to be 'AI Engine', got '%s'", result.Name)
			}

			if result.Status == "" {
				t.Error("Status should not be empty")
			}

			if result.Message == "" {
				t.Error("Message should not be empty")
			}

			// Typically will be "warning" when not running
			if result.Status == "warning" && result.Details == "" {
				t.Error("Warning status should include start instructions in details")
			}
		})
	}
}

func TestCheckSecurityTools(t *testing.T) {
	result := checkSecurityTools(false)

	if result.Name != "Security Tools" {
		t.Errorf("Expected Name to be 'Security Tools', got '%s'", result.Name)
	}

	if result.Status == "" {
		t.Error("Status should not be empty")
	}

	if result.Message == "" {
		t.Error("Message should not be empty")
	}

	// Message should contain tool count information
	if !strings.Contains(result.Message, "tool") {
		t.Error("Message should mention tools")
	}
}

func TestCheckConfigDir(t *testing.T) {
	result := checkConfigDir(false)

	if result.Name != "Configuration" {
		t.Errorf("Expected Name to be 'Configuration', got '%s'", result.Name)
	}

	if result.Status == "" {
		t.Error("Status should not be empty")
	}

	if result.Message == "" {
		t.Error("Message should not be empty")
	}

	// Should have a DocURL
	if result.DocURL == "" {
		t.Error("DocURL should not be empty")
	}
}

func TestCheckAPIKeys(t *testing.T) {
	// Save original env vars
	originalAnthropic := os.Getenv("ANTHROPIC_API_KEY")
	originalOpenAI := os.Getenv("OPENAI_API_KEY")
	originalGoogle := os.Getenv("GOOGLE_API_KEY")
	defer func() {
		os.Setenv("ANTHROPIC_API_KEY", originalAnthropic)
		os.Setenv("OPENAI_API_KEY", originalOpenAI)
		os.Setenv("GOOGLE_API_KEY", originalGoogle)
	}()

	tests := []struct {
		name       string
		setupEnv   func()
		wantStatus string
		wantInMsg  string
	}{
		{
			name: "no API keys",
			setupEnv: func() {
				os.Unsetenv("ANTHROPIC_API_KEY")
				os.Unsetenv("OPENAI_API_KEY")
				os.Unsetenv("GOOGLE_API_KEY")
			},
			wantStatus: "warning",
			wantInMsg:  "No API keys",
		},
		{
			name: "anthropic key set",
			setupEnv: func() {
				os.Setenv("ANTHROPIC_API_KEY", "test_key")
				os.Unsetenv("OPENAI_API_KEY")
				os.Unsetenv("GOOGLE_API_KEY")
			},
			wantStatus: "ok",
			wantInMsg:  "Claude",
		},
		{
			name: "multiple keys set",
			setupEnv: func() {
				os.Setenv("ANTHROPIC_API_KEY", "test_key1")
				os.Setenv("OPENAI_API_KEY", "test_key2")
				os.Unsetenv("GOOGLE_API_KEY")
			},
			wantStatus: "ok",
			wantInMsg:  "Configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv()
			result := checkAPIKeys(false)

			if result.Name != "API Keys" {
				t.Errorf("Expected Name to be 'API Keys', got '%s'", result.Name)
			}

			if result.Status != tt.wantStatus {
				t.Errorf("Expected status '%s', got '%s'", tt.wantStatus, result.Status)
			}

			if !strings.Contains(result.Message, tt.wantInMsg) {
				t.Errorf("Expected message to contain '%s', got '%s'", tt.wantInMsg, result.Message)
			}
		})
	}
}

func TestCheckNetworkConnectivity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	result := checkNetworkConnectivity(false)

	if result.Name != "Network" {
		t.Errorf("Expected Name to be 'Network', got '%s'", result.Name)
	}

	if result.Status == "" {
		t.Error("Status should not be empty")
	}

	if result.Message == "" {
		t.Error("Message should not be empty")
	}

	// In most environments this should work
	// Status should be either "ok" or "warning"
	validStatuses := map[string]bool{"ok": true, "warning": true}
	if !validStatuses[result.Status] {
		t.Errorf("Unexpected status for network check: %s", result.Status)
	}
}

func TestCheckDiskSpace(t *testing.T) {
	result := checkDiskSpace(false)

	if result.Name != "Disk Space" {
		t.Errorf("Expected Name to be 'Disk Space', got '%s'", result.Name)
	}

	if result.Status == "" {
		t.Error("Status should not be empty")
	}

	if result.Message == "" {
		t.Error("Message should not be empty")
	}

	// Should always return ok or warning (never error)
	if result.Status == "error" {
		t.Error("Disk space check should not return error status")
	}
}

// ===== STRUCT SERIALIZATION TESTS =====

func TestHealthCheck_Serialization(t *testing.T) {
	tests := []struct {
		name  string
		check HealthCheck
	}{
		{
			name: "complete health check",
			check: HealthCheck{
				Name:    "Test Check",
				Status:  "ok",
				Message: "Test message",
				Details: "Test details",
				DocURL:  "https://example.com",
			},
		},
		{
			name: "minimal health check",
			check: HealthCheck{
				Name:    "Minimal",
				Status:  "error",
				Message: "Error occurred",
			},
		},
		{
			name: "warning with details",
			check: HealthCheck{
				Name:    "Warning Check",
				Status:  "warning",
				Message: "Warning message",
				Details: "Run: some command",
				DocURL:  "https://docs.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := json.Marshal(tt.check)
			if err != nil {
				t.Fatalf("Failed to marshal HealthCheck: %v", err)
			}

			// Test deserialization
			var decoded HealthCheck
			err = json.Unmarshal(data, &decoded)
			if err != nil {
				t.Fatalf("Failed to unmarshal HealthCheck: %v", err)
			}

			// Verify fields
			if decoded.Name != tt.check.Name {
				t.Errorf("Name mismatch: got %s, want %s", decoded.Name, tt.check.Name)
			}
			if decoded.Status != tt.check.Status {
				t.Errorf("Status mismatch: got %s, want %s", decoded.Status, tt.check.Status)
			}
			if decoded.Message != tt.check.Message {
				t.Errorf("Message mismatch: got %s, want %s", decoded.Message, tt.check.Message)
			}
			if decoded.Details != tt.check.Details {
				t.Errorf("Details mismatch: got %s, want %s", decoded.Details, tt.check.Details)
			}
			if decoded.DocURL != tt.check.DocURL {
				t.Errorf("DocURL mismatch: got %s, want %s", decoded.DocURL, tt.check.DocURL)
			}
		})
	}
}

func TestDoctorReport_Serialization(t *testing.T) {
	now := time.Now()
	report := DoctorReport{
		Timestamp: now.Format(time.RFC3339),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		GoVersion: runtime.Version(),
		Checks: []HealthCheck{
			{
				Name:    "Check 1",
				Status:  "ok",
				Message: "All good",
			},
			{
				Name:    "Check 2",
				Status:  "warning",
				Message: "Minor issue",
				Details: "Fix with command X",
			},
			{
				Name:    "Check 3",
				Status:  "error",
				Message: "Critical issue",
				Details: "Install package Y",
				DocURL:  "https://docs.example.com",
			},
		},
		Summary: Summary{
			Total:    3,
			Passed:   1,
			Warnings: 1,
			Errors:   1,
		},
		Suggestions: []string{
			"Install Python 3.11+",
			"Start AI engine",
		},
	}

	// Test serialization
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Failed to marshal DoctorReport: %v", err)
	}

	// Test deserialization
	var decoded DoctorReport
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal DoctorReport: %v", err)
	}

	// Verify basic fields
	if decoded.OS != report.OS {
		t.Errorf("OS mismatch: got %s, want %s", decoded.OS, report.OS)
	}
	if decoded.Arch != report.Arch {
		t.Errorf("Arch mismatch: got %s, want %s", decoded.Arch, report.Arch)
	}

	// Verify checks count
	if len(decoded.Checks) != len(report.Checks) {
		t.Errorf("Checks count mismatch: got %d, want %d", len(decoded.Checks), len(report.Checks))
	}

	// Verify summary
	if decoded.Summary.Total != report.Summary.Total {
		t.Errorf("Total mismatch: got %d, want %d", decoded.Summary.Total, report.Summary.Total)
	}
	if decoded.Summary.Passed != report.Summary.Passed {
		t.Errorf("Passed mismatch: got %d, want %d", decoded.Summary.Passed, report.Summary.Passed)
	}
	if decoded.Summary.Warnings != report.Summary.Warnings {
		t.Errorf("Warnings mismatch: got %d, want %d", decoded.Summary.Warnings, report.Summary.Warnings)
	}
	if decoded.Summary.Errors != report.Summary.Errors {
		t.Errorf("Errors mismatch: got %d, want %d", decoded.Summary.Errors, report.Summary.Errors)
	}

	// Verify suggestions
	if len(decoded.Suggestions) != len(report.Suggestions) {
		t.Errorf("Suggestions count mismatch: got %d, want %d", len(decoded.Suggestions), len(report.Suggestions))
	}
}

func TestSummary_Serialization(t *testing.T) {
	summary := Summary{
		Total:    10,
		Passed:   7,
		Warnings: 2,
		Errors:   1,
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("Failed to marshal Summary: %v", err)
	}

	var decoded Summary
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal Summary: %v", err)
	}

	if decoded.Total != summary.Total {
		t.Errorf("Total mismatch: got %d, want %d", decoded.Total, summary.Total)
	}
	if decoded.Passed != summary.Passed {
		t.Errorf("Passed mismatch: got %d, want %d", decoded.Passed, summary.Passed)
	}
	if decoded.Warnings != summary.Warnings {
		t.Errorf("Warnings mismatch: got %d, want %d", decoded.Warnings, summary.Warnings)
	}
	if decoded.Errors != summary.Errors {
		t.Errorf("Errors mismatch: got %d, want %d", decoded.Errors, summary.Errors)
	}
}

// ===== SUGGESTION GENERATION TESTS =====

func TestGenerateSuggestions(t *testing.T) {
	tests := []struct {
		name            string
		checks          []HealthCheck
		wantSuggestions int
		wantContains    []string
	}{
		{
			name: "python error",
			checks: []HealthCheck{
				{Name: "Python", Status: "error"},
			},
			wantSuggestions: 1,
			wantContains:    []string{"Python"},
		},
		{
			name: "python deps error",
			checks: []HealthCheck{
				{Name: "Python Dependencies", Status: "error"},
			},
			wantSuggestions: 1,
			wantContains:    []string{"dependencies"},
		},
		{
			name: "security tools error",
			checks: []HealthCheck{
				{Name: "Security Tools", Status: "error"},
			},
			wantSuggestions: 1,
			wantContains:    []string{"tools"},
		},
		{
			name: "AI engine warning",
			checks: []HealthCheck{
				{Name: "AI Engine", Status: "warning"},
			},
			wantSuggestions: 1,
			wantContains:    []string{"AI engine"},
		},
		{
			name: "config warning",
			checks: []HealthCheck{
				{Name: "Configuration", Status: "warning"},
			},
			wantSuggestions: 1,
			wantContains:    []string{"setup"},
		},
		{
			name: "API keys warning",
			checks: []HealthCheck{
				{Name: "API Keys", Status: "warning"},
			},
			wantSuggestions: 1,
			wantContains:    []string{"config"},
		},
		{
			name: "multiple issues",
			checks: []HealthCheck{
				{Name: "Python", Status: "error"},
				{Name: "AI Engine", Status: "warning"},
				{Name: "Network", Status: "ok"},
			},
			wantSuggestions: 2,
		},
		{
			name: "all ok",
			checks: []HealthCheck{
				{Name: "Python", Status: "ok"},
				{Name: "AI Engine", Status: "ok"},
				{Name: "Network", Status: "ok"},
			},
			wantSuggestions: 0,
		},
		{
			name:            "no checks",
			checks:          []HealthCheck{},
			wantSuggestions: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suggestions := generateSuggestions(tt.checks)

			if len(suggestions) != tt.wantSuggestions {
				t.Errorf("Expected %d suggestions, got %d", tt.wantSuggestions, len(suggestions))
			}

			// Check for expected content
			for _, want := range tt.wantContains {
				found := false
				for _, suggestion := range suggestions {
					if strings.Contains(strings.ToLower(suggestion), strings.ToLower(want)) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected to find suggestion containing '%s', got: %v", want, suggestions)
				}
			}
		})
	}
}

func TestGenerateSuggestions_NoUnknownChecks(t *testing.T) {
	// Test that unknown check names don't generate suggestions
	checks := []HealthCheck{
		{Name: "Unknown Check", Status: "error"},
		{Name: "Another Unknown", Status: "warning"},
	}

	suggestions := generateSuggestions(checks)

	if len(suggestions) != 0 {
		t.Errorf("Unknown checks should not generate suggestions, got %d", len(suggestions))
	}
}

// ===== EDGE CASE TESTS =====

func TestHealthCheck_EmptyFields(t *testing.T) {
	check := HealthCheck{}

	data, err := json.Marshal(check)
	if err != nil {
		t.Fatalf("Failed to marshal empty HealthCheck: %v", err)
	}

	var decoded HealthCheck
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal empty HealthCheck: %v", err)
	}
}

func TestDoctorReport_EmptyChecks(t *testing.T) {
	report := DoctorReport{
		Timestamp: time.Now().Format(time.RFC3339),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		GoVersion: runtime.Version(),
		Checks:    []HealthCheck{},
		Summary: Summary{
			Total: 0,
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Failed to marshal empty report: %v", err)
	}

	var decoded DoctorReport
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal empty report: %v", err)
	}

	if len(decoded.Checks) != 0 {
		t.Errorf("Expected 0 checks, got %d", len(decoded.Checks))
	}
}

// ===== BENCHMARK TESTS =====

func BenchmarkCheckPython(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = checkPython(false)
	}
}

func BenchmarkCheckPythonDeps(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = checkPythonDeps(false)
	}
}

func BenchmarkCheckAIEngine(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = checkAIEngine(false)
	}
}

func BenchmarkCheckSecurityTools(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = checkSecurityTools(false)
	}
}

func BenchmarkCheckConfigDir(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = checkConfigDir(false)
	}
}

func BenchmarkCheckAPIKeys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = checkAPIKeys(false)
	}
}

func BenchmarkCheckDiskSpace(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = checkDiskSpace(false)
	}
}

func BenchmarkGenerateSuggestions(b *testing.B) {
	checks := []HealthCheck{
		{Name: "Python", Status: "error"},
		{Name: "AI Engine", Status: "warning"},
		{Name: "Network", Status: "ok"},
		{Name: "Python Dependencies", Status: "error"},
		{Name: "Security Tools", Status: "warning"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = generateSuggestions(checks)
	}
}

func BenchmarkHealthCheckSerialization(b *testing.B) {
	check := HealthCheck{
		Name:    "Test Check",
		Status:  "ok",
		Message: "All systems operational",
		Details: "Python 3.11.5 installed at /usr/bin/python3",
		DocURL:  "https://docs.example.com/python",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := json.Marshal(check)
		if err != nil {
			b.Fatal(err)
		}

		var decoded HealthCheck
		err = json.Unmarshal(data, &decoded)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDoctorReportSerialization(b *testing.B) {
	report := DoctorReport{
		Timestamp: time.Now().Format(time.RFC3339),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		GoVersion: runtime.Version(),
		Checks: []HealthCheck{
			{Name: "Check 1", Status: "ok", Message: "Good"},
			{Name: "Check 2", Status: "warning", Message: "Warning", Details: "Details"},
			{Name: "Check 3", Status: "error", Message: "Error", DocURL: "https://example.com"},
		},
		Summary: Summary{
			Total:    3,
			Passed:   1,
			Warnings: 1,
			Errors:   1,
		},
		Suggestions: []string{"Suggestion 1", "Suggestion 2"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := json.Marshal(report)
		if err != nil {
			b.Fatal(err)
		}

		var decoded DoctorReport
		err = json.Unmarshal(data, &decoded)
		if err != nil {
			b.Fatal(err)
		}
	}
}
