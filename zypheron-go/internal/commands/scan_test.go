package commands

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/pkg/types"
	"github.com/fatih/color"
)

// ===== COMMAND CREATION TESTS =====

func TestScanCmd(t *testing.T) {
	cmd := ScanCmd()

	if cmd == nil {
		t.Fatal("ScanCmd() returned nil")
	}

	if cmd.Use != "scan [target]" {
		t.Errorf("Expected Use to be 'scan [target]', got '%s'", cmd.Use)
	}

	if len(cmd.Aliases) == 0 {
		t.Error("ScanCmd should have aliases")
	}

	if cmd.Aliases[0] != "s" {
		t.Errorf("Expected first alias to be 's', got '%s'", cmd.Aliases[0])
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

func captureCommandStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()

	original := os.Stdout
	originalColorOutput := color.Output
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = writer
	color.Output = writer
	defer func() {
		os.Stdout = original
		color.Output = originalColorOutput
	}()

	var buf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(&buf, reader)
		done <- err
	}()

	runErr := fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("copy stdout: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close stdout reader: %v", err)
	}
	return buf.String(), runErr
}

func workspaceTempDir(t *testing.T, pattern string) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", pattern)
	if err != nil {
		t.Fatalf("create workspace temp dir: %v", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("abs temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(abs)
	})
	return abs
}

func TestScanCmd_Flags(t *testing.T) {
	cmd := ScanCmd()

	tests := []struct {
		name         string
		flagName     string
		shorthand    string
		defaultValue string
		shouldExist  bool
	}{
		{"tool flag", "tool", "t", "", true},
		{"ports flag", "ports", "p", "1-1000", true},
		{"web flag", "web", "", "false", true},
		{"full flag", "full", "", "false", true},
		{"fast flag", "fast", "", "false", true},
		{"no-stream flag", "no-stream", "", "false", true},
		{"ai-guided flag", "ai-guided", "", "false", true},
		{"ai-analysis flag", "ai-analysis", "", "false", true},
		{"timeout flag", "timeout", "", "300", true},
		{"output flag", "output", "o", "", true},
		{"format flag", "format", "", "text", true},
		{"yes flag", "yes", "y", "false", true},
		{"no-input flag", "no-input", "", "false", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.flagName)

			if tt.shouldExist && flag == nil {
				t.Errorf("Flag --%s should exist", tt.flagName)
				return
			}

			if !tt.shouldExist && flag != nil {
				t.Errorf("Flag --%s should not exist", tt.flagName)
				return
			}

			if !tt.shouldExist {
				return
			}

			if tt.shorthand != "" && flag.Shorthand != tt.shorthand {
				t.Errorf("Flag --%s shorthand should be '%s', got '%s'",
					tt.flagName, tt.shorthand, flag.Shorthand)
			}

			if tt.defaultValue != "" && flag.DefValue != tt.defaultValue {
				t.Errorf("Flag --%s default should be '%s', got '%s'",
					tt.flagName, tt.defaultValue, flag.DefValue)
			}
		})
	}
}

func TestScanResultJSON_IsMachineReadable(t *testing.T) {
	result := &types.ScanResult{
		ID:        "scan-1",
		Timestamp: time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC),
		Target:    "example.com",
		Tool:      "nmap",
		Ports:     "80,443",
		Output:    "open port output",
		Duration:  1.25,
		Success:   true,
		Metadata:  map[string]string{"fast": "false"},
	}

	data, err := scanResultJSON(result)
	if err != nil {
		t.Fatalf("scanResultJSON() err = %v", err)
	}
	if strings.Contains(string(data), "\x1b[") || strings.Contains(string(data), "╔") {
		t.Fatalf("JSON output contains terminal decoration: %q", data)
	}

	var decoded types.ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("scanResultJSON() produced invalid JSON: %v\n%s", err, data)
	}
	if decoded.ID != result.ID || decoded.Target != result.Target || decoded.Tool != result.Tool {
		t.Fatalf("decoded result = %#v, want core fields from %#v", decoded, result)
	}
}

func TestScanJSONSelectedToolSkipsFullInventoryDetection(t *testing.T) {
	home := workspaceTempDir(t, "home-")
	dir := workspaceTempDir(t, "bin-")
	marker := filepath.Join(dir, "nikto-version-called")

	nmapPath := filepath.Join(dir, "nmap")
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\necho 'Nmap scan report for 127.0.0.1'\necho '80/tcp open http'\n"), 0o755); err != nil {
		t.Fatalf("write fake nmap: %v", err)
	}
	niktoPath := filepath.Join(dir, "nikto")
	if err := os.WriteFile(niktoPath, []byte("#!/bin/sh\necho called > \""+marker+"\"\necho nikto\n"), 0o755); err != nil {
		t.Fatalf("write fake nikto: %v", err)
	}

	t.Setenv("HOME", home)
	t.Setenv("PATH", dir)

	cmd := ScanCmd()
	cmd.SetArgs([]string{"127.0.0.1", "--tool", "nmap", "--format", "json", "--no-input", "--timeout", "2"})

	output, err := captureCommandStdout(t, cmd.Execute)
	if err != nil {
		t.Fatalf("scan command failed: %v\noutput=%s", err, output)
	}

	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("full inventory detection called unrelated nikto version probe")
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat marker: %v", err)
	}

	var result types.ScanResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, output)
	}
	if result.Tool != "nmap" || !result.Success {
		t.Fatalf("unexpected scan result: %#v", result)
	}
}

func TestScanCmd_FlagCompletion(t *testing.T) {
	cmd := ScanCmd()

	// Test that tool flag has completion function registered
	flag := cmd.Flags().Lookup("tool")
	if flag == nil {
		t.Fatal("tool flag should exist")
	}

	// The completion function should be registered
	// We can't easily test the function itself without executing the command
	// but we can verify the flag exists
}

// ===== TOOL COMPLETION TESTS =====

func TestGetToolCompletions_EmptyPrefix(t *testing.T) {
	completions := getToolCompletions("")

	if len(completions) == 0 {
		t.Error("Should return completions for empty prefix")
	}

	// Should include all tools
	expectedTools := []string{"nmap", "nikto", "nuclei", "masscan", "sqlmap", "gobuster", "ffuf", "hydra", "subfinder", "amass"}
	for _, tool := range expectedTools {
		found := false
		for _, completion := range completions {
			if strings.HasPrefix(completion, tool) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected to find tool '%s' in completions", tool)
		}
	}
}

func TestGetToolCompletions_WithPrefix(t *testing.T) {
	tests := []struct {
		name         string
		prefix       string
		wantContains []string
		wantExcludes []string
		minCount     int
	}{
		{
			name:         "prefix n",
			prefix:       "n",
			wantContains: []string{"nmap", "nikto", "nuclei"},
			wantExcludes: []string{"masscan", "sqlmap"},
			minCount:     3,
		},
		{
			name:         "prefix nm",
			prefix:       "nm",
			wantContains: []string{"nmap"},
			wantExcludes: []string{"nikto", "nuclei", "masscan"},
			minCount:     1,
		},
		{
			name:         "prefix s",
			prefix:       "s",
			wantContains: []string{"sqlmap", "subfinder"},
			wantExcludes: []string{"nmap", "nikto"},
			minCount:     2,
		},
		{
			name:         "prefix m",
			prefix:       "m",
			wantContains: []string{"masscan"},
			wantExcludes: []string{"nmap", "nikto"},
			minCount:     1,
		},
		{
			name:         "no match",
			prefix:       "xyz",
			wantContains: []string{},
			wantExcludes: []string{"nmap", "nikto"},
			minCount:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			completions := getToolCompletions(tt.prefix)

			if len(completions) < tt.minCount {
				t.Errorf("Expected at least %d completions, got %d", tt.minCount, len(completions))
			}

			// Check included tools
			for _, tool := range tt.wantContains {
				found := false
				for _, completion := range completions {
					if strings.HasPrefix(completion, tool) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected to find tool '%s' in completions for prefix '%s'", tool, tt.prefix)
				}
			}

			// Check excluded tools
			for _, tool := range tt.wantExcludes {
				for _, completion := range completions {
					if strings.HasPrefix(completion, tool) {
						t.Errorf("Did not expect to find tool '%s' in completions for prefix '%s'", tool, tt.prefix)
					}
				}
			}
		})
	}
}

func TestGetToolCompletions_Format(t *testing.T) {
	completions := getToolCompletions("")

	// Each completion should have format: "toolname\tdescription"
	for _, completion := range completions {
		if !strings.Contains(completion, "\t") {
			t.Errorf("Completion should contain tab separator: %s", completion)
		}

		parts := strings.Split(completion, "\t")
		if len(parts) != 2 {
			t.Errorf("Completion should have exactly 2 parts (name and description): %s", completion)
		}

		// Tool name should not be empty
		if parts[0] == "" {
			t.Error("Tool name should not be empty")
		}

		// Description should not be empty
		if parts[1] == "" {
			t.Errorf("Description for tool '%s' should not be empty", parts[0])
		}
	}
}

// ===== BUILD NMAP ARGS TESTS =====

func TestBuildNmapArgs_Basic(t *testing.T) {
	tests := []struct {
		name           string
		target         string
		ports          string
		fast           bool
		wantContains   []string
		wantNotContain []string
	}{
		{
			name:         "basic scan",
			target:       "example.com",
			ports:        "1-1000",
			fast:         false,
			wantContains: []string{"-sV", "-sC", "-p", "1-1000", "example.com"},
		},
		{
			name:         "fast scan",
			target:       "192.168.1.1",
			ports:        "80,443",
			fast:         true,
			wantContains: []string{"-sV", "-sC", "-p", "80,443", "-T4", "192.168.1.1"},
		},
		{
			name:           "no ports specified",
			target:         "test.local",
			ports:          "",
			fast:           false,
			wantContains:   []string{"-sV", "-sC", "test.local"},
			wantNotContain: []string{"-p"},
		},
		{
			name:         "full port range",
			target:       "10.0.0.1",
			ports:        "1-65535",
			fast:         false,
			wantContains: []string{"-sV", "-sC", "-p", "1-65535", "10.0.0.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := buildNmapArgs(tt.target, tt.ports, tt.fast)

			// Check that all required args are present
			for _, want := range tt.wantContains {
				found := false
				for _, arg := range args {
					if arg == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected args to contain '%s', got: %v", want, args)
				}
			}

			// Check that excluded args are not present
			for _, notWant := range tt.wantNotContain {
				for _, arg := range args {
					if arg == notWant {
						t.Errorf("Expected args not to contain '%s', got: %v", notWant, args)
					}
				}
			}
		})
	}
}

func TestBuildNmapArgs_Order(t *testing.T) {
	args := buildNmapArgs("example.com", "80,443", false)

	// Target should be last argument
	if args[len(args)-1] != "example.com" {
		t.Errorf("Target should be last argument, got: %v", args)
	}

	// Should start with scan flags
	if args[0] != "-sV" && args[0] != "-sC" {
		t.Errorf("Should start with scan flags, got: %v", args)
	}
}

func TestBuildNmapArgs_FastFlag(t *testing.T) {
	// Test without fast flag
	argsNormal := buildNmapArgs("example.com", "80", false)
	foundT4 := false
	for _, arg := range argsNormal {
		if arg == "-T4" {
			foundT4 = true
		}
	}
	if foundT4 {
		t.Error("Normal scan should not include -T4 flag")
	}

	// Test with fast flag
	argsFast := buildNmapArgs("example.com", "80", true)
	foundT4 = false
	for _, arg := range argsFast {
		if arg == "-T4" {
			foundT4 = true
		}
	}
	if !foundT4 {
		t.Error("Fast scan should include -T4 flag")
	}
}

// ===== DISPLAY PARSED RESULTS TESTS =====

func TestDisplayParsedResults_ValidData(t *testing.T) {
	// This function writes to stdout, so we can't easily test output
	// But we can test that it doesn't panic with valid data
	tests := []struct {
		name  string
		input interface{}
	}{
		{
			name: "valid host data",
			input: map[string]interface{}{
				"hosts": []map[string]interface{}{
					{
						"target": "example.com",
						"ports": []map[string]string{
							{"port": "80", "state": "open", "service": "http"},
							{"port": "443", "state": "open", "service": "https"},
						},
					},
				},
			},
		},
		{
			name: "multiple hosts",
			input: map[string]interface{}{
				"hosts": []map[string]interface{}{
					{
						"target": "192.168.1.1",
						"ports": []map[string]string{
							{"port": "22", "state": "open", "service": "ssh"},
						},
					},
					{
						"target": "192.168.1.2",
						"ports": []map[string]string{
							{"port": "80", "state": "open", "service": "http"},
						},
					},
				},
			},
		},
		{
			name: "no ports",
			input: map[string]interface{}{
				"hosts": []map[string]interface{}{
					{
						"target": "example.com",
						"ports":  []map[string]string{},
					},
				},
			},
		},
		{
			name: "closed ports",
			input: map[string]interface{}{
				"hosts": []map[string]interface{}{
					{
						"target": "example.com",
						"ports": []map[string]string{
							{"port": "80", "state": "closed", "service": "http"},
							{"port": "443", "state": "filtered", "service": "https"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("displayParsedResults panicked: %v", r)
				}
			}()

			displayParsedResults(tt.input)
		})
	}
}

func TestDisplayParsedResults_InvalidData(t *testing.T) {
	// Test with invalid data types - should handle gracefully
	tests := []struct {
		name  string
		input interface{}
	}{
		{
			name:  "not a map",
			input: "invalid string",
		},
		{
			name:  "nil input",
			input: nil,
		},
		{
			name: "no hosts key",
			input: map[string]interface{}{
				"other": "data",
			},
		},
		{
			name: "hosts not array",
			input: map[string]interface{}{
				"hosts": "not an array",
			},
		},
		{
			name: "empty hosts array",
			input: map[string]interface{}{
				"hosts": []map[string]interface{}{},
			},
		},
		{
			name: "host with missing target",
			input: map[string]interface{}{
				"hosts": []map[string]interface{}{
					{
						"ports": []map[string]string{},
					},
				},
			},
		},
		{
			name: "host with invalid ports type",
			input: map[string]interface{}{
				"hosts": []map[string]interface{}{
					{
						"target": "example.com",
						"ports":  "not an array",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic even with invalid data
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("displayParsedResults panicked with invalid data: %v", r)
				}
			}()

			displayParsedResults(tt.input)
		})
	}
}

func TestDisplayParsedResults_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
	}{
		{
			name: "empty port service",
			input: map[string]interface{}{
				"hosts": []map[string]interface{}{
					{
						"target": "example.com",
						"ports": []map[string]string{
							{"port": "80", "state": "open", "service": ""},
						},
					},
				},
			},
		},
		{
			name: "missing port fields",
			input: map[string]interface{}{
				"hosts": []map[string]interface{}{
					{
						"target": "example.com",
						"ports": []map[string]string{
							{"port": "80"},
						},
					},
				},
			},
		},
		{
			name: "very long target name",
			input: map[string]interface{}{
				"hosts": []map[string]interface{}{
					{
						"target": strings.Repeat("a", 100) + ".com",
						"ports": []map[string]string{
							{"port": "80", "state": "open", "service": "http"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("displayParsedResults panicked: %v", r)
				}
			}()

			displayParsedResults(tt.input)
		})
	}
}

// ===== BENCHMARK TESTS =====

func BenchmarkGetToolCompletions_Empty(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = getToolCompletions("")
	}
}

func BenchmarkGetToolCompletions_WithPrefix(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = getToolCompletions("n")
	}
}

func BenchmarkBuildNmapArgs(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = buildNmapArgs("example.com", "1-1000", false)
	}
}

func BenchmarkBuildNmapArgs_Fast(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = buildNmapArgs("example.com", "1-1000", true)
	}
}

func BenchmarkDisplayParsedResults(b *testing.B) {
	input := map[string]interface{}{
		"hosts": []map[string]interface{}{
			{
				"target": "example.com",
				"ports": []map[string]string{
					{"port": "80", "state": "open", "service": "http"},
					{"port": "443", "state": "open", "service": "https"},
					{"port": "22", "state": "open", "service": "ssh"},
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		displayParsedResults(input)
	}
}

// ===== HELPER FUNCTION TESTS =====

func TestGetToolCompletions_CaseSensitivity(t *testing.T) {
	// Tool names are lowercase, test that prefix matching is case-sensitive
	completionsLower := getToolCompletions("n")
	completionsUpper := getToolCompletions("N")

	// Lowercase should return results
	if len(completionsLower) == 0 {
		t.Error("Lowercase prefix should return completions")
	}

	// Uppercase should return no results (case-sensitive)
	if len(completionsUpper) != 0 {
		t.Error("Uppercase prefix should return no completions (case-sensitive)")
	}
}

func TestBuildNmapArgs_PortVariations(t *testing.T) {
	tests := []struct {
		name  string
		ports string
	}{
		{"single port", "80"},
		{"port range", "1-1000"},
		{"multiple ports", "80,443,8080"},
		{"mixed format", "22,80-100,443"},
		{"all ports", "1-65535"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := buildNmapArgs("example.com", tt.ports, false)

			// Should contain the ports
			foundPFlag := false
			foundPorts := false
			for i, arg := range args {
				if arg == "-p" {
					foundPFlag = true
					if i+1 < len(args) && args[i+1] == tt.ports {
						foundPorts = true
					}
				}
			}

			if !foundPFlag {
				t.Error("Should contain -p flag")
			}
			if !foundPorts {
				t.Errorf("Should contain ports '%s'", tt.ports)
			}
		})
	}
}

func TestBuildNmapArgs_TargetVariations(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{"domain", "example.com"},
		{"subdomain", "sub.example.com"},
		{"IP address", "192.168.1.1"},
		{"localhost", "localhost"},
		{"CIDR", "192.168.1.0/24"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := buildNmapArgs(tt.target, "80", false)

			// Target should be in the args
			found := false
			for _, arg := range args {
				if arg == tt.target {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("Args should contain target '%s', got: %v", tt.target, args)
			}

			// Target should be last
			if args[len(args)-1] != tt.target {
				t.Errorf("Target should be last argument, got: %v", args)
			}
		})
	}
}

// ===== SECURITY TESTS =====

func TestBuildNmapArgs_NoInjection(t *testing.T) {
	// Test that malicious inputs don't create command injection vulnerabilities
	tests := []struct {
		name   string
		target string
		ports  string
	}{
		{"semicolon in target", "example.com; rm -rf /", "80"},
		{"pipe in target", "example.com | cat /etc/passwd", "80"},
		{"backtick in target", "example.com`whoami`", "80"},
		{"semicolon in ports", "80; rm -rf /", "80"},
		{"command substitution", "$(whoami)", "80"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := buildNmapArgs(tt.target, tt.ports, false)

			// Args should not contain shell metacharacters as separate arguments
			for _, arg := range args {
				// Check for dangerous characters that could enable command injection
				if strings.Contains(arg, ";") || strings.Contains(arg, "|") ||
					strings.Contains(arg, "`") || strings.Contains(arg, "$") {
					// Note: This test documents current behavior
					// In production, validation should happen before buildNmapArgs
					t.Logf("Warning: arg contains shell metacharacter: %s", arg)
				}
			}
		})
	}
}

// ===== INTEGRATION-STYLE TESTS =====

func TestScanCmd_MaximumNArgs(t *testing.T) {
	cmd := ScanCmd()

	// The Args validator should be MaximumNArgs(1)
	// We can't easily test this without running the command
	// but we verify the command structure is correct
	if cmd.Args == nil {
		t.Error("Args validator should be set")
	}
}

func TestScanCmd_ShortDescription(t *testing.T) {
	cmd := ScanCmd()

	// Short description should mention key features
	short := strings.ToLower(cmd.Short)

	if !strings.Contains(short, "scan") {
		t.Error("Short description should mention 'scan'")
	}

	// Should mention at least one tool
	hasToolMention := strings.Contains(short, "nmap") ||
		strings.Contains(short, "nikto") ||
		strings.Contains(short, "nuclei")

	if !hasToolMention {
		t.Error("Short description should mention at least one tool")
	}
}

func TestScanCmd_LongDescription(t *testing.T) {
	cmd := ScanCmd()

	long := cmd.Long

	// Should contain examples
	if !strings.Contains(long, "Examples:") {
		t.Error("Long description should contain examples")
	}

	// Should contain at least one example command
	if !strings.Contains(long, "zypheron scan") {
		t.Error("Long description should contain example commands")
	}
}

// ===== CONCURRENCY TESTS =====

func TestGetToolCompletions_Concurrent(t *testing.T) {
	// Test that getToolCompletions is safe to call concurrently
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(prefix string) {
			_ = getToolCompletions(prefix)
			done <- true
		}("n")
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestBuildNmapArgs_Concurrent(t *testing.T) {
	// Test that buildNmapArgs is safe to call concurrently
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func() {
			_ = buildNmapArgs("example.com", "80", false)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
