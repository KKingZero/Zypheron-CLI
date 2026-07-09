package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

// TestParseNmapOutput tests the Nmap output parser
func TestParseNmapOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantNil  bool
		validate func(t *testing.T, result interface{})
	}{
		{
			name:    "empty output",
			input:   "",
			wantNil: false,
			validate: func(t *testing.T, result interface{}) {
				parsed, ok := result.(map[string]interface{})
				if !ok {
					t.Fatal("expected map[string]interface{}")
				}
				hosts, ok := parsed["hosts"].([]map[string]interface{})
				if !ok {
					t.Fatal("expected hosts to be slice")
				}
				if len(hosts) != 0 {
					t.Errorf("expected empty hosts, got %d", len(hosts))
				}
			},
		},
		{
			name: "single host with ports",
			input: `Nmap scan report for example.com (93.184.216.34)
Host is up (0.0050s latency).
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https`,
			wantNil: false,
			validate: func(t *testing.T, result interface{}) {
				parsed, ok := result.(map[string]interface{})
				if !ok {
					t.Fatal("expected map[string]interface{}")
				}
				hosts, ok := parsed["hosts"].([]map[string]interface{})
				if !ok {
					t.Fatal("expected hosts to be slice")
				}
				if len(hosts) != 1 {
					t.Fatalf("expected 1 host, got %d", len(hosts))
				}
				ports := hosts[0]["ports"].([]map[string]string)
				if len(ports) != 2 {
					t.Errorf("expected 2 ports, got %d", len(ports))
				}
				if ports[0]["port"] != "80/tcp" {
					t.Errorf("expected port 80/tcp, got %s", ports[0]["port"])
				}
				if ports[0]["state"] != "open" {
					t.Errorf("expected state open, got %s", ports[0]["state"])
				}
				if ports[0]["service"] != "http" {
					t.Errorf("expected service http, got %s", ports[0]["service"])
				}
			},
		},
		{
			name: "multiple hosts",
			input: `Nmap scan report for host1.com (192.168.1.1)
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for host2.com (192.168.1.2)
PORT   STATE SERVICE
80/tcp open  http`,
			wantNil: false,
			validate: func(t *testing.T, result interface{}) {
				parsed, ok := result.(map[string]interface{})
				if !ok {
					t.Fatal("expected map[string]interface{}")
				}
				hosts := parsed["hosts"].([]map[string]interface{})
				if len(hosts) != 2 {
					t.Errorf("expected 2 hosts, got %d", len(hosts))
				}
			},
		},
		{
			name: "UDP ports",
			input: `Nmap scan report for test.local
PORT    STATE SERVICE
53/udp  open  domain
123/udp open  ntp`,
			wantNil: false,
			validate: func(t *testing.T, result interface{}) {
				parsed, ok := result.(map[string]interface{})
				if !ok {
					t.Fatal("expected map[string]interface{}")
				}
				hosts := parsed["hosts"].([]map[string]interface{})
				if len(hosts) != 1 {
					t.Fatalf("expected 1 host, got %d", len(hosts))
				}
				ports := hosts[0]["ports"].([]map[string]string)
				if len(ports) != 2 {
					t.Errorf("expected 2 ports, got %d", len(ports))
				}
				if ports[0]["port"] != "53/udp" {
					t.Errorf("expected port 53/udp, got %s", ports[0]["port"])
				}
			},
		},
		{
			name: "no ports found",
			input: `Nmap scan report for filtered.com
Host is up (0.010s latency).
All 1000 scanned ports on filtered.com are filtered`,
			wantNil: false,
			validate: func(t *testing.T, result interface{}) {
				parsed, ok := result.(map[string]interface{})
				if !ok {
					t.Fatal("expected map[string]interface{}")
				}
				hosts := parsed["hosts"].([]map[string]interface{})
				if len(hosts) != 1 {
					t.Fatalf("expected 1 host, got %d", len(hosts))
				}
				ports := hosts[0]["ports"].([]map[string]string)
				if len(ports) != 0 {
					t.Errorf("expected 0 ports, got %d", len(ports))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseNmapOutput(tt.input)
			if tt.wantNil && result != nil {
				t.Errorf("ParseNmapOutput() expected nil, got %v", result)
				return
			}
			if !tt.wantNil && result == nil {
				t.Error("ParseNmapOutput() returned nil unexpectedly")
				return
			}
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

func TestExecuteStreamTimeoutPreservesPartialOutput(t *testing.T) {
	dir := workspaceTempDir(t, "bin-")
	nmapPath := filepath.Join(dir, "nmap")
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\necho partial finding\n/bin/sleep 5\n"), 0o755); err != nil {
		t.Fatalf("write fake nmap: %v", err)
	}
	t.Setenv("PATH", dir)

	result, err := Execute(context.Background(), ExecutionOptions{
		Tool:    "nmap",
		Target:  "127.0.0.1",
		Stream:  true,
		Timeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !result.TimedOut {
		t.Fatalf("TimedOut = false, want true")
	}
	if result.Success {
		t.Fatalf("Success = true, want false for timeout")
	}
	if !strings.Contains(result.Output, "partial finding") {
		t.Fatalf("partial output not preserved: %q", result.Output)
	}
	if !strings.Contains(result.Error, "timed out") {
		t.Fatalf("timeout error metadata missing: %q", result.Error)
	}
}

// TestParseNucleiOutput tests the Nuclei output parser
func TestParseNucleiOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantNil  bool
		validate func(t *testing.T, result interface{})
	}{
		{
			name:    "empty output",
			input:   "",
			wantNil: true,
		},
		{
			name:    "whitespace only",
			input:   "   \n\t\n  ",
			wantNil: true,
		},
		{
			name:  "single JSON finding",
			input: `{"template":"test-template","severity":"high","host":"https://example.com"}`,
			validate: func(t *testing.T, result interface{}) {
				parsed, ok := result.(map[string]interface{})
				if !ok {
					t.Fatal("expected map[string]interface{}")
				}
				findings, ok := parsed["findings"].([]map[string]interface{})
				if !ok {
					t.Fatal("expected findings to be slice")
				}
				if len(findings) != 1 {
					t.Errorf("expected 1 finding, got %d", len(findings))
				}
				if findings[0]["template"] != "test-template" {
					t.Errorf("expected template test-template, got %v", findings[0]["template"])
				}
			},
		},
		{
			name: "multiple JSON findings",
			input: `{"template":"xss-test","severity":"medium","host":"https://example.com"}
{"template":"sqli-test","severity":"critical","host":"https://example.com"}
{"template":"lfi-test","severity":"high","host":"https://test.com"}`,
			validate: func(t *testing.T, result interface{}) {
				parsed := result.(map[string]interface{})
				findings := parsed["findings"].([]map[string]interface{})
				if len(findings) != 3 {
					t.Errorf("expected 3 findings, got %d", len(findings))
				}
			},
		},
		{
			name: "mixed valid and invalid JSON",
			input: `{"template":"valid","severity":"high"}
not json
{"template":"also-valid","severity":"low"}`,
			validate: func(t *testing.T, result interface{}) {
				parsed := result.(map[string]interface{})
				findings := parsed["findings"].([]map[string]interface{})
				if len(findings) != 2 {
					t.Errorf("expected 2 valid findings, got %d", len(findings))
				}
			},
		},
		{
			name:    "only invalid JSON",
			input:   "this is not json\nneither is this",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseNucleiOutput(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseNucleiOutput() expected nil, got %v", result)
				}
				return
			}
			if result == nil {
				t.Error("parseNucleiOutput() returned nil unexpectedly")
				return
			}
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

// TestParseNiktoOutput tests the Nikto output parser
func TestParseNiktoOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantNil  bool
		validate func(t *testing.T, result interface{})
	}{
		{
			name:    "empty output",
			input:   "",
			wantNil: true,
		},
		{
			name: "single finding",
			input: `- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.1
+ Server: Apache/2.4.41
+ The anti-clickjacking X-Frame-Options header is not present.`,
			validate: func(t *testing.T, result interface{}) {
				parsed := result.(map[string]interface{})
				findings := parsed["findings"].([]string)
				if len(findings) != 3 {
					t.Errorf("expected 3 findings, got %d", len(findings))
				}
				if !strings.Contains(findings[0], "Target IP") {
					t.Errorf("expected first finding to contain 'Target IP', got %s", findings[0])
				}
			},
		},
		{
			name: "multiple findings with various prefixes",
			input: `+ Target IP:          10.0.0.1
+ Start Time:         2023-01-01 12:00:00
+ Server: nginx/1.18.0
+ Cookie PHPSESSID created without the httponly flag
+ Cookie session created without the secure flag
Normal output line without plus prefix
+ Another finding with plus prefix`,
			validate: func(t *testing.T, result interface{}) {
				parsed := result.(map[string]interface{})
				findings := parsed["findings"].([]string)
				// Should only capture lines starting with +
				expectedCount := 6
				if len(findings) != expectedCount {
					t.Errorf("expected %d findings, got %d", expectedCount, len(findings))
				}
			},
		},
		{
			name:    "no findings (no plus prefixes)",
			input:   "- Nikto scan started\nScanning target...\nScan complete",
			wantNil: true,
		},
		{
			name: "findings with extra whitespace",
			input: `+    Target with spaces
+  Finding with leading spaces
+Finding without trailing space`,
			validate: func(t *testing.T, result interface{}) {
				parsed := result.(map[string]interface{})
				findings := parsed["findings"].([]string)
				// All should be trimmed
				for _, f := range findings {
					if strings.HasPrefix(f, " ") || strings.HasSuffix(f, " ") {
						t.Errorf("finding not properly trimmed: '%s'", f)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseNiktoOutput(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseNiktoOutput() expected nil, got %v", result)
				}
				return
			}
			if result == nil {
				t.Error("parseNiktoOutput() returned nil unexpectedly")
				return
			}
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

// TestParseMasscanOutput tests the Masscan output parser
func TestParseMasscanOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantNil  bool
		validate func(t *testing.T, result interface{})
	}{
		{
			name:    "empty output",
			input:   "",
			wantNil: true,
		},
		{
			name:  "single open port",
			input: "Discovered open port 80/tcp on 192.168.1.1",
			validate: func(t *testing.T, result interface{}) {
				parsed := result.(map[string]interface{})
				ports := parsed["open_ports"].([]map[string]string)
				if len(ports) != 1 {
					t.Errorf("expected 1 port, got %d", len(ports))
				}
				if ports[0]["port"] != "80/tcp" {
					t.Errorf("expected port 80/tcp, got %s", ports[0]["port"])
				}
				if ports[0]["host"] != "192.168.1.1" {
					t.Errorf("expected host 192.168.1.1, got %s", ports[0]["host"])
				}
			},
		},
		{
			name: "multiple open ports",
			input: `Starting masscan
Discovered open port 22/tcp on 10.0.0.1
Discovered open port 443/tcp on 10.0.0.1
Discovered open port 80/tcp on 10.0.0.2`,
			validate: func(t *testing.T, result interface{}) {
				parsed := result.(map[string]interface{})
				ports := parsed["open_ports"].([]map[string]string)
				if len(ports) != 3 {
					t.Errorf("expected 3 ports, got %d", len(ports))
				}
			},
		},
		{
			name:    "no open ports found",
			input:   "Starting masscan 1.0.5\nScanning 1000 ports\nScan complete",
			wantNil: true,
		},
		{
			name: "malformed lines ignored",
			input: `Discovered open port 80/tcp on 192.168.1.1
Invalid line format
Discovered port
Discovered open port 443/tcp on 192.168.1.2`,
			validate: func(t *testing.T, result interface{}) {
				parsed := result.(map[string]interface{})
				ports := parsed["open_ports"].([]map[string]string)
				// Only valid lines should be parsed
				if len(ports) != 2 {
					t.Errorf("expected 2 valid ports, got %d", len(ports))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseMasscanOutput(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseMasscanOutput() expected nil, got %v", result)
				}
				return
			}
			if result == nil {
				t.Error("parseMasscanOutput() returned nil unexpectedly")
				return
			}
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

// TestParseSQLMapOutput tests the SQLMap output parser
func TestParseSQLMapOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantNil  bool
		validate func(t *testing.T, result interface{})
	}{
		{
			name:    "empty output",
			input:   "",
			wantNil: true,
		},
		{
			name: "single finding",
			input: `Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 1234=1234 AND 'a'='a`,
			validate: func(t *testing.T, result interface{}) {
				parsed := result.(map[string]interface{})
				findings := parsed["findings"].([]map[string]string)
				if len(findings) != 1 {
					t.Errorf("expected 1 finding, got %d", len(findings))
				}
				if findings[0]["parameter"] != "id (GET)" {
					t.Errorf("expected parameter 'id (GET)', got %s", findings[0]["parameter"])
				}
				if findings[0]["type"] != "boolean-based blind" {
					t.Errorf("expected type 'boolean-based blind', got %s", findings[0]["type"])
				}
			},
		},
		{
			name: "multiple findings",
			input: `Parameter: username
    Type: error-based
    Title: MySQL >= 5.0 error-based
    Payload: username=admin'

Parameter: password
    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based
    Payload: password=test'`,
			validate: func(t *testing.T, result interface{}) {
				parsed := result.(map[string]interface{})
				findings := parsed["findings"].([]map[string]string)
				if len(findings) != 2 {
					t.Errorf("expected 2 findings, got %d", len(findings))
				}
			},
		},
		{
			name: "finding with all fields",
			input: `Parameter: search
    Type: UNION query
    Title: Generic UNION query (NULL)
    Payload: search=test' UNION ALL SELECT NULL--
    Vector: UNION ALL SELECT NULL`,
			validate: func(t *testing.T, result interface{}) {
				parsed := result.(map[string]interface{})
				findings := parsed["findings"].([]map[string]string)
				if len(findings) != 1 {
					t.Fatalf("expected 1 finding, got %d", len(findings))
				}
				f := findings[0]
				if f["parameter"] != "search" {
					t.Errorf("expected parameter 'search', got %s", f["parameter"])
				}
				if f["type"] != "UNION query" {
					t.Errorf("expected type 'UNION query', got %s", f["type"])
				}
				if f["title"] != "Generic UNION query (NULL)" {
					t.Errorf("unexpected title: %s", f["title"])
				}
				if _, ok := f["payload"]; !ok {
					t.Error("missing payload field")
				}
				if _, ok := f["vector"]; !ok {
					t.Error("missing vector field")
				}
			},
		},
		{
			name:    "no findings (informational output only)",
			input:   "sqlmap identified the back-end DBMS as MySQL\nfetching banner...",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSQLMapOutput(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseSQLMapOutput() expected nil, got %v", result)
				}
				return
			}
			if result == nil {
				t.Error("parseSQLMapOutput() returned nil unexpectedly")
				return
			}
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

// TestParseStructuredOutput tests the main parser dispatcher
func TestParseStructuredOutput(t *testing.T) {
	tests := []struct {
		name    string
		tool    string
		output  string
		wantNil bool
	}{
		{
			name:    "nmap with valid output",
			tool:    "nmap",
			output:  "Nmap scan report for example.com\n80/tcp open http",
			wantNil: false,
		},
		{
			name:    "nuclei with JSON",
			tool:    "nuclei",
			output:  `{"template":"test","severity":"high"}`,
			wantNil: false,
		},
		{
			name:    "nikto with findings",
			tool:    "nikto",
			output:  "+ Server: Apache",
			wantNil: false,
		},
		{
			name:    "masscan with open ports",
			tool:    "masscan",
			output:  "Discovered open port 80/tcp on 192.168.1.1",
			wantNil: false,
		},
		{
			name:    "sqlmap with vulnerabilities",
			tool:    "sqlmap",
			output:  "Parameter: id\n    Type: boolean-based blind",
			wantNil: false,
		},
		{
			name:    "unknown tool",
			tool:    "unknown",
			output:  "some output",
			wantNil: true,
		},
		{
			name:    "empty output",
			tool:    "nmap",
			output:  "",
			wantNil: true,
		},
		{
			name:    "whitespace only output",
			tool:    "nuclei",
			output:  "   \n\t  ",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseStructuredOutput(tt.tool, tt.output)
			if tt.wantNil && result != nil {
				t.Errorf("parseStructuredOutput() expected nil, got %v", result)
			}
			if !tt.wantNil && result == nil {
				t.Error("parseStructuredOutput() returned nil unexpectedly")
			}
		})
	}
}

// TestIsIPAddress tests IP address validation
func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"IPv4 address", "192.168.1.1", true},
		{"IPv4 with port", "192.168.1.1:8080", true},
		{"IPv6 address", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", true},
		{"IPv6 short", "::1", true},
		{"IPv6 with brackets", "[::1]", false}, // net.ParseIP doesn't parse brackets
		{"domain name", "example.com", false},
		{"domain with port", "example.com:8080", false},
		{"localhost", "localhost", false},
		{"empty string", "", false},
		{"invalid IP", "999.999.999.999", false},
		{"partial IP", "192.168", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isIPAddress(tt.target)
			if result != tt.want {
				t.Errorf("isIPAddress(%q) = %v, want %v", tt.target, result, tt.want)
			}
		})
	}
}

// TestDecorateArgs tests argument decoration for different tools
func TestDecorateArgs(t *testing.T) {
	tests := []struct {
		name     string
		opts     ExecutionOptions
		validate func(t *testing.T, args []string)
	}{
		{
			name: "nuclei adds JSON and no-color",
			opts: ExecutionOptions{
				Tool: "nuclei",
				Args: []string{"-u", "https://example.com"},
			},
			validate: func(t *testing.T, args []string) {
				if !containsArg(args, "-json") {
					t.Error("expected -json argument for nuclei")
				}
				if !containsArg(args, "-no-color") {
					t.Error("expected -no-color argument for nuclei")
				}
			},
		},
		{
			name: "nuclei doesn't duplicate existing args",
			opts: ExecutionOptions{
				Tool: "nuclei",
				Args: []string{"-json", "-u", "https://example.com"},
			},
			validate: func(t *testing.T, args []string) {
				count := 0
				for _, arg := range args {
					if arg == "-json" {
						count++
					}
				}
				if count != 1 {
					t.Errorf("expected -json to appear once, appeared %d times", count)
				}
			},
		},
		{
			name: "nikto with AssumeYes adds -ask no",
			opts: ExecutionOptions{
				Tool:      "nikto",
				Args:      []string{"-h", "example.com"},
				AssumeYes: true,
				Target:    "example.com",
			},
			validate: func(t *testing.T, args []string) {
				found := false
				for i := 0; i < len(args)-1; i++ {
					if args[i] == "-ask" && args[i+1] == "no" {
						found = true
						break
					}
				}
				if !found {
					t.Error("expected -ask no arguments for nikto with AssumeYes")
				}
			},
		},
		{
			name: "nikto with IP target adds -nolookup",
			opts: ExecutionOptions{
				Tool:   "nikto",
				Args:   []string{"-h", "192.168.1.1"},
				Target: "192.168.1.1",
			},
			validate: func(t *testing.T, args []string) {
				if !containsArg(args, "-nolookup") {
					t.Error("expected -nolookup for IP target")
				}
			},
		},
		{
			name: "nikto with domain does not add -nolookup",
			opts: ExecutionOptions{
				Tool:   "nikto",
				Args:   []string{"-h", "example.com"},
				Target: "example.com",
			},
			validate: func(t *testing.T, args []string) {
				if containsArg(args, "-nolookup") {
					t.Error("did not expect -nolookup for domain target")
				}
			},
		},
		{
			name: "sqlmap with AssumeYes adds batch and disable-coloring",
			opts: ExecutionOptions{
				Tool:      "sqlmap",
				Args:      []string{"-u", "https://example.com/test?id=1"},
				AssumeYes: true,
			},
			validate: func(t *testing.T, args []string) {
				if !containsArg(args, "--batch") {
					t.Error("expected --batch for sqlmap with AssumeYes")
				}
				if !containsArg(args, "--disable-coloring") {
					t.Error("expected --disable-coloring for sqlmap")
				}
			},
		},
		{
			name: "masscan adds --wait 0",
			opts: ExecutionOptions{
				Tool: "masscan",
				Args: []string{"-p80", "192.168.1.0/24"},
			},
			validate: func(t *testing.T, args []string) {
				found := false
				for i := 0; i < len(args)-1; i++ {
					if args[i] == "--wait" && args[i+1] == "0" {
						found = true
						break
					}
				}
				if !found {
					t.Error("expected --wait 0 for masscan")
				}
			},
		},
		{
			name: "unknown tool preserves args unchanged",
			opts: ExecutionOptions{
				Tool: "custom-tool",
				Args: []string{"arg1", "arg2"},
			},
			validate: func(t *testing.T, args []string) {
				if len(args) != 2 || args[0] != "arg1" || args[1] != "arg2" {
					t.Error("expected args to be unchanged for unknown tool")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decorateArgs(tt.opts)
			tt.validate(t, result)
		})
	}
}

// TestAppendIfMissing tests the appendIfMissing helper
func TestAppendIfMissing(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		values []string
		want   []string
	}{
		{
			name:   "append single missing value",
			args:   []string{"arg1", "arg2"},
			values: []string{"arg3"},
			want:   []string{"arg1", "arg2", "arg3"},
		},
		{
			name:   "don't append existing value",
			args:   []string{"arg1", "arg2"},
			values: []string{"arg1"},
			want:   []string{"arg1", "arg2"},
		},
		{
			name:   "append multiple missing values",
			args:   []string{"arg1"},
			values: []string{"arg2", "arg3"},
			want:   []string{"arg1", "arg2", "arg3"},
		},
		{
			name:   "mixed existing and missing",
			args:   []string{"arg1", "arg2"},
			values: []string{"arg2", "arg3", "arg4"},
			want:   []string{"arg1", "arg2", "arg3", "arg4"},
		},
		{
			name:   "empty args",
			args:   []string{},
			values: []string{"arg1"},
			want:   []string{"arg1"},
		},
		{
			name:   "empty values",
			args:   []string{"arg1"},
			values: []string{},
			want:   []string{"arg1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendIfMissing(tt.args, tt.values...)
			if len(result) != len(tt.want) {
				t.Errorf("length mismatch: got %d, want %d", len(result), len(tt.want))
			}
			for i := range tt.want {
				if i >= len(result) || result[i] != tt.want[i] {
					t.Errorf("appendIfMissing() = %v, want %v", result, tt.want)
					break
				}
			}
		})
	}
}

// TestEnsureArgPair tests the ensureArgPair helper
func TestEnsureArgPair(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		key   string
		value string
		want  []string
	}{
		{
			name:  "add new pair",
			args:  []string{"arg1", "arg2"},
			key:   "-key",
			value: "value",
			want:  []string{"arg1", "arg2", "-key", "value"},
		},
		{
			name:  "don't add if key exists",
			args:  []string{"-key", "existing", "arg2"},
			key:   "-key",
			value: "value",
			want:  []string{"-key", "existing", "arg2"},
		},
		{
			name:  "empty args",
			args:  []string{},
			key:   "-key",
			value: "value",
			want:  []string{"-key", "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ensureArgPair(tt.args, tt.key, tt.value)
			if len(result) != len(tt.want) {
				t.Errorf("length mismatch: got %d, want %d", len(result), len(tt.want))
			}
			for i := range tt.want {
				if i >= len(result) || result[i] != tt.want[i] {
					t.Errorf("ensureArgPair() = %v, want %v", result, tt.want)
					break
				}
			}
		})
	}
}

// TestContainsArg tests the containsArg helper
func TestContainsArg(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		value string
		want  bool
	}{
		{"found", []string{"arg1", "arg2", "arg3"}, "arg2", true},
		{"not found", []string{"arg1", "arg2"}, "arg3", false},
		{"empty args", []string{}, "arg1", false},
		{"empty value", []string{"arg1"}, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsArg(tt.args, tt.value)
			if result != tt.want {
				t.Errorf("containsArg() = %v, want %v", result, tt.want)
			}
		})
	}
}

// TestUniqueStrings tests the uniqueStrings helper
func TestUniqueStrings(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		want    []string
		lenWant int
	}{
		{
			name:    "remove duplicates",
			input:   []string{"a", "b", "a", "c", "b"},
			want:    []string{"a", "b", "c"},
			lenWant: 3,
		},
		{
			name:    "no duplicates",
			input:   []string{"a", "b", "c"},
			want:    []string{"a", "b", "c"},
			lenWant: 3,
		},
		{
			name:    "empty strings filtered",
			input:   []string{"a", "", "b", "", "c"},
			want:    []string{"a", "b", "c"},
			lenWant: 3,
		},
		{
			name:    "all empty",
			input:   []string{"", "", ""},
			want:    []string{},
			lenWant: 0,
		},
		{
			name:    "empty input",
			input:   []string{},
			want:    []string{},
			lenWant: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := uniqueStrings(tt.input)
			if len(result) != tt.lenWant {
				t.Errorf("uniqueStrings() length = %d, want %d", len(result), tt.lenWant)
			}
			// Check all expected values are present
			for _, w := range tt.want {
				found := false
				for _, r := range result {
					if r == w {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("uniqueStrings() missing expected value %s, got %v", w, result)
				}
			}
		})
	}
}

// TestContainsAny tests the containsAny helper
func TestContainsAny(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		keywords []string
		want     bool
	}{
		{"found first keyword", "this is a test", []string{"test", "example"}, true},
		{"found second keyword", "this is an example", []string{"test", "example"}, true},
		{"no keywords found", "this is a demo", []string{"test", "example"}, false},
		{"empty string", "", []string{"test"}, false},
		{"empty keywords", "test", []string{}, false},
		{"partial match", "testing", []string{"test"}, true},
		{"case sensitive", "TEST", []string{"test"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsAny(tt.s, tt.keywords)
			if result != tt.want {
				t.Errorf("containsAny(%q, %v) = %v, want %v", tt.s, tt.keywords, result, tt.want)
			}
		})
	}
}

// TestExecuteWithMissingTool tests Execute with a tool that doesn't exist
func TestExecuteWithMissingTool(t *testing.T) {
	ctx := context.Background()
	opts := ExecutionOptions{
		Tool:    "nonexistent-tool-that-should-not-exist",
		Target:  "example.com",
		Timeout: 1 * time.Second,
	}

	_, err := Execute(ctx, opts)
	if err == nil {
		t.Error("Execute() expected error for missing tool, got nil")
	}
	if !strings.Contains(err.Error(), "not installed") && !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("Execute() error should mention tool not installed/found/allowed, got: %v", err)
	}
}

// TestExecuteWithEmptyTool tests Execute with empty tool name
func TestExecuteWithEmptyTool(t *testing.T) {
	ctx := context.Background()
	opts := ExecutionOptions{
		Tool:   "",
		Target: "example.com",
	}

	_, err := Execute(ctx, opts)
	if err == nil {
		t.Error("Execute() expected error for empty tool name, got nil")
	}
	if !strings.Contains(err.Error(), "required") && !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("Execute() error should mention tool is required or empty, got: %v", err)
	}
}

// TestExecuteWithTimeout tests timeout handling
func TestExecuteWithTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timeout test in short mode")
	}

	ctx := context.Background()
	// Use 'sleep' command which should exist on Unix systems
	opts := ExecutionOptions{
		Tool:    "sleep",
		Args:    []string{"10"},         // Sleep for 10 seconds
		Timeout: 100 * time.Millisecond, // But timeout after 100ms
		Stream:  false,
	}

	result, err := Execute(ctx, opts)
	// On some systems sleep might not be in PATH or validation might fail
	// We're mainly testing the timeout mechanism if the command runs
	if err != nil {
		if strings.Contains(err.Error(), "not installed") || strings.Contains(err.Error(), "validation failed") {
			t.Skip("sleep command not available or failed validation, skipping timeout test")
		}
		// Other errors are ok as long as we got a result
	}

	if result != nil && result.TimedOut {
		// This is what we expect - the command timed out
		if result.Success {
			t.Error("Execute() expected Success=false for timed out command")
		}
	}
}

// Benchmark tests for parsers

func BenchmarkParseNmapOutput(b *testing.B) {
	output := `Nmap scan report for example.com (93.184.216.34)
Host is up (0.0050s latency).
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
3306/tcp open  mysql

Nmap scan report for test.com (192.168.1.1)
Host is up (0.0020s latency).
PORT    STATE SERVICE
80/tcp  open  http
8080/tcp open  http-proxy`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseNmapOutput(output)
	}
}

func BenchmarkParseNucleiOutput(b *testing.B) {
	output := `{"template":"xss-test","severity":"medium","host":"https://example.com"}
{"template":"sqli-test","severity":"critical","host":"https://example.com"}
{"template":"lfi-test","severity":"high","host":"https://test.com"}
{"template":"rce-test","severity":"critical","host":"https://vulnerable.com"}
{"template":"ssrf-test","severity":"high","host":"https://example.com"}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseNucleiOutput(output)
	}
}

func BenchmarkParseNiktoOutput(b *testing.B) {
	output := `- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.1
+ Server: Apache/2.4.41
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-Content-Type-Options header is not set.
+ Server may leak inodes via ETags
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS
+ OSVDB-3268: /admin/: Directory indexing found.
+ OSVDB-3092: /admin/: This might be interesting...`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseNiktoOutput(output)
	}
}

func BenchmarkParseMasscanOutput(b *testing.B) {
	output := `Starting masscan 1.0.5
Discovered open port 22/tcp on 10.0.0.1
Discovered open port 80/tcp on 10.0.0.1
Discovered open port 443/tcp on 10.0.0.1
Discovered open port 3306/tcp on 10.0.0.2
Discovered open port 5432/tcp on 10.0.0.3`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseMasscanOutput(output)
	}
}

func BenchmarkParseSQLMapOutput(b *testing.B) {
	output := `Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 1234=1234 AND 'a'='a
    Vector: AND [INFERENCE]

Parameter: username
    Type: error-based
    Title: MySQL >= 5.0 error-based
    Payload: username=admin' AND EXTRACTVALUE(1,CONCAT(0x5c,VERSION()))-- -`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseSQLMapOutput(output)
	}
}

func BenchmarkDecorateArgs(b *testing.B) {
	opts := ExecutionOptions{
		Tool:      "nuclei",
		Args:      []string{"-u", "https://example.com", "-t", "templates/"},
		AssumeYes: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = decorateArgs(opts)
	}
}

func BenchmarkIsIPAddress(b *testing.B) {
	tests := []string{
		"192.168.1.1",
		"example.com",
		"2001:0db8:85a3::8a2e:0370:7334",
		"192.168.1.1:8080",
		"invalid.ip.address",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, test := range tests {
			_ = isIPAddress(test)
		}
	}
}

func BenchmarkUniqueStrings(b *testing.B) {
	input := []string{"nmap", "nikto", "nmap", "nuclei", "sqlmap", "nikto", "masscan", "nmap"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uniqueStrings(input)
	}
}
