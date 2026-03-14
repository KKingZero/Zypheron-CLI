package aibridge

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func requireUnixListener(t *testing.T, socketPath string) net.Listener {
	t.Helper()

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("Skipping socket test: unix listen not permitted in this environment: %v", err)
		}
		t.Fatalf("Failed to create listener: %v", err)
	}
	return listener
}

// ===== UNIT TESTS =====

// TestRequestSerialization tests JSON serialization of Request struct
func TestRequestSerialization(t *testing.T) {
	tests := []struct {
		name     string
		request  Request
		wantJSON string
	}{
		{
			name: "simple request",
			request: Request{
				Method:    "chat",
				Params:    map[string]interface{}{"message": "hello"},
				AuthToken: "test_token",
			},
		},
		{
			name: "empty params",
			request: Request{
				Method:    "status",
				Params:    map[string]interface{}{},
				AuthToken: "token",
			},
		},
		{
			name: "complex params",
			request: Request{
				Method: "analyze",
				Params: map[string]interface{}{
					"target":    "192.168.1.1",
					"ports":     []int{80, 443, 8080},
					"scan_type": "full",
				},
				AuthToken: "auth123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := json.Marshal(tt.request)
			if err != nil {
				t.Errorf("Failed to marshal request: %v", err)
			}

			// Test deserialization roundtrip
			var decoded Request
			err = json.Unmarshal(data, &decoded)
			if err != nil {
				t.Errorf("Failed to unmarshal request: %v", err)
			}

			if decoded.Method != tt.request.Method {
				t.Errorf("Method mismatch: got %s, want %s", decoded.Method, tt.request.Method)
			}

			if decoded.AuthToken != tt.request.AuthToken {
				t.Errorf("AuthToken mismatch: got %s, want %s", decoded.AuthToken, tt.request.AuthToken)
			}
		})
	}
}

// TestResponseDeserialization tests JSON deserialization of Response struct
func TestResponseDeserialization(t *testing.T) {
	tests := []struct {
		name        string
		jsonData    string
		wantSuccess bool
		wantError   string
	}{
		{
			name:        "successful response",
			jsonData:    `{"success": true, "result": {"status": "ok"}}`,
			wantSuccess: true,
			wantError:   "",
		},
		{
			name:        "error response",
			jsonData:    `{"success": false, "error": "connection failed"}`,
			wantSuccess: false,
			wantError:   "connection failed",
		},
		{
			name:        "empty result",
			jsonData:    `{"success": true, "result": {}}`,
			wantSuccess: true,
			wantError:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp Response
			err := json.Unmarshal([]byte(tt.jsonData), &resp)
			if err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}

			if resp.Success != tt.wantSuccess {
				t.Errorf("Success mismatch: got %v, want %v", resp.Success, tt.wantSuccess)
			}

			if resp.Error != tt.wantError {
				t.Errorf("Error mismatch: got %s, want %s", resp.Error, tt.wantError)
			}
		})
	}
}

// TestMessageStruct tests Message struct serialization
func TestMessageStruct(t *testing.T) {
	messages := []Message{
		{Role: "user", Content: "Hello, analyze this target"},
		{Role: "assistant", Content: "I'll analyze the target for vulnerabilities"},
		{Role: "system", Content: "You are a security analyst"},
	}

	for _, msg := range messages {
		t.Run(msg.Role, func(t *testing.T) {
			data, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("Failed to marshal message: %v", err)
			}

			var decoded Message
			err = json.Unmarshal(data, &decoded)
			if err != nil {
				t.Fatalf("Failed to unmarshal message: %v", err)
			}

			if decoded.Role != msg.Role {
				t.Errorf("Role mismatch: got %s, want %s", decoded.Role, msg.Role)
			}
			if decoded.Content != msg.Content {
				t.Errorf("Content mismatch: got %s, want %s", decoded.Content, msg.Content)
			}
		})
	}
}

// TestVulnerabilityStruct tests Vulnerability struct serialization
func TestVulnerabilityStruct(t *testing.T) {
	cvss := 9.8
	cve := "CVE-2024-1234"
	port := 443
	host := "192.168.1.1"
	remediation := "Upgrade to version 2.0"

	vuln := Vulnerability{
		ID:               "VULN-001",
		Title:            "Critical SQL Injection",
		Description:      "SQL injection in login form",
		Severity:         "critical",
		CVSSScore:        &cvss,
		CVEID:            &cve,
		Port:             &port,
		Host:             &host,
		Remediation:      &remediation,
		ExploitAvailable: true,
		References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
	}

	data, err := json.Marshal(vuln)
	if err != nil {
		t.Fatalf("Failed to marshal vulnerability: %v", err)
	}

	var decoded Vulnerability
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal vulnerability: %v", err)
	}

	if decoded.ID != vuln.ID {
		t.Errorf("ID mismatch: got %s, want %s", decoded.ID, vuln.ID)
	}
	if decoded.Severity != vuln.Severity {
		t.Errorf("Severity mismatch: got %s, want %s", decoded.Severity, vuln.Severity)
	}
	if *decoded.CVSSScore != *vuln.CVSSScore {
		t.Errorf("CVSS mismatch: got %f, want %f", *decoded.CVSSScore, *vuln.CVSSScore)
	}
	if decoded.ExploitAvailable != vuln.ExploitAvailable {
		t.Error("ExploitAvailable should be true")
	}
}

// TestVulnerabilityPredictionStruct tests VulnerabilityPrediction struct
func TestVulnerabilityPredictionStruct(t *testing.T) {
	pred := VulnerabilityPrediction{
		VulnerabilityType:  "SQL Injection",
		Confidence:         0.95,
		Severity:           "high",
		Reasoning:          "Pattern matches known SQLi signatures",
		AffectedComponents: []string{"login.php", "auth.php"},
		RecommendedTests:   []string{"sqlmap", "manual testing"},
	}

	data, err := json.Marshal(pred)
	if err != nil {
		t.Fatalf("Failed to marshal prediction: %v", err)
	}

	var decoded VulnerabilityPrediction
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal prediction: %v", err)
	}

	if decoded.Confidence != pred.Confidence {
		t.Errorf("Confidence mismatch: got %f, want %f", decoded.Confidence, pred.Confidence)
	}
	if len(decoded.AffectedComponents) != len(pred.AffectedComponents) {
		t.Errorf("AffectedComponents length mismatch: got %d, want %d",
			len(decoded.AffectedComponents), len(pred.AffectedComponents))
	}
}

// TestNewAIBridge tests AIBridge creation
func TestNewAIBridge(t *testing.T) {
	bridge := NewAIBridge()

	if bridge == nil {
		t.Fatal("NewAIBridge returned nil")
	}

	// Initially not connected
	if bridge.connected {
		t.Error("New bridge should not be connected")
	}
}

// TestAIBridgeIsRunning tests IsRunning when no engine is running
func TestAIBridgeIsRunning_NoEngine(t *testing.T) {
	bridge := NewAIBridge()

	// Without a running engine, should return false
	if bridge.IsRunning() {
		t.Error("IsRunning should return false when no engine is running")
	}
}

// TestAIBridgeGetPoolStats tests GetPoolStats
func TestAIBridgeGetPoolStats(t *testing.T) {
	bridge := NewAIBridge()

	stats := bridge.GetPoolStats()

	// Stats should include 'enabled' key
	if _, ok := stats["enabled"]; !ok {
		t.Error("Stats should contain 'enabled' key")
	}
}

// TestConstants tests that constants have sensible values
func TestConstants(t *testing.T) {
	if MaxRetries < 1 {
		t.Errorf("MaxRetries should be at least 1, got %d", MaxRetries)
	}

	if MaxRetries > 20 {
		t.Errorf("MaxRetries seems too high: %d", MaxRetries)
	}

	if RetryDelay < time.Millisecond {
		t.Error("RetryDelay seems too short")
	}

	if RetryDelay > time.Minute {
		t.Error("RetryDelay seems too long")
	}
}

// TestGetPythonEnginePath tests engine path resolution
func TestGetPythonEnginePath(t *testing.T) {
	// Save and restore env var
	original := os.Getenv("ZYPHERON_AI_PATH")
	defer os.Setenv("ZYPHERON_AI_PATH", original)

	// Test with env var set
	os.Setenv("ZYPHERON_AI_PATH", "/custom/path/server.py")
	path := getPythonEnginePath()
	if path != "/custom/path/server.py" {
		t.Errorf("Expected custom path, got %s", path)
	}

	// Test without env var
	os.Unsetenv("ZYPHERON_AI_PATH")
	path = getPythonEnginePath()
	if path == "" {
		t.Error("Path should not be empty")
	}
}

// TestGetPythonCommand tests Python interpreter resolution
func TestGetPythonCommand(t *testing.T) {
	// Test with non-existent venv
	cmd := getPythonCommand("/nonexistent/core/server.py")

	// Should fallback to python3
	if cmd != "python3" {
		// Could also be a venv path if it exists
		if cmd == "" {
			t.Error("Python command should not be empty")
		}
	}
}

// ===== INTEGRATION TESTS =====

// TestAIBridgeWithMockServer tests AIBridge with a mock server
func TestAIBridgeWithMockServer(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create temp directory for socket
	tmpDir, err := os.MkdirTemp("", "aibridge_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "test.sock")

	// Start mock server
	listener := requireUnixListener(t, socketPath)
	defer listener.Close()

	// Handle connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleMockConnection(conn)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test connecting to the mock server
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	// Send a request
	req := Request{
		Method:    "status",
		Params:    map[string]interface{}{},
		AuthToken: "test_token",
	}
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}

	// Read response
	decoder := json.NewDecoder(conn)
	var resp Response
	if err := decoder.Decode(&resp); err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if !resp.Success {
		t.Errorf("Expected success, got error: %s", resp.Error)
	}
}

// handleMockConnection simulates AI engine responses
func handleMockConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	for {
		var req Request
		if err := decoder.Decode(&req); err != nil {
			return
		}

		// Generate mock response based on method
		var resp Response
		switch req.Method {
		case "status":
			resp = Response{
				Success: true,
				Result: map[string]interface{}{
					"status":  "running",
					"version": "1.0.0",
				},
			}
		case "chat":
			resp = Response{
				Success: true,
				Result: map[string]interface{}{
					"response": "Mock response from AI",
				},
			}
		case "analyze":
			resp = Response{
				Success: true,
				Result: map[string]interface{}{
					"vulnerabilities": []map[string]interface{}{
						{
							"id":       "MOCK-001",
							"severity": "high",
						},
					},
				},
			}
		default:
			resp = Response{
				Success: false,
				Error:   fmt.Sprintf("Unknown method: %s", req.Method),
			}
		}

		if err := encoder.Encode(resp); err != nil {
			return
		}
	}
}

// TestLoadAuthToken tests token file handling
func TestLoadAuthToken(t *testing.T) {
	// Test without token file (should fail)
	_, err := loadAuthToken()
	// This may or may not fail depending on whether ~/.zypheron/ipc.token exists
	// We just verify it doesn't panic
	_ = err
}

// ===== BENCHMARK TESTS =====

// BenchmarkRequestSerialization benchmarks JSON serialization of requests
func BenchmarkRequestSerialization(b *testing.B) {
	req := Request{
		Method: "analyze",
		Params: map[string]interface{}{
			"target":    "192.168.1.1",
			"ports":     "1-1000",
			"scan_type": "full",
			"options":   map[string]interface{}{"verbose": true, "timeout": 30},
		},
		AuthToken: "benchmark_token_123456789",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkResponseDeserialization benchmarks JSON deserialization of responses
func BenchmarkResponseDeserialization(b *testing.B) {
	jsonData := []byte(`{
		"success": true,
		"result": {
			"status": "running",
			"version": "1.0.0",
			"uptime": 3600,
			"memory_usage": 256000000,
			"active_connections": 5
		}
	}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var resp Response
		err := json.Unmarshal(jsonData, &resp)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVulnerabilitySerialization benchmarks vulnerability struct handling
func BenchmarkVulnerabilitySerialization(b *testing.B) {
	cvss := 9.8
	cve := "CVE-2024-1234"
	port := 443
	host := "192.168.1.1"
	remediation := "Upgrade to version 2.0"

	vuln := Vulnerability{
		ID:               "VULN-001",
		Title:            "Critical SQL Injection",
		Description:      "SQL injection vulnerability in login form allows authentication bypass",
		Severity:         "critical",
		CVSSScore:        &cvss,
		CVEID:            &cve,
		Port:             &port,
		Host:             &host,
		Remediation:      &remediation,
		ExploitAvailable: true,
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
			"https://example.com/advisory",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := json.Marshal(vuln)
		if err != nil {
			b.Fatal(err)
		}

		var decoded Vulnerability
		err = json.Unmarshal(data, &decoded)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConnectionPoolAcquireRelease benchmarks pool operations
func BenchmarkConnectionPoolAcquireRelease(b *testing.B) {
	// Create temp socket
	tmpDir, err := os.MkdirTemp("", "bench_pool")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "test.sock")

	// Start server
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		b.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					_, err := c.Read(buf)
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	pool := NewConnectionPool(socketPath, 10)
	defer pool.Close()

	// Pre-warm pool
	conns := make([]net.Conn, 5)
	for i := 0; i < 5; i++ {
		conn, err := pool.Acquire()
		if err != nil {
			b.Fatalf("Pre-warm failed: %v", err)
		}
		conns[i] = conn
	}
	for _, conn := range conns {
		pool.Release(conn)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := pool.Acquire()
		if err != nil {
			b.Fatal(err)
		}
		pool.Release(conn)
	}
}

// BenchmarkPoolStats benchmarks stats collection
func BenchmarkPoolStats(b *testing.B) {
	pool := NewConnectionPool("/tmp/bench.sock", 10)
	defer pool.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pool.Stats()
	}
}

// BenchmarkNewAIBridge benchmarks bridge creation
func BenchmarkNewAIBridge(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewAIBridge()
	}
}
