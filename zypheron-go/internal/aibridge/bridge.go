package aibridge

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
)

const (
	MaxRetries = 5
	RetryDelay = 2 * time.Second
)

// getPythonEnginePath returns the path to the Python AI engine
func getPythonEnginePath() string {
	// Check environment variable first
	if path := os.Getenv("ZYPHERON_AI_PATH"); path != "" {
		return path
	}
	
	// Try to find it relative to the binary location
	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		
		// Common installation paths
		possiblePaths := []string{
			// If installed in /usr/local/bin, look for AI engine in common locations
			"/usr/local/share/zypheron/zypheron-ai/core/server.py",
			filepath.Join(exeDir, "..", "zypheron-ai", "core", "server.py"),
			filepath.Join(exeDir, "..", "..", "zypheron-ai", "core", "server.py"),
			// Development path
			filepath.Join(exeDir, "..", "..", "Cobra-AI-Zypheron-CLI", "zypheron-ai", "core", "server.py"),
		}
		
		for _, path := range possiblePaths {
			absPath, err := filepath.Abs(path)
			if err == nil {
				if _, err := os.Stat(absPath); err == nil {
					return absPath
				}
			}
		}
	}
	
	// Try common development paths
	homeDir, err := os.UserHomeDir()
	if err == nil {
		devPaths := []string{
			filepath.Join(homeDir, "Downloads", "Cobra-AI-Zypheron-CLI", "zypheron-ai", "core", "server.py"),
			filepath.Join(homeDir, "Cobra-AI-Zypheron-CLI", "zypheron-ai", "core", "server.py"),
		}
		
		for _, path := range devPaths {
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}
	
	// Fallback to relative path (for backward compatibility)
	return "../zypheron-ai/core/server.py"
}

// getPythonCommand finds the best Python interpreter to use
func getPythonCommand(serverPath string) string {
	// Get the directory containing server.py
	serverDir := filepath.Dir(serverPath)
	aiEngineDir := filepath.Dir(serverDir) // Go up one level from core/ to zypheron-ai/
	
	// Check for venv in the AI engine directory
	venvPython := filepath.Join(aiEngineDir, "venv", "bin", "python3")
	if _, err := os.Stat(venvPython); err == nil {
		return venvPython
	}
	
	venvPython = filepath.Join(aiEngineDir, "venv", "bin", "python")
	if _, err := os.Stat(venvPython); err == nil {
		return venvPython
	}
	
	// Fallback to system python3
	return "python3"
}

// AIBridge manages communication with the Python AI engine
type AIBridge struct {
	socketPath    string
	pythonProcess *exec.Cmd
	connected     bool
	authToken     string
	
	// Connection pool for performance optimization
	connPool      *ConnectionPool
	usePool       bool // Enable/disable pooling for testing
}

// Request represents an IPC request
type Request struct {
	Method    string                 `json:"method"`
	Params    map[string]interface{} `json:"params"`
	AuthToken string                 `json:"auth_token"`
}

// Response represents an IPC response
type Response struct {
	Success bool                   `json:"success"`
	Result  map[string]interface{} `json:"result,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Severity         string   `json:"severity"`
	CVSSScore        *float64 `json:"cvss_score"`
	CVEID            *string  `json:"cve_id"`
	Port             *int     `json:"port"`
	Host             *string  `json:"host"`
	Remediation      *string  `json:"remediation"`
	ExploitAvailable bool     `json:"exploit_available"`
	References       []string `json:"references"`
}

// VulnerabilityPrediction represents an ML vulnerability prediction
type VulnerabilityPrediction struct {
	VulnerabilityType  string   `json:"vulnerability_type"`
	Confidence         float64  `json:"confidence"`
	Severity           string   `json:"severity"`
	Reasoning          string   `json:"reasoning"`
	AffectedComponents []string `json:"affected_components"`
	RecommendedTests   []string `json:"recommended_tests"`
}

// getSecureSocketPath finds the running AI engine socket
func getSecureSocketPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	socketDir := filepath.Join(homeDir, ".zypheron", "sockets")

	// Look for socket files matching pattern: ai-*.sock
	pattern := filepath.Join(socketDir, "ai-*.sock")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("failed to search for sockets: %w", err)
	}

	// Find the first valid socket
	for _, socketPath := range matches {
		// Validate socket ownership
		if err := validateSocketOwnership(socketPath); err != nil {
			fmt.Println(ui.WarningMsg(fmt.Sprintf("Skipping invalid socket: %s (%s)", socketPath, err)))
			continue
		}

		// Try to connect to verify it's responsive
		conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
		if err == nil {
			conn.Close()
			return socketPath, nil
		}
	}

	return "", fmt.Errorf("no running AI engine socket found in %s", socketDir)
}

// validateSocketOwnership is implemented in socket_validation_*.go (platform-specific)

// loadAuthToken loads the authentication token from file
func loadAuthToken() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	tokenFile := filepath.Join(homeDir, ".zypheron", "ipc.token")
	data, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("failed to read auth token: %w (start AI engine first)", err)
	}

	return strings.TrimSpace(string(data)), nil
}

// NewAIBridge creates a new AI bridge instance with connection pooling
func NewAIBridge() *AIBridge {
	token, _ := loadAuthToken()

	// Try to find running socket
	socketPath, err := getSecureSocketPath()
	if err != nil {
		// Fallback to empty, will be discovered on first use
		socketPath = ""
	}

	bridge := &AIBridge{
		socketPath: socketPath,
		connected:  false,
		authToken:  token,
		usePool:    true, // Enable connection pooling by default
	}

	// Initialize connection pool if socket is available
	if socketPath != "" {
		bridge.connPool = NewConnectionPool(socketPath, DefaultPoolSize)
	}

	return bridge
}

// Start starts the Python AI engine
func (b *AIBridge) Start() error {
	// Check if already running
	if b.IsRunning() {
		ui.Success.Println("AI Engine already running")
		b.connected = true
		return nil
	}

	fmt.Println(ui.InfoMsg("Starting AI Engine..."))

	// Get the Python engine path
	pythonPath := getPythonEnginePath()
	
	// Verify the file exists
	if _, err := os.Stat(pythonPath); os.IsNotExist(err) {
		return fmt.Errorf("Python AI engine not found at: %s\n"+
			"Please ensure zypheron-ai is installed or set ZYPHERON_AI_PATH environment variable", pythonPath)
	}

	fmt.Println(ui.Muted.Sprint(fmt.Sprintf("  Using AI engine at: %s", pythonPath)))

	// Find Python interpreter (prefer venv if it exists)
	pythonCmd := getPythonCommand(pythonPath)
	
	fmt.Println(ui.Muted.Sprint(fmt.Sprintf("  Using Python: %s", pythonCmd)))

	// Set working directory to zypheron-ai root (parent of core/)
	serverDir := filepath.Dir(pythonPath)
	aiEngineDir := filepath.Dir(serverDir)
	
	fmt.Println(ui.Muted.Sprint(fmt.Sprintf("  Working directory: %s", aiEngineDir)))

	// Start Python server
	b.pythonProcess = exec.Command(pythonCmd, pythonPath)
	b.pythonProcess.Dir = aiEngineDir // Set working directory
	b.pythonProcess.Stdout = os.Stdout
	b.pythonProcess.Stderr = os.Stderr

	if err := b.pythonProcess.Start(); err != nil {
		return fmt.Errorf("failed to start AI engine: %w", err)
	}

	// Wait for server to be ready
	for i := 0; i < MaxRetries; i++ {
		time.Sleep(RetryDelay)
		if b.IsRunning() {
			b.connected = true

			// Load auth token
			token, err := loadAuthToken()
			if err != nil {
				return fmt.Errorf("failed to load auth token: %w", err)
			}
			b.authToken = token

			ui.Success.Println("AI Engine started successfully")
			return nil
		}
		fmt.Printf(".")
	}

	return fmt.Errorf("AI engine failed to start after %d retries", MaxRetries)
}

// Stop stops the Python AI engine and closes connection pool
func (b *AIBridge) Stop() error {
	// Close connection pool first
	if b.connPool != nil {
		if err := b.connPool.Close(); err != nil {
			fmt.Println(ui.WarningMsg(fmt.Sprintf("Error closing connection pool: %s", err)))
		}
		b.connPool = nil
	}

	if b.pythonProcess != nil {
		fmt.Println(ui.InfoMsg("Stopping AI Engine..."))
		if err := b.pythonProcess.Process.Kill(); err != nil {
			return err
		}
		b.connected = false
		ui.Success.Println("AI Engine stopped")
	}
	return nil
}

// IsRunning checks if the AI engine is running
func (b *AIBridge) IsRunning() bool {
	// Try to find socket if we don't have one
	if b.socketPath == "" {
		socketPath, err := getSecureSocketPath()
		if err != nil {
			return false
		}
		b.socketPath = socketPath
	}

	// Validate ownership
	if err := validateSocketOwnership(b.socketPath); err != nil {
		return false
	}

	// Try to connect
	conn, err := net.DialTimeout("unix", b.socketPath, 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// SendRequest sends a request to the Python AI engine (with connection pooling)
func (b *AIBridge) SendRequest(method string, params map[string]interface{}) (*Response, error) {
	if !b.connected && !b.IsRunning() {
		return nil, fmt.Errorf("AI engine not running - start it with: zypheron ai start")
	}

	// Initialize pool if needed
	if b.usePool && b.connPool == nil && b.socketPath != "" {
		b.connPool = NewConnectionPool(b.socketPath, DefaultPoolSize)
	}

	var conn net.Conn
	var err error
	var fromPool bool

	// Try to get connection from pool first
	if b.usePool && b.connPool != nil {
		conn, err = b.connPool.Acquire()
		if err == nil {
			fromPool = true
			defer b.connPool.Release(conn) // Return to pool when done
		} else if err == ErrPoolExhausted {
			// Pool exhausted, fall through to create new connection
			fmt.Println(ui.WarningMsg("Connection pool exhausted, creating temporary connection"))
		} else {
			return nil, fmt.Errorf("failed to acquire connection from pool: %w", err)
		}
	}

	// Fallback: create new connection if pool unavailable or exhausted
	if conn == nil {
		// Validate socket ownership before connecting
		if err := validateSocketOwnership(b.socketPath); err != nil {
			return nil, fmt.Errorf("socket security validation failed: %w", err)
		}

		conn, err = net.DialTimeout("unix", b.socketPath, 5*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to AI engine: %w", err)
		}
		defer conn.Close() // Close immediately for non-pooled connections
	}

	// Prepare request
	req := Request{
		Method:    method,
		Params:    params,
		AuthToken: b.authToken,
	}

	// Send request with timeout
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		if fromPool {
			// Mark connection as unhealthy if send fails
			conn.Close()
		}
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response with timeout
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	decoder := json.NewDecoder(conn)
	var resp Response
	if err := decoder.Decode(&resp); err != nil {
		if fromPool {
			// Mark connection as unhealthy if read fails
			conn.Close()
		}
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Clear deadlines for pooled connections
	if fromPool {
		conn.SetDeadline(time.Time{})
	}

	if !resp.Success {
		return nil, fmt.Errorf("AI engine error: %s", resp.Error)
	}

	return &resp, nil
}

// GetPoolStats returns connection pool statistics
func (b *AIBridge) GetPoolStats() map[string]interface{} {
	if b.connPool == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}
	stats := b.connPool.Stats()
	stats["enabled"] = true
	return stats
}

// Chat sends a chat request to the AI
func (b *AIBridge) Chat(messages []Message, provider string, temperature float64, maxTokens int) (string, error) {
	params := map[string]interface{}{
		"messages":    messages,
		"provider":    provider,
		"temperature": temperature,
		"max_tokens":  maxTokens,
	}

	resp, err := b.SendRequest("chat", params)
	if err != nil {
		return "", err
	}

	content, ok := resp.Result["content"].(string)
	if !ok {
		return "", fmt.Errorf("invalid response format")
	}

	return content, nil
}

// AnalyzeScan analyzes scan output with AI
func (b *AIBridge) AnalyzeScan(scanOutput, tool, target string, useAI bool) ([]Vulnerability, string, error) {
	params := map[string]interface{}{
		"scan_output": scanOutput,
		"tool":        tool,
		"target":      target,
		"use_ai":      useAI,
	}

	resp, err := b.SendRequest("analyze_scan", params)
	if err != nil {
		return nil, "", err
	}

	// Parse vulnerabilities with safe type assertions
	var vulns []Vulnerability
	vulnsData, ok := resp.Result["vulnerabilities"].([]interface{})
	if ok {
		for _, v := range vulnsData {
			vMap, ok := v.(map[string]interface{})
			if !ok {
				// Skip invalid vulnerability entries
				continue
			}

			vuln := Vulnerability{}

			// Safe type assertions with zero-value fallbacks
			if id, ok := vMap["id"].(string); ok {
				vuln.ID = id
			}
			if title, ok := vMap["title"].(string); ok {
				vuln.Title = title
			}
			if desc, ok := vMap["description"].(string); ok {
				vuln.Description = desc
			}
			if severity, ok := vMap["severity"].(string); ok {
				vuln.Severity = severity
			}

			vulns = append(vulns, vuln)
		}
	}

	report, _ := resp.Result["report"].(string)

	return vulns, report, nil
}

// PredictVulnerabilities uses ML to predict vulnerabilities
func (b *AIBridge) PredictVulnerabilities(scanData map[string]interface{}, useAI bool) ([]VulnerabilityPrediction, error) {
	params := map[string]interface{}{
		"scan_data": scanData,
		"use_ai":    useAI,
	}

	resp, err := b.SendRequest("predict_vulnerabilities", params)
	if err != nil {
		return nil, err
	}

	// Parse predictions with safe type assertions
	var predictions []VulnerabilityPrediction
	predsData, ok := resp.Result["predictions"].([]interface{})
	if ok {
		for _, p := range predsData {
			pMap, ok := p.(map[string]interface{})
			if !ok {
				// Skip invalid prediction entries
				continue
			}

			pred := VulnerabilityPrediction{}

			// Safe type assertions with zero-value fallbacks
			if vulnType, ok := pMap["vulnerability_type"].(string); ok {
				pred.VulnerabilityType = vulnType
			}
			if confidence, ok := pMap["confidence"].(float64); ok {
				pred.Confidence = confidence
			}
			if severity, ok := pMap["severity"].(string); ok {
				pred.Severity = severity
			}
			if reasoning, ok := pMap["reasoning"].(string); ok {
				pred.Reasoning = reasoning
			}

			predictions = append(predictions, pred)
		}
	}

	return predictions, nil
}

// CreateAgent creates an autonomous AI agent
func (b *AIBridge) CreateAgent(objective, target string, scope, constraints []string) (string, error) {
	params := map[string]interface{}{
		"objective":   objective,
		"target":      target,
		"scope":       scope,
		"constraints": constraints,
	}

	resp, err := b.SendRequest("create_agent", params)
	if err != nil {
		return "", err
	}

	taskID, ok := resp.Result["task_id"].(string)
	if !ok {
		return "", fmt.Errorf("invalid response format")
	}

	return taskID, nil
}

// AgentStatus gets the status of an autonomous agent
func (b *AIBridge) AgentStatus(taskID string) (map[string]interface{}, error) {
	params := map[string]interface{}{
		"task_id": taskID,
	}

	resp, err := b.SendRequest("agent_status", params)
	if err != nil {
		return nil, err
	}

	return resp.Result, nil
}

// ListProviders lists available AI providers
func (b *AIBridge) ListProviders() ([]string, string, error) {
	resp, err := b.SendRequest("list_providers", map[string]interface{}{})
	if err != nil {
		return nil, "", err
	}

	providersData, _ := resp.Result["providers"].([]interface{})
	var providers []string
	for _, p := range providersData {
		providers = append(providers, p.(string))
	}

	defaultProvider, _ := resp.Result["default"].(string)

	return providers, defaultProvider, nil
}

// Health checks the health of the AI engine
func (b *AIBridge) Health() (map[string]interface{}, error) {
	resp, err := b.SendRequest("health", map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	return resp.Result, nil
}

// StoreAPIKey stores an API key in the system keyring
func (b *AIBridge) StoreAPIKey(params map[string]interface{}) (map[string]interface{}, error) {
	resp, err := b.SendRequest("store_api_key", params)
	if err != nil {
		return nil, err
	}

	return resp.Result, nil
}

// GetConfiguredProviders lists configured AI providers
func (b *AIBridge) GetConfiguredProviders() (map[string]interface{}, error) {
	resp, err := b.SendRequest("get_configured_providers", map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	return resp.Result, nil
}
