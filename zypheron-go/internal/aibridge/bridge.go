package aibridge

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
)

const (
	MaxRetries     = 5
	RetryDelay     = 2 * time.Second
	transportUnix  = "unix"
	transportTCP   = "tcp"
	transportStdio = "stdio"
)

// getPythonEnginePath returns the path to the Python AI engine
func getPythonEnginePath() string {
	// Check environment variable first
	if path := os.Getenv("ZYPHERON_AI_PATH"); path != "" {
		return path
	}

	// Prefer current workspace/project paths first.
	if cwd, err := os.Getwd(); err == nil {
		cwdPaths := []string{
			filepath.Join(cwd, "zypheron-ai", "core", "server.py"),
			filepath.Join(cwd, "..", "zypheron-ai", "core", "server.py"),
			filepath.Join(cwd, "..", "..", "zypheron-ai", "core", "server.py"),
		}
		for _, path := range cwdPaths {
			absPath, err := filepath.Abs(path)
			if err == nil {
				if _, err := os.Stat(absPath); err == nil {
					return absPath
				}
			}
		}
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
			// Development paths
			filepath.Join(exeDir, "..", "..", "Zypheron-CLI-Production", "zypheron-ai", "core", "server.py"),
			filepath.Join(exeDir, "..", "..", "Zypheron CLI", "zypheron-ai", "core", "server.py"),
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
			filepath.Join(homeDir, "Downloads", "Zypheron project", "Zypheron-CLI-Production", "zypheron-ai", "core", "server.py"),
			filepath.Join(homeDir, "Downloads", "Zypheron project", "Zypheron CLI", "zypheron-ai", "core", "server.py"),
			filepath.Join(homeDir, "Downloads", "Zypheron project", "Cobra-AI-Zypheron-CLI", "zypheron-ai", "core", "server.py"),
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
	venvPython := filepath.Join(aiEngineDir, ".venv", "bin", "python3")
	if _, err := os.Stat(venvPython); err == nil {
		return venvPython
	}

	venvPython = filepath.Join(aiEngineDir, ".venv", "bin", "python")
	if _, err := os.Stat(venvPython); err == nil {
		return venvPython
	}

	venvPython = filepath.Join(aiEngineDir, "venv", "bin", "python3")
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

// GetPythonEnginePath returns the resolved path to the AI engine entrypoint.
func GetPythonEnginePath() string {
	return getPythonEnginePath()
}

// GetPythonCommand returns the preferred Python interpreter for the AI engine.
func GetPythonCommand() string {
	return getPythonCommand(getPythonEnginePath())
}

// AIBridge manages communication with the Python AI engine
type AIBridge struct {
	transport     string
	endpoint      string
	socketPath    string
	pythonProcess *exec.Cmd
	pythonStdin   io.WriteCloser
	pythonStdout  *bufio.Reader
	connected     bool
	authToken     string

	// Connection pool for performance optimization
	connPool    *ConnectionPool
	usePool     bool // Enable/disable pooling for testing
	stdioMu     sync.Mutex
	lifecycleMu sync.Mutex
}

type ipcEndpointFile struct {
	Transport string `json:"transport"`
	Endpoint  string `json:"endpoint"`
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

	return "", fmt.Errorf("no running AI engine socket found in %s.\n  The AI engine is not currently running.\n  How to fix:\n    1. Start the AI engine: zypheron ai start\n    2. Or run scans without AI: zypheron scan <target> --no-ai\n    3. Check AI status: zypheron ai status", socketDir)
}

func getIPCEndpointFilePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(homeDir, ".zypheron", "ipc.endpoint.json"), nil
}

func readIPCEndpointFile() (*ipcEndpointFile, error) {
	path, err := getIPCEndpointFilePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ep ipcEndpointFile
	if err := json.Unmarshal(data, &ep); err != nil {
		return nil, fmt.Errorf("failed to parse endpoint file: %w", err)
	}
	ep.Transport = strings.TrimSpace(strings.ToLower(ep.Transport))
	ep.Endpoint = strings.TrimSpace(ep.Endpoint)
	if ep.Transport == "" || ep.Endpoint == "" {
		return nil, fmt.Errorf("invalid endpoint file contents")
	}
	return &ep, nil
}

func discoverRunningEndpoint() (string, string, error) {
	// Prefer explicit endpoint file written by Python engine.
	if ep, err := readIPCEndpointFile(); err == nil {
		switch ep.Transport {
		case transportStdio:
			return transportStdio, ep.Endpoint, nil
		case transportTCP:
			conn, err := net.DialTimeout("tcp", ep.Endpoint, 1*time.Second)
			if err == nil {
				conn.Close()
				return transportTCP, ep.Endpoint, nil
			}
		case transportUnix:
			if err := validateSocketOwnership(ep.Endpoint); err == nil {
				conn, err := net.DialTimeout("unix", ep.Endpoint, 1*time.Second)
				if err == nil {
					conn.Close()
					return transportUnix, ep.Endpoint, nil
				}
			}
		}
	}

	// Backward compatibility fallback: discover Unix socket directly.
	socketPath, err := getSecureSocketPath()
	if err != nil {
		return "", "", err
	}
	return transportUnix, socketPath, nil
}

// validateSocketOwnership is implemented in socket_validation_*.go (platform-specific)

// loadAuthToken loads the authentication token from file
func loadAuthToken() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	tokenFile := filepath.Join(homeDir, ".zypheron", "ipc.token")
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("failed to read authentication token: %w.\n  The AI engine may not have been started yet.\n  How to fix:\n    1. Start the AI engine: zypheron ai start\n    2. If the problem persists, restart the AI engine: zypheron ai restart", err)
	}

	return strings.TrimSpace(string(data)), nil
}

// NewAIBridge creates a new AI bridge instance with connection pooling
func NewAIBridge() *AIBridge {
	// Load auth token with proper error handling
	token, err := loadAuthToken()
	if err != nil {
		// Token will be loaded later when AI engine is started or on first request
		fmt.Println(ui.Muted.Sprint("Auth token not loaded yet (AI engine may not be running)"))
		token = ""
	}

	// Try to find running endpoint
	transport, endpoint, err := discoverRunningEndpoint()
	if err != nil {
		// Default to stdio transport for in-process persistent AI engine.
		transport = transportStdio
		endpoint = transportStdio
	}

	bridge := &AIBridge{
		transport: transport,
		endpoint:  endpoint,
		connected: false,
		authToken: token,
		usePool:   true, // Enable connection pooling by default
	}

	// Keep legacy field in sync for Unix transport.
	if bridge.transport == transportUnix {
		bridge.socketPath = bridge.endpoint
	}

	// Initialize connection pool only for Unix transport.
	if bridge.transport == transportUnix && bridge.socketPath != "" {
		bridge.connPool = NewConnectionPool(bridge.socketPath, DefaultPoolSize)
	}

	return bridge
}

// Start starts the Python AI engine
func (b *AIBridge) Start() error {
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()

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
			"  The AI engine Python files are missing.\n"+
			"  How to fix:\n"+
			"    1. Ensure zypheron-ai directory exists in your installation\n"+
			"    2. Reinstall Zypheron if needed\n"+
			"    3. Or set ZYPHERON_AI_PATH to point to server.py\n"+
			"  Example: export ZYPHERON_AI_PATH=/path/to/zypheron-ai/core/server.py", pythonPath)
	}

	fmt.Println(ui.Muted.Sprint(fmt.Sprintf("  Using AI engine at: %s", pythonPath)))

	// Find Python interpreter (prefer venv if it exists)
	pythonCmd := getPythonCommand(pythonPath)

	fmt.Println(ui.Muted.Sprint(fmt.Sprintf("  Using Python: %s", pythonCmd)))

	// Set working directory to zypheron-ai root (parent of core/)
	serverDir := filepath.Dir(pythonPath)
	aiEngineDir := filepath.Dir(serverDir)

	fmt.Println(ui.Muted.Sprint(fmt.Sprintf("  Working directory: %s", aiEngineDir)))

	// Start Python server in stdio mode.
	b.pythonProcess = exec.Command(pythonCmd, pythonPath)
	b.pythonProcess.Dir = aiEngineDir // Set working directory
	b.pythonProcess.Env = append(os.Environ(), "IPC_TRANSPORT=stdio")

	stdoutPipe, err := b.pythonProcess.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to capture AI stdout pipe: %w", err)
	}
	stdinPipe, err := b.pythonProcess.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to capture AI stdin pipe: %w", err)
	}
	// Avoid corrupting TUI rendering with provider init logs in normal mode.
	// Keep stderr visible when debug mode is explicitly enabled.
	if os.Getenv("ZYPHERON_DEBUG") == "1" {
		b.pythonProcess.Stderr = os.Stderr
	} else {
		b.pythonProcess.Stderr = io.Discard
	}

	if err := b.pythonProcess.Start(); err != nil {
		return fmt.Errorf("failed to start AI engine: %w.\n  Possible causes:\n    1. Python not installed or not in PATH\n    2. Missing Python dependencies (loguru, etc.)\n    3. Permission issues\n  How to fix:\n    1. Install Python: sudo apt-get install python3\n    2. Install dependencies: pip3 install -r zypheron-ai/requirements.txt\n    3. Check Python version: python3 --version (needs 3.8+)", err)
	}

	b.pythonStdout = bufio.NewReader(stdoutPipe)
	b.pythonStdin = stdinPipe
	b.transport = transportStdio
	b.endpoint = transportStdio
	b.socketPath = ""
	b.connPool = nil

	// Wait for server to be ready
	for i := 0; i < MaxRetries; i++ {
		time.Sleep(RetryDelay)
		if b.IsRunning() {
			token, err := loadAuthToken()
			if err != nil {
				fmt.Printf(".")
				continue
			}
			b.authToken = token
			b.connected = true

			ui.Success.Println("AI Engine started successfully")
			return nil
		}
		fmt.Printf(".")
	}

	return fmt.Errorf("AI engine failed to start after %d retries.\n  The AI engine process started but is not responding.\n  Possible causes:\n    1. Python dependencies missing\n    2. Port/socket permissions issue\n    3. AI engine crashed during startup\n  How to fix:\n    1. Check AI engine logs in ~/.zypheron/logs/\n    2. Install Python dependencies: cd zypheron-ai && pip3 install -r requirements.txt\n    3. Try manual start for debugging: cd zypheron-ai && python3 core/server.py", MaxRetries)
}

// Stop stops the Python AI engine and closes connection pool
func (b *AIBridge) Stop() error {
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()

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
		b.pythonProcess = nil
		b.pythonStdout = nil
		b.pythonStdin = nil
		b.connected = false
		ui.Success.Println("AI Engine stopped")
	}
	return nil
}

func (b *AIBridge) processAlive() bool {
	if b.pythonProcess == nil || b.pythonProcess.Process == nil {
		return false
	}
	if err := b.pythonProcess.Process.Signal(syscall.Signal(0)); err != nil {
		return false
	}
	return true
}

// IsRunning checks if the AI engine is running
func (b *AIBridge) IsRunning() bool {
	tryCurrentEndpoint := func() bool {
		if b.transport == transportStdio {
			return b.processAlive()
		}

		var conn net.Conn
		var err error
		switch b.transport {
		case transportTCP:
			conn, err = net.DialTimeout("tcp", b.endpoint, 1*time.Second)
		case transportUnix:
			// Validate ownership for Unix sockets.
			if err := validateSocketOwnership(b.endpoint); err != nil {
				return false
			}
			conn, err = net.DialTimeout("unix", b.endpoint, 1*time.Second)
		default:
			return false
		}
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}

	// For stdio transport we only need process liveness.
	if b.transport == transportStdio && b.endpoint == transportStdio {
		return tryCurrentEndpoint()
	}

	// Try to find endpoint if we don't have one.
	if b.endpoint == "" {
		transport, endpoint, err := discoverRunningEndpoint()
		if err != nil {
			return false
		}
		b.transport = transport
		b.endpoint = endpoint
		if b.transport == transportUnix {
			b.socketPath = b.endpoint
		}
	}

	if tryCurrentEndpoint() {
		return true
	}

	// For stdio transport, don't endpoint-discover; process either lives or not.
	if b.transport == transportStdio {
		return false
	}

	// Endpoint may be stale (e.g. TCP ephemeral port after restart). Re-discover once.
	transport, endpoint, err := discoverRunningEndpoint()
	if err != nil {
		return false
	}
	b.transport = transport
	b.endpoint = endpoint
	if b.transport == transportUnix {
		b.socketPath = b.endpoint
	}

	return tryCurrentEndpoint()
}

// SendRequest sends a request to the Python AI engine (with connection pooling)
func (b *AIBridge) SendRequest(method string, params map[string]interface{}) (*Response, error) {
	if !b.IsRunning() {
		if err := b.Start(); err != nil {
			return nil, fmt.Errorf("AI engine not running and failed to auto-start: %w", err)
		}
	}

	if b.authToken == "" {
		token, err := loadAuthToken()
		if err != nil {
			return nil, fmt.Errorf("failed to load AI auth token: %w", err)
		}
		b.authToken = token
	}

	// Stdio transport: in-process persistent IPC over stdin/stdout.
	if b.transport == transportStdio {
		if b.pythonStdin == nil || b.pythonStdout == nil {
			return nil, fmt.Errorf("AI stdio transport not initialized")
		}

		b.stdioMu.Lock()
		defer b.stdioMu.Unlock()

		req := Request{
			Method:    method,
			Params:    params,
			AuthToken: b.authToken,
		}

		encoder := json.NewEncoder(b.pythonStdin)
		if err := encoder.Encode(req); err != nil {
			return nil, fmt.Errorf("failed to send stdio request: %w", err)
		}

		line, err := b.pythonStdout.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read stdio response: %w", err)
		}

		var resp Response
		if err := json.Unmarshal(line, &resp); err != nil {
			return nil, fmt.Errorf("failed to decode stdio response: %w", err)
		}
		if !resp.Success {
			if strings.Contains(resp.Error, "Request too large") {
				return nil, fmt.Errorf("AI engine error: %s\n  Tip: Reduce prompt size or tool output, or increase IPC_MAX_REQUEST_BYTES.", resp.Error)
			}
			return nil, fmt.Errorf("AI engine error: %s", resp.Error)
		}
		return &resp, nil
	}

	// Initialize pool only for Unix transport.
	if b.usePool && b.transport == transportUnix && b.connPool == nil && b.socketPath != "" {
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
		switch b.transport {
		case transportTCP:
			conn, err = net.DialTimeout("tcp", b.endpoint, 5*time.Second)
			if err != nil {
				return nil, fmt.Errorf("failed to connect to AI engine over tcp (%s): %w", b.endpoint, err)
			}
		case transportUnix:
			// Validate socket ownership before connecting.
			if err := validateSocketOwnership(b.socketPath); err != nil {
				return nil, fmt.Errorf("socket security validation failed: %w", err)
			}
			conn, err = net.DialTimeout("unix", b.socketPath, 5*time.Second)
			if err != nil {
				return nil, fmt.Errorf("failed to connect to AI engine over unix socket (%s): %w", b.socketPath, err)
			}
		default:
			return nil, fmt.Errorf("unknown AI transport: %q", b.transport)
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
		if strings.Contains(resp.Error, "Request too large") {
			return nil, fmt.Errorf("AI engine error: %s\n  Tip: Reduce prompt size or tool output, or increase IPC_MAX_REQUEST_BYTES.", resp.Error)
		}
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

// Chat sends a chat request to the AI engine.
func (b *AIBridge) Chat(messages []Message, provider string, model string, temperature float64, maxTokens int) (string, error) {
	params := map[string]interface{}{
		"messages":    messages,
		"provider":    provider,
		"temperature": temperature,
		"max_tokens":  maxTokens,
	}
	if strings.TrimSpace(model) != "" {
		params["model"] = model
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

	// Safe type assertion with check
	var providers []string
	if providersData, ok := resp.Result["providers"].([]interface{}); ok {
		for _, p := range providersData {
			if provider, ok := p.(string); ok {
				providers = append(providers, provider)
			} else {
				fmt.Println(ui.WarningMsg(fmt.Sprintf("Skipping invalid provider type: %T", p)))
			}
		}
	}

	// Safe type assertion for default provider
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

// ValidateAPIKey validates an API key without storing it.
func (b *AIBridge) ValidateAPIKey(params map[string]interface{}) (map[string]interface{}, error) {
	resp, err := b.SendRequest("validate_api_key", params)
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

// ParseIntent parses natural language query to extract intent
func (b *AIBridge) ParseIntent(query string) (map[string]interface{}, error) {
	params := map[string]interface{}{
		"query": query,
	}

	resp, err := b.SendRequest("parse_intent", params)
	if err != nil {
		return nil, err
	}

	return resp.Result, nil
}

// AnalyzeMultiToolResults analyzes aggregated results from multiple tools
func (b *AIBridge) AnalyzeMultiToolResults(aggregatedData map[string]interface{}, analysisType, userQuery string, provider string) (string, error) {
	params := map[string]interface{}{
		"aggregated_data": aggregatedData,
		"analysis_type":   analysisType,
		"user_query":      userQuery,
		"provider":        provider,
	}

	resp, err := b.SendRequest("analyze_multi_tool_results", params)
	if err != nil {
		return "", err
	}

	summary, ok := resp.Result["summary"].(string)
	if !ok {
		return "", fmt.Errorf("invalid response format: missing summary")
	}

	return summary, nil
}
