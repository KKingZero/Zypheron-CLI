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
	DefaultSocketPath = "/tmp/zypheron-ai.sock"
	PythonEnginePath  = "../zypheron-ai/core/server.py"
	MaxRetries        = 5
	RetryDelay        = 2 * time.Second
)

// AIBridge manages communication with the Python AI engine
type AIBridge struct {
	socketPath    string
	pythonProcess *exec.Cmd
	connected     bool
	authToken     string
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

// NewAIBridge creates a new AI bridge instance
func NewAIBridge() *AIBridge {
	token, _ := loadAuthToken()
	return &AIBridge{
		socketPath: DefaultSocketPath,
		connected:  false,
		authToken:  token,
	}
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

	// Start Python server
	b.pythonProcess = exec.Command("python3", PythonEnginePath)
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

// Stop stops the Python AI engine
func (b *AIBridge) Stop() error {
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
	_, err := os.Stat(b.socketPath)
	if os.IsNotExist(err) {
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

// sendRequest sends a request to the Python AI engine
func (b *AIBridge) sendRequest(method string, params map[string]interface{}) (*Response, error) {
	if !b.connected && !b.IsRunning() {
		return nil, fmt.Errorf("AI engine not running - start it with: zypheron ai start")
	}

	// Connect to Unix socket
	conn, err := net.DialTimeout("unix", b.socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to AI engine: %w", err)
	}
	defer conn.Close()

	// Prepare request
	req := Request{
		Method:    method,
		Params:    params,
		AuthToken: b.authToken,
	}

	// Send request
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	decoder := json.NewDecoder(conn)
	var resp Response
	if err := decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("AI engine error: %s", resp.Error)
	}

	return &resp, nil
}

// Chat sends a chat request to the AI
func (b *AIBridge) Chat(messages []Message, provider string, temperature float64, maxTokens int) (string, error) {
	params := map[string]interface{}{
		"messages":    messages,
		"provider":    provider,
		"temperature": temperature,
		"max_tokens":  maxTokens,
	}

	resp, err := b.sendRequest("chat", params)
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

	resp, err := b.sendRequest("analyze_scan", params)
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

	resp, err := b.sendRequest("predict_vulnerabilities", params)
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

	resp, err := b.sendRequest("create_agent", params)
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

	resp, err := b.sendRequest("agent_status", params)
	if err != nil {
		return nil, err
	}

	return resp.Result, nil
}

// ListProviders lists available AI providers
func (b *AIBridge) ListProviders() ([]string, string, error) {
	resp, err := b.sendRequest("list_providers", map[string]interface{}{})
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
	resp, err := b.sendRequest("health", map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	return resp.Result, nil
}

// StoreAPIKey stores an API key in the system keyring
func (b *AIBridge) StoreAPIKey(params map[string]interface{}) (map[string]interface{}, error) {
	resp, err := b.sendRequest("store_api_key", params)
	if err != nil {
		return nil, err
	}

	return resp.Result, nil
}

// GetConfiguredProviders lists configured AI providers
func (b *AIBridge) GetConfiguredProviders() (map[string]interface{}, error) {
	resp, err := b.sendRequest("get_configured_providers", map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	return resp.Result, nil
}
