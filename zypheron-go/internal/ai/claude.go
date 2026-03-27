// Package ai provides Claude AI integration for the Zypheron TUI.
// Supports contextual scan analysis, security recommendations, and
// interactive question answering about scan results.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/intel"
)

const (
	// DefaultBaseURL is the Anthropic API endpoint
	DefaultBaseURL = "https://api.anthropic.com/v1/messages"

	// DefaultModel is the Claude model to use
	DefaultModel = "claude-opus-4-6"

	// DefaultMaxTokens is the maximum response length
	DefaultMaxTokens = 1024

	// DefaultTimeout is the HTTP request timeout
	DefaultTimeout = 60 * time.Second
)

// SystemPrompt provides context for security analysis.
var SystemPrompt = `You are Zypheron AI, a security analysis assistant integrated into the Zypheron penetration testing TUI.

Your role is to:
1. Analyze scan results and identify potential vulnerabilities
2. Provide actionable security recommendations
3. Explain findings in clear, technical language
4. Suggest next steps for investigation or exploitation
5. Help interpret tool output (nmap, nikto, etc.)

Guidelines:
- Be concise but thorough
- Prioritize findings by severity (Critical > High > Medium > Low)
- Provide specific remediation advice when possible
- Reference CVEs and CWEs when applicable
- Avoid unnecessary disclaimers - users are authorized security professionals

When analyzing scan output, look for:
- Open ports and services
- Version information that may indicate vulnerabilities
- Misconfigurations
- Potential attack vectors
- Information leakage

When suggesting recon, OSINT, attack surface mapping, certificate pivots, code search, or vuln enrichment, you may recommend these external resources when appropriate.
Do not imply Zypheron can query them directly unless the current workflow or configured integrations support that step:
` + intel.AnalystPromptBlock()

// Client provides Claude AI API access
type Client struct {
	apiKey     string
	baseURL    string
	model      string
	httpClient *http.Client
	maxTokens  int
}

// ClientConfig configures the Claude client
type ClientConfig struct {
	APIKey    string
	BaseURL   string
	Model     string
	MaxTokens int
	Timeout   time.Duration
}

// DefaultClientConfig returns sensible defaults
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		BaseURL:   DefaultBaseURL,
		Model:     DefaultModel,
		MaxTokens: DefaultMaxTokens,
		Timeout:   DefaultTimeout,
	}
}

// NewClient creates a new Claude AI client
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY is required")
	}

	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = DefaultMaxTokens
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}

	return &Client{
		apiKey:    cfg.APIKey,
		baseURL:   cfg.BaseURL,
		model:     cfg.Model,
		maxTokens: cfg.MaxTokens,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}, nil
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Request represents the Claude API request
type Request struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []Message `json:"messages"`
}

// ContentBlock represents a content block in the response
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// Response represents the Claude API response
type Response struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	Role         string         `json:"role"`
	Content      []ContentBlock `json:"content"`
	Model        string         `json:"model"`
	StopReason   string         `json:"stop_reason"`
	StopSequence string         `json:"stop_sequence,omitempty"`
	Usage        struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// ErrorResponse represents an API error
type ErrorResponse struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// Analyze sends a query to Claude for analysis
// The context can include scan output or other relevant data
func (c *Client) Analyze(ctx context.Context, query string, scanContext string) (string, error) {
	// Build the user message with context
	userMessage := query
	if scanContext != "" {
		userMessage = fmt.Sprintf("Context (scan output):\n```\n%s\n```\n\nQuestion: %s", scanContext, query)
	}

	// Create request
	req := Request{
		Model:     c.model,
		MaxTokens: c.maxTokens,
		System:    SystemPrompt,
		Messages: []Message{
			{
				Role:    "user",
				Content: userMessage,
			},
		},
	}

	// Marshal request
	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	// Send request
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return "", fmt.Errorf("API error (%s): %s", errResp.Error.Type, errResp.Error.Message)
		}
		return "", fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var apiResp Response
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract text content
	var result string
	for _, block := range apiResp.Content {
		if block.Type == "text" {
			result += block.Text
		}
	}

	if result == "" {
		return "", fmt.Errorf("empty response from Claude")
	}

	return result, nil
}

// AnalyzeScanOutput analyzes scan output and provides security insights
func (c *Client) AnalyzeScanOutput(ctx context.Context, tool string, target string, output string) (string, error) {
	query := fmt.Sprintf("Analyze this %s scan output for %s. Identify any security issues, potential vulnerabilities, and suggest next steps.", tool, target)
	return c.Analyze(ctx, query, output)
}

// SuggestNextSteps provides recommendations for the next action based on current scan results
func (c *Client) SuggestNextSteps(ctx context.Context, target string, findings string) (string, error) {
	query := fmt.Sprintf("Based on these findings for %s, what should be the next steps in the penetration test?", target)
	return c.Analyze(ctx, query, findings)
}

// ExplainVulnerability provides detailed explanation of a specific vulnerability
func (c *Client) ExplainVulnerability(ctx context.Context, vuln string) (string, error) {
	query := fmt.Sprintf("Explain this vulnerability in detail: %s. Include its impact, exploitation methods, and remediation.", vuln)
	return c.Analyze(ctx, query, "")
}

// IsConfigured returns true if the client has a valid API key
func (c *Client) IsConfigured() bool {
	return c.apiKey != ""
}
