// Package licensing provides API client for Zypheron backend
package licensing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

// APIClient handles communication with Zypheron backend
type APIClient struct {
	baseURL    string
	httpClient *http.Client
	manager    *LicenseManager
}

// API endpoints
const (
	DefaultAPIURL = "https://api.zypheron.net"
)

// NewAPIClient creates a new API client
func NewAPIClient() *APIClient {
	baseURL := os.Getenv("ZYPHERON_API_URL")
	if baseURL == "" {
		baseURL = DefaultAPIURL
	}

	return &APIClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		manager: GetManager(),
	}
}

// ============ Authentication ============

// LoginRequest represents login credentials
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse represents login result
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	User         struct {
		ID          string `json:"id"`
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Tier        string `json:"tier"`
	} `json:"user"`
}

// Login authenticates with email and password
func (c *APIClient) Login(email, password string) (*LoginResponse, error) {
	req := LoginRequest{Email: email, Password: password}

	var resp LoginResponse
	if err := c.post("/auth/login", req, &resp); err != nil {
		return nil, err
	}

	// Store session
	session := &AuthSession{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour), // 30 days
		UserID:       resp.User.ID,
		Email:        resp.User.Email,
	}
	c.manager.SetSession(session)

	// Fetch and store license
	if err := c.FetchLicense(); err != nil {
		// Non-fatal - we can work with session only
		fmt.Fprintf(os.Stderr, "Warning: Could not fetch license: %v\n", err)
	}

	return &resp, nil
}

// DeviceCodeResponse contains the full device code flow response
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// DeviceLoginRequest for CLI device authentication
type DeviceLoginRequest struct {
	DeviceCode string            `json:"device_code"`
	DeviceInfo map[string]string `json:"device_info"`
}

// DeviceLoginResponse for CLI device authentication
type DeviceLoginResponse struct {
	Status       string `json:"status"` // pending, authorized, expired
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	Email        string `json:"email,omitempty"`
}

// RequestDeviceCode initiates device auth flow and returns full response
func (c *APIClient) RequestDeviceCode() (*DeviceCodeResponse, error) {
	hostname, _ := os.Hostname()

	req := map[string]interface{}{
		"device_info": map[string]string{
			"platform":    runtime.GOOS,
			"hostname":    hostname,
			"device_name": fmt.Sprintf("%s on %s", hostname, runtime.GOOS),
		},
	}

	var resp DeviceCodeResponse

	if err := c.post("/auth/device/code", req, &resp); err != nil {
		return nil, err
	}

	// Set default interval if not provided by API
	if resp.Interval == 0 {
		resp.Interval = 5 // Default to 5 seconds
	}

	return &resp, nil
}

// PollDeviceAuth polls for device authentication completion
func (c *APIClient) PollDeviceAuth(deviceCode string) (*DeviceLoginResponse, error) {
	hostname, _ := os.Hostname()

	req := DeviceLoginRequest{
		DeviceCode: deviceCode,
		DeviceInfo: map[string]string{
			"platform":    runtime.GOOS,
			"hostname":    hostname,
			"device_name": fmt.Sprintf("%s on %s", hostname, runtime.GOOS),
		},
	}

	var resp DeviceLoginResponse
	if err := c.post("/auth/device/login", req, &resp); err != nil {
		return nil, err
	}

	if resp.Status == "authorized" {
		// Store session
		session := &AuthSession{
			AccessToken:  resp.AccessToken,
			RefreshToken: resp.RefreshToken,
			ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
			UserID:       resp.UserID,
			Email:        resp.Email,
		}
		c.manager.SetSession(session)

		// Fetch license
		c.FetchLicense()
	}

	return &resp, nil
}

// RefreshToken refreshes the access token
func (c *APIClient) RefreshToken() error {
	session := c.manager.GetSession()
	if session == nil || session.RefreshToken == "" {
		return &NotAuthenticatedError{Message: "no refresh token available"}
	}

	req := map[string]string{
		"refresh_token": session.RefreshToken,
	}

	var resp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}

	if err := c.post("/auth/refresh", req, &resp); err != nil {
		return err
	}

	session.AccessToken = resp.AccessToken
	session.ExpiresAt = time.Now().Add(30 * 24 * time.Hour)
	c.manager.SetSession(session)

	return nil
}

// ============ License ============

// LicenseValidationResponse from API
type LicenseValidationResponse struct {
	Valid           bool     `json:"valid"`
	Tier            string   `json:"tier"`
	Status          string   `json:"status"`
	TokensRemaining int64    `json:"tokens_remaining"`
	TokensUsed      int64    `json:"tokens_used"`
	TokensLimit     int64    `json:"tokens_limit"`
	DevicesUsed     int      `json:"devices_used"`
	DevicesLimit    int      `json:"devices_limit"`
	Features        []string `json:"features"`
	ExpiresAt       string   `json:"expires_at"`
	OfflineToken    string   `json:"offline_token,omitempty"`
}

// FetchLicense retrieves current license from API
func (c *APIClient) FetchLicense() error {
	var resp LicenseValidationResponse

	if err := c.get("/license/validate", &resp); err != nil {
		return err
	}

	if !resp.Valid {
		return fmt.Errorf("license not valid")
	}

	// Parse expiry
	expiresAt, _ := time.Parse(time.RFC3339, resp.ExpiresAt)

	// Convert features
	features := make([]Feature, len(resp.Features))
	for i, f := range resp.Features {
		features[i] = Feature(f)
	}

	session := c.manager.GetSession()
	email := ""
	userID := ""
	if session != nil {
		email = session.Email
		userID = session.UserID
	}

	license := &License{
		UserID:          userID,
		Email:           email,
		Tier:            Tier(resp.Tier),
		Features:        features,
		TokensRemaining: resp.TokensRemaining,
		TokensUsed:      resp.TokensUsed,
		TokensLimit:     resp.TokensLimit,
		ExpiresAt:       expiresAt,
		IssuedAt:        time.Now(),
		DeviceID:        c.manager.GetDeviceID(),
		OfflineDays:     TierConfigs[Tier(resp.Tier)].OfflineDays,
	}

	c.manager.SetLicense(license)
	return nil
}

// GetOfflineToken requests an offline validation token
func (c *APIClient) GetOfflineToken() (string, error) {
	var resp struct {
		OfflineToken string `json:"offline_token"`
		ValidUntil   string `json:"valid_until"`
	}

	if err := c.get("/license/offline-token", &resp); err != nil {
		return "", err
	}

	return resp.OfflineToken, nil
}

// ReportUsage reports token usage to the API
func (c *APIClient) ReportUsage(tokens int64, provider, action string) error {
	req := map[string]interface{}{
		"tokens_used": tokens,
		"provider":    provider,
		"endpoint":    action,
	}

	return c.post("/tokens/usage", req, nil)
}

// ============ Devices ============

// RegisterDevice registers this device with the API
func (c *APIClient) RegisterDevice() (*Device, error) {
	hostname, _ := os.Hostname()

	req := map[string]interface{}{
		"device_info": map[string]string{
			"device_id":   c.manager.GetDeviceID(),
			"device_name": hostname,
			"platform":    runtime.GOOS,
			"hostname":    hostname,
		},
	}

	var resp Device
	if err := c.post("/devices/register", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetDevices returns all registered devices
func (c *APIClient) GetDevices() ([]Device, error) {
	var resp struct {
		Devices []Device `json:"devices"`
		Limit   int      `json:"limit"`
	}

	if err := c.get("/devices", &resp); err != nil {
		return nil, err
	}

	return resp.Devices, nil
}

// Heartbeat sends a device heartbeat
func (c *APIClient) Heartbeat() error {
	req := map[string]string{
		"device_id": c.manager.GetDeviceID(),
	}

	return c.post("/devices/"+c.manager.GetDeviceID()+"/ping", req, nil)
}

// ============ HTTP helpers ============

func (c *APIClient) get(path string, result interface{}) error {
	return c.request("GET", path, nil, result)
}

func (c *APIClient) post(path string, body interface{}, result interface{}) error {
	return c.request("POST", path, body, result)
}

func (c *APIClient) request(method, path string, body interface{}, result interface{}) error {
	return c.doRequest(method, path, body, result, false)
}

func (c *APIClient) doRequest(method, path string, body interface{}, result interface{}, isRetry bool) error {
	url := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Zypheron-CLI/1.0")

	// Add auth header if we have a session
	session := c.manager.GetSession()
	if session != nil && session.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+session.AccessToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check for errors
	if resp.StatusCode >= 400 {
		// Handle 401 Unauthorized - try token refresh (once only)
		if resp.StatusCode == http.StatusUnauthorized && !isRetry && !strings.Contains(path, "/auth/refresh") {
			if refreshErr := c.RefreshToken(); refreshErr == nil {
				return c.doRequest(method, path, body, result, true)
			}
		}

		var errResp struct {
			Detail string `json:"detail"`
		}
		json.Unmarshal(respBody, &errResp)
		if errResp.Detail != "" {
			return fmt.Errorf("API error (%d): %s", resp.StatusCode, errResp.Detail)
		}
		return fmt.Errorf("API error: %d", resp.StatusCode)
	}

	// Parse result if provided
	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}

// ============ Sync Functions ============

// RetryConfig defines retry behavior
type RetryConfig struct {
	MaxRetries     int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	BackoffFactor  float64
}

// DefaultRetryConfig provides sensible defaults
var DefaultRetryConfig = RetryConfig{
	MaxRetries:     3,
	InitialBackoff: 1 * time.Second,
	MaxBackoff:     30 * time.Second,
	BackoffFactor:  2.0,
}

// withRetry executes a function with exponential backoff
func withRetry(config RetryConfig, fn func() error) error {
	var lastErr error
	backoff := config.InitialBackoff

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff = time.Duration(float64(backoff) * config.BackoffFactor)
			if backoff > config.MaxBackoff {
				backoff = config.MaxBackoff
			}
		}

		if err := fn(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}

	return fmt.Errorf("failed after %d retries: %w", config.MaxRetries+1, lastErr)
}

// SyncLicense synchronizes license with server with retry logic
func SyncLicense() error {
	client := NewAPIClient()
	manager := GetManager()

	if !manager.IsAuthenticated() {
		return nil // No session to sync
	}

	// Try to fetch license with retries
	err := withRetry(DefaultRetryConfig, func() error {
		if err := client.FetchLicense(); err != nil {
			// If we get 401, try refreshing token first
			if refreshErr := client.RefreshToken(); refreshErr != nil {
				return refreshErr
			}
			// Retry license fetch after token refresh
			return client.FetchLicense()
		}
		return nil
	})

	if err != nil {
		// Mark as offline mode but don't fail completely
		manager.mu.Lock()
		manager.offlineMode = true
		manager.mu.Unlock()
	}

	return err
}

// SyncLicenseAsync synchronizes license in background without blocking
func SyncLicenseAsync() {
	go func() {
		if err := SyncLicense(); err != nil {
			// Log but don't propagate error - we're in background
			fmt.Fprintf(os.Stderr, "Background license sync failed: %v\n", err)
		}
	}()
}

// RegisterCurrentDevice registers this device with the server
func RegisterCurrentDevice() error {
	client := NewAPIClient()
	manager := GetManager()

	if !manager.IsAuthenticated() {
		return nil
	}

	_, err := client.RegisterDevice()
	return err
}

// SendHeartbeat sends a heartbeat to keep device active
func SendHeartbeat() error {
	client := NewAPIClient()
	return client.Heartbeat()
}
