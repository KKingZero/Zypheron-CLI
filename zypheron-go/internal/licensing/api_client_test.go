package licensing

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockServer creates a test HTTP server for API testing
// This allows us to test API client behavior without hitting real endpoints
type mockServer struct {
	server   *httptest.Server
	handler  http.HandlerFunc
	requests []*http.Request
}

// newMockServer creates a new mock HTTP server
func newMockServer(t *testing.T, handler http.HandlerFunc) *mockServer {
	t.Helper()

	ms := &mockServer{
		handler:  handler,
		requests: make([]*http.Request, 0),
	}

	// Wrap handler to capture requests
	defer func() {
		if r := recover(); r != nil {
			panicText := fmt.Sprint(r)
			if strings.Contains(panicText, "failed to listen on a port") ||
				strings.Contains(panicText, "operation not permitted") {
				t.Skipf("Skipping network listener test: %s", panicText)
			}
			panic(r)
		}
	}()
	ms.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ms.requests = append(ms.requests, r)
		handler(w, r)
	}))

	return ms
}

func (ms *mockServer) Close() {
	ms.server.Close()
}

func (ms *mockServer) URL() string {
	return ms.server.URL
}

// TestRequestDeviceCode_Success tests successful device code request
func TestRequestDeviceCode_Success(t *testing.T) {
	resetManager()

	// Create mock server
	mockResp := DeviceCodeResponse{
		DeviceCode:      "test-device-code-123",
		UserCode:        "ABCD-1234",
		VerificationURL: "https://zypheron.io/activate",
		ExpiresIn:       300,
		Interval:        5,
	}

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and path
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/auth/device/code" {
			t.Errorf("Expected /api/v1/auth/device/code, got %s", r.URL.Path)
		}

		// Send successful response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResp)
	})
	defer server.Close()

	// Create client pointing to mock server
	client := &APIClient{
		baseURL:    server.URL() + "/api/v1",
		httpClient: &http.Client{},
		manager:    GetManager(),
	}

	// Request device code
	resp, err := client.RequestDeviceCode()
	if err != nil {
		t.Fatalf("RequestDeviceCode failed: %v", err)
	}

	// Verify response
	if resp.DeviceCode != mockResp.DeviceCode {
		t.Errorf("Expected device code %s, got %s", mockResp.DeviceCode, resp.DeviceCode)
	}
	if resp.UserCode != mockResp.UserCode {
		t.Errorf("Expected user code %s, got %s", mockResp.UserCode, resp.UserCode)
	}
	if resp.VerificationURL != mockResp.VerificationURL {
		t.Errorf("Expected verification URL %s, got %s", mockResp.VerificationURL, resp.VerificationURL)
	}
	if resp.ExpiresIn != mockResp.ExpiresIn {
		t.Errorf("Expected expires in %d, got %d", mockResp.ExpiresIn, resp.ExpiresIn)
	}
	if resp.Interval != mockResp.Interval {
		t.Errorf("Expected interval %d, got %d", mockResp.Interval, resp.Interval)
	}
}

// TestRequestDeviceCode_Error tests error handling for device code request
func TestRequestDeviceCode_Error(t *testing.T) {
	resetManager()

	// Create mock server that returns error
	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"detail": "Internal server error",
		})
	})
	defer server.Close()

	client := &APIClient{
		baseURL:    server.URL() + "/api/v1",
		httpClient: &http.Client{},
		manager:    GetManager(),
	}

	// Request device code
	_, err := client.RequestDeviceCode()
	if err == nil {
		t.Error("RequestDeviceCode should return error on server error")
	}
}

// TestPollDeviceAuth_Pending tests polling when authorization is pending
func TestPollDeviceAuth_Pending(t *testing.T) {
	resetManager()

	// Mock response for pending authorization
	mockResp := DeviceLoginResponse{
		Status: "pending",
	}

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/device/login" {
			t.Errorf("Expected /api/v1/auth/device/login, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResp)
	})
	defer server.Close()

	client := &APIClient{
		baseURL:    server.URL() + "/api/v1",
		httpClient: &http.Client{},
		manager:    GetManager(),
	}

	// Poll for device auth
	resp, err := client.PollDeviceAuth("test-device-code")
	if err != nil {
		t.Fatalf("PollDeviceAuth failed: %v", err)
	}

	// Verify response
	if resp.Status != "pending" {
		t.Errorf("Expected status pending, got %s", resp.Status)
	}

	// Session should not be set for pending status
	manager := GetManager()
	if manager.IsAuthenticated() {
		t.Error("Manager should not be authenticated for pending status")
	}
}

// TestPollDeviceAuth_Authorized tests successful device authorization
func TestPollDeviceAuth_Authorized(t *testing.T) {
	resetManager()

	// Mock response for authorized device
	mockResp := DeviceLoginResponse{
		Status:       "authorized",
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		UserID:       "user-123",
		Email:        "test@example.com",
	}

	// Track if license fetch was called
	licenseFetchCalled := false

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v1/auth/device/login" {
			json.NewEncoder(w).Encode(mockResp)
		} else if r.URL.Path == "/api/v1/license/validate" {
			licenseFetchCalled = true
			// Return valid license
			json.NewEncoder(w).Encode(LicenseValidationResponse{
				Valid:           true,
				Tier:            "pro",
				Status:          "active",
				TokensRemaining: 1000000,
				TokensLimit:     3000000,
				Features:        []string{"cloud_ai", "autopent"},
				ExpiresAt:       time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
			})
		}
	})
	defer server.Close()

	client := &APIClient{
		baseURL:    server.URL() + "/api/v1",
		httpClient: &http.Client{},
		manager:    GetManager(),
	}

	// Poll for device auth
	resp, err := client.PollDeviceAuth("test-device-code")
	if err != nil {
		t.Fatalf("PollDeviceAuth failed: %v", err)
	}

	// Verify response
	if resp.Status != "authorized" {
		t.Errorf("Expected status authorized, got %s", resp.Status)
	}
	if resp.AccessToken != mockResp.AccessToken {
		t.Errorf("Expected access token %s, got %s", mockResp.AccessToken, resp.AccessToken)
	}

	// Session should be set
	manager := GetManager()
	if !manager.IsAuthenticated() {
		t.Error("Manager should be authenticated after authorization")
	}

	session := manager.GetSession()
	if session == nil {
		t.Fatal("Session should not be nil after authorization")
	}
	if session.AccessToken != mockResp.AccessToken {
		t.Errorf("Expected session access token %s, got %s", mockResp.AccessToken, session.AccessToken)
	}
	if session.UserID != mockResp.UserID {
		t.Errorf("Expected user ID %s, got %s", mockResp.UserID, session.UserID)
	}

	// License fetch should have been called
	if !licenseFetchCalled {
		t.Error("License fetch should be called after authorization")
	}
}

// TestPollDeviceAuth_Expired tests expired device code
func TestPollDeviceAuth_Expired(t *testing.T) {
	resetManager()

	mockResp := DeviceLoginResponse{
		Status: "expired",
	}

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResp)
	})
	defer server.Close()

	client := &APIClient{
		baseURL:    server.URL() + "/api/v1",
		httpClient: &http.Client{},
		manager:    GetManager(),
	}

	// Poll for device auth
	resp, err := client.PollDeviceAuth("test-device-code")
	if err != nil {
		t.Fatalf("PollDeviceAuth failed: %v", err)
	}

	// Verify expired status
	if resp.Status != "expired" {
		t.Errorf("Expected status expired, got %s", resp.Status)
	}

	// Should not be authenticated
	if GetManager().IsAuthenticated() {
		t.Error("Manager should not be authenticated for expired device code")
	}
}

// TestAutoTokenRefresh tests automatic token refresh on 401
func TestAutoTokenRefresh(t *testing.T) {
	resetManager()

	requestCount := 0
	accessToken := "initial-token"

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		requestCount++

		if r.URL.Path == "/api/v1/license/validate" {
			// First request: return 401 (unauthorized)
			if requestCount == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"detail": "Token expired",
				})
				return
			}

			// Second request after refresh: return success
			json.NewEncoder(w).Encode(LicenseValidationResponse{
				Valid:           true,
				Tier:            "pro",
				TokensRemaining: 1000000,
				Features:        []string{"cloud_ai"},
				ExpiresAt:       time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
			})
		} else if r.URL.Path == "/api/v1/auth/refresh" {
			// Token refresh endpoint
			accessToken = "refreshed-token"
			json.NewEncoder(w).Encode(map[string]string{
				"access_token": accessToken,
				"token_type":   "Bearer",
			})
		}
	})
	defer server.Close()

	// Set up initial session with refresh token
	manager := GetManager()
	manager.SetSession(&AuthSession{
		AccessToken:  "initial-token",
		RefreshToken: "refresh-token-123",
		UserID:       "user-123",
		Email:        "test@example.com",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})

	client := &APIClient{
		baseURL:    server.URL() + "/api/v1",
		httpClient: &http.Client{},
		manager:    manager,
	}

	// Fetch license (should trigger auto-refresh)
	err := client.FetchLicense()
	if err != nil {
		t.Fatalf("FetchLicense should succeed after auto-refresh, got error: %v", err)
	}

	// Should have made 3 requests: initial (401), refresh, retry
	if requestCount < 2 {
		t.Errorf("Expected at least 2 requests (initial + refresh endpoint), got %d", requestCount)
	}

	// Access token should be refreshed
	session := manager.GetSession()
	if session.AccessToken != "refreshed-token" {
		t.Errorf("Expected access token to be refreshed to 'refreshed-token', got %s", session.AccessToken)
	}
}

// TestLogin_Success tests successful email/password login
func TestLogin_Success(t *testing.T) {
	resetManager()

	mockLoginResp := LoginResponse{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
	}
	mockLoginResp.User.ID = "user-123"
	mockLoginResp.User.Email = "test@example.com"
	mockLoginResp.User.DisplayName = "Test User"
	mockLoginResp.User.Tier = "pro"

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v1/auth/login" {
			// Verify login credentials
			var req LoginRequest
			json.NewDecoder(r.Body).Decode(&req)

			if req.Email != "test@example.com" || req.Password != "password123" {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"detail": "Invalid credentials"})
				return
			}

			json.NewEncoder(w).Encode(mockLoginResp)
		} else if r.URL.Path == "/api/v1/license/validate" {
			// Return license info
			json.NewEncoder(w).Encode(LicenseValidationResponse{
				Valid:           true,
				Tier:            "pro",
				TokensRemaining: 2000000,
				Features:        []string{"cloud_ai", "autopent"},
				ExpiresAt:       time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
			})
		}
	})
	defer server.Close()

	client := &APIClient{
		baseURL:    server.URL() + "/api/v1",
		httpClient: &http.Client{},
		manager:    GetManager(),
	}

	// Login
	resp, err := client.Login("test@example.com", "password123")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Verify response
	if resp.AccessToken != mockLoginResp.AccessToken {
		t.Errorf("Expected access token %s, got %s", mockLoginResp.AccessToken, resp.AccessToken)
	}
	if resp.User.Email != "test@example.com" {
		t.Errorf("Expected email test@example.com, got %s", resp.User.Email)
	}

	// Session should be set
	manager := GetManager()
	if !manager.IsAuthenticated() {
		t.Error("Manager should be authenticated after login")
	}
}

// TestFetchLicense_Success tests successful license fetching
func TestFetchLicense_Success(t *testing.T) {
	resetManager()

	mockLicense := LicenseValidationResponse{
		Valid:           true,
		Tier:            "enterprise",
		Status:          "active",
		TokensRemaining: 10000000,
		TokensUsed:      5000000,
		TokensLimit:     15000000,
		DevicesUsed:     3,
		DevicesLimit:    -1,
		Features:        []string{"cloud_ai", "autopent", "teams", "compliance"},
		ExpiresAt:       time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
		OfflineToken:    "offline-token-xyz",
	}

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer test-token" {
			t.Errorf("Expected Authorization: Bearer test-token, got %s", authHeader)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockLicense)
	})
	defer server.Close()

	// Set up authenticated session
	manager := GetManager()
	manager.SetSession(&AuthSession{
		AccessToken: "test-token",
		UserID:      "user-123",
		Email:       "test@example.com",
	})

	client := &APIClient{
		baseURL:    server.URL() + "/api/v1",
		httpClient: &http.Client{},
		manager:    manager,
	}

	// Fetch license
	err := client.FetchLicense()
	if err != nil {
		t.Fatalf("FetchLicense failed: %v", err)
	}

	// Verify license was stored
	license := manager.License()
	if license.Tier != TierEnterprise {
		t.Errorf("Expected tier Enterprise, got %v", license.Tier)
	}
	if license.TokensRemaining != mockLicense.TokensRemaining {
		t.Errorf("Expected tokens remaining %d, got %d", mockLicense.TokensRemaining, license.TokensRemaining)
	}
	if len(license.Features) != len(mockLicense.Features) {
		t.Errorf("Expected %d features, got %d", len(mockLicense.Features), len(license.Features))
	}
}

// TestReportUsage_Success tests usage reporting
func TestReportUsage_Success(t *testing.T) {
	resetManager()

	requestReceived := false

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/tokens/usage" {
			requestReceived = true

			// Verify request body
			var req map[string]interface{}
			json.NewDecoder(r.Body).Decode(&req)

			if req["tokens_used"] != float64(50000) {
				t.Errorf("Expected tokens_used 50000, got %v", req["tokens_used"])
			}
			if req["provider"] != "claude" {
				t.Errorf("Expected provider claude, got %v", req["provider"])
			}
			if req["endpoint"] != "autopent" {
				t.Errorf("Expected endpoint autopent, got %v", req["endpoint"])
			}

			w.WriteHeader(http.StatusOK)
		}
	})
	defer server.Close()

	manager := GetManager()
	manager.SetSession(&AuthSession{AccessToken: "test-token"})

	client := &APIClient{
		baseURL:    server.URL() + "/api/v1",
		httpClient: &http.Client{},
		manager:    manager,
	}

	// Report usage
	err := client.ReportUsage(50000, "claude", "autopent")
	if err != nil {
		t.Fatalf("ReportUsage failed: %v", err)
	}

	if !requestReceived {
		t.Error("Usage report request was not received by server")
	}
}

// TestRegisterDevice_Success tests device registration
func TestRegisterDevice_Success(t *testing.T) {
	resetManager()

	mockDevice := Device{
		ID:        "device-record-123",
		DeviceID:  "hash-abc123",
		Name:      "test-hostname",
		Platform:  "linux",
		LastSeen:  time.Now(),
		CreatedAt: time.Now(),
	}

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/devices/register" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(mockDevice)
		}
	})
	defer server.Close()

	manager := GetManager()
	manager.SetSession(&AuthSession{AccessToken: "test-token"})

	client := &APIClient{
		baseURL:    server.URL() + "/api/v1",
		httpClient: &http.Client{},
		manager:    manager,
	}

	// Register device
	device, err := client.RegisterDevice()
	if err != nil {
		t.Fatalf("RegisterDevice failed: %v", err)
	}

	if device.ID != mockDevice.ID {
		t.Errorf("Expected device ID %s, got %s", mockDevice.ID, device.ID)
	}
	if device.Platform != mockDevice.Platform {
		t.Errorf("Expected platform %s, got %s", mockDevice.Platform, device.Platform)
	}
}

// TestGetDevices_Success tests fetching device list
func TestGetDevices_Success(t *testing.T) {
	resetManager()

	mockDevices := []Device{
		{ID: "1", DeviceID: "dev-1", Name: "device-1", Platform: "linux"},
		{ID: "2", DeviceID: "dev-2", Name: "device-2", Platform: "darwin"},
	}

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"devices": mockDevices,
			"limit":   3,
		})
	})
	defer server.Close()

	manager := GetManager()
	manager.SetSession(&AuthSession{AccessToken: "test-token"})

	client := &APIClient{
		baseURL:    server.URL() + "/api/v1",
		httpClient: &http.Client{},
		manager:    manager,
	}

	// Get devices
	devices, err := client.GetDevices()
	if err != nil {
		t.Fatalf("GetDevices failed: %v", err)
	}

	if len(devices) != 2 {
		t.Errorf("Expected 2 devices, got %d", len(devices))
	}
	if devices[0].Name != "device-1" {
		t.Errorf("Expected first device name 'device-1', got %s", devices[0].Name)
	}
}

// TestHeartbeat_Success tests device heartbeat
func TestHeartbeat_Success(t *testing.T) {
	resetManager()

	heartbeatReceived := false

	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/devices/") && strings.HasSuffix(r.URL.Path, "/ping") {
			heartbeatReceived = true
			w.WriteHeader(http.StatusOK)
		}
	})
	defer server.Close()

	manager := GetManager()
	manager.SetSession(&AuthSession{AccessToken: "test-token"})

	client := &APIClient{
		baseURL:    server.URL() + "/api/v1",
		httpClient: &http.Client{},
		manager:    manager,
	}

	// Send heartbeat
	err := client.Heartbeat()
	if err != nil {
		t.Fatalf("Heartbeat failed: %v", err)
	}

	if !heartbeatReceived {
		t.Error("Heartbeat was not received by server")
	}
}

// TestWithRetry tests retry logic with exponential backoff
func TestWithRetry(t *testing.T) {
	attempts := 0
	maxAttempts := 3

	// Function that fails first 2 times, succeeds on 3rd
	fn := func() error {
		attempts++
		if attempts < maxAttempts {
			return fmt.Errorf("simulated failure attempt %d", attempts)
		}
		return nil
	}

	config := RetryConfig{
		MaxRetries:     2,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
		BackoffFactor:  2.0,
	}

	err := withRetry(config, fn)
	if err != nil {
		t.Fatalf("withRetry should succeed on 3rd attempt, got error: %v", err)
	}

	if attempts != maxAttempts {
		t.Errorf("Expected %d attempts, got %d", maxAttempts, attempts)
	}
}
