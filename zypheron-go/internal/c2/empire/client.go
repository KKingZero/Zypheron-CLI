package empire

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

var (
	userInfoRe = regexp.MustCompile(`(://)[^/@\s"]+@`)
	queryRe    = regexp.MustCompile(`(\?)[^\s"]+`)
)

const (
	maxResponseBytes = 4 << 20 // 4 MiB
	maxErrorBodyLen  = 512     // bytes of response body included in error messages
)

// Client talks to the Empire REST API. Created lazily so CLI startup has no
// Empire dependency. Safe for concurrent use — token access is mutex-guarded.
type Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client

	mu    sync.Mutex
	token string
}

// NewFromEnv creates an Empire client from EMPIRE_HOST, EMPIRE_USER, EMPIRE_PASS.
func NewFromEnv() (*Client, error) {
	host := strings.TrimSpace(os.Getenv("EMPIRE_HOST"))
	user := strings.TrimSpace(os.Getenv("EMPIRE_USER"))
	pass := os.Getenv("EMPIRE_PASS")
	if host == "" || user == "" || pass == "" {
		return nil, errors.New("Empire RPC requires EMPIRE_HOST, EMPIRE_USER, and EMPIRE_PASS")
	}

	baseURL, err := normalizeBaseURL(host)
	if err != nil {
		return nil, err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if os.Getenv("EMPIRE_INSECURE_TLS") == "1" {
		if !hostIsLocalOrPrivate(baseURL) {
			fmt.Fprintln(os.Stderr,
				"WARNING: EMPIRE_INSECURE_TLS=1 with a non-local/non-RFC1918 host disables TLS verification across the public internet.")
		}
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in for lab TLS
	}

	return &Client{
		baseURL:  baseURL,
		username: user,
		password: pass,
		// No httpClient.Timeout — callers pass a context.Context with their
		// own deadline (avoids ensureToken eating the caller's budget).
		httpClient: &http.Client{Transport: transport},
	}, nil
}

// ListAgents returns the raw Empire agents response as formatted JSON.
func (c *Client) ListAgents(ctx context.Context) (string, error) {
	body, err := c.do(ctx, http.MethodGet, "/api/agents", nil)
	if err != nil {
		return "", err
	}
	return prettyJSON(body), nil
}

// StartListener requests an Empire listener with a small default option set.
func (c *Client) StartListener(ctx context.Context, listenerType string) (string, error) {
	listenerType = strings.ToLower(strings.TrimSpace(listenerType))
	if listenerType == "" {
		return "", errors.New("listener type is required")
	}
	if !isValidListenerType(listenerType) {
		return "", fmt.Errorf("invalid listener type: %q", listenerType)
	}

	payload := map[string]interface{}{
		"name": "zypheron-" + listenerType,
		"options": map[string]interface{}{
			"Name": "zypheron-" + listenerType,
			"Host": "0.0.0.0",
			"Port": defaultListenerPort(listenerType),
		},
	}
	body, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/api/listeners/%s", url.PathEscape(listenerType)), payload)
	if err != nil {
		return "", err
	}
	return prettyJSON(body), nil
}

func (c *Client) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" {
		return nil
	}
	payload := map[string]string{
		"username": c.username,
		"password": c.password,
	}
	body, err := c.doNoAuth(ctx, http.MethodPost, "/api/admin/login", payload)
	if err != nil {
		return err
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("Empire login returned non-JSON response: %w", err)
	}
	for _, key := range []string{"token", "access_token", "jwt"} {
		if value, ok := parsed[key].(string); ok && value != "" {
			c.token = value
			return nil
		}
	}
	return errors.New("Empire login response did not include a token")
}

func (c *Client) currentToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

func (c *Client) do(ctx context.Context, method, path string, payload interface{}) ([]byte, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}
	return c.doWithToken(ctx, method, path, payload)
}

func (c *Client) doWithToken(ctx context.Context, method, path string, payload interface{}) ([]byte, error) {
	body, err := encodePayload(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.currentToken())
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.send(req)
}

func (c *Client) doNoAuth(ctx context.Context, method, path string, payload interface{}) ([]byte, error) {
	body, err := encodePayload(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.send(req)
}

func (c *Client) send(req *http.Request) ([]byte, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("Empire RPC context %w", err)
		}
		return nil, fmt.Errorf("Empire RPC unreachable: %w", redactErr(err))
	}
	defer resp.Body.Close()

	// Detect silent truncation: read one extra byte to see if body exceeded cap.
	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("Empire RPC response exceeded %d byte cap", maxResponseBytes)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := strings.TrimSpace(string(data))
		if len(snippet) > maxErrorBodyLen {
			snippet = snippet[:maxErrorBodyLen] + "...[truncated]"
		}
		return nil, fmt.Errorf("Empire RPC %s returned %s: %s", req.URL.Path, resp.Status, snippet)
	}
	return data, nil
}

func encodePayload(payload interface{}) (io.Reader, error) {
	if payload == nil {
		return nil, nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

// normalizeBaseURL parses user-supplied host, then rebuilds from Scheme+Host
// ONLY — rejects any userinfo/path/query/fragment to prevent request hijack.
func normalizeBaseURL(host string) (string, error) {
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}
	u, err := url.Parse(host)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported Empire URL scheme: %s", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("EMPIRE_HOST missing host component")
	}
	if u.User != nil {
		return "", errors.New("EMPIRE_HOST must not contain userinfo (user:pass@)")
	}
	if path := strings.TrimRight(u.Path, "/"); path != "" {
		return "", fmt.Errorf("EMPIRE_HOST must not contain a path: %q", u.Path)
	}
	if u.RawQuery != "" {
		return "", errors.New("EMPIRE_HOST must not contain a query string")
	}
	if u.Fragment != "" {
		return "", errors.New("EMPIRE_HOST must not contain a fragment")
	}
	// Rebuild from trusted components only.
	clean := &url.URL{Scheme: u.Scheme, Host: u.Host}
	return strings.TrimRight(clean.String(), "/"), nil
}

func defaultListenerPort(listenerType string) string {
	switch listenerType {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return "8080"
	}
}

func isValidListenerType(t string) bool {
	switch t {
	case "http", "https", "http_hop", "http_com", "http_foreign", "http_malleable", "smb", "dbx", "onedrive":
		return true
	}
	return false
}

func hostIsLocalOrPrivate(baseURL string) bool {
	u, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	h := u.Hostname()
	if h == "localhost" || h == "" {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	return false
}

// redactErr strips user:pass@ and query strings from net/url errors so
// EMPIRE_PASS (if it somehow leaked into a URL) doesn't reach stderr/logs.
func redactErr(err error) error {
	s := err.Error()
	// Common patterns: "Get \"https://user:pass@host/...\": ..." and raw URLs.
	out := userInfoRe.ReplaceAllString(s, "$1REDACTED@")
	out = queryRe.ReplaceAllString(out, "$1?REDACTED")
	if out == s {
		return err
	}
	return errors.New(out)
}

func prettyJSON(data []byte) string {
	var parsed interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return string(data)
	}
	formatted, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		return string(data)
	}
	return string(formatted)
}
