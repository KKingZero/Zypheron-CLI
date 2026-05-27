package desktopbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

// Client is the high-level Control API client. It wraps endpoint discovery,
// bearer-auth, and one-shot automatic refresh on 401. All authenticated CLI
// commands should go through this type rather than calling http directly.
//
// Threading: safe for concurrent use. The refresh path serializes via mu so
// two parallel 401s don't double-spend the (one-time-use) refresh token.
type Client struct {
	ep         *EndpointFile
	httpClient *http.Client

	mu           sync.Mutex
	accessToken  string
	refreshToken string
}

// NewClient builds a Client from a freshly-loaded endpoint file and the
// credentials currently in keyring/env. Callers should invoke Handshake
// before NewClient if they need protocol-version validation up-front.
func NewClient(ep *EndpointFile) (*Client, error) {
	access, err := LoadAccessToken()
	if err != nil {
		return nil, err
	}
	refresh, err := LoadRefreshToken()
	if err != nil {
		return nil, err
	}
	return &Client{
		ep:           ep,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		accessToken:  access,
		refreshToken: refresh,
	}, nil
}

// ErrUnauthorized is returned when a request fails authentication AND the
// auto-refresh path also fails — caller should prompt the user to re-pair.
var ErrUnauthorized = errors.New("desktop refused credentials; re-run `zypheron login` to re-pair")

// Do executes an authenticated request and applies the auto-refresh dance.
// The request body, if any, must be re-readable: we read it into memory so the
// retried attempt can resend the same payload after rotating the access token.
func (c *Client) Do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		payload = b
	}

	resp, err := c.doWithToken(ctx, method, path, payload)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	// 401: drain and close before refresh so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if err := c.refresh(ctx); err != nil {
		// Refresh tokens are one-time-use; if rotation fails there's no
		// recovery short of re-pairing. Wipe stored creds so the next CLI
		// run prompts cleanly.
		_ = DeleteTokens()
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}

	return c.doWithToken(ctx, method, path, payload)
}

// doWithToken issues a single authenticated request using the current access
// token. It does NOT recursively refresh on 401 — Do owns that dance.
//
// Defense in depth (H2 from the 2026-05-27 security review): re-verify the
// cached endpoint URL is still loopback before every request. Catches the
// case where LoadEndpoint() succeeded against a legitimate file but a later
// attacker swapped desktop.json in-process — without this check, the cached
// `c.ep.URL` would carry the CLI's bearer token to wherever the swapped
// file pointed. The cost is one URL parse per request; negligible.
func (c *Client) doWithToken(ctx context.Context, method, path string, payload []byte) (*http.Response, error) {
	if err := verifyLoopbackURL(c.ep.URL, c.ep.Port); err != nil {
		return nil, err
	}

	c.mu.Lock()
	token := c.accessToken
	c.mu.Unlock()

	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.ep.URL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "zypheron-cli/"+ClientVersion)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.httpClient.Do(req)
}

// refresh exchanges the stored refresh token for a fresh pair via
// POST /v1/auth/refresh. The refresh token rotates per architecture
// decision 10, so the new pair must be persisted before the next request.
//
// File-locked so two concurrent CLI processes sharing a keyring don't both
// spend the one-time-use refresh token. If we acquire the lock and discover
// the keyring already holds a fresh token, we skip the POST entirely and
// just reload — the other process did the work.
func (c *Client) refresh(ctx context.Context) error {
	lockPath, err := refreshLockPath()
	if err != nil {
		return err
	}
	lock := flock.New(lockPath)
	// Hard 5s ceiling on lock acquisition independent of the caller's
	// context (M2 from the 2026-05-27 security review). Without this, a
	// local attacker who holds an flock on ~/.zypheron/refresh.lock can
	// stall every CLI request for the caller's full request timeout.
	lockCtx, cancelLock := context.WithTimeout(ctx, 5*time.Second)
	defer cancelLock()
	if _, err := lock.TryLockContext(lockCtx, 50*time.Millisecond); err != nil {
		return fmt.Errorf("acquire refresh lock: %w", err)
	}
	defer func() { _ = lock.Unlock() }()

	c.mu.Lock()
	previous := c.refreshToken
	c.mu.Unlock()

	// Under the lock, re-read the keyring. If another process already
	// rotated, our `previous` is stale — just pick up the new pair.
	if rotated, _ := LoadRefreshToken(); rotated != "" && rotated != previous {
		access, _ := LoadAccessToken()
		c.mu.Lock()
		c.accessToken = access
		c.refreshToken = rotated
		c.mu.Unlock()
		return nil
	}

	current := previous
	if current == "" {
		return ErrNoCredentials
	}

	body, err := json.Marshal(map[string]string{"refresh_token": current})
	if err != nil {
		return fmt.Errorf("marshal refresh body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ep.URL+"/v1/auth/refresh", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "zypheron-cli/"+ClientVersion)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("refresh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if code := readErrorCode(resp.Body); code != "" {
			return fmt.Errorf("refresh denied: HTTP %d (%s)", resp.StatusCode, code)
		}
		return fmt.Errorf("refresh denied: HTTP %d", resp.StatusCode)
	}

	var pair TokenPair
	if err := json.NewDecoder(resp.Body).Decode(&pair); err != nil {
		return fmt.Errorf("decode refresh response: %w", err)
	}

	c.mu.Lock()
	c.accessToken = pair.AccessToken
	c.refreshToken = pair.RefreshToken
	c.mu.Unlock()

	if err := SaveTokens(pair); err != nil {
		return fmt.Errorf("persist rotated tokens: %w", err)
	}
	return nil
}

// AccessToken returns the current (possibly-refreshed) bearer token. SSE
// consumers need this to build their initial GET; refresh-on-401 happens in
// the SSE layer separately.
func (c *Client) AccessToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accessToken
}

// Endpoint exposes the discovered endpoint for callers that need the raw URL
// (e.g., SSE consumers that bypass Do).
func (c *Client) Endpoint() *EndpointFile {
	return c.ep
}

// refreshLockPath honors ZYPHERON_HOME for tests; production callers always
// land in ~/.zypheron/refresh.lock.
func refreshLockPath() (string, error) {
	if override := os.Getenv("ZYPHERON_HOME"); override != "" {
		return filepath.Join(override, "refresh.lock"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home: %w", err)
	}
	return filepath.Join(home, ".zypheron", "refresh.lock"), nil
}
