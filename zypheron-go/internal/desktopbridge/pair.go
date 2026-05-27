package desktopbridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Nonce TTL on the desktop side is 5 minutes; we cap the long-poll exactly
// there so we return a clean ErrPairTimeout instead of hanging.
const PairTimeout = 5 * time.Minute

// Pair-flow domain errors. Callers map these to user-facing remediation.
var (
	ErrPairDenied  = errors.New("desktop user denied the pairing request")
	ErrPairExpired = errors.New("pairing nonce expired or never reached the desktop modal")
	ErrPairTimeout = errors.New("pairing timed out waiting for user approval")
)

// GenerateNonce mints a 48-char lowercase hex string from 24 bytes of
// crypto/rand entropy. Matches the format the desktop expects (see
// electron/services/control-api-nonces.ts:NONCE_BYTES).
func GenerateNonce() (string, error) {
	var buf [24]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("read entropy: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// BuildPairURL constructs the deep-link URL the OS will dispatch to the
// desktop. The host segment ("pair") is what the desktop's deep-link service
// uses as the dispatch key.
func BuildPairURL(nonce, agentName, cliVersion, cliPlatform string) string {
	q := url.Values{}
	q.Set("nonce", nonce)
	q.Set("agent_name", agentName)
	if cliVersion != "" {
		q.Set("cli_version", cliVersion)
	}
	if cliPlatform != "" {
		q.Set("cli_platform", cliPlatform)
	}
	return "zypheron://pair?" + q.Encode()
}

// RequestPair is the long-poll companion to OpenDeepLink. It POSTs to
// /v1/auth/pair which blocks until the user approves the modal, denies it,
// or the nonce TTL elapses. The five-minute context inside this call matches
// the desktop's nonce expiry exactly.
func RequestPair(ctx context.Context, ep *EndpointFile, nonce, agentName, cliVersion, cliPlatform string) (*TokenPair, error) {
	ctx, cancel := context.WithTimeout(ctx, PairTimeout)
	defer cancel()

	body, err := json.Marshal(map[string]string{
		"nonce":        nonce,
		"agent_name":   agentName,
		"cli_version":  cliVersion,
		"cli_platform": cliPlatform,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal pair body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL+"/v1/auth/pair", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build pair request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "zypheron-cli/"+ClientVersion)

	// Use a dedicated client with no top-level timeout — context governs.
	client := &http.Client{Timeout: 0}
	resp, err := client.Do(req)
	if err != nil {
		// context.DeadlineExceeded surfaces here through url.Error.
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ErrPairTimeout
		}
		return nil, fmt.Errorf("pair request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var pair TokenPair
		if err := json.NewDecoder(resp.Body).Decode(&pair); err != nil {
			return nil, fmt.Errorf("decode pair response: %w", err)
		}
		return &pair, nil
	case http.StatusForbidden:
		if code := readErrorCode(resp.Body); code != "" {
			return nil, fmt.Errorf("%w (%s)", ErrPairDenied, code)
		}
		return nil, ErrPairDenied
	case http.StatusConflict:
		if code := readErrorCode(resp.Body); code != "" {
			return nil, fmt.Errorf("%w (%s)", ErrPairExpired, code)
		}
		return nil, ErrPairExpired
	case http.StatusRequestTimeout:
		return nil, ErrPairTimeout
	default:
		if code := readErrorCode(resp.Body); code != "" {
			return nil, fmt.Errorf("pair: HTTP %d (%s)", resp.StatusCode, code)
		}
		return nil, fmt.Errorf("pair: HTTP %d", resp.StatusCode)
	}
}

// RevokeSelf hits POST /v1/auth/revoke using the supplied access token. Used
// by the `logout` command before wiping local keyring state — if the desktop
// already gone, callers should swallow network errors but still wipe locally.
func RevokeSelf(ctx context.Context, ep *EndpointFile, accessToken string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL+"/v1/auth/revoke", nil)
	if err != nil {
		return fmt.Errorf("build revoke request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", "zypheron-cli/"+ClientVersion)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("revoke request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		if code := readErrorCode(resp.Body); code != "" {
			return fmt.Errorf("revoke: HTTP %d (%s)", resp.StatusCode, code)
		}
		return fmt.Errorf("revoke: HTTP %d", resp.StatusCode)
	}
	return nil
}
