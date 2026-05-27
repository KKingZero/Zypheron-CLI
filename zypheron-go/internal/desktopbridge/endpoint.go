// Package desktopbridge talks to the Zypheron desktop app's local Control API
// over loopback HTTP. The desktop publishes connection metadata to
// ~/.zypheron/desktop.json on listen; this file is the CLI's discovery path.
package desktopbridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	endpointFilename       = "desktop.json"
	endpointReachTimeoutMs = 200
)

// EndpointFile mirrors the JSON shape written by the desktop in
// electron/services/control-api-service.ts:writeEndpointFile.
type EndpointFile struct {
	URL             string `json:"url"`
	Port            int    `json:"port"`
	PID             int    `json:"pid"`
	ProductVersion  string `json:"product_version"`
	ProtocolVersion string `json:"protocol_version"`
	StartedAt       int64  `json:"started_at"`
}

var (
	ErrEndpointMissing  = errors.New("desktop endpoint file not found — is the Zypheron desktop app running?")
	ErrEndpointStale    = errors.New("desktop endpoint reachable address did not respond — desktop may have crashed")
	ErrEndpointInvalid  = errors.New("desktop endpoint file is malformed")
	ErrEndpointInsecure = errors.New("desktop endpoint file fails security validation (perms, owner, or non-loopback URL)")
)

// EndpointPath returns the absolute path of the discovery file, honoring
// ZYPHERON_HOME override for tests.
func EndpointPath() (string, error) {
	if override := os.Getenv("ZYPHERON_HOME"); override != "" {
		return filepath.Join(override, endpointFilename), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".zypheron", endpointFilename), nil
}

// LoadEndpoint reads desktop.json, validates its shape, and enforces a strict
// trust contract before returning it. Validation is split into three layers
// because each catches a distinct attacker:
//
//  1. Filesystem ownership + mode (C1 from the 2026-05-27 security review).
//     A local non-root attacker can otherwise drop a malicious desktop.json
//     and redirect the CLI's bearer tokens to an attacker-controlled URL.
//  2. JSON shape (well-formed, required fields present).
//  3. Loopback URL whitelist. The whole bridge design assumes 127.0.0.1; a
//     non-loopback URL is either a misconfiguration or an attack and must
//     not be honored even if the file otherwise looks valid.
//
// Reach is a separate concern — it only proves *something* is bound on the
// declared port, not that this file is trustworthy.
func LoadEndpoint() (*EndpointFile, error) {
	path, err := EndpointPath()
	if err != nil {
		return nil, err
	}
	if err := verifyEndpointFilePerms(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrEndpointMissing
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var ep EndpointFile
	if err := json.Unmarshal(raw, &ep); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEndpointInvalid, err)
	}
	if ep.URL == "" || ep.Port == 0 || ep.ProtocolVersion == "" {
		return nil, fmt.Errorf("%w: missing url/port/protocol_version", ErrEndpointInvalid)
	}
	if err := verifyLoopbackURL(ep.URL, ep.Port); err != nil {
		return nil, err
	}
	return &ep, nil
}

// verifyLoopbackURL fails closed for any URL that doesn't resolve to a
// loopback host, mismatches the declared port, or uses a non-http scheme.
// Exposed for the per-request re-check in client.go (H2 mitigation).
func verifyLoopbackURL(rawURL string, declaredPort int) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: parse url: %v", ErrEndpointInsecure, err)
	}
	if u.Scheme != "http" {
		return fmt.Errorf("%w: scheme %q (expected http)", ErrEndpointInsecure, u.Scheme)
	}
	host := u.Hostname()
	switch host {
	case "127.0.0.1", "localhost", "::1":
		// loopback — OK
	default:
		return fmt.Errorf("%w: non-loopback host %q", ErrEndpointInsecure, host)
	}
	if portStr := u.Port(); portStr != "" {
		urlPort, err := strconv.Atoi(portStr)
		if err != nil || urlPort != declaredPort {
			return fmt.Errorf("%w: url port %q != declared port %d", ErrEndpointInsecure, portStr, declaredPort)
		}
	}
	return nil
}

// Reach performs a 200ms TCP dial against the published port. Returns
// ErrEndpointStale on connection refused / timeout so callers can prompt the
// user to relaunch the desktop. Fast-fail per architecture decision 12.
func (e *EndpointFile) Reach() error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(e.Port))
	conn, err := net.DialTimeout("tcp", addr, time.Duration(endpointReachTimeoutMs)*time.Millisecond)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEndpointStale, err)
	}
	_ = conn.Close()
	return nil
}
