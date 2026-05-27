package desktopbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Hard-coded for now. Phase 0 (OpenAPI codegen) will inject this from build
// metadata so client/server can't drift. Bump alongside protocol changes.
const ClientVersion = "0.1.0"

// HandshakeResponse mirrors GET /v1/handshake in
// electron/services/control-api-service.ts.
type HandshakeResponse struct {
	ProductVersion   string   `json:"product_version"`
	ProtocolVersion  string   `json:"protocol_version"`
	MinClientVersion string   `json:"min_client_version"`
	Features         []string `json:"features"`
}

var (
	ErrProtocolMismatch = errors.New("desktop and CLI use incompatible protocol versions")
	ErrClientTooOld     = errors.New("CLI version is below desktop's minimum — upgrade required")
	ErrHandshakeFailed  = errors.New("handshake request failed")
)

// Handshake hits GET /v1/handshake on the desktop and validates that the CLI
// can speak to this desktop. Per architecture decision 11, a too-old client
// gets a 426 from authenticated routes — but the handshake itself is unauth
// and surfaces version data so we can refuse cleanly *before* attempting auth.
func Handshake(ctx context.Context, ep *EndpointFile) (*HandshakeResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.URL+"/v1/handshake", nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}
	req.Header.Set("User-Agent", "zypheron-cli/"+ClientVersion)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUpgradeRequired {
		return nil, ErrClientTooOld
	}
	if resp.StatusCode != http.StatusOK {
		if code := readErrorCode(resp.Body); code != "" {
			return nil, fmt.Errorf("%w: HTTP %d (%s)", ErrHandshakeFailed, resp.StatusCode, code)
		}
		return nil, fmt.Errorf("%w: HTTP %d", ErrHandshakeFailed, resp.StatusCode)
	}

	var h HandshakeResponse
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return nil, fmt.Errorf("%w: decode body: %v", ErrHandshakeFailed, err)
	}

	if h.ProtocolVersion != ep.ProtocolVersion {
		return nil, fmt.Errorf("%w: endpoint=%s handshake=%s",
			ErrProtocolMismatch, ep.ProtocolVersion, h.ProtocolVersion)
	}
	if !versionAtLeast(ClientVersion, h.MinClientVersion) {
		return nil, fmt.Errorf("%w: cli=%s desktop wants >=%s",
			ErrClientTooOld, ClientVersion, h.MinClientVersion)
	}
	return &h, nil
}

// versionAtLeast performs a simple dotted-numeric semver comparison. We only
// support MAJOR.MINOR.PATCH numerics — pre-release suffixes are not used by
// the desktop's MIN_CLIENT_VERSION constant.
func versionAtLeast(have, min string) bool {
	if min == "" {
		return true
	}
	h := parseVersion(have)
	m := parseVersion(min)
	for i := range 3 {
		if h[i] != m[i] {
			return h[i] > m[i]
		}
	}
	return true
}

func parseVersion(v string) [3]int {
	var out [3]int
	parts := strings.SplitN(v, ".", 3)
	for i := 0; i < len(parts) && i < 3; i++ {
		n, _ := strconv.Atoi(strings.TrimSpace(parts[i]))
		out[i] = n
	}
	return out
}

// HasFeature returns true if the desktop advertised `name` in its features
// list. CLI commands gated on a feature should hide themselves when this is
// false (decision 11: features[] drives capability negotiation).
func (h *HandshakeResponse) HasFeature(name string) bool {
	return slices.Contains(h.Features, name)
}
