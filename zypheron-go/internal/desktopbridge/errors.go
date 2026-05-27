package desktopbridge

import (
	"encoding/json"
	"io"
)

// errorEnvelope mirrors the desktop's typed error response.
// See components/schemas/ErrorEnvelope in schema/control-api.yaml.
type errorEnvelope struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// readErrorCode reads up to 512 bytes of the body and pulls out the typed
// `code` field. Returns "" if the body isn't a recognizable error envelope.
//
// Per the 2026-05-27 security review (H1): we deliberately do NOT include
// raw response bodies in error strings — that channel is uncontrolled and
// could echo sensitive material back through `fmt.Errorf`. The enumerated
// `code` field is safe because the desktop authors it from a closed list.
func readErrorCode(body io.Reader) string {
	var env errorEnvelope
	if err := json.NewDecoder(io.LimitReader(body, 512)).Decode(&env); err != nil {
		return ""
	}
	return env.Code
}
