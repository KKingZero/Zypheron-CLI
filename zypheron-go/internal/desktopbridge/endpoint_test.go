package desktopbridge

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func writeEndpointFixture(t *testing.T, ep EndpointFile) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("ZYPHERON_HOME", dir)
	raw, err := json.Marshal(ep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, endpointFilename), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadEndpoint_Missing(t *testing.T) {
	t.Setenv("ZYPHERON_HOME", t.TempDir())
	_, err := LoadEndpoint()
	if err != ErrEndpointMissing {
		t.Fatalf("want ErrEndpointMissing, got %v", err)
	}
}

func TestLoadEndpoint_Malformed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ZYPHERON_HOME", dir)
	if err := os.WriteFile(filepath.Join(dir, endpointFilename), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadEndpoint()
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("want ErrEndpointInvalid, got %v", err)
	}
}

func TestLoadEndpoint_MissingFields(t *testing.T) {
	writeEndpointFixture(t, EndpointFile{URL: "http://127.0.0.1:1234"}) // missing port + protocol
	_, err := LoadEndpoint()
	if err == nil {
		t.Fatal("want error for incomplete endpoint")
	}
}

func TestLoadEndpoint_OK(t *testing.T) {
	writeEndpointFixture(t, EndpointFile{
		URL:             "http://127.0.0.1:39595",
		Port:            39595,
		PID:             1000,
		ProductVersion:  "1.1.0",
		ProtocolVersion: "v1",
		StartedAt:       42,
	})
	ep, err := LoadEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	if ep.Port != 39595 || ep.ProtocolVersion != "v1" {
		t.Fatalf("decoded wrong shape: %+v", ep)
	}
}

// Security regression tests for C1 — defend against a local attacker who
// drops a malicious desktop.json and tries to redirect bearer tokens.

func TestLoadEndpoint_RejectsNonLoopback(t *testing.T) {
	writeEndpointFixture(t, EndpointFile{
		URL:             "http://attacker.example.com:39595",
		Port:            39595,
		ProtocolVersion: "v1",
	})
	_, err := LoadEndpoint()
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("want non-loopback rejection, got %v", err)
	}
}

func TestLoadEndpoint_RejectsHTTPS(t *testing.T) {
	writeEndpointFixture(t, EndpointFile{
		URL:             "https://127.0.0.1:39595",
		Port:            39595,
		ProtocolVersion: "v1",
	})
	_, err := LoadEndpoint()
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("want scheme rejection, got %v", err)
	}
}

func TestLoadEndpoint_RejectsPortMismatch(t *testing.T) {
	writeEndpointFixture(t, EndpointFile{
		URL:             "http://127.0.0.1:1234",
		Port:            39595,
		ProtocolVersion: "v1",
	})
	_, err := LoadEndpoint()
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("want port mismatch rejection, got %v", err)
	}
}

func TestLoadEndpoint_RejectsLooseMode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ZYPHERON_HOME", dir)
	raw, _ := json.Marshal(EndpointFile{
		URL: "http://127.0.0.1:39595", Port: 39595, ProtocolVersion: "v1",
	})
	if err := os.WriteFile(filepath.Join(dir, endpointFilename), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadEndpoint()
	if err == nil || !strings.Contains(err.Error(), "group/other") {
		t.Fatalf("want mode rejection, got %v", err)
	}
}

func TestLoadEndpoint_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ZYPHERON_HOME", dir)
	// Write a real file outside ZYPHERON_HOME, then symlink to it.
	real := filepath.Join(t.TempDir(), "decoy.json")
	raw, _ := json.Marshal(EndpointFile{
		URL: "http://127.0.0.1:39595", Port: 39595, ProtocolVersion: "v1",
	})
	if err := os.WriteFile(real, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, endpointFilename)); err != nil {
		t.Skip("cannot create symlink in this filesystem:", err)
	}
	_, err := LoadEndpoint()
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("want symlink rejection, got %v", err)
	}
}

func TestReach_DeadPort(t *testing.T) {
	ep := EndpointFile{Port: 1} // port 1 should refuse on any sane machine
	if err := ep.Reach(); err == nil {
		t.Fatal("want stale error, got nil")
	}
}

func TestReach_LivePort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	ep := EndpointFile{Port: port}
	if err := ep.Reach(); err != nil {
		t.Fatalf("want reachable, got %v", err)
	}
}

func TestHandshake_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/handshake" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"product_version":"1.1.0","protocol_version":"v1","min_client_version":"0.0.1","features":["sse","mcp"]}`))
	}))
	defer srv.Close()

	port, _ := strconv.Atoi(strings.TrimPrefix(srv.URL, "http://127.0.0.1:"))
	ep := &EndpointFile{URL: srv.URL, Port: port, ProtocolVersion: "v1"}
	h, err := Handshake(context.Background(), ep)
	if err != nil {
		t.Fatal(err)
	}
	if !h.HasFeature("sse") || !h.HasFeature("mcp") {
		t.Fatalf("features missing: %+v", h.Features)
	}
}

func TestHandshake_ProtocolMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"product_version":"2.0.0","protocol_version":"v2","min_client_version":"0.0.1","features":[]}`))
	}))
	defer srv.Close()

	ep := &EndpointFile{URL: srv.URL, Port: 1, ProtocolVersion: "v1"}
	_, err := Handshake(context.Background(), ep)
	if err == nil || !strings.Contains(err.Error(), "incompatible protocol") {
		t.Fatalf("want protocol mismatch, got %v", err)
	}
}

func TestHandshake_426ClientTooOld(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUpgradeRequired)
	}))
	defer srv.Close()

	ep := &EndpointFile{URL: srv.URL, Port: 1, ProtocolVersion: "v1"}
	_, err := Handshake(context.Background(), ep)
	if err != ErrClientTooOld {
		t.Fatalf("want ErrClientTooOld, got %v", err)
	}
}

func TestVersionAtLeast(t *testing.T) {
	cases := []struct {
		have, min string
		want      bool
	}{
		{"1.0.0", "1.0.0", true},
		{"1.0.1", "1.0.0", true},
		{"1.1.0", "1.0.99", true},
		{"0.9.9", "1.0.0", false},
		{"0.1.0", "", true},
		{"2.0.0", "1.99.99", true},
	}
	for _, c := range cases {
		if got := versionAtLeast(c.have, c.min); got != c.want {
			t.Errorf("versionAtLeast(%q,%q)=%v want %v", c.have, c.min, got, c.want)
		}
	}
}
