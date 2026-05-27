package desktopbridge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenerateNonce(t *testing.T) {
	a, err := GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 48 || len(b) != 48 {
		t.Fatalf("want 48-char hex, got %d / %d", len(a), len(b))
	}
	if a == b {
		t.Fatal("two consecutive nonces should not collide")
	}
}

func TestBuildPairURL(t *testing.T) {
	got := BuildPairURL("deadbeef", "test-agent", "0.1.0", "linux/amd64")
	if !strings.HasPrefix(got, "zypheron://pair?") {
		t.Fatalf("missing prefix: %s", got)
	}
	for _, want := range []string{"nonce=deadbeef", "agent_name=test-agent", "cli_version=0.1.0", "cli_platform=linux%2Famd64"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %s", want, got)
		}
	}
}

func TestRequestPair_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/auth/pair" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["nonce"] == "" || body["agent_name"] == "" {
			t.Fatalf("missing required fields: %+v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"a","refresh_token":"r","access_expires_in":900,"refresh_expires_in":7776000}`))
	}))
	defer srv.Close()
	ep := &EndpointFile{URL: srv.URL}
	pair, err := RequestPair(context.Background(), ep, "deadbeef", "test", "0.1.0", "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	if pair.AccessToken != "a" || pair.RefreshToken != "r" || pair.AccessExpiresIn != 900 {
		t.Fatalf("bad decode: %+v", pair)
	}
}

func TestRequestPair_Denied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"code":"pair_denied","message":"user clicked deny"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := RequestPair(context.Background(), &EndpointFile{URL: srv.URL}, "n", "a", "", "")
	if !errors.Is(err, ErrPairDenied) {
		t.Fatalf("want ErrPairDenied, got %v", err)
	}
}

func TestRequestPair_NonceExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"code":"invalid_nonce"}`, http.StatusConflict)
	}))
	defer srv.Close()
	_, err := RequestPair(context.Background(), &EndpointFile{URL: srv.URL}, "n", "a", "", "")
	if !errors.Is(err, ErrPairExpired) {
		t.Fatalf("want ErrPairExpired, got %v", err)
	}
}

func TestRevokeSelf_OK(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/revoke" {
			t.Fatalf("wrong path %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Fatalf("wrong auth: %q", r.Header.Get("Authorization"))
		}
		hit = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	if err := RevokeSelf(context.Background(), &EndpointFile{URL: srv.URL}, "tok"); err != nil {
		t.Fatal(err)
	}
	if !hit {
		t.Fatal("server not called")
	}
}
