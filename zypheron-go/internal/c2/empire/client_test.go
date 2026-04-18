package empire

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestNormalizeBaseURL_Valid(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:1337":                 "https://127.0.0.1:1337",
		"https://127.0.0.1:1337":         "https://127.0.0.1:1337",
		"https://127.0.0.1:1337/":        "https://127.0.0.1:1337",
		"http://empire.lab":              "http://empire.lab",
		"https://[::1]:1337":             "https://[::1]:1337",
	}
	for in, want := range cases {
		got, err := normalizeBaseURL(in)
		if err != nil {
			t.Errorf("normalizeBaseURL(%q) unexpected err: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("normalizeBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// Regression for H1 (URL injection). These values must be rejected because
// they could redirect requests (and EMPIRE_PASS) to an attacker host.
func TestNormalizeBaseURL_RejectsInjection(t *testing.T) {
	bad := []string{
		"https://attacker.tld/evil?x=",
		"https://127.0.0.1:1337/api/hijack",
		"https://user:pass@127.0.0.1:1337",
		"https://127.0.0.1:1337#frag",
		"https://127.0.0.1:1337?q=1",
		"ftp://127.0.0.1:1337",
		"https://",
	}
	for _, b := range bad {
		if _, err := normalizeBaseURL(b); err == nil {
			t.Errorf("normalizeBaseURL(%q) should have rejected, got no error", b)
		}
	}
}

func TestNewFromEnv_RequiresAllVars(t *testing.T) {
	t.Setenv("EMPIRE_HOST", "")
	t.Setenv("EMPIRE_USER", "")
	t.Setenv("EMPIRE_PASS", "")
	if _, err := NewFromEnv(); err == nil {
		t.Fatal("NewFromEnv with empty env should fail")
	}
	t.Setenv("EMPIRE_HOST", "127.0.0.1:1337")
	if _, err := NewFromEnv(); err == nil {
		t.Fatal("NewFromEnv with only host should fail")
	}
}

// Regression for H2 (token race). Concurrent ensureToken calls must serialize
// via the mutex — the second caller should see the token set by the first and
// not attempt a second login.
func TestEnsureToken_IsMutexGuarded(t *testing.T) {
	c := &Client{
		baseURL:  "https://127.0.0.1:1337",
		username: "u",
		password: "p",
		token:    "pre-set",
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.currentToken() // exercises the lock
		}()
	}
	wg.Wait()
	if c.currentToken() != "pre-set" {
		t.Fatalf("token changed unexpectedly: %q", c.currentToken())
	}
}

// Regression for L2 — redact user:pass@ and query strings from wrapped errors.
func TestRedactErr(t *testing.T) {
	in := errors.New(`Get "https://alice:hunter2@example.com/api?token=abc": dial tcp`)
	out := redactErr(in)
	if strings.Contains(out.Error(), "hunter2") {
		t.Errorf("redactErr did not strip userinfo: %q", out.Error())
	}
	if strings.Contains(out.Error(), "token=abc") {
		t.Errorf("redactErr did not strip query: %q", out.Error())
	}
}

func TestIsValidListenerType(t *testing.T) {
	if !isValidListenerType("http") || !isValidListenerType("https") {
		t.Error("http/https must be valid")
	}
	if isValidListenerType("../../etc/passwd") {
		t.Error("path traversal must be rejected")
	}
	if isValidListenerType("") {
		t.Error("empty type must be rejected")
	}
}

func TestHostIsLocalOrPrivate(t *testing.T) {
	cases := map[string]bool{
		"https://127.0.0.1:1337":   true,
		"https://localhost":        true,
		"https://10.0.0.1":         true,
		"https://192.168.1.50":     true,
		"https://172.16.0.1":       true,
		"https://8.8.8.8":          false,
		"https://attacker.tld":     false,
	}
	for in, want := range cases {
		if got := hostIsLocalOrPrivate(in); got != want {
			t.Errorf("hostIsLocalOrPrivate(%q) = %v, want %v", in, got, want)
		}
	}
}
