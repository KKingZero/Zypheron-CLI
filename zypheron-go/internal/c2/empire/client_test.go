package empire

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestNormalizeBaseURL_Valid(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:1337":          "https://127.0.0.1:1337",
		"https://127.0.0.1:1337":  "https://127.0.0.1:1337",
		"https://127.0.0.1:1337/": "https://127.0.0.1:1337",
		"http://empire.lab":       "http://empire.lab",
		"https://[::1]:1337":      "https://[::1]:1337",
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
		"https://127.0.0.1:1337": true,
		"https://localhost":      true,
		"https://10.0.0.1":       true,
		"https://192.168.1.50":   true,
		"https://172.16.0.1":     true,
		"https://8.8.8.8":        false,
		"https://attacker.tld":   false,
	}
	for in, want := range cases {
		if got := hostIsLocalOrPrivate(in); got != want {
			t.Errorf("hostIsLocalOrPrivate(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestClientListAgents_AuthenticatesAndPrettyPrints(t *testing.T) {
	var loginCount int
	c := &Client{
		baseURL:  "http://empire.test",
		username: "u",
		password: "p",
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var body string
			status := http.StatusOK

			switch r.URL.Path {
			case "/api/admin/login":
				loginCount++
				body = `{"token":"tok"}`
			case "/api/agents":
				if got := r.Header.Get("Authorization"); got != "Bearer tok" {
					t.Fatalf("Authorization = %q, want Bearer tok", got)
				}
				body = `{"agents":["A1"]}`
			default:
				status = http.StatusNotFound
				body = `{"error":"not found"}`
			}
			return testResponse(status, body), nil
		})},
	}

	out, err := c.ListAgents(context.Background())
	if err != nil {
		t.Fatalf("ListAgents() err = %v", err)
	}
	if loginCount != 1 {
		t.Fatalf("loginCount = %d, want 1", loginCount)
	}
	if !strings.Contains(out, `"agents"`) || !strings.Contains(out, `"A1"`) {
		t.Fatalf("ListAgents() output = %q", out)
	}
}

func TestClientStartListener_PayloadShape(t *testing.T) {
	var payload map[string]interface{}
	c := &Client{
		baseURL:  "http://empire.test",
		username: "u",
		password: "p",
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.URL.Path {
			case "/api/admin/login":
				return testResponse(http.StatusOK, `{"access_token":"tok"}`), nil
			case "/api/listeners/http":
				if got := r.Header.Get("Authorization"); got != "Bearer tok" {
					t.Fatalf("Authorization = %q, want Bearer tok", got)
				}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatalf("decode payload: %v", err)
				}
				return testResponse(http.StatusOK, `{"status":"ok"}`), nil
			default:
				return testResponse(http.StatusNotFound, `{"error":"not found"}`), nil
			}
		})},
	}

	if _, err := c.StartListener(context.Background(), "http"); err != nil {
		t.Fatalf("StartListener() err = %v", err)
	}
	if payload["name"] != "zypheron-http" {
		t.Fatalf("payload name = %#v", payload["name"])
	}
	options, ok := payload["options"].(map[string]interface{})
	if !ok {
		t.Fatalf("payload options = %#v", payload["options"])
	}
	if options["Host"] != "0.0.0.0" || options["Port"] != "80" {
		t.Fatalf("payload options = %#v", options)
	}
}

func TestClientEnsureToken_RejectsMissingToken(t *testing.T) {
	c := &Client{
		baseURL:  "http://empire.test",
		username: "u",
		password: "p",
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return testResponse(http.StatusOK, `{"message":"ok"}`), nil
		})},
	}
	err := c.ensureToken(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not include a token") {
		t.Fatalf("ensureToken() err = %v, want missing token", err)
	}
}

func TestClientSend_ResponseSizeCap(t *testing.T) {
	c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return testResponse(http.StatusOK, strings.Repeat("x", maxResponseBytes+1)), nil
	})}}
	req, err := http.NewRequest(http.MethodGet, "http://empire.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.send(req)
	if err == nil || !strings.Contains(err.Error(), "response exceeded") {
		t.Fatalf("send() err = %v, want response exceeded", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func testResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
