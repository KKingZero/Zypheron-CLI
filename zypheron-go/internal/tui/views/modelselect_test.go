package views

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestModelToCredentialProvider(t *testing.T) {
	tests := []struct {
		model string
		want  string
	}{
		{ClaudeModelLabel, "anthropic"},
		{ChatGPTModelLabel, "openai"},
		{GeminiModelLabel, "google"},
		{KimiModelLabel, "kimi"},
		{"grok-3", "grok"},
		{LocalAIModelLabel, ""},
		{"", ""},
	}

	for _, tt := range tests {
		if got := ModelToCredentialProvider(tt.model); got != tt.want {
			t.Errorf("ModelToCredentialProvider(%q) = %q, want %q", tt.model, got, tt.want)
		}
	}
}

func TestModelRequiresAPIKey(t *testing.T) {
	if !ModelRequiresAPIKey(ClaudeModelLabel) {
		t.Fatal("claude model should require API key")
	}
	if ModelRequiresAPIKey(LocalAIModelLabel) {
		t.Fatal("ollama model should not require API key")
	}
}

func TestCredentialProviderHelpers(t *testing.T) {
	if got := CredentialProviderEnvVar("google"); got != "GOOGLE_API_KEY" {
		t.Errorf("CredentialProviderEnvVar(google) = %s", got)
	}
	if got := CredentialProviderLabel("anthropic"); got != "Claude" {
		t.Errorf("CredentialProviderLabel(anthropic) = %s", got)
	}
	if got := CredentialProviderLabel("openai"); got != "ChatGPT" {
		t.Errorf("CredentialProviderLabel(openai) = %s", got)
	}
	if got := CredentialProviderLabel("custom"); got != "custom" {
		t.Errorf("CredentialProviderLabel(custom) = %s", got)
	}
}

func TestFindModelIndex(t *testing.T) {
	models := []string{"a", "b", "c"}
	if got := FindModelIndex(models, "b"); got != 1 {
		t.Errorf("FindModelIndex() = %d, want 1", got)
	}
	if got := FindModelIndex(models, "missing"); got != -1 {
		t.Errorf("FindModelIndex() = %d, want -1", got)
	}
}

func TestModelSelectorHeight(t *testing.T) {
	selector := NewModelSelector(100)
	if got := selector.Height(); got != 1 {
		t.Fatalf("closed selector Height() = %d, want 1", got)
	}

	selector.Open()
	wantOpenHeight := lipgloss.Height(selector.View())
	if got := selector.Height(); got != wantOpenHeight {
		t.Fatalf("open selector Height() = %d, want %d", got, wantOpenHeight)
	}
}

func TestModelToProviderLocalAI(t *testing.T) {
	if got := ModelToProvider(LocalAIModelLabel); got != "ollama" {
		t.Fatalf("ModelToProvider(%q) = %q, want ollama", LocalAIModelLabel, got)
	}
}

func TestModelToEngineModelLocalAIFallback(t *testing.T) {
	originalURL := os.Getenv("OLLAMA_URL")
	originalModel := os.Getenv("OLLAMA_MODEL")
	defer func() {
		_ = os.Setenv("OLLAMA_URL", originalURL)
		_ = os.Setenv("OLLAMA_MODEL", originalModel)
	}()

	_ = os.Setenv("OLLAMA_URL", "http://127.0.0.1:1")
	_ = os.Setenv("OLLAMA_MODEL", "llama3.3:70b")

	if got := ModelToEngineModel(LocalAIModelLabel); got != "llama3.3:70b" {
		t.Fatalf("ModelToEngineModel(%q) = %q, want env fallback", LocalAIModelLabel, got)
	}
}

func TestModelToEngineModelLocalAIDefaultFallback(t *testing.T) {
	originalURL := os.Getenv("OLLAMA_URL")
	originalModel := os.Getenv("OLLAMA_MODEL")
	defer func() {
		_ = os.Setenv("OLLAMA_URL", originalURL)
		_ = os.Setenv("OLLAMA_MODEL", originalModel)
	}()

	_ = os.Setenv("OLLAMA_URL", "http://127.0.0.1:1")
	_ = os.Unsetenv("OLLAMA_MODEL")

	if got := ModelToEngineModel(LocalAIModelLabel); got != DefaultOllamaModel {
		t.Fatalf("ModelToEngineModel(%q) = %q, want default fallback", LocalAIModelLabel, got)
	}
}

func TestNormalizeOllamaURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "http://localhost:11434"},
		{"localhost:11434/", "http://localhost:11434"},
		{" http://example.com:11434/// ", "http://example.com:11434"},
		{"https://ollama.example.com", "https://ollama.example.com"},
	}

	for _, tt := range tests {
		if got := normalizeOllamaURL(tt.in); got != tt.want {
			t.Fatalf("normalizeOllamaURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestListOllamaModelsNativeTags(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/tags" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return jsonResponse(http.StatusOK, `{"models":[{"name":" llama3.2:latest ","size":1},{"name":""}]}`), nil
	})}

	models, err := listOllamaModels("http://ollama.test", client)
	if err != nil {
		t.Fatalf("listOllamaModels() error = %v", err)
	}
	if len(models) != 1 || models[0] != "llama3.2:latest" {
		t.Fatalf("listOllamaModels() = %#v, want llama3.2:latest", models)
	}
}

func TestListOllamaModelsOpenAICompatibleFallback(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/tags":
			return jsonResponse(http.StatusNotFound, `{"error":"missing"}`), nil
		case "/v1/models":
			return jsonResponse(http.StatusOK, `{"data":[{"id":"qwen2.5-coder:latest"},{"id":" "}]}`), nil
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
			return nil, nil
		}
	})}

	models, err := listOllamaModels("http://ollama.test", client)
	if err != nil {
		t.Fatalf("listOllamaModels() error = %v", err)
	}
	if len(models) != 1 || models[0] != "qwen2.5-coder:latest" {
		t.Fatalf("listOllamaModels() = %#v, want qwen2.5-coder:latest", models)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestSelectOllamaModelPriority(t *testing.T) {
	tests := []struct {
		name      string
		preferred string
		available []string
		want      string
	}{
		{
			name:      "exact preferred match",
			preferred: "llama3.2",
			available: []string{"mistral:latest", "llama3.2"},
			want:      "llama3.2",
		},
		{
			name:      "tag tolerant match",
			preferred: "llama3.2",
			available: []string{"mistral:latest", "llama3.2:latest"},
			want:      "llama3.2:latest",
		},
		{
			name:      "first non embedding model",
			preferred: "llama3.2",
			available: []string{"nomic-embed-text:latest", "mistral:latest"},
			want:      "mistral:latest",
		},
		{
			name:      "first available if all embedding",
			preferred: "llama3.2",
			available: []string{"nomic-embed-text:latest", "all-minilm:embedding"},
			want:      "nomic-embed-text:latest",
		},
		{
			name:      "empty list keeps preferred",
			preferred: "llama3.3:70b",
			available: nil,
			want:      "llama3.3:70b",
		},
		{
			name:      "empty preferred falls back default",
			preferred: "",
			available: nil,
			want:      DefaultOllamaModel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SelectOllamaModel(tt.preferred, tt.available); got != tt.want {
				t.Fatalf("SelectOllamaModel() = %q, want %q", got, tt.want)
			}
		})
	}
}
