package views

import (
	"os"
	"testing"
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
