package views

import "testing"

func TestModelToCredentialProvider(t *testing.T) {
	tests := []struct {
		model string
		want  string
	}{
		{"claude-opus-4-6", "anthropic"},
		{"gpt-5.4", "openai"},
		{"gemini-3-flash-preview", "google"},
		{"kimi-k2", "kimi"},
		{"deepseek-r1", "deepseek"},
		{"grok-3", "grok"},
		{"ollama-llama3.2:3b", ""},
		{"", ""},
	}

	for _, tt := range tests {
		if got := ModelToCredentialProvider(tt.model); got != tt.want {
			t.Errorf("ModelToCredentialProvider(%q) = %q, want %q", tt.model, got, tt.want)
		}
	}
}

func TestModelRequiresAPIKey(t *testing.T) {
	if !ModelRequiresAPIKey("claude-opus-4-6") {
		t.Fatal("claude model should require API key")
	}
	if ModelRequiresAPIKey("ollama-qwen3-coder") {
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
