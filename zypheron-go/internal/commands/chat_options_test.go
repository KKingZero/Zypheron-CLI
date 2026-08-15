package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
)

func TestValidateChatEffort(t *testing.T) {
	tests := []struct {
		name      string
		provider  string
		effort    string
		wantError bool
	}{
		{name: "openai low", provider: "openai", effort: "low"},
		{name: "openai none", provider: "openai", effort: "none"},
		{name: "claude max", provider: "claude", effort: "max"},
		{name: "claude none invalid", provider: "claude", effort: "none", wantError: true},
		{name: "gemini unsupported", provider: "gemini", effort: "low", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateChatEffort(tt.provider, tt.effort)
			if tt.wantError && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBuildChatOptionsRepeatsImageAndMCP(t *testing.T) {
	dir := t.TempDir()
	imagePath := filepath.Join(dir, "shot.png")
	if err := os.WriteFile(imagePath, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, 0o600); err != nil {
		t.Fatalf("write image: %v", err)
	}

	options, err := buildChatOptions(
		"openai",
		"low",
		[]string{imagePath, "https://example.com/screenshot.png"},
		[]string{"local-test", "filesystem"},
		"~/custom-mcp.json",
	)
	if err != nil {
		t.Fatalf("buildChatOptions failed: %v", err)
	}

	if options.Effort != "low" {
		t.Fatalf("effort not carried: %q", options.Effort)
	}
	if len(options.Images) != 2 {
		t.Fatalf("expected 2 images, got %d", len(options.Images))
	}
	if options.Images[0].MimeType != "image/png" || options.Images[0].DataBase64 == "" {
		t.Fatalf("local image was not encoded: %#v", options.Images[0])
	}
	if options.Images[1].URL != "https://example.com/screenshot.png" {
		t.Fatalf("URL image not carried: %#v", options.Images[1])
	}
	if len(options.MCP) != 2 || options.MCP[0].Label != "local-test" || options.MCP[1].Label != "filesystem" {
		t.Fatalf("MCP labels not carried: %#v", options.MCP)
	}
}

func TestBuildChatOptionsRejectsVisionForUnsupportedProvider(t *testing.T) {
	_, err := buildChatOptions("ollama", "", []string{"https://example.com/a.png"}, nil, "")
	if err == nil {
		t.Fatal("expected unsupported vision error")
	}
}

func TestPrepareChatImageRejectsRenamedNonImage(t *testing.T) {
	dir := t.TempDir()
	imagePath := filepath.Join(dir, "not-really.png")
	if err := os.WriteFile(imagePath, []byte("plain text"), 0o600); err != nil {
		t.Fatalf("write image: %v", err)
	}

	_, err := prepareChatImage(imagePath)
	if err == nil {
		t.Fatal("expected MIME sniffing error")
	}
}

func TestChatOptionsJSONShape(t *testing.T) {
	payload := aibridge.ChatOptions{
		Effort: "medium",
		Images: []aibridge.ImageInput{{
			Source:     "file",
			MimeType:   "image/png",
			DataBase64: "abcd",
		}},
		MCPConfig: "/tmp/mcp.json",
		MCP: []aibridge.MCPSelection{{
			Label:        "local-test",
			AllowedTools: []string{"read"},
		}},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal options: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal options: %v", err)
	}
	if decoded["effort"] != "medium" || decoded["mcp_config"] != "/tmp/mcp.json" {
		t.Fatalf("unexpected JSON shape: %s", data)
	}
}
