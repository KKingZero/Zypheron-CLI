package tui

import (
	"testing"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/views"
)

func TestParseRuntimeKeyValuePairs(t *testing.T) {
	metadata := parseRuntimeKeyValuePairs([]string{
		"session_id=sess-123",
		"method=post",
		"required_role=admin",
		"actual_role=user",
		"target_user_id=42",
		"header.Authorization=Bearer-token",
	})

	if got := metadata["session_id"]; got != "sess-123" {
		t.Fatalf("session_id = %v", got)
	}
	if got := metadata["method"]; got != "POST" {
		t.Fatalf("method = %v", got)
	}
	headers, ok := metadata["headers"].(map[string]string)
	if !ok {
		t.Fatalf("headers missing or wrong type: %#v", metadata["headers"])
	}
	if headers["Authorization"] != "Bearer-token" {
		t.Fatalf("header Authorization = %q", headers["Authorization"])
	}
}

func TestBuildRuntimeMessageMetadataUsesActiveAuthSession(t *testing.T) {
	model := &Model{activeAuthSession: "sess-active"}

	metadata := model.buildRuntimeMessageMetadata("run authenticated IDOR checks on https://example.com/api/users/1")

	if metadata["session_id"] != "sess-active" {
		t.Fatalf("session_id = %v", metadata["session_id"])
	}
}

func TestBottomAreaHeightTracksModelSelectorState(t *testing.T) {
	model := Model{modelSelector: views.NewModelSelector(100)}

	closedHeight := model.bottomAreaHeight()
	if closedHeight != 1 {
		t.Fatalf("closed bottom area height = %d, want 1", closedHeight)
	}

	model.modelSelector.Open()
	openHeight := model.bottomAreaHeight()
	if openHeight <= closedHeight {
		t.Fatalf("open bottom area height = %d, want greater than closed height %d", openHeight, closedHeight)
	}
	if openHeight != model.modelSelector.Height() {
		t.Fatalf("bottom area height = %d, selector height = %d", openHeight, model.modelSelector.Height())
	}
}
