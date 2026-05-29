package tui

import "testing"

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
