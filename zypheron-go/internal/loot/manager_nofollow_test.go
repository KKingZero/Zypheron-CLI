package loot

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSaveLoot_RefusesSymlinkFinalComponent verifies the M-09 fix: if the final
// file path is a symlink pointing outside the session directory, SaveLoot must
// NOT follow it (O_NOFOLLOW) and must not write to the symlink target.
func TestSaveLoot_RefusesSymlinkFinalComponent(t *testing.T) {
	root := t.TempDir()
	session := filepath.Join(root, "session")
	category := "creds"
	if err := os.MkdirAll(filepath.Join(session, category), 0o700); err != nil {
		t.Fatal(err)
	}

	// A file outside the session dir that an attacker wants us to overwrite.
	outside := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(outside, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Plant a symlink at the final component pointing to the outside file.
	link := filepath.Join(session, category, "loot.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	lm := &LootManager{SessionDir: session}
	err := lm.SaveLoot(category, "loot.txt", []byte("PWNED"))
	if err == nil {
		t.Fatalf("expected SaveLoot to refuse writing through a symlink, got nil")
	}

	// The outside target must be untouched.
	data, readErr := os.ReadFile(outside)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "ORIGINAL" {
		t.Fatalf("symlink target was overwritten: %q", string(data))
	}
}

// TestSaveLoot_NormalWrite confirms the happy path still works.
func TestSaveLoot_NormalWrite(t *testing.T) {
	session := filepath.Join(t.TempDir(), "session")
	lm := &LootManager{SessionDir: session}
	if err := os.MkdirAll(session, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := lm.SaveLoot("hosts", "h.txt", []byte("data")); err != nil {
		t.Fatalf("normal write failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(session, "hosts", "h.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "data" {
		t.Fatalf("unexpected content: %q", string(got))
	}
}
