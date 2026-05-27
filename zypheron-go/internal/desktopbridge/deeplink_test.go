package desktopbridge

import (
	"errors"
	"testing"
)

func TestLauncherFor_Linux(t *testing.T) {
	prog, args, err := launcherFor("linux", "zypheron://pair?nonce=abc")
	if err != nil {
		// Skip if xdg-open isn't on this machine — exec.LookPath check inside
		// launcherFor returns ErrLauncherUnavailable in that case, which is
		// a legitimate environment outcome, not a code bug.
		if errors.Is(err, ErrLauncherUnavailable) {
			t.Skip("xdg-open not installed; skipping linux launcher test")
		}
		t.Fatal(err)
	}
	if prog == "" || prog == "xdg-open" {
		t.Fatalf("expected absolute path, got %q", prog)
	}
	if len(args) != 1 || args[0] != "zypheron://pair?nonce=abc" {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestLauncherFor_Windows(t *testing.T) {
	prog, args, err := launcherFor("windows", "zypheron://pair?nonce=abc")
	if err != nil {
		t.Fatal(err)
	}
	if prog != "rundll32.exe" {
		t.Fatalf("want rundll32.exe, got %q", prog)
	}
	want := []string{"url.dll,FileProtocolHandler", "zypheron://pair?nonce=abc"}
	if len(args) != len(want) {
		t.Fatalf("want %v, got %v", want, args)
	}
	for i, a := range args {
		if a != want[i] {
			t.Fatalf("arg %d: want %q got %q", i, want[i], a)
		}
	}
}

// Windows launcher hardening test (M3): even if a URL contains characters
// that cmd.exe would re-parse (&, |, >), rundll32 receives them as a single
// argv element without shell expansion.
func TestLauncherFor_WindowsURLWithShellChars(t *testing.T) {
	url := "zypheron://pair?nonce=abc&agent_name=foo|bar>baz"
	prog, args, err := launcherFor("windows", url)
	if err != nil {
		t.Fatal(err)
	}
	if prog != "rundll32.exe" || args[1] != url {
		t.Fatalf("URL got mangled: prog=%q args=%v", prog, args)
	}
}

func TestLauncherFor_Unsupported(t *testing.T) {
	_, _, err := launcherFor("plan9", "zypheron://pair")
	if !errors.Is(err, ErrLauncherUnavailable) {
		t.Fatalf("want ErrLauncherUnavailable, got %v", err)
	}
}

func TestIsHeadless_SSH(t *testing.T) {
	t.Setenv("SSH_TTY", "/dev/pts/0")
	t.Setenv("DISPLAY", ":0")
	if !IsHeadless() {
		t.Fatal("SSH_TTY should force headless")
	}
}
