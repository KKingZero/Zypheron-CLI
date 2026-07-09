package kali

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBlackArchPackageMappings(t *testing.T) {
	tests := map[string]string{
		"nmap":       "nmap",
		"metasploit": "metasploit",
		"msfconsole": "metasploit",
		"strings":    "binutils",
	}

	for tool, want := range tests {
		if got := blackArchPackage(tool); got != want {
			t.Fatalf("blackArchPackage(%q) = %q, want %q", tool, got, want)
		}
	}
}

func TestGetToolVersionTimesOutSlowProbe(t *testing.T) {
	dir := t.TempDir()
	toolPath := filepath.Join(dir, "slowtool")
	if err := os.WriteFile(toolPath, []byte("#!/bin/sh\nsleep 5\n"), 0o755); err != nil {
		t.Fatalf("write fake tool: %v", err)
	}
	t.Setenv("PATH", dir)

	start := time.Now()
	version := getToolVersion("slowtool")
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("getToolVersion took %s, want bounded timeout", elapsed)
	}
	if version != "installed" {
		t.Fatalf("getToolVersion slow probe = %q, want installed fallback", version)
	}
}
