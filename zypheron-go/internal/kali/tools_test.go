package kali

import "testing"

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
