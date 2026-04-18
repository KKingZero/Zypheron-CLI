package tools

import (
	"strings"
	"testing"
)

func TestGetBulkInstallCommandUsesAptNamesOnNonBlackArch(t *testing.T) {
	cmd := GetBulkInstallCommand([]ToolInfo{
		{Name: "msfconsole", InstallCmd: "metasploit-framework"},
	})

	if strings.Contains(cmd, " metasploit ") {
		t.Fatalf("bulk install command used BlackArch package name on non-BlackArch host: %q", cmd)
	}
	if !strings.Contains(cmd, "metasploit-framework") {
		t.Fatalf("bulk install command missing apt package name: %q", cmd)
	}
}

func TestGetBulkInstallCommandSkipsC2Frameworks(t *testing.T) {
	cmd := GetBulkInstallCommand([]ToolInfo{
		{Name: "sliver", InstallCmd: "sliver", Categories: []string{"c2", "post"}},
		{Name: "empire", InstallCmd: "powershell-empire", Categories: []string{"c2", "post"}},
		{Name: "nmap", InstallCmd: "nmap", Categories: []string{"scan"}},
	})

	if strings.Contains(cmd, "sliver") || strings.Contains(cmd, "powershell-empire") {
		t.Fatalf("bulk install command should not auto-install C2 frameworks: %q", cmd)
	}
	if !strings.Contains(cmd, "nmap") {
		t.Fatalf("bulk install command should keep non-C2 tools: %q", cmd)
	}
}
