package views

import (
	"strings"
	"testing"
)

func TestSlashMenuMetadataIncludesDiscoverableSubcommands(t *testing.T) {
	required := []string{
		"/agents use",
		"/agents edit",
		"/agents delete",
		"/auth use",
		"/auth status",
		"/auth clear",
		"/auth test",
	}

	for _, command := range required {
		item, ok := SlashMenuItemByCommand(command)
		if !ok {
			t.Fatalf("missing slash menu command %q", command)
		}
		if item.Usage == "" {
			t.Fatalf("command %q has empty usage", command)
		}
		if !strings.HasPrefix(item.Usage, "/") {
			t.Fatalf("command %q usage = %q, want slash-prefixed", command, item.Usage)
		}
	}
}

func TestSlashCommandUsageIsSlashPrefixed(t *testing.T) {
	for _, item := range SlashMenuItems {
		if item.Usage == "" {
			t.Fatalf("command %q has empty usage", item.Command)
		}
		if !strings.HasPrefix(item.Usage, "/") {
			t.Fatalf("command %q usage = %q, want slash-prefixed", item.Command, item.Usage)
		}
	}
}

func TestQuickStartUsesSlashPrefixedExplicitCommands(t *testing.T) {
	rendered := renderQuickStartCard(100)

	for _, want := range []string{"/ai <question>", "/autopent <target>", "/dork <query>", "/scan <target>"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("quick start missing %q in:\n%s", want, rendered)
		}
	}
	for _, bare := range []string{"ai <question>", "autopent <target>", "dork <query>"} {
		if strings.Contains(rendered, "\n"+bare) || strings.Contains(rendered, " "+bare) {
			t.Fatalf("quick start contains bare command example %q in:\n%s", bare, rendered)
		}
	}
}
