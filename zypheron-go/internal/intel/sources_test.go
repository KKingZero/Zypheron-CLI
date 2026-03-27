package intel

import (
	"strings"
	"testing"
)

func TestAnalystPromptBlockFramesSourcesAsRecommendations(t *testing.T) {
	block := AnalystPromptBlock()

	required := []string{
		"External analyst resources you may recommend when they fit the task:",
		"shodan.io",
		"censys.io",
		"vulners.com",
	}

	for _, want := range required {
		if !strings.Contains(block, want) {
			t.Fatalf("AnalystPromptBlock() missing %q in block:\n%s", want, block)
		}
	}
}

func TestWebSearchPromptBlockRestrictsToWebSafeSyntax(t *testing.T) {
	block := WebSearchPromptBlock("duckduckgo")

	required := []string{
		"Use only query syntax that is valid for duckduckgo web search.",
		"site filters or plain search terms only",
		"grep.app",
		"searchcode.com",
		"publicwww.com",
		"crt.sh",
	}

	for _, want := range required {
		if !strings.Contains(block, want) {
			t.Fatalf("WebSearchPromptBlock() missing %q in block:\n%s", want, block)
		}
	}

	unexpected := []string{
		"shodan.io",
		"censys.io",
		"fofa.info",
	}

	for _, reject := range unexpected {
		if strings.Contains(block, reject) {
			t.Fatalf("WebSearchPromptBlock() unexpectedly included %q in block:\n%s", reject, block)
		}
	}
}
