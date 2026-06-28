package tui

import (
	"strings"
	"testing"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/components"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/views"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func newDashboardTestModel() Model {
	model := NewModel()
	model.state = stateDashboard
	model.width = 100
	model.height = 36
	model.header = components.NewHeader()
	model.console = views.NewConsole(100, 20)
	model.summary = views.NewSummary(100)
	model.input = views.NewInput(100)
	model.modelSelector = views.NewModelSelector(100)
	model.applyInteractionMode()
	return model
}

func TestTabKeysRenderDistinctContextPanels(t *testing.T) {
	testCases := []struct {
		key  rune
		want string
	}{
		{'R', "Recon context is setup/status-only"},
		{'S', "Quick actions: /scan <target>"},
		{'A', "Active model:"},
		{'T', "Entry points: /tools, /doctor"},
		{'H', "No scan history is loaded"},
	}

	seen := map[string]bool{}
	for _, tc := range testCases {
		model := newDashboardTestModel()
		updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{tc.key}})
		rendered := updated.(Model).View()
		if !strings.Contains(rendered, tc.want) {
			t.Fatalf("tab %q rendered content missing %q:\n%s", string(tc.key), tc.want, rendered)
		}
		if seen[rendered] {
			t.Fatalf("tab %q rendered duplicate context panel", string(tc.key))
		}
		seen[rendered] = true
	}
}

func TestInitialEmptyDashboardKeepsWelcomeScreen(t *testing.T) {
	model := newDashboardTestModel()
	rendered := model.View()

	if !strings.Contains(rendered, "Quick Start") {
		t.Fatalf("initial dashboard should render welcome quick start:\n%s", rendered)
	}
	if strings.Contains(rendered, "No active scan") {
		t.Fatalf("initial dashboard rendered scan context before tab navigation:\n%s", rendered)
	}
}

func TestEmptyStatePanelFitsNarrowViewport(t *testing.T) {
	model := newDashboardTestModel()
	model.width = 30
	model.console = views.NewConsole(30, 10)

	rendered := model.renderTabContextPanel()
	for _, line := range strings.Split(rendered, "\n") {
		if width := lipgloss.Width(line); width > model.width {
			t.Fatalf("line width = %d, want <= %d:\n%s", width, model.width, rendered)
		}
	}
}

func TestModeInputFitsNarrowViewport(t *testing.T) {
	model := newDashboardTestModel()
	model.width = 30
	model.input = views.NewInput(30)
	model.applyInteractionMode()

	rendered := model.renderModeInput()
	for _, line := range strings.Split(rendered, "\n") {
		if width := lipgloss.Width(line); width > model.width {
			t.Fatalf("line width = %d, want <= %d:\n%s", width, model.width, rendered)
		}
	}
}

func TestShiftTabCyclesToPlanWithoutOpeningModelSelector(t *testing.T) {
	model := newDashboardTestModel()

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	got := updated.(Model)

	if got.mode != modePlan {
		t.Fatalf("mode = %s, want Plan", got.mode.Label())
	}
	if got.modelSelector.IsOpen() {
		t.Fatal("shift+tab opened model selector; Tab should remain the model selector key")
	}
	if got.input.TextInput.Placeholder != modePlan.Placeholder() {
		t.Fatalf("placeholder = %q, want %q", got.input.TextInput.Placeholder, modePlan.Placeholder())
	}
}

func TestHelpUsesSlashPrefixedCommandExamples(t *testing.T) {
	model := newDashboardTestModel()
	rendered := model.renderHelp()

	for _, want := range []string{"/ai <question>", "/autopent <target>", "/dork <query>", "/scan <target>", "/recon <domain>"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("help missing %q in:\n%s", want, rendered)
		}
	}

	for _, bare := range []string{"  ai <question>", "  autopent <target>", "  dork <query>"} {
		if strings.Contains(rendered, bare) {
			t.Fatalf("help contains bare command example %q in:\n%s", bare, rendered)
		}
	}
}

func TestReconCommandDocumentsStatusOnlyBehavior(t *testing.T) {
	model := newDashboardTestModel()

	cmd := model.handleCommand("/recon example.com")
	if cmd != nil {
		t.Fatal("/recon returned a command; expected status/context-only behavior")
	}

	rendered := model.console.View()
	if !strings.Contains(rendered, "Recon context set for example.com") {
		t.Fatalf("recon output missing context message:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Next: /scan example.com --tool nmap") {
		t.Fatalf("recon output missing slash-prefixed next actions:\n%s", rendered)
	}
}
