package components

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestNewStatusBar verifies default initialization
func TestNewStatusBar(t *testing.T) {
	sb := NewStatusBar()

	if sb.phase != PhaseIdle {
		t.Errorf("Expected phase PhaseIdle, got %v", sb.phase)
	}

	if sb.width != 80 {
		t.Errorf("Expected width 80, got %d", sb.width)
	}
}

// TestSetPhase verifies phase setting
func TestSetPhase(t *testing.T) {
	sb := NewStatusBar()

	tests := []Phase{
		PhaseIdle,
		PhaseRecon,
		PhaseScan,
		PhaseAnalysis,
		PhaseComplete,
	}

	for _, phase := range tests {
		sb = sb.SetPhase(phase)
		if sb.phase != phase {
			t.Errorf("Expected phase %v, got %v", phase, sb.phase)
		}
	}
}

// TestSetWidth verifies width setting
func TestSetWidth(t *testing.T) {
	sb := NewStatusBar()
	sb = sb.SetWidth(120)

	if sb.width != 120 {
		t.Errorf("Expected width 120, got %d", sb.width)
	}
}

// TestSetMessage verifies message setting
func TestSetMessage(t *testing.T) {
	sb := NewStatusBar()
	msg := "Scanning port 443..."
	sb = sb.SetMessage(msg)

	if sb.message != msg {
		t.Errorf("Expected message '%s', got '%s'", msg, sb.message)
	}
}

// TestUpdate verifies window resize handling
func TestUpdate(t *testing.T) {
	sb := NewStatusBar()

	// Simulate window resize
	msg := tea.WindowSizeMsg{
		Width:  100,
		Height: 40,
	}

	sb, _ = sb.Update(msg)

	if sb.width != 100 {
		t.Errorf("Expected width 100 after WindowSizeMsg, got %d", sb.width)
	}
}

// TestView verifies the component renders without panicking
func TestView(t *testing.T) {
	sb := NewStatusBar()

	// Test all phases render correctly
	phases := []Phase{
		PhaseIdle,
		PhaseRecon,
		PhaseScan,
		PhaseAnalysis,
		PhaseComplete,
	}

	for _, phase := range phases {
		sb = sb.SetPhase(phase)
		view := sb.View()

		// Basic sanity checks
		if len(view) == 0 {
			t.Errorf("View() returned empty string for phase %v", phase)
		}

		// Should contain phase names
		if !strings.Contains(view, "Recon") {
			t.Error("View() should contain 'Recon'")
		}
		if !strings.Contains(view, "Scan") {
			t.Error("View() should contain 'Scan'")
		}
		if !strings.Contains(view, "Analysis") {
			t.Error("View() should contain 'Analysis'")
		}

		// Should contain key hints
		if !strings.Contains(view, "cmd") {
			t.Error("View() should contain 'cmd' hint")
		}
		if !strings.Contains(view, "search") {
			t.Error("View() should contain 'search' hint")
		}
		if !strings.Contains(view, "help") {
			t.Error("View() should contain 'help' hint")
		}
		if !strings.Contains(view, "quit") {
			t.Error("View() should contain 'quit' hint")
		}
	}
}

// TestInit verifies Init() returns nil
func TestInit(t *testing.T) {
	sb := NewStatusBar()
	cmd := sb.Init()

	if cmd != nil {
		t.Error("Init() should return nil")
	}
}
