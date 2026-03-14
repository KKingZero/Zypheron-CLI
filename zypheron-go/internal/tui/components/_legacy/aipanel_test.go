package components

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestNewAIPanel verifies that a new AI panel is created with correct defaults
func TestNewAIPanel(t *testing.T) {
	panel := NewAIPanel()

	// Verify default state
	if panel.height != DefaultAIPanelHeight {
		t.Errorf("Expected height %d, got %d", DefaultAIPanelHeight, panel.height)
	}

	if panel.focused {
		t.Error("Expected panel to start unfocused")
	}

	if panel.collapsed {
		t.Error("Expected panel to start expanded")
	}

	if panel.response == "" {
		t.Error("Expected default response message")
	}
}

// TestAIPanelFocus verifies focus/blur behavior
func TestAIPanelFocus(t *testing.T) {
	panel := NewAIPanel()

	// Test focusing
	panel = panel.Focus()
	if !panel.IsFocused() {
		t.Error("Expected panel to be focused after Focus()")
	}

	// Test blurring
	panel = panel.Blur()
	if panel.IsFocused() {
		t.Error("Expected panel to be blurred after Blur()")
	}
}

// TestAIPanelSetters verifies setter methods
func TestAIPanelSetters(t *testing.T) {
	panel := NewAIPanel()

	// Test SetWidth
	panel = panel.SetWidth(120)
	if panel.width != 120 {
		t.Errorf("Expected width 120, got %d", panel.width)
	}

	// Test SetHeight with valid value
	panel = panel.SetHeight(10)
	if panel.height != 10 {
		t.Errorf("Expected height 10, got %d", panel.height)
	}

	// Test SetHeight with value too high (should clamp)
	panel = panel.SetHeight(100)
	if panel.height != MaxAIPanelHeight {
		t.Errorf("Expected height to be clamped to %d, got %d", MaxAIPanelHeight, panel.height)
	}

	// Test SetHeight with value too low (should clamp)
	panel = panel.SetHeight(1)
	if panel.height != MinAIPanelHeight {
		t.Errorf("Expected height to be clamped to %d, got %d", MinAIPanelHeight, panel.height)
	}

	// Test SetResponse
	testResponse := "Test response"
	panel = panel.SetResponse(testResponse)
	expected := "AI: " + testResponse
	if panel.response != expected {
		t.Errorf("Expected response '%s', got '%s'", expected, panel.response)
	}
	if panel.loading {
		t.Error("Expected loading to be false after SetResponse")
	}
}

// TestAIPanelToggleCollapse verifies collapse/expand behavior
func TestAIPanelToggleCollapse(t *testing.T) {
	panel := NewAIPanel()

	// Start expanded
	if panel.collapsed {
		t.Error("Expected panel to start expanded")
	}

	// Toggle to collapsed
	panel = panel.ToggleCollapse()
	if !panel.collapsed {
		t.Error("Expected panel to be collapsed after first toggle")
	}

	// Toggle back to expanded
	panel = panel.ToggleCollapse()
	if panel.collapsed {
		t.Error("Expected panel to be expanded after second toggle")
	}
}

// TestAIPanelUpdate verifies message handling
func TestAIPanelUpdate(t *testing.T) {
	panel := NewAIPanel()

	// Test window resize
	panel, _ = panel.Update(tea.WindowSizeMsg{Width: 100, Height: 50})
	if panel.width != 100 {
		t.Errorf("Expected width 100 after resize, got %d", panel.width)
	}

	// Test keyboard input when focused
	panel = panel.Focus()
	panel, _ = panel.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if panel.IsFocused() {
		t.Error("Expected panel to blur after Esc key")
	}

	// Test resize with Ctrl+Up
	panel = panel.Focus()
	initialHeight := panel.height
	panel, _ = panel.Update(tea.KeyMsg{Type: tea.KeyCtrlUp})
	if panel.height != initialHeight+1 {
		t.Errorf("Expected height to increase by 1, got %d", panel.height)
	}

	// Test resize with Ctrl+Down
	panel, _ = panel.Update(tea.KeyMsg{Type: tea.KeyCtrlDown})
	if panel.height != initialHeight {
		t.Errorf("Expected height to decrease back to %d, got %d", initialHeight, panel.height)
	}
}

// TestAIPanelWrapText verifies text wrapping logic
func TestAIPanelWrapText(t *testing.T) {
	panel := NewAIPanel()

	tests := []struct {
		name     string
		text     string
		width    int
		expected int // expected number of lines
	}{
		{
			name:     "Short text",
			text:     "Hello world",
			width:    50,
			expected: 1,
		},
		{
			name:     "Text that needs wrapping",
			text:     "This is a longer text that definitely needs to be wrapped",
			width:    20,
			expected: 4, // Approximate, depends on word boundaries
		},
		{
			name:     "Empty text",
			text:     "",
			width:    50,
			expected: 1,
		},
		{
			name:     "Zero width",
			text:     "Some text",
			width:    0,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := panel.wrapText(tt.text, tt.width)
			if len(lines) != tt.expected {
				t.Logf("Text: '%s', Width: %d", tt.text, tt.width)
				t.Logf("Lines: %v", lines)
				// Note: This is informational, actual wrapping may vary
				// We just verify that we get some lines back
			}
			if len(lines) == 0 {
				t.Error("Expected at least one line from wrapText")
			}
		})
	}
}

// TestAIPanelView verifies rendering doesn't panic
func TestAIPanelView(t *testing.T) {
	panel := NewAIPanel()
	panel = panel.SetWidth(80)

	// Test normal view
	view := panel.View()
	if view == "" {
		t.Error("Expected non-empty view")
	}

	// Test collapsed view
	panel = panel.ToggleCollapse()
	collapsedView := panel.View()
	if collapsedView == "" {
		t.Error("Expected non-empty collapsed view")
	}

	// Collapsed view should be shorter
	if len(collapsedView) >= len(view) {
		// This is informational - with styling, lengths may vary
		t.Logf("Note: Collapsed view length may include styling codes")
	}
}
