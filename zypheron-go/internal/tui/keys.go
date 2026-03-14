package tui

import "github.com/charmbracelet/bubbles/key"

type KeyMap struct {
	Up          key.Binding
	Down        key.Binding
	Left        key.Binding
	Right       key.Binding
	Tab         key.Binding
	Enter       key.Binding
	Quit        key.Binding
	ScanView    key.Binding
	ReconView   key.Binding
	AIView      key.Binding
	ToolsView   key.Binding
	HistoryView key.Binding
	Settings    key.Binding
	Help        key.Binding
	Command     key.Binding
}

func DefaultKeyMap() KeyMap {
	return KeyMap{
		Up: key.NewBinding(
			key.WithKeys("k", "up"),
			key.WithHelp("k/↑", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("j", "down"),
			key.WithHelp("j/↓", "down"),
		),
		Left: key.NewBinding(
			key.WithKeys("h", "left"),
			key.WithHelp("h/←", "left"),
		),
		Right: key.NewBinding(
			key.WithKeys("l", "right"),
			key.WithHelp("l/→", "right"),
		),
		Tab: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", "switch view mode"),
		),
		Enter: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "select"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
		ScanView: key.NewBinding(
			key.WithKeys("S"),
			key.WithHelp("S", "scan"),
		),
		ReconView: key.NewBinding(
			key.WithKeys("R"),
			key.WithHelp("R", "recon"),
		),
		AIView: key.NewBinding(
			key.WithKeys("A"),
			key.WithHelp("A", "ai panel"),
		),
		ToolsView: key.NewBinding(
			key.WithKeys("T"),
			key.WithHelp("T", "tools"),
		),
		HistoryView: key.NewBinding(
			key.WithKeys("H"), // Lowercase 'h' is left navigation
			key.WithHelp("H", "history"),
		),
		Settings: key.NewBinding(
			key.WithKeys("ctrl+i"),
			key.WithHelp("ctrl+i", "settings"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
		Command: key.NewBinding(
			key.WithKeys(":", "/"),
			key.WithHelp(":", "command"),
		),
	}
}
