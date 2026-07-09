package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCommandWantsJSONOutput(t *testing.T) {
	cmd := &cobra.Command{Use: "scan"}
	format := "text"
	cmd.Flags().StringVar(&format, "format", "text", "")

	if commandWantsJSONOutput(cmd) {
		t.Fatal("commandWantsJSONOutput() = true for default text format")
	}

	if err := cmd.Flags().Set("format", "JSON"); err != nil {
		t.Fatalf("set format: %v", err)
	}
	if !commandWantsJSONOutput(cmd) {
		t.Fatal("commandWantsJSONOutput() = false for JSON format")
	}
}

func TestJSONScanModeSuppressesStartupSideEffects(t *testing.T) {
	root := &cobra.Command{Use: "zypheron"}
	scan := &cobra.Command{Use: "scan"}
	format := "text"
	scan.Flags().StringVar(&format, "format", "text", "")
	root.AddCommand(scan)

	if err := scan.Flags().Set("format", "json"); err != nil {
		t.Fatalf("set format: %v", err)
	}

	if shouldShowStartupBanner(root, scan) {
		t.Fatal("JSON scan mode should suppress startup banner")
	}
	if shouldAutoStartAI(scan) {
		t.Fatal("JSON scan mode should suppress background AI auto-start")
	}
}

func TestCompletionCommandSuppressesStartupSideEffects(t *testing.T) {
	cmd := &cobra.Command{Use: "completion"}
	if shouldAutoStartAI(cmd) {
		t.Fatal("completion command should not auto-start AI")
	}
	if shouldShowStartupBanner(&cobra.Command{Use: "zypheron"}, cmd) {
		t.Fatal("completion command should not show startup banner")
	}
}

func TestAutopentSuppressesStartupSideEffectsBeforeGate(t *testing.T) {
	cmd := &cobra.Command{Use: "autopent"}
	if shouldAutoStartAI(cmd) {
		t.Fatal("autopent command should not auto-start AI before feature flag gate")
	}
}

func TestRootCommandRegistersAutopent(t *testing.T) {
	root := newRootCommand()
	cmd, _, err := root.Find([]string{"autopent", "--help"})
	if err != nil {
		t.Fatalf("Find autopent: %v", err)
	}
	if cmd == nil || cmd.Name() != "autopent" {
		t.Fatalf("autopent command not registered, got %#v", cmd)
	}
	if !strings.Contains(cmd.Long, "ZYPHERON_ENABLE_AUTOPENT=1") {
		t.Fatalf("autopent help does not document feature flag: %q", cmd.Long)
	}
}
