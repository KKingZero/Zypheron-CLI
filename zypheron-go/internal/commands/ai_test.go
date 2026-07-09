package commands

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

type fakeAIStatusBridge struct {
	running    bool
	startErr   error
	health     map[string]interface{}
	healthErr  error
	startCalls int
}

func (f *fakeAIStatusBridge) IsRunning() bool {
	return f.running
}

func (f *fakeAIStatusBridge) StartQuiet() error {
	f.startCalls++
	if f.startErr == nil {
		f.running = true
	}
	return f.startErr
}

func (f *fakeAIStatusBridge) Health() (map[string]interface{}, error) {
	return f.health, f.healthErr
}

func withFakeAIStatusBridge(t *testing.T, bridge *fakeAIStatusBridge) {
	t.Helper()
	original := newAIStatusBridge
	newAIStatusBridge = func() aiStatusBridge {
		return bridge
	}
	t.Cleanup(func() {
		newAIStatusBridge = original
	})
}

func TestRunAIStatusPrintsRunningOnlyAfterHealthSuccess(t *testing.T) {
	bridge := &fakeAIStatusBridge{
		running: true,
		health:  map[string]interface{}{"version": "test", "socket": "stdio"},
	}
	withFakeAIStatusBridge(t, bridge)

	output, err := captureCommandStdout(t, func() error {
		return runAIStatus(&cobra.Command{}, nil)
	})
	if err != nil {
		t.Fatalf("runAIStatus failed: %v", err)
	}
	if !strings.Contains(output, "RUNNING") {
		t.Fatalf("status output did not include RUNNING: %q", output)
	}
}

func TestRunAIStatusStartupFailurePrintsNotRunning(t *testing.T) {
	bridge := &fakeAIStatusBridge{startErr: errors.New("broken startup")}
	withFakeAIStatusBridge(t, bridge)

	output, err := captureCommandStdout(t, func() error {
		return runAIStatus(&cobra.Command{}, nil)
	})
	if err == nil {
		t.Fatal("runAIStatus succeeded despite startup failure")
	}
	if !strings.Contains(output, "NOT RUNNING") {
		t.Fatalf("status output did not include NOT RUNNING: %q", output)
	}
	if !strings.Contains(err.Error(), "broken startup") {
		t.Fatalf("startup error missing underlying cause: %v", err)
	}
}

func TestRunAIStatusHealthFailureDoesNotPrintRunning(t *testing.T) {
	bridge := &fakeAIStatusBridge{
		running:   true,
		healthErr: errors.New("broken pipe"),
	}
	withFakeAIStatusBridge(t, bridge)

	output, err := captureCommandStdout(t, func() error {
		return runAIStatus(&cobra.Command{}, nil)
	})
	if err == nil {
		t.Fatal("runAIStatus succeeded despite health failure")
	}
	if strings.Contains(output, "RUNNING") {
		t.Fatalf("status printed RUNNING before health success: %q", output)
	}
	if !strings.Contains(output, "UNHEALTHY") {
		t.Fatalf("status output did not include UNHEALTHY: %q", output)
	}
	if !strings.Contains(err.Error(), "broken pipe") {
		t.Fatalf("health error missing underlying cause: %v", err)
	}
}
