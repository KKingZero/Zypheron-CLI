package commands

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"
)

func TestListStoredWorkflows(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ConfigDir = tempDir

	prev := config.Get()
	config.Set(cfg)
	defer config.Set(prev)

	workflowDir := filepath.Join(tempDir, "workflows")
	if err := os.MkdirAll(workflowDir, 0o700); err != nil {
		t.Fatalf("failed to create workflow dir: %v", err)
	}

	files := []string{
		"z-last.json",
		"alpha.yaml",
		"ignored.txt",
		"beta.yml",
	}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(workflowDir, name), []byte("{}"), 0o600); err != nil {
			t.Fatalf("failed to create workflow fixture %s: %v", name, err)
		}
	}

	got, err := listStoredWorkflows()
	if err != nil {
		t.Fatalf("listStoredWorkflows() error = %v", err)
	}

	want := []string{"alpha", "beta", "z-last"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("listStoredWorkflows() = %#v, want %#v", got, want)
	}
}

func TestListStoredWorkflowsEmpty(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ConfigDir = tempDir

	prev := config.Get()
	config.Set(cfg)
	defer config.Set(prev)

	got, err := listStoredWorkflows()
	if err != nil {
		t.Fatalf("listStoredWorkflows() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("listStoredWorkflows() = %#v, want empty", got)
	}
}
