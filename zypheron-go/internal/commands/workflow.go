package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

// WorkflowCmd returns the workflow command
func WorkflowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workflow",
		Short: "Workflow automation management",
		Long:  "Create, edit, run, and list automated security workflows.",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "create [name]",
		Short: "Create a new workflow",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(ui.InfoMsg("Opening workflow editor..."))
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List available workflows",
		RunE: func(cmd *cobra.Command, args []string) error {
			workflows, err := listStoredWorkflows()
			if err != nil {
				return err
			}

			fmt.Println(ui.Primary.Sprint("Available Workflows:"))
			if len(workflows) == 0 {
				fmt.Println(ui.Muted.Sprint("  No stored workflows found"))
				fmt.Println(ui.Muted.Sprint("  Create one with: zypheron workflow create <name>"))
				return nil
			}

			for _, workflow := range workflows {
				fmt.Println(ui.Muted.Sprint("  - " + workflow))
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "run [name]",
		Short: "Run a workflow",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("workflow name required")
			}
			fmt.Printf("Running workflow: %s\n", ui.Accent.Sprint(args[0]))
			return nil
		},
	})

	return cmd
}

func listStoredWorkflows() ([]string, error) {
	cfg := config.Get()
	workflowDir := filepath.Join(cfg.ConfigDir, "workflows")

	if err := os.MkdirAll(workflowDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to access workflow storage: %w", err)
	}

	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read workflow storage: %w", err)
	}

	workflows := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		switch strings.ToLower(filepath.Ext(name)) {
		case ".json", ".yaml", ".yml":
			workflows = append(workflows, strings.TrimSuffix(name, filepath.Ext(name)))
		}
	}

	sort.Strings(workflows)
	return workflows, nil
}
