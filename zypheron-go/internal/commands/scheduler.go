package commands

import (
	"fmt"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

// SchedulerCmd returns the scheduler command
func SchedulerCmd() *cobra.Command {
	var cronSpec string

	cmd := &cobra.Command{
		Use:   "scheduler",
		Short: "Task scheduling management",
		Long:  "Schedule and manage recurring security tasks.",
	}

	createCmd := &cobra.Command{
		Use:   "create [task]",
		Short: "Create a scheduled task",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Scheduling task with cron: %s\n", ui.Accent.Sprint(cronSpec))
			return nil
		},
	}
	createCmd.Flags().StringVar(&cronSpec, "cron", "", "Cron expression (e.g. '0 0 * * *')")

	cmd.AddCommand(createCmd)
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List scheduled tasks",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(ui.Primary.Sprint("Scheduled Tasks:"))
			return nil
		},
	})

	return cmd
}
