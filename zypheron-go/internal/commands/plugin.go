package commands

import (
	"fmt"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

// PluginCmd returns the plugin command
func PluginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Plugin system management",
		Long:  "Manage extensions and plugins for Zypheron.",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List installed plugins",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(ui.Primary.Sprint("Installed Plugins:"))
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "search [keyword]",
		Short: "Search plugin marketplace",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(ui.InfoMsg("Searching marketplace..."))
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "install [plugin]",
		Short: "Install a plugin",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Installing plugin: %s\n", ui.Accent.Sprint(args[0]))
			return nil
		},
	})

	return cmd
}
