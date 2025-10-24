package commands

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/yourusername/zypheron/internal/ui"
)

// ConfigCmd returns the config management command
func ConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration management",
		Long:  "Manage Zypheron CLI configuration settings",
	}

	cmd.AddCommand(configGetCmd())
	cmd.AddCommand(configSetCmd())
	cmd.AddCommand(configPathCmd())
	cmd.AddCommand(configWizardCmd())

	return cmd
}

// configGetCmd gets a config value
func configGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get [key]",
		Short: "Get configuration value",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			initConfig()

			if len(args) == 0 {
				// Show all config
				settings := viper.AllSettings()
				fmt.Printf("\n%s\n\n", ui.Primary.Sprint("Configuration:"))
				for key, value := range settings {
					fmt.Printf("  %s: %v\n", ui.Accent.Sprint(key), value)
				}
				fmt.Println()
			} else {
				// Show specific key
				key := args[0]
				value := viper.Get(key)
				if value == nil {
					return fmt.Errorf("configuration key '%s' not found", key)
				}
				fmt.Printf("%s: %v\n", ui.Accent.Sprint(key), value)
			}

			return nil
		},
	}
}

// configSetCmd sets a config value
func configSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set configuration value",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			initConfig()

			key := args[0]
			value := args[1]

			viper.Set(key, value)
			if err := viper.WriteConfig(); err != nil {
				return err
			}

			fmt.Println(ui.SuccessMsg(fmt.Sprintf("Set %s = %s", key, value)))
			return nil
		},
	}
}

// configPathCmd shows the config file path
func configPathCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "path",
		Short: "Show configuration file path",
		RunE: func(cmd *cobra.Command, args []string) error {
			initConfig()
			configFile := viper.ConfigFileUsed()
			if configFile == "" {
				configFile = "~/.config/zypheron/config.yaml (default)"
			}
			fmt.Printf("Config file: %s\n", ui.Accent.Sprint(configFile))
			return nil
		},
	}
}

// configWizardCmd runs the configuration wizard
func configWizardCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "wizard",
		Short: "Run configuration wizard",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("\n%s\n\n", ui.Primary.Sprint("╔═══ CONFIGURATION WIZARD ═══════════════════════════╗"))
			fmt.Println(ui.InfoMsg("Interactive configuration wizard"))
			fmt.Println(ui.Muted.Sprint("  Configure API endpoints, AI settings, and more"))
			fmt.Printf("\n%s\n\n", ui.Primary.Sprint("╚════════════════════════════════════════════════════╝"))

			// This would be an interactive wizard using survey
			fmt.Println(ui.InfoMsg("Wizard implementation coming soon!"))
			fmt.Println(ui.InfoMsg("For now, use: zypheron config set <key> <value>"))
			fmt.Println()

			return nil
		},
	}
}

// initConfig initializes the configuration
func initConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("$HOME/.config/zypheron")
	viper.AddConfigPath(".")

	// Set defaults
	viper.SetDefault("api.url", "http://localhost:3001")
	viper.SetDefault("api.timeout", 30000)
	viper.SetDefault("scanning.default_ports", "1-1000")
	viper.SetDefault("scanning.timeout", 300)
	viper.SetDefault("output.format", "text")
	viper.SetDefault("output.colorize", true)

	// Read config if it exists
	viper.ReadInConfig()
}

