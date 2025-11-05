package commands

import (
	"errors"
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	cmd.AddCommand(configSetKeyCmd())
	cmd.AddCommand(configGetProvidersCmd())

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

// configSetKeyCmd securely stores an API key
func configSetKeyCmd() *cobra.Command {
	var readFromStdin bool

	cmd := &cobra.Command{
		Use:   "set-key <provider> [api-key]",
		Short: "Securely store an API key in system keyring",
		Long: `Store an API key securely in the system keyring.
		
Supported providers:
  • anthropic  - Claude API
  • openai     - GPT-4 API
  • google     - Gemini API
  • kimi       - Kimi/Moonshot API
  • deepseek   - DeepSeek API
  • grok       - Grok/xAI API
  • nvd        - NVD API for CVE data

Example:
  zypheron config set-key anthropic
  zypheron config set-key anthropic sk-ant-your-key-here`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := args[0]
			var apiKey string

			interactive := isInteractive(cmd) && !readFromStdin

			// Get API key from args or prompt securely
			if len(args) >= 2 {
				apiKey = args[1]
			} else if !interactive {
				var err error
				apiKey, err = readLineFromInput(cmd)
				if err != nil {
					return fmt.Errorf("failed to read API key from stdin: %w", err)
				}
				if apiKey == "" {
					return fmt.Errorf("no API key provided via stdin")
				}
			} else {
				prompt := &survey.Password{
					Message: fmt.Sprintf("Enter API key for %s:", provider),
				}
				if err := survey.AskOne(prompt, &apiKey, survey.WithValidator(survey.Required)); err != nil {
					if errors.Is(err, terminal.InterruptErr) {
						return fmt.Errorf("API key entry cancelled")
					}
					return err
				}
			}

			// Send to AI engine to store in keyring
			bridge := aibridge.NewAIBridge()
			if !bridge.IsRunning() {
				return fmt.Errorf("AI engine not running. Start it with: zypheron ai start")
			}

			params := map[string]interface{}{
				"provider": provider,
				"api_key":  apiKey,
			}

			resp, err := bridge.StoreAPIKey(params)
			if err != nil {
				return fmt.Errorf("failed to store API key: %w", err)
			}

			success, _ := resp["success"].(bool)
			if success {
				fmt.Println(ui.SuccessMsg(fmt.Sprintf("API key for '%s' stored securely in keyring", provider)))
			} else {
				if msg, ok := resp["error"].(string); ok && msg != "" {
					return fmt.Errorf("failed to store API key: %s", msg)
				}
				return fmt.Errorf("failed to store API key")
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&readFromStdin, "stdin", false, "Read API key from stdin instead of interactive prompt")

	return cmd
}

// configGetProvidersCmd lists configured API providers
func configGetProvidersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get-providers",
		Short: "List configured AI providers",
		Long:  "Show which AI providers have API keys configured in the system keyring",
		RunE: func(cmd *cobra.Command, args []string) error {
			bridge := aibridge.NewAIBridge()
			if !bridge.IsRunning() {
				return fmt.Errorf("AI engine not running. Start it with: zypheron ai start")
			}

			resp, err := bridge.GetConfiguredProviders()
			if err != nil {
				return fmt.Errorf("failed to get providers: %w", err)
			}

			providers := resp["providers"].([]interface{})

			fmt.Printf("\n%s\n\n", ui.Primary.Sprint("Configured AI Providers:"))
			if len(providers) == 0 {
				fmt.Println(ui.Muted.Sprint("  No providers configured yet"))
				fmt.Println()
				fmt.Println(ui.InfoMsg("Configure a provider with: zypheron config set-key <provider>"))
			} else {
				for _, p := range providers {
					fmt.Printf("  %s %s\n", ui.Success.Sprint("✓"), p)
				}
			}
			fmt.Println()

			return nil
		},
	}
}
