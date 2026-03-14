package commands

import (
    "fmt"
    "os"

    "github.com/AlecAivazis/survey/v2"
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
    cmd.AddCommand(configShowCmd())
    cmd.AddCommand(configResetCmd())

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
    return &cobra.Command{
        Use:   "set-key <provider> [api-key]",
        Short: "Securely store an API key in system keyring",
        Long: `Store an API key securely in the system keyring.

Supported providers:
  • anthropic  - Claude API (claude-opus-4-6, claude-sonnet-4-6)
  • openai     - OpenAI API (gpt-5.4)
  • google     - Gemini API (gemini-3.1-pro-preview)
  • kimi       - Kimi/Moonshot API (kimi-k2)
  • deepseek   - DeepSeek API (deepseek-r1)
  • nvd        - NVD API for CVE data

Example:
  zypheron config set-key anthropic
  zypheron config set-key anthropic sk-ant-your-key-here`,
        Args: cobra.RangeArgs(1, 2),
        RunE: func(cmd *cobra.Command, args []string) error {
            provider := args[0]
            var apiKey string

            // Get API key from args or prompt securely
            if len(args) >= 2 {
                apiKey = args[1]
            } else {
                prompt := &survey.Password{
                    Message: fmt.Sprintf("Enter API key for %s:", provider),
                }
                if err := survey.AskOne(prompt, &apiKey, survey.WithValidator(survey.Required)); err != nil {
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

            if resp["success"].(bool) {
                fmt.Println(ui.SuccessMsg(fmt.Sprintf("API key for '%s' stored securely in keyring", provider)))
            } else {
                return fmt.Errorf("failed to store API key")
            }

            return nil
        },
    }
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

// configShowCmd shows all configuration in a formatted way
func configShowCmd() *cobra.Command {
    return &cobra.Command{
        Use:   "show",
        Short: "Show current configuration",
        Long:  "Display all current configuration settings in a formatted table",
        RunE: func(cmd *cobra.Command, args []string) error {
            initConfig()

            fmt.Printf("\n%s\n", ui.Primary.Sprint("═══════════════════════════════════════"))
            fmt.Printf("%s\n", ui.Primary.Sprint("  CONFIGURATION"))
            fmt.Printf("%s\n\n", ui.Primary.Sprint("═══════════════════════════════════════"))

            configFile := viper.ConfigFileUsed()
            if configFile == "" {
                configFile = "~/.config/zypheron/config.yaml (default location)"
            }
            fmt.Printf("%s\n", ui.Accent.Sprint("Config File:"))
            fmt.Printf("  %s\n\n", ui.Muted.Sprint(configFile))

            settings := viper.AllSettings()
            if len(settings) == 0 {
                fmt.Println(ui.InfoMsg("No custom configuration found, using defaults"))
                fmt.Println()
                fmt.Println(ui.Muted.Sprint("Set configuration with: zypheron config set <key> <value>"))
                fmt.Println()
                return nil
            }

            fmt.Printf("%s\n", ui.Accent.Sprint("Settings:"))

            // Display settings in organized groups
            displayConfigGroup("API Settings", []string{"api.url", "api.timeout"})
            displayConfigGroup("Scanning Settings", []string{"scanning.default_ports", "scanning.timeout"})
            displayConfigGroup("Output Settings", []string{"output.format", "output.colorize"})

            // Display any other settings not in the groups above
            knownKeys := map[string]bool{
                "api.url": true, "api.timeout": true,
                "scanning.default_ports": true, "scanning.timeout": true,
                "output.format": true, "output.colorize": true,
            }

            var otherSettings []string
            for key := range settings {
                if !knownKeys[key] {
                    otherSettings = append(otherSettings, key)
                }
            }

            if len(otherSettings) > 0 {
                fmt.Printf("\n  %s\n", ui.Accent.Sprint("Other:"))
                for _, key := range otherSettings {
                    fmt.Printf("    %-25s %v\n", ui.Muted.Sprint(key+":"), viper.Get(key))
                }
            }

            fmt.Println()
            fmt.Println(ui.Muted.Sprint("Modify with: zypheron config set <key> <value>"))
            fmt.Println(ui.Muted.Sprint("Reset to defaults: zypheron config reset"))
            fmt.Println()

            return nil
        },
    }
}

// displayConfigGroup displays a group of related config settings
func displayConfigGroup(title string, keys []string) {
    hasValues := false
    for _, key := range keys {
        if viper.IsSet(key) {
            hasValues = true
            break
        }
    }

    if !hasValues {
        return
    }

    fmt.Printf("\n  %s\n", ui.Accent.Sprint(title+":"))
    for _, key := range keys {
        if viper.IsSet(key) {
            value := viper.Get(key)
            displayKey := key
            for i := len(key) - 1; i >= 0; i-- {
                if key[i] == '.' {
                    displayKey = key[i+1:]
                    break
                }
            }
            fmt.Printf("    %-25s %v\n", ui.Muted.Sprint(displayKey+":"), value)
        }
    }
}

// configResetCmd resets configuration to defaults
func configResetCmd() *cobra.Command {
    var force bool

    cmd := &cobra.Command{
        Use:   "reset",
        Short: "Reset configuration to defaults",
        Long:  "Reset all configuration settings to their default values. This will remove your config file.",
        RunE: func(cmd *cobra.Command, args []string) error {
            if !force {
                fmt.Println()
                fmt.Println(ui.WarningMsg("This will reset ALL configuration to defaults!"))
                fmt.Print(ui.Muted.Sprint("Are you sure? (yes/no): "))

                var response string
                fmt.Scanln(&response)

                if response != "yes" && response != "y" {
                    fmt.Println(ui.InfoMsg("Cancelled"))
                    return nil
                }
            }

            initConfig()
            configFile := viper.ConfigFileUsed()

            if configFile == "" {
                fmt.Println(ui.InfoMsg("No configuration file found, already using defaults"))
                return nil
            }

            if err := os.Remove(configFile); err != nil {
                if !os.IsNotExist(err) {
                    return fmt.Errorf("failed to remove config file: %w", err)
                }
            }

            fmt.Println(ui.SuccessMsg("Configuration reset to defaults"))
            fmt.Println()
            fmt.Println(ui.InfoMsg("Default settings:"))
            fmt.Printf("  api.url:               %s\n", "http://localhost:3001")
            fmt.Printf("  api.timeout:           %v\n", 30000)
            fmt.Printf("  scanning.default_ports: %s\n", "1-1000")
            fmt.Printf("  scanning.timeout:      %v\n", 300)
            fmt.Printf("  output.format:         %s\n", "text")
            fmt.Printf("  output.colorize:       %v\n", true)
            fmt.Println()

            return nil
        },
    }

    cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")

    return cmd
}
