package commands

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/yourusername/zypheron/internal/aibridge"
	"github.com/yourusername/zypheron/internal/ui"
)

var (
	aiProvider string
	aiList     bool
)

// AICmd manages the AI engine
func AICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ai",
		Short: "Manage the AI engine",
		Long: `Manage the Zypheron AI engine.

The AI engine provides:
  • Multi-provider AI support (Claude, OpenAI, Gemini, DeepSeek, Grok, Ollama)
  • ML-powered vulnerability prediction
  • Autonomous pentesting agents
  • Intelligent scan analysis
  • CVE enrichment`,
	}

	// Start command
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the AI engine",
		RunE:  runAIStart,
	}

	// Stop command
	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the AI engine",
		RunE:  runAIStop,
	}

	// Status command
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Check AI engine status",
		RunE:  runAIStatus,
	}

	// Providers command
	providersCmd := &cobra.Command{
		Use:   "providers",
		Short: "List available AI providers",
		RunE:  runAIProviders,
	}

	// Test command
	testCmd := &cobra.Command{
		Use:   "test",
		Short: "Test AI engine with a simple query",
		RunE:  runAITest,
	}
	testCmd.Flags().StringVarP(&aiProvider, "provider", "p", "", "AI provider to test (claude, openai, gemini, etc.)")

	cmd.AddCommand(startCmd, stopCmd, statusCmd, providersCmd, testCmd)

	return cmd
}

func runAIStart(cmd *cobra.Command, args []string) error {
	bridge := aibridge.NewAIBridge()

	if bridge.IsRunning() {
		ui.Success.Println("✓ AI Engine is already running")
		return nil
	}

	fmt.Println(ui.InfoMsg("Starting AI Engine..."))
	fmt.Println(ui.Muted.Sprint("  This may take a few seconds..."))
	fmt.Println()

	if err := bridge.Start(); err != nil {
		return fmt.Errorf("failed to start AI engine: %w", err)
	}

	fmt.Println()
	ui.Success.Println("✓ AI Engine started successfully")
	fmt.Println()

	// Show available providers
	providers, defaultProvider, err := bridge.ListProviders()
	if err == nil {
		fmt.Println(ui.InfoMsg("Available AI Providers:"))
		for _, p := range providers {
			if p == defaultProvider {
				ui.Primary.Printf("  • %s (default)\n", p)
			} else {
				fmt.Printf("  • %s\n", p)
			}
		}
	}

	return nil
}

func runAIStop(cmd *cobra.Command, args []string) error {
	bridge := aibridge.NewAIBridge()

	if !bridge.IsRunning() {
		ui.Warning.Println("⚠ AI Engine is not running")
		return nil
	}

	if err := bridge.Stop(); err != nil {
		return fmt.Errorf("failed to stop AI engine: %w", err)
	}

	return nil
}

func runAIStatus(cmd *cobra.Command, args []string) error {
	bridge := aibridge.NewAIBridge()

	fmt.Println(ui.InfoMsg("AI Engine Status:"))
	fmt.Println()

	if !bridge.IsRunning() {
		ui.Danger.Println("  Status: ✗ NOT RUNNING")
		fmt.Println()
		fmt.Println(ui.InfoMsg("Start the AI engine with: zypheron ai start"))
		return nil
	}

	ui.Success.Println("  Status: ✓ RUNNING")
	fmt.Println()

	// Get health info
	health, err := bridge.Health()
	if err != nil {
		return fmt.Errorf("failed to get health status: %w", err)
	}

	// Display health info
	fmt.Println(ui.InfoMsg("Details:"))
	fmt.Printf("  Version: %v\n", health["version"])
	fmt.Printf("  Socket: %v\n", health["socket"])

	if providers, ok := health["providers"].([]interface{}); ok {
		fmt.Println("  Providers:")
		for _, p := range providers {
			ui.Success.Printf("    ✓ %s\n", p)
		}
	}

	return nil
}

func runAIProviders(cmd *cobra.Command, args []string) error {
	bridge := aibridge.NewAIBridge()

	providers, defaultProvider, err := bridge.ListProviders()
	if err != nil {
		return fmt.Errorf("failed to list providers: %w", err)
	}

	fmt.Println(ui.InfoMsg("Available AI Providers:"))
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "PROVIDER\tSTATUS\tNOTES")
	fmt.Fprintln(w, "--------\t------\t-----")

	for _, p := range providers {
		status := ui.Success.Sprint("✓ Available")
		notes := ""

		if p == defaultProvider {
			notes = ui.Primary.Sprint("(default)")
		}

		fmt.Fprintf(w, "%s\t%s\t%s\n", p, status, notes)
	}

	w.Flush()
	fmt.Println()

	fmt.Println(ui.Muted.Sprint("Set provider with: --provider <name> or in .env file"))

	return nil
}

func runAITest(cmd *cobra.Command, args []string) error {
	bridge := aibridge.NewAIBridge()

	if !bridge.IsRunning() {
		return fmt.Errorf("AI engine not running - start it with: zypheron ai start")
	}

	fmt.Println(ui.InfoMsg("Testing AI Engine..."))
	fmt.Println()

	// Test query
	testQuery := "What is a SQL injection vulnerability? Explain in one sentence."

	if aiProvider != "" {
		fmt.Printf("Using provider: %s\n", ui.Accent.Sprint(aiProvider))
	} else {
		fmt.Println("Using default provider")
	}
	fmt.Println()

	fmt.Printf("%s %s\n", ui.Accent.Sprint("Query:"), testQuery)
	fmt.Println()

	// Send to AI
	messages := []aibridge.Message{
		{Role: "user", Content: testQuery},
	}

	fmt.Print(ui.InfoMsg("Waiting for response..."))

	response, err := bridge.Chat(messages, aiProvider, 0.7, 200)
	if err != nil {
		return fmt.Errorf("AI test failed: %w", err)
	}

	fmt.Print("\r" + ui.Success.Sprint("✓ Response received    ") + "\n")
	fmt.Println()

	fmt.Printf("%s %s\n", ui.ClaudeAccent.Sprint("🤖 AI:"), response)
	fmt.Println()

	ui.Success.Println("✓ AI Engine test successful!")

	return nil
}

