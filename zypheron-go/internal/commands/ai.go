package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

var (
	aiProvider string
)

type aiStatusBridge interface {
	IsRunning() bool
	StartQuiet() error
	Health() (map[string]interface{}, error)
}

var newAIStatusBridge = func() aiStatusBridge {
	return aibridge.NewAIBridge()
}

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

	// Doctor command
	doctorCmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose AI engine setup and connectivity",
		RunE:  runAIDoctor,
	}

	cmd.AddCommand(startCmd, stopCmd, statusCmd, providersCmd, testCmd, doctorCmd)

	return cmd
}

func runAIStart(cmd *cobra.Command, args []string) error {
	bridge := aibridge.NewAIBridge()

	if bridge.IsRunning() {
		ui.Success.Println("✓ AI Engine is already running (core always-on)")
		return nil
	}

	fmt.Println(ui.InfoMsg("Ensuring AI Engine is ready (core always-on)..."))
	fmt.Println(ui.Muted.Sprint("  This may take a few seconds."))
	fmt.Println()

	if err := bridge.Start(); err != nil {
		return fmt.Errorf("failed to start AI engine: %w", err)
	}

	fmt.Println()
	ui.Success.Println("✓ AI Engine ready")
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
	ui.Warning.Println("⚠ AI engine is a core always-on component and cannot be stopped.")
	fmt.Println(ui.Muted.Sprint("  It will remain active and auto-restart if needed."))
	return nil
}

func runAIStatus(cmd *cobra.Command, args []string) error {
	bridge := newAIStatusBridge()

	fmt.Println(ui.InfoMsg("AI Engine Status:"))
	fmt.Println()

	if !bridge.IsRunning() {
		if err := bridge.StartQuiet(); err != nil {
			ui.Danger.Println("  Status: ✗ NOT RUNNING")
			fmt.Println()
			return fmt.Errorf("failed to auto-start core AI engine: %w", err)
		}
	}

	// Get health info
	health, err := bridge.Health()
	if err != nil {
		ui.Danger.Println("  Status: ✗ UNHEALTHY")
		fmt.Println()
		return fmt.Errorf("AI engine health check failed: %w", err)
	}

	ui.Success.Println("  Status: ✓ RUNNING")
	fmt.Println()

	// Display health info
	fmt.Println(ui.InfoMsg("Details:"))
	fmt.Printf("  Version: %v\n", health["version"])
	if endpoint, ok := health["endpoint"]; ok {
		transport := health["transport"]
		fmt.Printf("  IPC: %v (%v)\n", endpoint, transport)
	} else {
		fmt.Printf("  Socket: %v\n", health["socket"])
	}

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

	response, err := runRuntimeChatTurn(bridge, messages, aiProvider, "", 0.7, 200, "", true)
	if err != nil {
		return fmt.Errorf("AI test failed: %w", err)
	}
	if response.TaskStatus == "aborted" || response.TaskStatus == "failed" {
		return fmt.Errorf("AI test did not complete successfully: %s", response.Content)
	}

	fmt.Print("\r" + ui.Success.Sprint("✓ Response received    ") + "\n")
	fmt.Println()

	fmt.Printf("%s %s\n", ui.Accent.Sprint("🤖 AI:"), response.Content)
	fmt.Println()

	ui.Success.Println("✓ AI Engine test successful!")

	return nil
}

func runAIDoctor(cmd *cobra.Command, args []string) error {
	bridge := aibridge.NewAIBridge()

	fmt.Println(ui.InfoMsg("AI Doctor:"))
	fmt.Println()

	// Engine path + Python
	enginePath := aibridge.GetPythonEnginePath()
	pythonCmd := aibridge.GetPythonCommand()

	fmt.Printf("  Engine: %s\n", enginePath)
	fmt.Printf("  Python: %s\n", pythonCmd)

	if _, err := os.Stat(enginePath); err == nil {
		ui.Success.Println("  ✓ Engine path exists")
	} else {
		ui.Warning.Println("  ⚠ Engine path missing")
	}

	if strings.HasPrefix(pythonCmd, "/") {
		if _, err := os.Stat(pythonCmd); err == nil {
			ui.Success.Println("  ✓ Python interpreter exists")
		} else {
			ui.Warning.Println("  ⚠ Python interpreter not found")
		}
	}

	// IPC endpoint + running
	homeDir, _ := os.UserHomeDir()
	socketPath := filepath.Join(homeDir, ".zypheron", "sockets", "ai-default.sock")
	endpointFile := filepath.Join(homeDir, ".zypheron", "ipc.endpoint.json")
	fmt.Printf("  Legacy Socket: %s\n", socketPath)
	fmt.Printf("  Endpoint File: %s\n", endpointFile)

	if bridge.IsRunning() {
		ui.Success.Println("  ✓ AI engine running")

		health, err := bridge.Health()
		if err == nil {
			if v, ok := health["version"]; ok {
				fmt.Printf("  Version: %v\n", v)
			}
			if ep, ok := health["endpoint"]; ok {
				fmt.Printf("  IPC Endpoint: %v\n", ep)
			}
			if tr, ok := health["transport"]; ok {
				fmt.Printf("  IPC Transport: %v\n", tr)
			}
		}
	} else {
		ui.Warning.Println("  ⚠ AI engine not running")
		fmt.Println(ui.Muted.Sprint("  Start it with: zypheron ai start"))
	}

	return nil
}
