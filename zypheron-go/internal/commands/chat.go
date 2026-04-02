package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

var (
	chatProvider    string
	chatInteractive bool
	chatTemperature float64
)

// ChatCmd returns the chat command
func ChatCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chat [message]",
		Short: "Chat with AI security expert",
		Long: `Chat with AI-powered security assistant for pentesting guidance.

Supports multiple AI providers:
  • Claude (Anthropic) - Default
  • GPT-4 (OpenAI)
  • Gemini (Google)
  • DeepSeek
  • Grok (xAI)
  • Kimi (Moonshot)
  • Ollama (Local)

Example:
  zypheron chat "How do I test for SQL injection?"
  zypheron chat --provider gpt-4 "Explain XSS vulnerabilities"
  zypheron chat --interactive`,
		RunE: runChat,
	}

	cmd.Flags().StringVarP(&chatProvider, "provider", "p", "", "AI provider (claude, openai, gemini, deepseek, kimi, ollama)")
	cmd.Flags().BoolVarP(&chatInteractive, "interactive", "i", false, "Interactive chat mode")
	cmd.Flags().Float64VarP(&chatTemperature, "temperature", "t", 0.7, "Sampling temperature (0-1)")

	return cmd
}

func runChat(cmd *cobra.Command, args []string) error {
	bridge := aibridge.NewAIBridge()

	// Check if AI engine is running
	if !bridge.IsRunning() {
		fmt.Println(ui.Error("AI Engine not running"))
		fmt.Println()
		fmt.Println(ui.InfoMsg("Start the AI engine with:"))
		fmt.Println(ui.Primary.Sprint("  zypheron ai start"))
		fmt.Println()
		return nil
	}

	// Show provider info
	if chatProvider == "" {
		_, defaultProvider, _ := bridge.ListProviders()
		chatProvider = defaultProvider
		fmt.Println(ui.Muted.Sprint(fmt.Sprintf("Using provider: %s", chatProvider)))
	} else {
		fmt.Println(ui.Muted.Sprint(fmt.Sprintf("Using provider: %s", chatProvider)))
	}
	fmt.Println()

	// Interactive mode
	if chatInteractive || len(args) == 0 {
		return runInteractiveChat(bridge)
	}

	// Single message mode
	message := strings.Join(args, " ")
	return runSingleMessage(bridge, message)
}

func runInteractiveChat(bridge *aibridge.AIBridge) error {
	fmt.Println(ui.Accent.Sprint("╔═══════════════════════════════════════════════════╗"))
	fmt.Println(ui.Accent.Sprint("║  🤖 ZYPHERON AI SECURITY ASSISTANT               ║"))
	fmt.Println(ui.Accent.Sprint("╚═══════════════════════════════════════════════════╝"))
	fmt.Println()
	fmt.Println(ui.InfoMsg("Interactive AI Chat Mode"))
	fmt.Println(ui.Muted.Sprint("  Type your security questions and get expert AI insights"))
	fmt.Println(ui.Muted.Sprint("  Type 'exit' or 'quit' to end the session"))
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	sessionID := ""
	conversationHistory := []aibridge.Message{
		{
			Role: "system",
			Content: `You are an expert penetration tester and cybersecurity consultant. 
Provide clear, actionable security advice. When discussing vulnerabilities or attack techniques, 
always emphasize ethical hacking practices and legal boundaries.`,
		},
	}

	for {
		// Prompt for user input
		fmt.Print(ui.Primary.Sprint("You: "))
		input, err := reader.ReadString('\n')
		if err != nil {
			return err
		}

		input = strings.TrimSpace(input)

		// Check for exit commands
		if input == "exit" || input == "quit" || input == "q" {
			fmt.Println()
			fmt.Println(ui.InfoMsg("Goodbye! Stay secure! 🔒"))
			break
		}

		if input == "" {
			continue
		}

		// Add user message to history
		conversationHistory = append(conversationHistory, aibridge.Message{
			Role:    "user",
			Content: input,
		})

		// Get AI response
		fmt.Println()
		fmt.Print(ui.Accent.Sprint("🤖 AI: "))

		response, err := runRuntimeChatTurn(bridge, conversationHistory, chatProvider, "", chatTemperature, 2048, sessionID, true)
		if err != nil {
			fmt.Println(ui.Error(fmt.Sprintf("Error: %s", err)))
			fmt.Println()
			continue
		}
		if response.SessionID != "" {
			sessionID = response.SessionID
		}

		// Display response
		fmt.Println(response.Content)
		fmt.Println()

		// Add AI response to history
		conversationHistory = append(conversationHistory, aibridge.Message{
			Role:    "assistant",
			Content: response.Content,
		})
	}

	return nil
}

func runSingleMessage(bridge *aibridge.AIBridge, message string) error {
	fmt.Printf("%s %s\n", ui.Primary.Sprint("You:"), message)
	fmt.Println()

	messages := []aibridge.Message{
		{
			Role: "system",
			Content: `You are an expert penetration tester and cybersecurity consultant. 
Provide clear, actionable security advice.`,
		},
		{
			Role:    "user",
			Content: message,
		},
	}

	fmt.Print(ui.InfoMsg("Thinking..."))

	response, err := runRuntimeChatTurn(bridge, messages, chatProvider, "", chatTemperature, 2048, "", true)
	if err != nil {
		return fmt.Errorf("AI chat failed: %w", err)
	}

	fmt.Print("\r" + ui.Success.Sprint("✓ Response received") + "\n")
	fmt.Println()
	fmt.Printf("%s %s\n", ui.Accent.Sprint("🤖 AI:"), response.Content)
	fmt.Println()

	return nil
}
