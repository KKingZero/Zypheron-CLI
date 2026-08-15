package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/licensing"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ChatCmd returns the chat command
func ChatCmd() *cobra.Command {
	flags := chatFlagOptions{
		Temperature: 0.7,
		MCPConfig:   defaultMCPConfigPath(),
	}
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return runChatWithFlags(cmd, args, &flags)
		},
	}

	cmd.Flags().StringVarP(&flags.Provider, "provider", "p", "", "AI provider (claude, openai, gemini, deepseek, kimi, ollama)")
	cmd.Flags().BoolVarP(&flags.Interactive, "interactive", "i", false, "Interactive chat mode")
	cmd.Flags().Float64VarP(&flags.Temperature, "temperature", "t", flags.Temperature, "Sampling temperature (0-1)")
	cmd.Flags().StringArrayVar(&flags.Images, "image", nil, "Attach an image from a local path or http(s) URL (repeatable)")
	cmd.Flags().StringVar(&flags.Effort, "effort", "", "Provider-specific reasoning effort (OpenAI: none,minimal,low,medium,high,xhigh; Claude: low,medium,high,xhigh,max)")
	cmd.Flags().StringArrayVar(&flags.MCPLabels, "mcp", nil, "Validate and request tools from an MCP server label in --mcp-config (client execution experimental; repeatable)")
	cmd.Flags().StringVar(&flags.MCPConfig, "mcp-config", flags.MCPConfig, "MCP client config path")

	return cmd
}

func runChatWithFlags(cmd *cobra.Command, args []string, flags *chatFlagOptions) error {
	if flags.Provider == "" {
		initConfig()
		if configured := strings.TrimSpace(viper.GetString("ai.provider")); configured != "" {
			flags.Provider = configured
		}
	}

	if flags.Provider == "zypheron-cloud" {
		if err := rejectCloudUnsupportedChatOptions(*flags); err != nil {
			return err
		}
		fmt.Println(ui.Muted.Sprint("Using provider: zypheron-cloud"))
		fmt.Println()
		if flags.Interactive || len(args) == 0 {
			return runInteractiveCloudChat(*flags)
		}
		return runSingleCloudMessage(*flags, strings.Join(args, " "))
	}

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
	if flags.Provider == "" {
		_, defaultProvider, _ := bridge.ListProviders()
		flags.Provider = defaultProvider
		fmt.Println(ui.Muted.Sprint(fmt.Sprintf("Using provider: %s", flags.Provider)))
	} else {
		fmt.Println(ui.Muted.Sprint(fmt.Sprintf("Using provider: %s", flags.Provider)))
	}
	fmt.Println()

	// Interactive mode
	if flags.Interactive || len(args) == 0 {
		if len(flags.Images) > 0 {
			return fmt.Errorf("--image is only supported for single-message chat")
		}
		options, err := buildChatOptions(flags.Provider, flags.Effort, nil, flags.MCPLabels, flags.MCPConfig)
		if err != nil {
			return err
		}
		return runInteractiveChat(bridge, flags.Provider, flags.Temperature, options)
	}

	// Single message mode
	message := strings.Join(args, " ")
	return runSingleMessage(bridge, *flags, message)
}

func runInteractiveCloudChat(flags chatFlagOptions) error {
	fmt.Println(ui.Accent.Sprint("╔═══════════════════════════════════════════════════╗"))
	fmt.Println(ui.Accent.Sprint("║  ZYPHERON CLOUD AI                               ║"))
	fmt.Println(ui.Accent.Sprint("╚═══════════════════════════════════════════════════╝"))
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	conversationHistory := []licensing.CloudChatMessage{
		{
			Role:    "system",
			Content: "You are an expert penetration tester and cybersecurity consultant. Provide clear, actionable security advice.",
		},
	}

	for {
		fmt.Print(ui.Primary.Sprint("You: "))
		input, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		input = strings.TrimSpace(input)
		if input == "exit" || input == "quit" || input == "q" {
			fmt.Println()
			break
		}
		if input == "" {
			continue
		}

		conversationHistory = append(conversationHistory, licensing.CloudChatMessage{
			Role:    "user",
			Content: input,
		})

		fmt.Println()
		fmt.Print(ui.Accent.Sprint("🤖 AI: "))
		resp, err := runCloudChatTurn(conversationHistory, "", flags.Temperature, 2048)
		if err != nil {
			fmt.Println(ui.Error(fmt.Sprintf("Error: %s", formatCloudAIError(err))))
			fmt.Println()
			continue
		}
		fmt.Println(resp.Content)
		fmt.Println()

		conversationHistory = append(conversationHistory, licensing.CloudChatMessage{
			Role:    "assistant",
			Content: resp.Content,
		})
	}
	return nil
}

func runSingleCloudMessage(flags chatFlagOptions, message string) error {
	fmt.Printf("%s %s\n", ui.Primary.Sprint("You:"), message)
	fmt.Println()

	messages := []licensing.CloudChatMessage{
		{
			Role:    "system",
			Content: "You are an expert penetration tester and cybersecurity consultant. Provide clear, actionable security advice.",
		},
		{
			Role:    "user",
			Content: message,
		},
	}

	fmt.Print(ui.InfoMsg("Thinking..."))
	response, err := runCloudChatTurn(messages, "", flags.Temperature, 2048)
	if err != nil {
		return fmt.Errorf("cloud AI chat failed: %s", formatCloudAIError(err))
	}

	fmt.Print("\r" + ui.Success.Sprint("✓ Response received") + "\n")
	fmt.Println()
	fmt.Printf("%s %s\n", ui.Accent.Sprint("🤖 AI:"), response.Content)
	fmt.Println()
	return nil
}

func runCloudChatTurn(messages []licensing.CloudChatMessage, model string, temperature float64, maxTokens int) (*licensing.CloudChatResponse, error) {
	manager := licensing.GetManager()
	if !manager.IsAuthenticated() {
		return nil, fmt.Errorf("cloud AI requires login. Run: zypheron login or use: zypheron config set ai.provider ollama")
	}

	client := licensing.NewAPIClient()
	return client.CloudChat(licensing.CloudChatRequest{
		Messages:    messages,
		Model:       model,
		Temperature: temperature,
		MaxTokens:   maxTokens,
		Metadata: map[string]string{
			"command": "chat",
		},
	})
}

func formatCloudAIError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "401"):
		return "your Zypheron token is invalid or expired. Run: zypheron login"
	case strings.Contains(msg, "402"), strings.Contains(msg, "quota"):
		return "monthly cloud usage limit reached. Your local CLI still works; switch with: zypheron config set ai.provider ollama"
	case strings.Contains(msg, "403"):
		return "your account does not have active CLI Cloud access. Manage billing at https://zypheron.net/account/billing"
	case strings.Contains(msg, "429"):
		return "cloud AI rate limit reached. Try again later."
	default:
		return msg
	}
}

func runInteractiveChat(bridge *aibridge.AIBridge, provider string, temperature float64, options aibridge.ChatOptions) error {
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

		response, err := runRuntimeChatTurn(bridge, conversationHistory, provider, "", temperature, 2048, sessionID, true, options)
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

func runSingleMessage(bridge *aibridge.AIBridge, flags chatFlagOptions, message string) error {
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

	options, err := buildChatOptions(flags.Provider, flags.Effort, flags.Images, flags.MCPLabels, flags.MCPConfig)
	if err != nil {
		return err
	}

	fmt.Print(ui.InfoMsg("Thinking..."))

	response, err := runRuntimeChatTurn(bridge, messages, flags.Provider, "", flags.Temperature, 2048, "", true, options)
	if err != nil {
		return fmt.Errorf("AI chat failed: %w", err)
	}

	fmt.Print("\r" + ui.Success.Sprint("✓ Response received") + "\n")
	fmt.Println()
	fmt.Printf("%s %s\n", ui.Accent.Sprint("🤖 AI:"), response.Content)
	fmt.Println()

	return nil
}
