package commands

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/yourusername/zypheron/internal/ui"
)

// ChatCmd returns the chat command
func ChatCmd() *cobra.Command {
	var (
		continue_session string
		model           string
	)

	cmd := &cobra.Command{
		Use:   "chat [message]",
		Short: "AI chat for security assistance",
		Long:  "Interactive AI chat for penetration testing guidance and analysis",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("\n%s\n", ui.Primary.Sprint("╔═══════════════════════════════════════╗"))
			fmt.Printf("%s\n", ui.Primary.Sprint("║  🤖 ZYPHERON AI ASSISTANT            ║"))
			fmt.Printf("%s\n\n", ui.Primary.Sprint("╚═══════════════════════════════════════╝"))

			if len(args) > 0 {
				message := args[0]
				fmt.Printf("%s %s\n\n", ui.Accent.Sprint("You:"), message)
				fmt.Printf("%s ", ui.Info.Sprint("🤖 Zypheron:"))
				fmt.Println("AI chat integration with your backend API...")
				fmt.Println(ui.Muted.Sprint("  (Connect to your existing TypeScript backend for AI responses)"))
				fmt.Println()
			} else {
				fmt.Println(ui.InfoMsg("Interactive AI Chat Mode"))
				fmt.Println(ui.Muted.Sprint("  Type your security questions and get AI-powered insights"))
				fmt.Println(ui.Muted.Sprint("  Implementation connects to your existing backend API"))
				fmt.Println()
				fmt.Println(ui.InfoMsg("Usage: zypheron chat \"How do I test for SQL injection?\""))
				fmt.Println()
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&continue_session, "continue", "", "Continue previous session")
	cmd.Flags().StringVar(&model, "model", "gpt-4", "AI model to use")

	return cmd
}

