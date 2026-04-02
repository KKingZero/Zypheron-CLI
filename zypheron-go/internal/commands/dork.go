package commands

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/browser"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/intel"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/utils"
	"github.com/spf13/cobra"
)

const maxAIDorkQueryLength = 512

// DorkCmd returns the dork command
func DorkCmd() *cobra.Command {
	var (
		query      string
		engine     string
		maxResults int
		aiGuided   bool
		output     string
		assumeYes  bool
		noInput    bool
	)

	cmd := &cobra.Command{
		Use:   "dork [query]",
		Short: "AI-powered search engine dorking",
		Long:  "Perform Google/Bing dorking with AI-guided query generation and browser automation",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var searchQuery string
			interactive := isInteractive(cmd) && !noInput

			// Get query (from args or prompt)
			if len(args) > 0 {
				searchQuery = args[0]
			} else if query != "" {
				searchQuery = query
			} else {
				if !interactive {
					return fmt.Errorf("query argument required when running non-interactively")
				}
				prompt := &survey.Input{
					Message: "Enter search query:",
				}
				if err := survey.AskOne(prompt, &searchQuery, survey.WithValidator(survey.Required)); err != nil {
					if errors.Is(err, terminal.InterruptErr) {
						return fmt.Errorf("query prompt interrupted")
					}
					return err
				}
			}

			// Default engine
			if engine == "" {
				engine = "google"
			}

			// Print header
			fmt.Printf("\n%s\n", ui.Primary.Sprint("╔═══════════════════════════════════════╗"))
			fmt.Printf("%s\n", ui.Primary.Sprint("║  ZYPHERON AI-POWERED DORKING           ║"))
			fmt.Printf("%s\n\n", ui.Primary.Sprint("╚═══════════════════════════════════════╝"))

			// AI-guided query enhancement
			if aiGuided {
				fmt.Println(ui.InfoMsg("🤖 AI-Guided Query Enhancement..."))

				enhancedQuery, err := enhanceQueryWithAI(searchQuery, engine)
				if err == nil && enhancedQuery != "" {
					fmt.Printf("%s Enhanced query: %s\n", ui.Success.Sprint("✓"), ui.Accent.Sprint(enhancedQuery))
					searchQuery = enhancedQuery
				} else {
					fmt.Println(ui.WarningMsg("AI enhancement failed, using original query"))
				}
			}

			// Show configuration
			fmt.Printf("\n%s\n", ui.InfoMsg("Dorking Configuration:"))
			fmt.Println(ui.Separator(60))
			fmt.Printf("  Query:      %s\n", ui.Accent.Sprint(searchQuery))
			fmt.Printf("  Engine:     %s\n", ui.Accent.Sprint(engine))
			fmt.Printf("  Max Results: %d\n", maxResults)
			if aiGuided {
				fmt.Printf("  AI Mode:    %s\n", ui.Success.Sprint("Enabled"))
			}
			fmt.Println(ui.Separator(60))
			fmt.Println()

			// Confirm
			confirm := true
			if assumeYes || !interactive {
				confirm = true
			} else {
				confirmPrompt := &survey.Confirm{
					Message: "Start dorking?",
					Default: true,
				}
				if err := survey.AskOne(confirmPrompt, &confirm); err != nil {
					if errors.Is(err, terminal.InterruptErr) {
						fmt.Println(ui.InfoMsg("Dorking cancelled"))
						return nil
					}
					return err
				}
			}

			if !confirm {
				fmt.Println(ui.InfoMsg("Dorking cancelled"))
				return nil
			}

			// Create browser agent
			agent, err := browser.NewGeminiBrowserAgent()
			if err != nil {
				// Check if Chromium is installed and provide detailed instructions
				installed, _, instructions := browser.CheckChromiumInstalled()
				if !installed {
					fmt.Println(ui.ErrorWithRecovery(
						"Chromium is not installed",
						instructions...,
					))
				} else {
					fmt.Println(ui.ErrorWithRecovery(
						"Failed to initialize browser",
						"Chromium was found but failed to start",
						"Try running: chromium --version",
						"Ensure Chromium is properly installed",
						"Check system logs for browser errors",
					))
				}
				return fmt.Errorf("browser initialization failed: %w", err)
			}
			defer agent.Close()

			// Create dorker
			dorker := browser.NewDorker(agent)

			// Execute dork
			fmt.Println(ui.InfoMsg("Executing search..."))

			dorkQuery := browser.DorkQuery{
				Query:      searchQuery,
				Engine:     engine,
				MaxResults: maxResults,
			}

			results, err := dorker.ExecuteDork(dorkQuery)
			if err != nil {
				return fmt.Errorf("dorking failed: %w", err)
			}

			// Display results
			fmt.Printf("\n%s\n", ui.SuccessMsg(fmt.Sprintf("Found %d results", len(results))))
			fmt.Println()

			if len(results) > 0 {
				fmt.Printf("%s\n", ui.InfoMsg("Search Results:"))
				fmt.Println(ui.Separator(60))

				for i, result := range results {
					fmt.Printf("\n  %d. %s\n", i+1, ui.Accent.Sprint(result.Title))
					fmt.Printf("     %s\n", ui.Primary.Sprint(result.URL))
					if result.Description != "" {
						desc := result.Description
						if len(desc) > 80 {
							desc = desc[:80] + "..."
						}
						fmt.Printf("     %s\n", ui.Muted.Sprint(desc))
					}
				}
				fmt.Println()
			} else {
				fmt.Printf("%s\n", ui.WarningMsg("No results found"))
			}

			// Save output if requested
			if output != "" {
				var outputText string
				for i, result := range results {
					outputText += fmt.Sprintf("%d. %s\n   %s\n   %s\n\n",
						i+1, result.Title, result.URL, result.Description)
				}

				// Use secure file writer for security-sensitive output
				writer := utils.NewSecureFileWriter()
				if err := writer.WriteSecure(output, []byte(outputText)); err != nil {
					fmt.Println(ui.Error(fmt.Sprintf("Failed to save output: %s", err)))
				} else {
					fmt.Println(ui.SuccessMsg(fmt.Sprintf("Results saved securely to: %s (permissions: 0600)", output)))
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&query, "query", "q", "", "Search query")
	cmd.Flags().StringVarP(&engine, "engine", "e", "google", "Search engine (google, bing, duckduckgo)")
	cmd.Flags().IntVarP(&maxResults, "max-results", "m", 10, "Maximum number of results")
	cmd.Flags().BoolVar(&aiGuided, "ai-guided", false, "Use AI to enhance query")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file")
	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "Assume yes for confirmation prompts")
	cmd.Flags().BoolVar(&noInput, "no-input", false, "Disable interactive prompts")

	return cmd
}

// enhanceQueryWithAI enhances a dork query using AI.
func enhanceQueryWithAI(query string, engine string) (string, error) {
	bridge := aibridge.GetSharedBridge()
	if !bridge.IsRunning() {
		if err := bridge.Start(); err != nil {
			return "", err
		}
	}

	providers, defaultProvider, err := bridge.ListProviders()
	if err != nil {
		return "", err
	}

	provider := chooseDorkEnhancementProvider(providers, defaultProvider)
	if provider == "" {
		return "", fmt.Errorf("no AI provider available for dork enhancement")
	}

	prompt := buildDorkEnhancementPrompt(query, engine)

	resp, err := runRuntimeChatTurn(bridge, []aibridge.Message{
		{Role: "user", Content: prompt},
	}, provider, "", 0.2, 120, "", true)
	if err != nil {
		return "", err
	}
	if resp.TaskStatus == "aborted" || resp.TaskStatus == "failed" {
		return "", fmt.Errorf("AI enhancement did not complete successfully: %s", resp.Content)
	}

	enhanced := strings.TrimSpace(resp.Content)
	sanitized, err := sanitizeAIDorkQuery(enhanced)
	if err != nil {
		return "", err
	}
	return sanitized, nil
}

func buildDorkEnhancementPrompt(query string, engine string) string {
	return strings.TrimSpace(`
You generate concise, effective security search dorks.

Task:
- Improve the user's query for reconnaissance or bug bounty style search.
- Preserve the user's intent.
- Prefer a single high-signal dork instead of multiple options.
- Generate a query that can run directly on the selected web search engine.
- If you bias toward a source, express that as valid web-search syntax such as site filters or plain keywords.
- Do not use native syntax from Shodan, Censys, FOFA, or other external platforms.
- Do not add explanation or markdown.
- Output only the final query text.

Selected engine: ` + engine + `

` + intel.WebSearchPromptBlock(engine) + `

User query: ` + query)
}

func chooseDorkEnhancementProvider(providers []string, defaultProvider string) string {
	if defaultProvider != "" {
		for _, provider := range providers {
			if provider == defaultProvider {
				return defaultProvider
			}
		}
	}

	for _, preferred := range []string{"ollama", "claude", "gemini", "openai", "deepseek", "kimi"} {
		for _, provider := range providers {
			if provider == preferred {
				return provider
			}
		}
	}

	if len(providers) > 0 {
		return providers[0]
	}
	return ""
}

func sanitizeAIDorkQuery(query string) (string, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return "", fmt.Errorf("AI returned an empty dork query")
	}

	var b strings.Builder
	b.Grow(len(query))
	lastWasSpace := false
	for _, r := range query {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			if b.Len() > 0 && !lastWasSpace {
				b.WriteByte(' ')
				lastWasSpace = true
			}
		case unicode.IsControl(r):
			continue
		case unicode.IsSpace(r):
			if b.Len() > 0 && !lastWasSpace {
				b.WriteByte(' ')
				lastWasSpace = true
			}
		default:
			b.WriteRune(r)
			lastWasSpace = false
		}
	}

	sanitized := strings.TrimSpace(b.String())
	if sanitized == "" {
		return "", fmt.Errorf("AI returned an empty dork query")
	}
	if len(sanitized) > maxAIDorkQueryLength {
		return "", fmt.Errorf("AI returned an oversized dork query")
	}
	if strings.ContainsAny(sanitized, "`\x00") {
		return "", fmt.Errorf("AI returned unsupported characters in dork query")
	}
	if strings.HasPrefix(sanitized, "-") {
		return "", fmt.Errorf("AI returned malformed dork query")
	}

	return sanitized, nil
}
