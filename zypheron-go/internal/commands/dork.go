package commands

import (
	"errors"
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/browser"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/utils"
	"github.com/spf13/cobra"
)

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

				bridge := aibridge.NewAIBridge()
				if bridge.IsRunning() {
					// Enhance query with AI
					enhancedQuery, err := enhanceQueryWithAI(searchQuery)
					if err == nil && enhancedQuery != "" {
						fmt.Printf("%s Enhanced query: %s\n", ui.Success.Sprint("✓"), ui.Accent.Sprint(enhancedQuery))
						searchQuery = enhancedQuery
					} else {
						fmt.Println(ui.WarningMsg("AI enhancement failed, using original query"))
					}
				} else {
					fmt.Println(ui.WarningMsg("AI Engine not running - starting without AI enhancement"))
					fmt.Println(ui.InfoMsg("Start AI engine with: zypheron ai start"))
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
			agent := browser.NewGeminiBrowserAgent()
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
	cmd.Flags().StringVarP(&engine, "engine", "e", "google", "Search engine (google, bing)")
	cmd.Flags().IntVarP(&maxResults, "max-results", "m", 10, "Maximum number of results")
	cmd.Flags().BoolVar(&aiGuided, "ai-guided", false, "Use AI to enhance query")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file")
	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "Assume yes for confirmation prompts")
	cmd.Flags().BoolVar(&noInput, "no-input", false, "Disable interactive prompts")

	return cmd
}

// enhanceQueryWithAI enhances a dork query using AI
// TODO: Integrate with AI bridge when ready
func enhanceQueryWithAI(query string) (string, error) {
	// This would call the AI bridge to enhance the query
	// For now, return the original query
	return query, nil
}
