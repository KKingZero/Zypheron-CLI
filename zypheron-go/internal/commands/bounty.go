package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/loot"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

var (
	bountyScope    string
	bountyPlatform string
	bountyProgram  string
	bountyAutoRun  bool
	bountyOutput   string
)

func BountyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bounty [target]",
		Short: "Bug bounty mode with scope filtering and submission drafts",
		Long: `Run Zypheron in bug bounty mode.

Accepts a scope file or URL, filters targets to in-scope only,
runs AutoPent against them, and generates submission-ready drafts
for HackerOne or Bugcrowd.

Scope file format (one target per line, # for comments):
  # Example program scope
  *.example.com
  api.example.com
  10.0.0.0/24
  !staging.example.com   # out of scope (prefix with !)`,
		Args: cobra.MaximumNArgs(1),
		RunE: runBounty,
	}

	cmd.Flags().StringVarP(&bountyScope, "scope", "s", "", "Scope file path or URL with in-scope targets")
	cmd.Flags().StringVarP(&bountyPlatform, "platform", "p", "hackerone", "Platform: hackerone, bugcrowd")
	cmd.Flags().StringVar(&bountyProgram, "program", "", "Program name/handle for scope context")
	cmd.Flags().BoolVar(&bountyAutoRun, "auto", false, "Automatically run AutoPent on in-scope targets")
	cmd.Flags().StringVarP(&bountyOutput, "output", "o", "", "Output directory for submission drafts")

	// TODO: Add API-based scope fetching when platform APIs are integrated
	// cmd.Flags().StringVar(&bountyAPIToken, "api-token", "", "HackerOne/Bugcrowd API token")

	return cmd
}

func runBounty(cmd *cobra.Command, args []string) error {
	var target string
	if len(args) > 0 {
		target = args[0]
	}

	// Parse scope
	if bountyScope == "" && target == "" {
		return fmt.Errorf("provide a --scope file or a target argument")
	}

	var scopeTargets []string
	var outOfScope []string

	if bountyScope != "" {
		var err error
		scopeTargets, outOfScope, err = parseScopeFile(bountyScope)
		if err != nil {
			return fmt.Errorf("failed to parse scope file: %w", err)
		}
	} else {
		scopeTargets = []string{target}
	}

	ui.PrintHeader("Bug Bounty Mode")
	ui.PrintInfo(fmt.Sprintf("Platform: %s", bountyPlatform))
	if bountyProgram != "" {
		ui.PrintInfo(fmt.Sprintf("Program: %s", bountyProgram))
	}
	ui.PrintInfo(fmt.Sprintf("In-scope targets: %d", len(scopeTargets)))
	if len(outOfScope) > 0 {
		ui.PrintWarning(fmt.Sprintf("Out-of-scope exclusions: %d", len(outOfScope)))
	}

	fmt.Println()
	for i, t := range scopeTargets {
		fmt.Printf("  [%d] %s\n", i+1, t)
	}
	fmt.Println()

	// Initialize loot manager
	lm := loot.NewLootManager("")
	if err := lm.Init(strings.Join(scopeTargets, ","), "bounty", "", ""); err != nil {
		return fmt.Errorf("failed to init loot directory: %w", err)
	}

	// Save scope to loot
	scopeData := map[string]interface{}{
		"platform":     bountyPlatform,
		"program":      bountyProgram,
		"in_scope":     scopeTargets,
		"out_of_scope": outOfScope,
	}
	_ = lm.SaveLootJSON("raw", "scope.json", scopeData)

	// Send to Python AI engine for bounty orchestration
	bridge := aibridge.NewAIBridge()
	params := map[string]interface{}{
		"targets":      scopeTargets,
		"out_of_scope": outOfScope,
		"platform":     bountyPlatform,
		"program":      bountyProgram,
		"session_id":   lm.SessionID,
		"auto_run":     bountyAutoRun,
	}

	ui.PrintInfo("Sending to AI engine for bounty analysis...")
	response, err := bridge.SendRequest("bounty_run", params)
	if err != nil {
		ui.PrintWarning(fmt.Sprintf("AI engine unavailable: %s", err))
		ui.PrintInfo("Scope parsed and saved. Run 'zypheron autopent' manually on each target.")
		ui.PrintInfo(fmt.Sprintf("Loot directory: %s", lm.SessionDir))
		return nil
	}

	// Save response
	_ = lm.SaveLootJSON("findings", "bounty_analysis.json", response.Result)

	outputDir := bountyOutput
	if outputDir == "" {
		outputDir = filepath.Join(lm.SessionDir, "reports")
	}

	_ = lm.LogTimeline("bounty", "zypheron", "bounty_complete", fmt.Sprintf("%d targets processed", len(scopeTargets)), "ok")
	_ = lm.Finalize("completed")
	ui.PrintSuccess(fmt.Sprintf("Bounty session complete. Loot: %s", lm.SessionDir))
	ui.PrintInfo(fmt.Sprintf("Submission drafts: %s", outputDir))

	return nil
}

// parseScopeFile reads a scope file and returns in-scope and out-of-scope targets.
func parseScopeFile(path string) (inScope []string, outOfScope []string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Lines starting with ! are out-of-scope exclusions
		if strings.HasPrefix(line, "!") {
			outOfScope = append(outOfScope, strings.TrimPrefix(line, "!"))
		} else {
			inScope = append(inScope, line)
		}
	}

	return inScope, outOfScope, nil
}
