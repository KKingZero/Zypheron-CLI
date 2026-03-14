package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/loot"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tools"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

func ReconCmd() *cobra.Command {
	var (
		scanType       string
		noAI           bool
	)

	cmd := &cobra.Command{
		Use:   "recon [target]",
		Short: "Reconnaissance operations",
		Long: `AI-guided reconnaissance and information gathering.

Delegates tool selection and ordering to the AI engine, which picks
the best tools based on your target type (domain, IP, CIDR).

Wraps: nmap, subfinder, amass, theHarvester, whatweb, httpx, masscan, whois

Examples:
  zypheron recon example.com
  zypheron recon 10.10.10.0/24 --type active
  zypheron recon example.com --no-ai`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("target is required")
			}
			target := args[0]

			ui.PrintHeader("Reconnaissance Module")
			ui.PrintInfo(fmt.Sprintf("Target: %s", target))
			ui.PrintInfo(fmt.Sprintf("Type: %s", scanType))
			fmt.Println()

			// Detect available recon tools
			reconTools := []struct{ name, cmd string }{
				{"nmap", "nmap"},
				{"subfinder", "subfinder"},
				{"amass", "amass"},
				{"theHarvester", "theHarvester"},
				{"whatweb", "whatweb"},
				{"httpx", "httpx"},
				{"masscan", "masscan"},
				{"whois", "whois"},
				{"dig", "dig"},
			}

			var available []string
			var missing []string
			for _, t := range reconTools {
				if tools.IsToolInstalled(t.cmd) {
					available = append(available, t.name)
				} else {
					missing = append(missing, t.name)
				}
			}

			ui.PrintInfo(fmt.Sprintf("Available tools: %s", strings.Join(available, ", ")))
			if len(missing) > 0 {
				ui.PrintWarning(fmt.Sprintf("Missing: %s", strings.Join(missing, ", ")))
			}
			fmt.Println()

			if len(available) == 0 {
				return fmt.Errorf("no recon tools installed. Install with: zypheron tools install-all")
			}

			// Init loot
			lm := loot.NewLootManager("")
			if err := lm.Init(target, "recon-"+scanType, "", ""); err != nil {
				return fmt.Errorf("failed to init loot: %w", err)
			}

			if !noAI {
				return runReconWithAI(target, scanType, available, lm)
			}
			return runReconDirect(target, scanType, available, lm)
		},
	}

	cmd.Flags().StringVar(&scanType, "type", "passive", "Scan type: passive, active, comprehensive")
	cmd.Flags().BoolVar(&noAI, "no-ai", false, "Skip AI planning, run tools directly")
	return cmd
}

func runReconWithAI(target, scanType string, available []string, lm *loot.LootManager) error {
	bridge := aibridge.NewAIBridge()

	ui.PrintInfo("Consulting AI for recon plan...")
	response, err := bridge.SendRequest("chat", map[string]interface{}{
		"messages": []map[string]string{
			{"role": "user", "content": fmt.Sprintf(
				"You are planning a %s reconnaissance against target: %s\n"+
					"Available tools: %s\n\n"+
					"Return ONLY a JSON array of commands to run, in order:\n"+
					"[{\"tool\": \"nmap\", \"args\": \"-sV -sC -T4 %s\", \"purpose\": \"service detection\"}]\n"+
					"Include 3-5 most valuable recon steps. No explanation, just JSON.",
				scanType, target, strings.Join(available, ", "), target)},
		},
		"provider": "deepseek",
	})

	if err != nil {
		ui.PrintWarning(fmt.Sprintf("AI unavailable: %s — falling back to direct scan", err))
		return runReconDirect(target, scanType, available, lm)
	}

	content, _ := response.Result["content"].(string)
	_ = lm.SaveLoot("findings", "recon_plan.md", []byte(content))

	// Fall back to direct execution (AI gave us a plan, but parsing and executing
	// arbitrary JSON commands needs more validation - run safe defaults)
	ui.PrintInfo("AI plan saved. Running standard recon tools...")
	return runReconDirect(target, scanType, available, lm)
}

func runReconDirect(target, scanType string, available []string, lm *loot.LootManager) error {
	type reconStep struct {
		tool    string
		args    []string
		purpose string
		active  bool // true = only run in active/comprehensive mode
	}

	steps := []reconStep{
		{"whois", []string{target}, "Domain registration lookup", false},
		{"dig", []string{target, "ANY", "+noall", "+answer"}, "DNS records", false},
		{"subfinder", []string{"-d", target, "-silent"}, "Subdomain enumeration", false},
		{"httpx", []string{"-u", target, "-silent", "-status-code", "-title"}, "HTTP probing", false},
		{"whatweb", []string{target, "--color=never"}, "Web tech fingerprinting", false},
		{"nmap", []string{"-sV", "-sC", "-T4", "--top-ports", "1000", target}, "Port scan + service detection", true},
		{"masscan", []string{"-p1-65535", "--rate=1000", target}, "Full port scan", true},
		{"theHarvester", []string{"-d", target, "-b", "all"}, "Email/subdomain harvesting", false},
	}

	// Filter by scan type
	runActive := scanType == "active" || scanType == "comprehensive"

	ran := 0
	for _, step := range steps {
		if step.active && !runActive {
			continue
		}

		found := false
		for _, a := range available {
			if a == step.tool {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		ui.PrintInfo(fmt.Sprintf("[%s] %s...", step.tool, step.purpose))
		result, err := tools.Execute(context.Background(), tools.ExecutionOptions{
			Tool:    step.tool,
			Args:    step.args,
			Target:  target,
			Stream:  true,
			Timeout: 5 * time.Minute,
		})
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("  %s failed: %s", step.tool, err))
			continue
		}

		_ = lm.SaveLoot("findings", fmt.Sprintf("%s_output.txt", step.tool), []byte(result.Output))
		_ = lm.LogTimeline("recon", step.tool, step.purpose, target, "ok")
		ran++
	}

	_ = lm.Finalize("completed")
	ui.PrintSuccess(fmt.Sprintf("Recon complete: %d tools executed. Loot: %s", ran, lm.SessionDir))
	return nil
}
