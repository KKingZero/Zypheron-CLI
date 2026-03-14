package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/loot"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

var (
	mitreObjective string
	mitreTarget    string
)

// MitreCmd returns the MITRE ATT&CK command
func MitreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mitre",
		Short: "MITRE ATT&CK framework — objective-driven attack execution",
		Long: `Use MITRE ATT&CK to plan and execute attacks by objective.

Tell Zypheron your objective (e.g. "Initial Access", "Lateral Movement")
and it selects the right techniques and tools automatically.

Examples:
  zypheron mitre run --objective "Initial Access" --target 10.10.10.1
  zypheron mitre run --objective "Persistence" --target web.example.com
  zypheron mitre list                    # List all tactics
  zypheron mitre show T1558             # Show technique details
  zypheron mitre update                  # Download latest ATT&CK data`,
	}

	cmd.AddCommand(mitreListCmd())
	cmd.AddCommand(mitreShowCmd())
	cmd.AddCommand(mitreRunCmd())
	cmd.AddCommand(mitreUpdateCmd())

	return cmd
}

func mitreListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all MITRE ATT&CK tactics",
		RunE: func(cmd *cobra.Command, args []string) error {
			bridge := aibridge.NewAIBridge()
			response, err := bridge.SendRequest("mitre_list_tactics", map[string]interface{}{})
			if err != nil {
				// Fallback: print built-in tactic list
				ui.PrintHeader("MITRE ATT&CK Enterprise Tactics")
				tactics := []struct{ id, name string }{
					{"TA0043", "Reconnaissance"},
					{"TA0042", "Resource Development"},
					{"TA0001", "Initial Access"},
					{"TA0002", "Execution"},
					{"TA0003", "Persistence"},
					{"TA0004", "Privilege Escalation"},
					{"TA0005", "Defense Evasion"},
					{"TA0006", "Credential Access"},
					{"TA0007", "Discovery"},
					{"TA0008", "Lateral Movement"},
					{"TA0009", "Collection"},
					{"TA0011", "Command and Control"},
					{"TA0010", "Exfiltration"},
					{"TA0040", "Impact"},
				}
				for _, t := range tactics {
					fmt.Printf("  %s  %s\n", ui.Accent.Sprint(t.id), t.name)
				}
				return nil
			}

			respJSON, _ := json.MarshalIndent(response.Result, "", "  ")
			fmt.Println(string(respJSON))
			return nil
		},
	}
}

func mitreShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show [technique-id]",
		Short: "Show details for a MITRE ATT&CK technique",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			bridge := aibridge.NewAIBridge()
			response, err := bridge.SendRequest("mitre_show_technique", map[string]interface{}{
				"technique_id": args[0],
			})
			if err != nil {
				ui.PrintWarning(fmt.Sprintf("AI engine unavailable: %s. Use 'zypheron mitre update' to download ATT&CK data.", err))
				return nil
			}

			respJSON, _ := json.MarshalIndent(response.Result, "", "  ")
			fmt.Println(string(respJSON))
			return nil
		},
	}
}

func mitreRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Execute an objective-driven attack using MITRE ATT&CK mapping",
		Long: `Define your attack objective and Zypheron maps it to ATT&CK techniques,
selects the right tools, and executes the kill-chain with AI guidance.

Objectives can be tactic names or natural language:
  --objective "Initial Access"
  --objective "Credential Access"
  --objective "I want to move laterally through the network"
  --objective "Establish persistence on the target"`,
		RunE: runMitre,
	}

	cmd.Flags().StringVarP(&mitreObjective, "objective", "O", "", "Attack objective (tactic name or description)")
	cmd.Flags().StringVarP(&mitreTarget, "target", "t", "", "Target host/network")
	_ = cmd.MarkFlagRequired("objective")
	_ = cmd.MarkFlagRequired("target")

	return cmd
}

func mitreUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Download/update MITRE ATT&CK data from STIX repository",
		RunE: func(cmd *cobra.Command, args []string) error {
			ui.PrintInfo("Downloading MITRE ATT&CK Enterprise data...")
			bridge := aibridge.NewAIBridge()
			response, err := bridge.SendRequest("mitre_update_data", map[string]interface{}{})
			if err != nil {
				return fmt.Errorf("failed to update ATT&CK data: %w", err)
			}

			if msg, ok := response.Result["message"].(string); ok {
				ui.PrintSuccess(msg)
			} else {
				ui.PrintSuccess("ATT&CK data updated successfully")
			}
			return nil
		},
	}
}

func runMitre(cmd *cobra.Command, args []string) error {
	objective := strings.TrimSpace(mitreObjective)

	ui.PrintHeader("MITRE ATT&CK Objective Execution")
	ui.PrintInfo(fmt.Sprintf("Objective: %s", objective))
	ui.PrintInfo(fmt.Sprintf("Target: %s", mitreTarget))
	fmt.Println()

	// Init loot
	lm := loot.NewLootManager("")
	if err := lm.Init(mitreTarget, "mitre", "", ""); err != nil {
		return fmt.Errorf("failed to init loot: %w", err)
	}

	// Send to AI engine for technique selection and execution
	bridge := aibridge.NewAIBridge()
	params := map[string]interface{}{
		"objective":  objective,
		"target":     mitreTarget,
		"session_id": lm.SessionID,
	}

	ui.PrintInfo("AI engine mapping objective to ATT&CK techniques...")
	response, err := bridge.SendRequest("mitre_run_objective", params)
	if err != nil {
		return fmt.Errorf("AI engine unavailable: %w (run 'zypheron ai start' first)", err)
	}

	_ = lm.SaveLootJSON("attack", "mitre_execution.json", response.Result)

	// Display results
	if techniques, ok := response.Result["techniques"].([]interface{}); ok {
		ui.PrintSuccess(fmt.Sprintf("Mapped %d techniques:", len(techniques)))
		for _, t := range techniques {
			if m, ok := t.(map[string]interface{}); ok {
				fmt.Printf("  %s — %s\n",
					ui.Accent.Sprint(m["id"]),
					m["name"],
				)
			}
		}
	}

	_ = lm.LogTimeline("mitre", "zypheron", "mitre_run_complete", objective, "ok")
	_ = lm.Finalize("completed")
	ui.PrintSuccess(fmt.Sprintf("Loot: %s", lm.SessionDir))
	return nil
}
