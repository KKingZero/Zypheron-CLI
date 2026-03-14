package commands

import (
	"fmt"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/loot"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

var (
	adTarget string
	adDomain string
	adMode   string
	adUser   string
	adPass   string
	adHash   string
)

func ADCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ad",
		Short: "Active Directory attack module",
		Long: `AI-guided Active Directory kill-chain.

Kill-chain: ldapdomaindump -> PingCastle -> BloodHound -> Responder ->
  Impacket Kerberoasting + NetExec -> Certipy ADCS -> Isassy + Snaffler -> domain takeover

Each exploitation step requires operator approval.

Examples:
  zypheron ad --target 10.10.10.1 --domain corp.local
  zypheron ad --target 10.10.10.1 --domain corp.local --mode enum
  zypheron ad check   # Show installed AD tools`,
		RunE: runAD,
	}

	cmd.Flags().StringVarP(&adTarget, "target", "t", "", "Domain controller IP")
	cmd.Flags().StringVarP(&adDomain, "domain", "D", "", "Domain name (e.g. corp.local)")
	cmd.Flags().StringVarP(&adMode, "mode", "m", "full", "Mode: enum (safe recon) or full (complete kill-chain)")
	cmd.Flags().StringVarP(&adUser, "user", "u", "", "Domain username (optional)")
	cmd.Flags().StringVarP(&adPass, "pass", "p", "", "Domain password (optional)")
	cmd.Flags().StringVar(&adHash, "hash", "", "NTLM hash for pass-the-hash (optional)")

	cmd.AddCommand(adCheckCmd())

	return cmd
}

type adTool struct {
	Name       string
	Cmd        string
	Phase      string
	Purpose    string
	InstallCmd string
}

var adTools = []adTool{
	{"ldapdomaindump", "ldapdomaindump", "enum", "LDAP domain enumeration", "pip3 install ldapdomaindump"},
	{"pingcastle", "PingCastle", "enum", "AD health check & risk scoring", "Download from pingcastle.com"},
	{"bloodhound", "bloodhound-python", "enum", "AD attack path mapping", "pip3 install bloodhound"},
	{"responder", "responder", "initial_access", "LLMNR/NBT-NS hash capture", "apt install responder"},
	{"impacket", "impacket-GetUserSPNs", "exploit", "Kerberoasting & AD protocol exploitation", "pip3 install impacket"},
	{"netexec", "nxc", "exploit", "SMB/WinRM/LDAP spray & execution", "pip3 install netexec"},
	{"certipy", "certipy", "exploit", "ADCS certificate abuse (ESC1-13)", "pip3 install certipy-ad"},
	{"lsassy", "lsassy", "post_exploit", "Remote LSASS credential dumping", "pip3 install lsassy"},
	{"snaffler", "Snaffler", "post_exploit", "SMB share sensitive file discovery", "Download from github.com/SnaffCon/Snaffler"},
	{"mimikatz", "mimikatz", "post_exploit", "Credential extraction & pass-the-hash", "Pre-installed or download"},
}

func adCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Check installed AD attack tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			ui.PrintHeader("Active Directory Tools Status")
			fmt.Println()

			phases := []string{"enum", "initial_access", "exploit", "post_exploit"}
			phaseNames := map[string]string{
				"enum":           "Enumeration",
				"initial_access": "Initial Access",
				"exploit":        "Exploitation",
				"post_exploit":   "Post-Exploitation",
			}

			for _, phase := range phases {
				fmt.Printf("  [%s]\n", phaseNames[phase])
				for _, t := range adTools {
					if t.Phase != phase {
						continue
					}
					installed := isToolInstalled(t.Cmd)
					status := ui.Danger.Sprint("MISSING")
					if installed {
						status = ui.Success.Sprint("OK")
					}
					fmt.Printf("    %-18s %s  %s\n", t.Name, status, t.Purpose)
				}
				fmt.Println()
			}
			return nil
		},
	}
}

func runAD(cmd *cobra.Command, args []string) error {
	if adTarget == "" {
		return fmt.Errorf("--target (DC IP) is required")
	}
	if adDomain == "" {
		return fmt.Errorf("--domain is required")
	}

	mode := strings.ToLower(adMode)
	if mode != "enum" && mode != "full" {
		return fmt.Errorf("--mode must be 'enum' or 'full'")
	}

	ui.PrintHeader("Active Directory Attack Module")
	ui.PrintInfo(fmt.Sprintf("Target DC: %s", adTarget))
	ui.PrintInfo(fmt.Sprintf("Domain: %s", adDomain))
	ui.PrintInfo(fmt.Sprintf("Mode: %s", mode))
	if adUser != "" {
		ui.PrintInfo(fmt.Sprintf("User: %s", adUser))
	}
	fmt.Println()

	// Check tools
	var available []string
	var missing []string
	for _, t := range adTools {
		if isToolInstalled(t.Cmd) {
			available = append(available, t.Name)
		} else {
			missing = append(missing, t.Name)
		}
	}

	if len(missing) > 0 {
		ui.PrintWarning(fmt.Sprintf("%d AD tools missing: %s", len(missing), strings.Join(missing, ", ")))
	}

	// Init loot
	lm := loot.NewLootManager("")
	if err := lm.Init(adTarget, "ad-"+mode, "", ""); err != nil {
		return fmt.Errorf("failed to init loot: %w", err)
	}

	// Send to Python AI engine
	bridge := aibridge.NewAIBridge()
	params := map[string]interface{}{
		"target":          adTarget,
		"domain":          adDomain,
		"mode":            mode,
		"user":            adUser,
		"password":        adPass,
		"hash":            adHash,
		"session_id":      lm.SessionID,
		"available_tools": available,
	}

	ui.PrintInfo("Sending to AI engine for AD kill-chain orchestration...")
	response, err := bridge.SendRequest("ad_attack", params)
	if err != nil {
		ui.PrintWarning(fmt.Sprintf("AI engine unavailable: %s", err))
		ui.PrintInfo("Run AD tools manually. Available: " + strings.Join(available, ", "))
		ui.PrintInfo(fmt.Sprintf("Loot directory: %s", lm.SessionDir))
		return nil
	}

	_ = lm.SaveLootJSON("ad", "ad_analysis.json", response.Result)
	_ = lm.LogTimeline("ad", "zypheron", "ad_scan_complete", adDomain, "ok")
	_ = lm.Finalize("completed")

	ui.PrintSuccess(fmt.Sprintf("AD assessment complete. Loot: %s", lm.SessionDir))
	return nil
}
