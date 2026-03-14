package commands

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/loot"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

var (
	cloudProvider string
	cloudTarget   string
	cloudMode     string
	cloudProfile  string
)

// Cloud security tools by provider
var cloudTools = map[string][]cloudTool{
	"aws": {
		{Name: "prowler", Cmd: "prowler", InstallCmd: "pip3 install prowler", Purpose: "Security posture & compliance"},
		{Name: "pacu", Cmd: "pacu", InstallCmd: "pip3 install pacu", Purpose: "AWS exploitation framework"},
		{Name: "scoutsuite", Cmd: "scout", InstallCmd: "pip3 install scoutsuite", Purpose: "Multi-cloud security audit"},
		{Name: "cloudbrute", Cmd: "cloudbrute", InstallCmd: "go install github.com/0xsha/CloudBrute@latest", Purpose: "Cloud asset discovery"},
	},
	"azure": {
		{Name: "scoutsuite", Cmd: "scout", InstallCmd: "pip3 install scoutsuite", Purpose: "Multi-cloud security audit"},
		{Name: "aadinternals", Cmd: "AADInternals", InstallCmd: "Install-Module AADInternals -Scope CurrentUser", Purpose: "Azure AD attack toolkit"},
		{Name: "roadtools", Cmd: "roadrecon", InstallCmd: "pip3 install roadtools", Purpose: "Azure AD enum & graph"},
		{Name: "cloudbrute", Cmd: "cloudbrute", InstallCmd: "go install github.com/0xsha/CloudBrute@latest", Purpose: "Cloud asset discovery"},
	},
	"gcp": {
		{Name: "scoutsuite", Cmd: "scout", InstallCmd: "pip3 install scoutsuite", Purpose: "Multi-cloud security audit"},
		{Name: "cloudbrute", Cmd: "cloudbrute", InstallCmd: "go install github.com/0xsha/CloudBrute@latest", Purpose: "Cloud asset discovery"},
	},
	"k8s": {
		{Name: "trivy", Cmd: "trivy", InstallCmd: "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh", Purpose: "Container & image scanning"},
		{Name: "kube-hunter", Cmd: "kube-hunter", InstallCmd: "pip3 install kube-hunter", Purpose: "K8s cluster pentest"},
		{Name: "checkov", Cmd: "checkov", InstallCmd: "pip3 install checkov", Purpose: "IaC misconfiguration scanner"},
	},
}

type cloudTool struct {
	Name       string
	Cmd        string
	InstallCmd string
	Purpose    string
}

func CloudCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloud",
		Short: "Cloud security scanning (AWS, Azure, GCP, K8s)",
		Long: `Run cloud security assessments using AI-guided tool chains.

No competitor covers cloud properly. This is Zypheron's first-mover advantage.

Wraps: Prowler, Pacu, ScoutSuite, CloudBrute, AADInternals, Trivy, kube-hunter, Checkov.

Examples:
  zypheron cloud --provider aws --target <account>
  zypheron cloud --provider azure --target <tenant>
  zypheron cloud --provider k8s --target <cluster>
  zypheron cloud check    # Show installed cloud tools`,
		RunE: runCloud,
	}

	cmd.Flags().StringVarP(&cloudProvider, "provider", "p", "aws", "Cloud provider: aws, azure, gcp, k8s")
	cmd.Flags().StringVarP(&cloudTarget, "target", "t", "", "Target account/tenant/cluster")
	cmd.Flags().StringVarP(&cloudMode, "mode", "m", "audit", "Mode: audit, exploit, full")
	cmd.Flags().StringVar(&cloudProfile, "profile", "", "Cloud credentials profile name")

	cmd.AddCommand(cloudCheckCmd())

	return cmd
}

func cloudCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Check installed cloud security tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			ui.PrintHeader("Cloud Security Tools Status")
			fmt.Println()

			for provider, tools := range cloudTools {
				fmt.Printf("  [%s]\n", strings.ToUpper(provider))
				for _, tool := range tools {
					installed := isToolInstalled(tool.Cmd)
					status := ui.Danger.Sprint("MISSING")
					if installed {
						status = ui.Success.Sprint("OK")
					}
					fmt.Printf("    %-16s %s  %s\n", tool.Name, status, tool.Purpose)
				}
				fmt.Println()
			}
			return nil
		},
	}
}

func runCloud(cmd *cobra.Command, args []string) error {
	if cloudTarget == "" {
		return fmt.Errorf("--target is required")
	}

	provider := strings.ToLower(cloudProvider)
	tools, ok := cloudTools[provider]
	if !ok {
		return fmt.Errorf("unsupported provider: %s (use aws, azure, gcp, k8s)", provider)
	}

	ui.PrintHeader(fmt.Sprintf("Cloud Security Scan — %s", strings.ToUpper(provider)))
	ui.PrintInfo(fmt.Sprintf("Target: %s", cloudTarget))
	ui.PrintInfo(fmt.Sprintf("Mode: %s", cloudMode))
	fmt.Println()

	// Check tools
	var available []cloudTool
	var missing []cloudTool
	for _, t := range tools {
		if isToolInstalled(t.Cmd) {
			available = append(available, t)
		} else {
			missing = append(missing, t)
		}
	}

	if len(missing) > 0 {
		ui.PrintWarning(fmt.Sprintf("%d cloud tools missing:", len(missing)))
		for _, t := range missing {
			fmt.Printf("    %s: %s\n", t.Name, t.InstallCmd)
		}
		fmt.Println()
	}

	if len(available) == 0 {
		return fmt.Errorf("no cloud tools installed. Run the install commands above")
	}

	// Init loot
	lm := loot.NewLootManager("")
	if err := lm.Init(cloudTarget, "cloud-"+provider, "", ""); err != nil {
		return fmt.Errorf("failed to init loot: %w", err)
	}

	// Send to AI engine
	bridge := aibridge.NewAIBridge()
	params := map[string]interface{}{
		"provider":        provider,
		"target":          cloudTarget,
		"mode":            cloudMode,
		"profile":         cloudProfile,
		"session_id":      lm.SessionID,
		"available_tools": toolNames(available),
	}

	ui.PrintInfo("Sending to AI engine for cloud analysis...")
	response, err := bridge.SendRequest("cloud_scan", params)
	if err != nil {
		ui.PrintWarning(fmt.Sprintf("AI engine unavailable: %s", err))
		ui.PrintInfo("Install tools listed above, then run 'zypheron cloud' again with AI engine running.")
		ui.PrintInfo(fmt.Sprintf("Loot directory: %s", lm.SessionDir))
	} else {
		_ = lm.SaveLootJSON("cloud", "ai_analysis.json", response.Result)
	}

	_ = lm.LogTimeline("cloud", "zypheron", "cloud_scan_complete", provider, "ok")
	_ = lm.Finalize("completed")
	ui.PrintSuccess(fmt.Sprintf("Cloud scan complete. Loot: %s", lm.SessionDir))

	return nil
}

func isToolInstalled(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func toolNames(tools []cloudTool) []string {
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = t.Name
	}
	return names
}
