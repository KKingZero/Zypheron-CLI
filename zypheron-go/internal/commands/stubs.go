package commands

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/loot"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tools"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

// SetupCmd returns the setup command — first-time configuration wizard
func SetupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Initial setup and configuration",
		Long: `Run the first-time setup wizard.

Checks and configures:
  • Security tool detection (nmap, nuclei, nikto, etc.)
  • AI provider API keys
  • Shell completion installation
  • Python AI engine dependencies

Examples:
  zypheron setup`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ui.PrintHeader("Zypheron Setup Wizard")
			fmt.Println()

			// Step 1: Detect tools
			ui.PrintInfo("Step 1/4: Detecting security tools...")
			statuses := tools.CheckAllTools()
			installed := 0
			for _, s := range statuses {
				if s.Installed {
					installed++
				}
			}
			ui.PrintSuccess(fmt.Sprintf("  Found %d/%d tools installed", installed, len(statuses)))

			missing := tools.GetMissingRequiredTools()
			if len(missing) > 0 {
				ui.PrintWarning(fmt.Sprintf("  %d required tools missing:", len(missing)))
				for _, m := range missing {
					fmt.Printf("    - %s: %s\n", m.Tool.Name, tools.GetInstallCommand(m.Tool))
				}
			}
			fmt.Println()

			// Step 2: Check Python engine
			ui.PrintInfo("Step 2/4: Checking AI engine...")
			pythonOK := false
			for _, py := range []string{"python3", "python"} {
				if _, err := exec.LookPath(py); err == nil {
					pythonOK = true
					ui.PrintSuccess(fmt.Sprintf("  Python found: %s", py))
					break
				}
			}
			if !pythonOK {
				ui.PrintWarning("  Python3 not found — AI features require Python 3.8+")
			}
			fmt.Println()

			// Step 3: Check API keys
			ui.PrintInfo("Step 3/4: Checking API keys...")
			providers := map[string]string{
				"ANTHROPIC_API_KEY": "Claude",
				"OPENAI_API_KEY":   "OpenAI",
				"GEMINI_API_KEY":   "Gemini",
				"GOOGLE_API_KEY":   "Google",
			}
			keyCount := 0
			for env, name := range providers {
				if os.Getenv(env) != "" {
					ui.PrintSuccess(fmt.Sprintf("  %s: configured", name))
					keyCount++
				}
			}
			if keyCount == 0 {
				ui.PrintWarning("  No cloud AI keys found. Use 'zypheron config set-key <provider>' or set environment variables")
				ui.PrintInfo("  Local AI (Ollama) works without API keys")
			}
			fmt.Println()

			// Step 4: Shell completions
			ui.PrintInfo("Step 4/4: Shell completions")
			shell := os.Getenv("SHELL")
			if strings.Contains(shell, "bash") {
				ui.PrintInfo("  Generate: zypheron completion bash > /etc/bash_completion.d/zypheron")
			} else if strings.Contains(shell, "zsh") {
				ui.PrintInfo("  Generate: zypheron completion zsh > ~/.zsh/completion/_zypheron")
			} else if strings.Contains(shell, "fish") {
				ui.PrintInfo("  Generate: zypheron completion fish > ~/.config/fish/completions/zypheron.fish")
			}
			fmt.Println()

			ui.PrintSuccess("Setup complete!")
			ui.PrintInfo("Next steps:")
			fmt.Println("  1. Install missing tools: zypheron tools install-all")
			fmt.Println("  2. Start AI engine: zypheron ai start")
			fmt.Println("  3. Run your first scan: zypheron scan <target>")
			fmt.Println()
			return nil
		},
	}
}

// BruteforceCmd returns the bruteforce command
func BruteforceCmd() *cobra.Command {
	var (
		protocol  string
		userFile  string
		passFile  string
		threads   int
		bfTimeout int
	)

	cmd := &cobra.Command{
		Use:   "bruteforce [target]",
		Short: "Credential bruteforce attacks",
		Long: `AI-guided credential bruteforce using hydra, medusa, or hashcat.

Supported protocols: ssh, ftp, http-post, rdp, smb, mysql, postgresql, vnc

Examples:
  zypheron bruteforce 10.10.10.1 --protocol ssh
  zypheron bruteforce 10.10.10.1 --protocol ssh -U users.txt -P passwords.txt
  zypheron bruteforce 10.10.10.1 --protocol http-post --threads 16`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("target is required")
			}
			target := args[0]

			ui.PrintHeader("Bruteforce Module")
			ui.PrintInfo(fmt.Sprintf("Target: %s", target))
			ui.PrintInfo(fmt.Sprintf("Protocol: %s", protocol))

			// Determine tool
			tool := "hydra"
			if !tools.IsToolInstalled("hydra") {
				if tools.IsToolInstalled("medusa") {
					tool = "medusa"
				} else {
					return fmt.Errorf("hydra or medusa required. Install: sudo apt install hydra")
				}
			}

			var toolArgs []string
			switch tool {
			case "hydra":
				if userFile != "" {
					toolArgs = append(toolArgs, "-L", userFile)
				} else {
					toolArgs = append(toolArgs, "-l", "admin")
				}
				if passFile != "" {
					toolArgs = append(toolArgs, "-P", passFile)
				} else {
					toolArgs = append(toolArgs, "-P", "/usr/share/wordlists/rockyou.txt")
				}
				toolArgs = append(toolArgs, "-t", fmt.Sprintf("%d", threads))
				toolArgs = append(toolArgs, "-f", target, protocol)
			case "medusa":
				if userFile != "" {
					toolArgs = append(toolArgs, "-U", userFile)
				}
				if passFile != "" {
					toolArgs = append(toolArgs, "-P", passFile)
				}
				toolArgs = append(toolArgs, "-h", target, "-M", protocol, "-t", fmt.Sprintf("%d", threads))
			}

			lm := loot.NewLootManager("")
			if err := lm.Init(target, "bruteforce", "", ""); err != nil {
				return fmt.Errorf("failed to init loot: %w", err)
			}

			ui.PrintInfo(fmt.Sprintf("Running %s...", tool))
			result, err := tools.Execute(context.Background(), tools.ExecutionOptions{
				Tool:    tool,
				Args:    toolArgs,
				Target:  target,
				Stream:  true,
				Timeout: time.Duration(bfTimeout) * time.Minute,
			})
			if err != nil {
				return fmt.Errorf("%s failed: %w", tool, err)
			}

			_ = lm.SaveLoot("creds", fmt.Sprintf("%s_output.txt", tool), []byte(result.Output))
			_ = lm.LogTimeline("bruteforce", tool, "bruteforce_complete", target, "ok")
			_ = lm.Finalize("completed")

			ui.PrintSuccess(fmt.Sprintf("Bruteforce complete. Loot: %s", lm.SessionDir))
			return nil
		},
	}

	cmd.Flags().StringVarP(&protocol, "protocol", "P", "ssh", "Protocol: ssh, ftp, http-post, rdp, smb, mysql, vnc")
	cmd.Flags().StringVarP(&userFile, "users", "U", "", "Username wordlist file")
	cmd.Flags().StringVar(&passFile, "passwords", "", "Password wordlist file")
	cmd.Flags().IntVarP(&threads, "threads", "t", 4, "Number of parallel threads")
	cmd.Flags().IntVar(&bfTimeout, "timeout", 30, "Timeout in minutes")

	return cmd
}

// FuzzCmd returns the fuzz command
func FuzzCmd() *cobra.Command {
	var (
		wordlist string
		fuzzMode string
		fThreads int
		mc       string
		fc       string
	)

	cmd := &cobra.Command{
		Use:   "fuzz [target]",
		Short: "Web fuzzing operations",
		Long: `AI-guided web fuzzing using ffuf, gobuster, or feroxbuster.

Modes: dir (directory), dns (subdomain), vhost (virtual host)

Examples:
  zypheron fuzz http://10.10.10.1 --mode dir
  zypheron fuzz http://10.10.10.1 --mode dir -w /usr/share/wordlists/dirb/common.txt
  zypheron fuzz example.com --mode dns`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("target URL is required")
			}
			target := args[0]

			ui.PrintHeader("Web Fuzzing Module")
			ui.PrintInfo(fmt.Sprintf("Target: %s", target))
			ui.PrintInfo(fmt.Sprintf("Mode: %s", fuzzMode))

			// Select best available tool
			tool := ""
			for _, t := range []string{"ffuf", "feroxbuster", "gobuster", "dirsearch", "wfuzz"} {
				if tools.IsToolInstalled(t) {
					tool = t
					break
				}
			}
			if tool == "" {
				return fmt.Errorf("no fuzzing tool found. Install one: sudo apt install ffuf")
			}

			if wordlist == "" {
				for _, wl := range []string{
					"/usr/share/wordlists/dirb/common.txt",
					"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
					"/usr/share/seclists/Discovery/Web-Content/common.txt",
				} {
					if _, err := os.Stat(wl); err == nil {
						wordlist = wl
						break
					}
				}
				if wordlist == "" {
					return fmt.Errorf("no wordlist found. Specify with -w <path>")
				}
			}

			var toolArgs []string
			switch tool {
			case "ffuf":
				toolArgs = []string{"-u", target + "/FUZZ", "-w", wordlist, "-t", fmt.Sprintf("%d", fThreads)}
				if mc != "" {
					toolArgs = append(toolArgs, "-mc", mc)
				}
				if fc != "" {
					toolArgs = append(toolArgs, "-fc", fc)
				}
			case "feroxbuster":
				toolArgs = []string{"-u", target, "-w", wordlist, "-t", fmt.Sprintf("%d", fThreads), "-q"}
			case "gobuster":
				toolArgs = []string{"dir", "-u", target, "-w", wordlist, "-t", fmt.Sprintf("%d", fThreads)}
			case "dirsearch":
				toolArgs = []string{"-u", target, "-w", wordlist, "-t", fmt.Sprintf("%d", fThreads), "-q"}
			case "wfuzz":
				toolArgs = []string{"-w", wordlist, target + "/FUZZ"}
			}

			lm := loot.NewLootManager("")
			if err := lm.Init(target, "fuzz-"+fuzzMode, "", ""); err != nil {
				return fmt.Errorf("failed to init loot: %w", err)
			}

			ui.PrintInfo(fmt.Sprintf("Running %s with %s...", tool, filepath.Base(wordlist)))
			result, err := tools.Execute(context.Background(), tools.ExecutionOptions{
				Tool:    tool,
				Args:    toolArgs,
				Target:  target,
				Stream:  true,
				Timeout: 30 * time.Minute,
			})
			if err != nil {
				return fmt.Errorf("%s failed: %w", tool, err)
			}

			_ = lm.SaveLoot("web", fmt.Sprintf("%s_output.txt", tool), []byte(result.Output))
			_ = lm.LogTimeline("fuzz", tool, "fuzz_complete", target, "ok")
			_ = lm.Finalize("completed")

			ui.PrintSuccess(fmt.Sprintf("Fuzzing complete. Loot: %s", lm.SessionDir))
			return nil
		},
	}

	cmd.Flags().StringVarP(&wordlist, "wordlist", "w", "", "Wordlist file path")
	cmd.Flags().StringVarP(&fuzzMode, "mode", "m", "dir", "Fuzz mode: dir, dns, vhost")
	cmd.Flags().IntVarP(&fThreads, "threads", "t", 40, "Number of threads")
	cmd.Flags().StringVar(&mc, "match-codes", "", "Match HTTP status codes (e.g. 200,301)")
	cmd.Flags().StringVar(&fc, "filter-codes", "404", "Filter HTTP status codes")

	return cmd
}

// OsintCmd returns the OSINT command
func OsintCmd() *cobra.Command {
	var osintType string

	cmd := &cobra.Command{
		Use:   "osint [target]",
		Short: "OSINT operations",
		Long: `Open-source intelligence gathering using AI-guided tool selection.

Wraps: theHarvester, amass, subfinder, sherlock, holehe, shodan

Types: email, domain, username, ip

Examples:
  zypheron osint example.com --type domain
  zypheron osint john@example.com --type email
  zypheron osint johndoe --type username`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("target is required")
			}
			target := args[0]

			ui.PrintHeader("OSINT Module")
			ui.PrintInfo(fmt.Sprintf("Target: %s", target))
			ui.PrintInfo(fmt.Sprintf("Type: %s", osintType))
			fmt.Println()

			lm := loot.NewLootManager("")
			if err := lm.Init(target, "osint-"+osintType, "", ""); err != nil {
				return fmt.Errorf("failed to init loot: %w", err)
			}

			// Send to AI engine for orchestration
			bridge := aibridge.NewAIBridge()

			ui.PrintInfo("Sending to AI engine for OSINT orchestration...")
			response, err := bridge.SendRequest("chat", map[string]interface{}{
				"messages": []map[string]string{
					{"role": "user", "content": fmt.Sprintf(
						"You are an OSINT analyst. Plan an OSINT investigation for target '%s' (type: %s). "+
							"List the tools to use and what information to gather. "+
							"Available tools: theHarvester, amass, subfinder, sherlock, shodan CLI. "+
							"Return a structured plan with steps.", target, osintType)},
				},
				"provider": "deepseek",
			})
			if err != nil {
				ui.PrintWarning(fmt.Sprintf("AI engine unavailable: %s", err))
				// Fallback: run available tools directly
				return runOsintFallback(target, osintType, lm)
			}

			if content, ok := response.Result["content"].(string); ok {
				_ = lm.SaveLoot("findings", "osint_plan.md", []byte(content))
				fmt.Println(content)
			}

			_ = lm.LogTimeline("osint", "zypheron", "osint_complete", target, "ok")
			_ = lm.Finalize("completed")

			ui.PrintSuccess(fmt.Sprintf("OSINT complete. Loot: %s", lm.SessionDir))
			return nil
		},
	}

	cmd.Flags().StringVar(&osintType, "type", "domain", "OSINT type: domain, email, username, ip")
	return cmd
}

func runOsintFallback(target, osintType string, lm *loot.LootManager) error {
	// Run whatever OSINT tools are installed
	osintTools := map[string][]string{
		"domain":   {"subfinder", "amass", "theHarvester"},
		"email":    {"theHarvester"},
		"username": {"sherlock"},
		"ip":       {"shodan"},
	}

	toolList := osintTools[osintType]
	if toolList == nil {
		toolList = osintTools["domain"]
	}

	for _, t := range toolList {
		if !tools.IsToolInstalled(t) {
			ui.PrintWarning(fmt.Sprintf("  %s not installed, skipping", t))
			continue
		}

		var toolArgs []string
		switch t {
		case "subfinder":
			toolArgs = []string{"-d", target, "-silent"}
		case "amass":
			toolArgs = []string{"enum", "-passive", "-d", target}
		case "theHarvester":
			toolArgs = []string{"-d", target, "-b", "all"}
		case "sherlock":
			toolArgs = []string{target, "--print-found"}
		}

		ui.PrintInfo(fmt.Sprintf("Running %s...", t))
		result, err := tools.Execute(context.Background(), tools.ExecutionOptions{
			Tool:    t,
			Args:    toolArgs,
			Target:  target,
			Stream:  true,
			Timeout: 5 * time.Minute,
		})
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("  %s failed: %s", t, err))
			continue
		}
		_ = lm.SaveLoot("findings", fmt.Sprintf("%s_output.txt", t), []byte(result.Output))
	}

	_ = lm.LogTimeline("osint", "zypheron", "osint_fallback_complete", target, "ok")
	_ = lm.Finalize("completed")
	return nil
}

// ThreatCmd returns the threat intelligence command
func ThreatCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "threat [target]",
		Short: "Threat intelligence analysis",
		Long: `AI-powered threat intelligence lookups.

Queries AI for threat context on IPs, domains, hashes, and CVEs.
For API-based lookups, configure keys for VirusTotal, Shodan, AbuseIPDB.

Examples:
  zypheron threat 192.168.1.1
  zypheron threat evil.example.com
  zypheron threat CVE-2024-1234`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("target (IP, domain, hash, or CVE) is required")
			}
			target := args[0]

			ui.PrintHeader("Threat Intelligence")
			ui.PrintInfo(fmt.Sprintf("Target: %s", target))
			fmt.Println()

			bridge := aibridge.NewAIBridge()
			response, err := bridge.SendRequest("chat", map[string]interface{}{
				"messages": []map[string]string{
					{"role": "user", "content": fmt.Sprintf(
						"You are a threat intelligence analyst. Analyze this indicator: '%s'\n"+
							"Provide:\n"+
							"1. Indicator type (IP/domain/hash/CVE)\n"+
							"2. Known threat associations\n"+
							"3. Risk assessment (critical/high/medium/low)\n"+
							"4. Recommended actions\n"+
							"5. Related IOCs if applicable\n"+
							"Be specific and actionable.", target)},
				},
				"provider": "deepseek",
			})
			if err != nil {
				return fmt.Errorf("AI engine unavailable: %w. Start it with: zypheron ai start", err)
			}

			if content, ok := response.Result["content"].(string); ok {
				fmt.Println(content)
			}

			fmt.Println()
			return nil
		},
	}

	return cmd
}

// DashboardCmd returns the dashboard command — redirects to TUI
func DashboardCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dashboard",
		Short: "Launch real-time monitoring dashboard",
		Long: `Launch the Zypheron interactive TUI dashboard.

The dashboard provides real-time monitoring of:
  • Active scans and their progress
  • Discovered vulnerabilities
  • AI analysis results
  • Tool status

This is an alias for 'zypheron tui'.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ui.PrintInfo("Launching TUI dashboard...")
			ui.PrintInfo("(This is equivalent to running 'zypheron tui')")
			fmt.Println()

			// Import and run TUI
			tuiCmd := TUICmd()
			return tuiCmd.RunE(tuiCmd, args)
		},
	}
}

// KaliCmd returns the Kali Linux operations command
func KaliCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kali",
		Short: "Kali Linux specific operations",
		Long: `Kali Linux detection and tool management.

Subcommands:
  detect    Check if running on Kali Linux
  install   Install Kali metapackages
  update    Update Kali tools`,
	}

	cmd.AddCommand(kaliDetectCmd())
	cmd.AddCommand(kaliInstallCmd())

	return cmd
}

func kaliDetectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "detect",
		Short: "Detect Kali Linux environment",
		RunE: func(cmd *cobra.Command, args []string) error {
			ui.PrintHeader("Kali Linux Detection")
			fmt.Println()

			if runtime.GOOS != "linux" {
				ui.PrintWarning(fmt.Sprintf("Not running Linux (detected: %s)", runtime.GOOS))
				return nil
			}

			// Check /etc/os-release for Kali
			data, err := os.ReadFile("/etc/os-release")
			if err != nil {
				ui.PrintWarning("Could not read /etc/os-release")
				return nil
			}

			content := string(data)
			if strings.Contains(content, "Kali") {
				ui.PrintSuccess("Running on Kali Linux")
				// Extract version
				for _, line := range strings.Split(content, "\n") {
					if strings.HasPrefix(line, "VERSION=") || strings.HasPrefix(line, "PRETTY_NAME=") {
						fmt.Printf("  %s\n", line)
					}
				}
			} else {
				ui.PrintInfo("Not running Kali Linux (tools still work on any Linux)")
			}

			fmt.Println()

			// Check WSL
			if _, err := os.Stat("/proc/sys/fs/binfmt_misc/WSLInterop"); err == nil {
				ui.PrintInfo("WSL detected — some tools may need additional configuration")
			}

			return nil
		},
	}
}

func kaliInstallCmd() *cobra.Command {
	var metapackage string

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install Kali metapackages",
		Long: `Install Kali Linux metapackages for security testing.

Available metapackages:
  default       Standard Kali tools
  large         Full Kali tool suite
  web           Web application testing tools
  wireless      Wireless testing tools
  forensics     Digital forensics tools`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !tools.IsToolInstalled("apt") {
				return fmt.Errorf("apt package manager not found — this command requires Debian/Kali/Ubuntu")
			}

			pkgMap := map[string]string{
				"default":   "kali-tools-top10",
				"large":     "kali-linux-large",
				"web":       "kali-tools-web",
				"wireless":  "kali-tools-wireless",
				"forensics": "kali-tools-forensics",
			}

			pkg, ok := pkgMap[metapackage]
			if !ok {
				return fmt.Errorf("unknown metapackage: %s (available: default, large, web, wireless, forensics)", metapackage)
			}

			ui.PrintInfo(fmt.Sprintf("Installing %s (%s)...", metapackage, pkg))
			ui.PrintWarning("This requires sudo and may take a while")
			fmt.Printf("\n  sudo apt install -y %s\n\n", pkg)

			return nil
		},
	}

	cmd.Flags().StringVarP(&metapackage, "package", "p", "default", "Metapackage to install")
	return cmd
}
