package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/utils"
	"github.com/spf13/cobra"
)

type manifestPair struct {
	label    string
	manifest string
	lockfile string
}

func checkPythonLockfiles() {
	pairs := []manifestPair{
		{
			label:    "Core runtime",
			manifest: "zypheron-ai/requirements.txt",
			lockfile: "zypheron-ai/requirements.lock",
		},
		{
			label:    "ML pack",
			manifest: "zypheron-ai/requirements-ml.txt",
			lockfile: "zypheron-ai/requirements-ml.lock",
		},
		{
			label:    "Security pack",
			manifest: "zypheron-ai/requirements-security.txt",
			lockfile: "zypheron-ai/requirements-security.lock",
		},
		{
			label:    "Web pack",
			manifest: "zypheron-ai/requirements-web.txt",
			lockfile: "zypheron-ai/requirements-web.lock",
		},
	}

	for _, pair := range pairs {
		manifestInfo, err := os.Stat(pair.manifest)
		if err != nil {
			continue
		}

		lockInfo, err := os.Stat(pair.lockfile)
		if err != nil {
			fmt.Println(ui.WarningMsg(fmt.Sprintf("%s lockfile missing (%s). Refresh with `uv pip compile %s -o %s`.", pair.label, pair.lockfile, pair.manifest, pair.lockfile)))
			continue
		}

		if lockInfo.ModTime().Before(manifestInfo.ModTime()) {
			fmt.Println(ui.WarningMsg(fmt.Sprintf("%s lockfile is older than %s. Run `uv pip compile %s -o %s` to update.", pair.label, pair.manifest, pair.manifest, pair.lockfile)))
		}
	}
}

// DepsCmd returns the dependency checking command
func DepsCmd() *cobra.Command {
	var (
		manifestFile string
		recursive    bool
		outputFile   string
		generateSBOM bool
		sbomFormat   string
	)

	cmd := &cobra.Command{
		Use:   "deps [directory]",
		Short: "Check dependencies for known vulnerabilities",
		Long:  "Scan package manifests (requirements.txt, package.json, go.mod) for vulnerable dependencies",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			directory := "."
			if len(args) > 0 {
				directory = args[0]
			}

			// Print scan configuration
			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║  ZYPHERON DEPENDENCY SCANNER             ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════╝"))

			fmt.Println("\n" + ui.Primary.Sprint("Scan Configuration:"))
			fmt.Println(strings.Repeat("─", 60))
			fmt.Printf("  Directory:      %s\n", ui.Info.Sprint(directory))
			fmt.Printf("  Recursive:      %s\n", ui.Warning.Sprint(fmt.Sprintf("%v", recursive)))
			if generateSBOM {
				fmt.Printf("  Generate SBOM:  %s (%s)\n", ui.Success.Sprint("Yes"), ui.Accent.Sprint(sbomFormat))
			}
			fmt.Println(strings.Repeat("─", 60))

			checkPythonLockfiles()

			// Call Python AI engine for dependency scanning
			bridge := aibridge.NewAIBridge()

			fmt.Println(ui.WarningMsg("Scanning dependencies..."))

			scanParams := map[string]interface{}{
				"directory":     directory,
				"recursive":     recursive,
				"generate_sbom": generateSBOM,
				"sbom_format":   sbomFormat,
			}

			resp, err := bridge.SendRequest("scan_dependencies", scanParams)
			if err != nil {
				return fmt.Errorf("dependency scan failed: %w", err)
			}

			// Parse results
			var vulns []interface{}
			var total int
			if resp.Result != nil {
				if v, ok := resp.Result["vulnerabilities"].([]interface{}); ok {
					vulns = v
					total = len(vulns)
				}
			}

			// Display results
			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║  DEPENDENCY SCAN RESULTS                 ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════╝"))

			if total == 0 {
				fmt.Println(ui.Success.Sprint("\n✓ No vulnerable dependencies found!"))
			} else {
				fmt.Printf("\n%s %s\n", ui.Danger.Sprint("[!] Found"), ui.Danger.Sprint(fmt.Sprintf("%d vulnerable dependencies", total)))

				// Group by severity
				bySeverity := make(map[string]int)
				byEcosystem := make(map[string]int)

				for _, v := range vulns {
					vuln := v.(map[string]interface{})
					severity := vuln["severity"].(string)
					ecosystem := vuln["ecosystem"].(string)

					bySeverity[severity]++
					byEcosystem[ecosystem]++
				}

				fmt.Println("\nBy Severity:")
				if bySeverity["critical"] > 0 {
					fmt.Printf("  %s: %d\n", ui.Danger.Sprint("Critical"), bySeverity["critical"])
				}
				if bySeverity["high"] > 0 {
					fmt.Printf("  %s: %d\n", ui.Danger.Sprint("High"), bySeverity["high"])
				}
				if bySeverity["medium"] > 0 {
					fmt.Printf("  %s: %d\n", ui.Warning.Sprint("Medium"), bySeverity["medium"])
				}

				fmt.Println("\nBy Ecosystem:")
				for eco, count := range byEcosystem {
					fmt.Printf("  %s: %d\n", eco, count)
				}

				// Show critical vulnerabilities
				critical := 0
				fmt.Println(ui.Danger.Sprint("\nCritical Vulnerabilities:"))
				for _, v := range vulns {
					vuln := v.(map[string]interface{})
					if vuln["severity"].(string) == "critical" {
						critical++
						if critical <= 5 {
							fmt.Printf("\n  %d. %s@%s\n", critical, vuln["package_name"], vuln["installed_version"])
							if vuln["cve_id"] != nil {
								fmt.Printf("     CVE: %s\n", vuln["cve_id"])
							}
							if vuln["fixed_version"] != nil {
								fmt.Printf("     Fix: Upgrade to %s\n", vuln["fixed_version"])
							}
						}
					}
				}
				if critical > 5 {
					fmt.Printf("\n  ... and %d more critical vulnerabilities\n", critical-5)
				}
			}

			// SBOM generation
			if generateSBOM && resp.Result != nil {
				sbomFile := fmt.Sprintf("sbom-%s.json", sbomFormat)
				if sbomData, ok := resp.Result["sbom"]; ok {
					data, _ := json.MarshalIndent(sbomData, "", "  ")
					// Use secure file writer for SBOM (contains dependency info)
					writer := utils.NewSecureFileWriter()
					if err := writer.WriteSecure(sbomFile, data); err != nil {
						fmt.Println(ui.Error(fmt.Sprintf("Failed to save SBOM: %s", err)))
					} else {
						fmt.Printf("\n[+] SBOM saved securely to: %s (permissions: 0600)\n", sbomFile)
					}
				}
			}

			// Save results if output file specified
			if outputFile != "" && resp.Result != nil {
				data, _ := json.MarshalIndent(resp.Result, "", "  ")
				// Use secure file writer for vulnerability scan results
				writer := utils.NewSecureFileWriter()
				if err := writer.WriteSecure(outputFile, data); err != nil {
					fmt.Println(ui.Error(fmt.Sprintf("Failed to save output: %s", err)))
				} else {
					fmt.Printf("[+] Results saved securely to: %s (permissions: 0600)\n", outputFile)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&manifestFile, "manifest", "m", "", "Specific manifest file to scan")
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", true, "Scan subdirectories")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for results")
	cmd.Flags().BoolVar(&generateSBOM, "sbom", false, "Generate Software Bill of Materials")
	cmd.Flags().StringVar(&sbomFormat, "sbom-format", "cyclonedx", "SBOM format (cyclonedx, spdx, json)")

	return cmd
}
