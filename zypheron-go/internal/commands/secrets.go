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

// SecretsCmd returns the secrets scanning command
func SecretsCmd() *cobra.Command {
	var (
		recursive      bool
		extensions     []string
		outputFile     string
		excludePattern string
		minEntropy     float64
	)

	cmd := &cobra.Command{
		Use:   "secrets [directory]",
		Short: "Scan for hardcoded secrets and credentials",
		Long:  "Scan code and configuration files for hardcoded API keys, passwords, tokens, and private keys",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			directory := "."
			if len(args) > 0 {
				directory = args[0]
			}

			// Verify directory exists
			if _, err := os.Stat(directory); os.IsNotExist(err) {
				return fmt.Errorf("directory not found: %s", directory)
			}

			// Print scan configuration
			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║  ZYPHERON SECRETS SCANNER                ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════╝"))

			fmt.Println("\n" + ui.Primary.Sprint("Scan Configuration:"))
			fmt.Println(strings.Repeat("─", 60))
			fmt.Printf("  Directory:   %s\n", ui.Info.Sprint(directory))
			fmt.Printf("  Recursive:   %s\n", ui.Warning.Sprint(fmt.Sprintf("%v", recursive)))
			fmt.Printf("  Min Entropy: %s\n", ui.Warning.Sprint(fmt.Sprintf("%.1f", minEntropy)))
			fmt.Println(strings.Repeat("─", 60))

			// Call Python AI engine for secrets scanning
			bridge := aibridge.NewAIBridge()

			fmt.Println(ui.WarningMsg("Scanning for secrets..."))

			scanParams := map[string]interface{}{
				"directory":   directory,
				"recursive":   recursive,
				"extensions":  extensions,
				"min_entropy": minEntropy,
			}

			resp, err := bridge.SendRequest("scan_secrets", scanParams)
			if err != nil {
				return fmt.Errorf("secrets scan failed: %w", err)
			}

			// Parse results
			var findings []interface{}
			var total int
			if resp.Result != nil {
				if f, ok := resp.Result["findings"].([]interface{}); ok {
					findings = f
					total = len(findings)
				}
			}

			// Display results
			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║  SECRETS SCAN RESULTS                    ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════╝"))

			if total == 0 {
				fmt.Println(ui.Success.Sprint("\n✓ No secrets found! Good job!"))
			} else {
				fmt.Printf("\n%s %s\n", ui.Danger.Sprint("[!] Found"), ui.Danger.Sprint(fmt.Sprintf("%d secrets", total)))

				// Group by severity
				bySeverity := make(map[string]int)
				byType := make(map[string]int)

				for _, f := range findings {
					finding := f.(map[string]interface{})
					severity := finding["severity"].(string)
					secretType := finding["secret_type"].(string)

					bySeverity[severity]++
					byType[secretType]++
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

				fmt.Println("\nBy Type:")
				for secretType, count := range byType {
					fmt.Printf("  %s: %d\n", secretType, count)
				}

				// Show top 5 critical findings
				critical := 0
				fmt.Println(ui.Danger.Sprint("\nCritical Findings:"))
				for _, f := range findings {
					finding := f.(map[string]interface{})
					if sev, ok := finding["severity"].(string); ok && sev == "critical" {
						critical++
						if critical <= 5 {
							if st, ok := finding["secret_type"].(string); ok {
								fmt.Printf("\n  %d. %s\n", critical, ui.Danger.Sprint(st))
							}
							fmt.Printf("     File: %s:%v\n", finding["file_path"], finding["line_number"])
							fmt.Printf("     Type: %s\n", finding["pattern_name"])
						}
					}
				}
				if critical > 5 {
					fmt.Printf("\n  ... and %d more critical secrets\n", critical-5)
				}
			}

			// Save to file if requested
			if outputFile != "" {
				data, _ := json.MarshalIndent(resp, "", "  ")
				// Use secure file writer for secrets scan results
				writer := utils.NewSecureFileWriter()
				if err := writer.WriteSecure(outputFile, data); err != nil {
					fmt.Println(ui.Error(fmt.Sprintf("Failed to save output: %s", err)))
				} else {
					fmt.Printf("\n[+] Results saved securely to: %s (permissions: 0600)\n", outputFile)
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&recursive, "recursive", "r", true, "Scan subdirectories")
	cmd.Flags().StringSliceVarP(&extensions, "extensions", "e", []string{}, "File extensions to scan (e.g., .py,.js,.env)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for results")
	cmd.Flags().StringVar(&excludePattern, "exclude", "", "Exclude pattern (regex)")
	cmd.Flags().Float64Var(&minEntropy, "min-entropy", 4.5, "Minimum entropy for high-entropy string detection")

	return cmd
}
