package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/spf13/cobra"
)

// InstallDepsCmd returns the dependency installation command
func InstallDepsCmd() *cobra.Command {
	var (
		all        bool
		ml         bool
		security   bool
		web        bool
		mcp        bool
		venv       string
		useUv      bool
		skipVenv   bool
	)

	cmd := &cobra.Command{
		Use:   "install-deps",
		Short: "Install Python dependencies for AI features",
		Long: `Install Python dependencies required for Zypheron AI features.

This command installs Python packages from requirements files located in the
zypheron-ai directory. By default, it installs core runtime dependencies.
You can optionally install additional capability packs.

Dependency Packs:
  • core      - Core runtime (always installed)
  • ml        - Machine learning features
  • security  - Security scanning tools
  • web       - Web UI and browser automation
  • mcp       - MCP server integration

Examples:
  zypheron install-deps                    # Install core dependencies only
  zypheron install-deps --all               # Install all dependencies
  zypheron install-deps --ml --security     # Install ML and security packs
  zypheron install-deps --venv ./venv      # Use specific virtual environment`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(ui.Primary.Sprint("\n╔═══════════════════════════════════════════════════════════╗"))
			fmt.Println(ui.Primary.Sprint("║  ZYPHERON DEPENDENCY INSTALLER                          ║"))
			fmt.Println(ui.Primary.Sprint("╚═══════════════════════════════════════════════════════════╝\n"))

			// Find zypheron-ai directory
			aiDir, err := findAIDirectory()
			if err != nil {
				fmt.Println(ui.ErrorWithRecovery(
					"Failed to find zypheron-ai directory",
					"Ensure you're running from the project root directory",
					"Check if zypheron-ai/ directory exists",
					"Verify the project structure is intact",
				))
				return fmt.Errorf("failed to find zypheron-ai directory: %w", err)
			}

			fmt.Printf("%s: %s\n\n", ui.Info.Sprint("AI Engine Directory"), aiDir)

			// Check Python availability
			pythonCmd, err := findPython()
			if err != nil {
				fmt.Println(ui.ErrorWithRecovery(
					"Python 3.9+ not found",
					"Install Python 3.9 or higher from python.org or your package manager",
					"On Ubuntu/Debian: sudo apt-get install python3 python3-venv python3-pip",
					"On macOS: brew install python3",
					"Verify installation: python3 --version",
				))
				return fmt.Errorf("python not found: %w", err)
			}

			fmt.Printf("%s: %s\n", ui.Success.Sprint("✓ Python found"), pythonCmd)
			if useUv {
				if _, err := exec.LookPath("uv"); err != nil {
					fmt.Println(ui.WarningMsg("uv not found, falling back to pip"))
					useUv = false
				} else {
					fmt.Printf("%s: uv (fast Python package installer)\n", ui.Success.Sprint("✓ Using"))
				}
			}
			fmt.Println()

			// Handle virtual environment
			var venvPath string
			if !skipVenv {
				if venv == "" {
					venv = filepath.Join(aiDir, ".venv")
				}
				venvPath = venv

				// Check if venv exists
				if _, err := os.Stat(venvPath); os.IsNotExist(err) {
					fmt.Printf("%s Creating virtual environment at %s...\n", ui.Info.Sprint("[*]"), venvPath)
					createCmd := exec.Command(pythonCmd, "-m", "venv", venvPath)
					createCmd.Dir = aiDir
					if output, err := createCmd.CombinedOutput(); err != nil {
						fmt.Println(ui.ErrorWithRecovery(
							"Failed to create virtual environment",
							"Ensure python3-venv package is installed: sudo apt-get install python3-venv",
							"Check disk space and permissions",
							"Try creating manually: python3 -m venv .venv",
						))
						return fmt.Errorf("failed to create virtual environment: %w. Output: %s", err, string(output))
					}
					fmt.Println(ui.SuccessMsg("Virtual environment created"))
				} else {
					fmt.Printf("%s Using existing virtual environment: %s\n", ui.Info.Sprint("[*]"), venvPath)
				}
			}

			// Determine which requirements files to install
			var requirementsFiles []string
			requirementsFiles = append(requirementsFiles, filepath.Join(aiDir, "requirements.txt"))

			if all {
				ml = true
				security = true
				web = true
				mcp = true
			}

			if ml {
				requirementsFiles = append(requirementsFiles, filepath.Join(aiDir, "requirements-ml.txt"))
			}
			if security {
				requirementsFiles = append(requirementsFiles, filepath.Join(aiDir, "requirements-security.txt"))
			}
			if web {
				requirementsFiles = append(requirementsFiles, filepath.Join(aiDir, "requirements-web.txt"))
			}
			if mcp {
				requirementsFiles = append(requirementsFiles, filepath.Join(aiDir, "requirements-mcp.txt"))
			}

			// Verify files exist
			var validFiles []string
			for _, file := range requirementsFiles {
				if _, err := os.Stat(file); err == nil {
					validFiles = append(validFiles, file)
				} else {
					fmt.Printf("%s Skipping missing file: %s\n", ui.Warning.Sprint("[!]"), file)
				}
			}

			if len(validFiles) == 0 {
				fmt.Println(ui.ErrorWithRecovery(
					"No requirements files found",
					fmt.Sprintf("Check if %s contains requirements.txt", aiDir),
					"Verify the zypheron-ai directory is complete",
					"Re-clone the repository if files are missing",
				))
				return fmt.Errorf("no requirements files found in %s", aiDir)
			}

			fmt.Printf("%s Installing from %d requirement file(s)...\n\n", ui.Info.Sprint("[*]"), len(validFiles))

			// Install dependencies
			var installCmd *exec.Cmd
			var pipCmd string

			if skipVenv {
				pipCmd = "pip3"
				if useUv {
					pipCmd = "uv"
				}
			} else {
				// Use pip from virtual environment
				if useUv {
					pipCmd = filepath.Join(venvPath, "bin", "uv")
					if _, err := os.Stat(pipCmd); os.IsNotExist(err) {
						// uv might not be in venv, use system uv
						if path, err := exec.LookPath("uv"); err == nil {
							pipCmd = path
						} else {
							pipCmd = filepath.Join(venvPath, "bin", "pip")
							useUv = false
						}
					}
				} else {
					pipCmd = filepath.Join(venvPath, "bin", "pip")
				}
			}

			// Install dependencies from each requirements file
			for _, reqFile := range validFiles {
				fmt.Printf("%s Installing from %s...\n", ui.Info.Sprint("[*]"), filepath.Base(reqFile))
				
				if useUv {
					// uv pip install -r <file>
					installCmd = exec.Command(pipCmd, "pip", "install", "-r", reqFile)
				} else {
					// pip install -r <file>
					installCmd = exec.Command(pipCmd, "install", "-r", reqFile)
				}
				
				installCmd.Dir = aiDir
				installCmd.Stdout = os.Stdout
				installCmd.Stderr = os.Stderr
				if err := installCmd.Run(); err != nil {
					fmt.Println(ui.ErrorWithRecovery(
						fmt.Sprintf("Failed to install dependencies from %s", filepath.Base(reqFile)),
						"Check your internet connection",
						"Verify pip/uv is up to date: pip install --upgrade pip",
						"Try installing with verbose output for details",
						"Check if there are conflicting package versions",
					))
					return fmt.Errorf("failed to install dependencies from %s: %w", reqFile, err)
				}
			}

			fmt.Println()
			fmt.Println(ui.SuccessMsg("All dependencies installed successfully!"))

			if !skipVenv {
				fmt.Println()
				fmt.Printf("%s To activate the virtual environment, run:\n", ui.Info.Sprint("[*]"))
				fmt.Printf("  source %s/bin/activate\n", venvPath)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "Install all optional dependency packs")
	cmd.Flags().BoolVar(&ml, "ml", false, "Install ML/transformer dependencies")
	cmd.Flags().BoolVar(&security, "security", false, "Install security scanning dependencies")
	cmd.Flags().BoolVar(&web, "web", false, "Install web UI dependencies")
	cmd.Flags().BoolVar(&mcp, "mcp", false, "Install MCP server dependencies")
	cmd.Flags().StringVar(&venv, "venv", "", "Path to virtual environment (default: zypheron-ai/.venv)")
	cmd.Flags().BoolVar(&useUv, "uv", false, "Use uv for faster installation (if available)")
	cmd.Flags().BoolVar(&skipVenv, "no-venv", false, "Install to system Python (not recommended)")

	return cmd
}

// findAIDirectory locates the zypheron-ai directory
func findAIDirectory() (string, error) {
	// Try multiple possible locations
	possiblePaths := []string{
		"../zypheron-ai",
		"../../zypheron-ai",
		"./zypheron-ai",
		"zypheron-ai",
	}

	// Also check current working directory and parent
	cwd, _ := os.Getwd()
	possiblePaths = append(possiblePaths,
		filepath.Join(cwd, "zypheron-ai"),
		filepath.Join(filepath.Dir(cwd), "zypheron-ai"),
	)

	for _, path := range possiblePaths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		if info, err := os.Stat(absPath); err == nil && info.IsDir() {
			// Verify it contains requirements.txt
			reqFile := filepath.Join(absPath, "requirements.txt")
			if _, err := os.Stat(reqFile); err == nil {
				return absPath, nil
			}
		}
	}

	return "", fmt.Errorf("zypheron-ai directory not found. Make sure you're running from the project root. Current directory: %s", cwd)
}

// findPython locates a Python 3 executable
func findPython() (string, error) {
	commands := []string{"python3", "python3.11", "python3.10", "python3.9", "python"}
	for _, cmd := range commands {
		if path, err := exec.LookPath(cmd); err == nil {
			// Verify it's Python 3
			versionCmd := exec.Command(path, "--version")
			output, err := versionCmd.Output()
			if err == nil && strings.Contains(string(output), "Python 3") {
				return path, nil
			}
		}
	}
	return "", fmt.Errorf("python 3.9+ not found in PATH")
}

