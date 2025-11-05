package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/edition"
	"github.com/spf13/cobra"
)

var (
	mcpServerURL string
	mcpDebug     bool
)

// NewMCPCmd creates the MCP command
func NewMCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Manage Zypheron MCP server",
		Long: `Manage the Model Context Protocol (MCP) server for Zypheron.

The MCP server exposes Zypheron's security tools to AI agents like:
- Claude Desktop
- Cursor IDE
- VS Code Copilot
- Any MCP-compatible AI client

This enables natural language security testing and autonomous pentesting.`,
	}

	cmd.AddCommand(newMCPStartCmd())
	cmd.AddCommand(newMCPStopCmd())
	cmd.AddCommand(newMCPStatusCmd())
	cmd.AddCommand(newMCPConfigCmd())

	return cmd
}

func newMCPStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the MCP server",
		Long: `Start the Zypheron MCP server to expose security tools to AI agents.

The server will run in the foreground and handle MCP protocol communications.`,
		RunE: runMCPStart,
	}

	cmd.Flags().StringVar(&mcpServerURL, "backend", "http://localhost:8080", "Zypheron backend server URL")
	cmd.Flags().BoolVar(&mcpDebug, "debug", false, "Enable debug logging")

	return cmd
}

func newMCPStopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the MCP server",
		Long:  `Stop the running Zypheron MCP server.`,
		RunE:  runMCPStop,
	}

	return cmd
}

func newMCPStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check MCP server status",
		Long:  `Check if the Zypheron MCP server is running and accessible.`,
		RunE:  runMCPStatus,
	}

	return cmd
}

func newMCPConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Generate MCP configuration file",
		Long: `Generate the MCP configuration file for AI clients.

The configuration file can be used with:
- Claude Desktop: ~/.config/Claude/claude_desktop_config.json
- Cursor: Add to Cursor settings
- VS Code: Add to VS Code settings`,
		RunE: runMCPConfig,
	}

	cmd.Flags().StringP("output", "o", "", "Output file path (default: print to stdout)")

	return cmd
}

func runMCPStart(cmd *cobra.Command, args []string) error {
	fmt.Println("🚀 Starting Zypheron MCP Server...")
	fmt.Println("")

	// Find Python 3
	python3Path, err := exec.LookPath("python3")
	if err != nil {
		return fmt.Errorf("python3 not found in PATH. Please install Python 3.9+")
	}

	// Get the project root (assuming we're in zypheron-go/)
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	execDir := filepath.Dir(execPath)
	
	// Try to find zypheron-ai directory
	mcpServerPath := filepath.Join(execDir, "..", "zypheron-ai", "mcp_interface", "server.py")
	
	// Alternative: look for it relative to current directory
	if _, err := os.Stat(mcpServerPath); os.IsNotExist(err) {
		// Try current working directory
		cwd, _ := os.Getwd()
		mcpServerPath = filepath.Join(cwd, "zypheron-ai", "mcp_interface", "server.py")
		
		if _, err := os.Stat(mcpServerPath); os.IsNotExist(err) {
			return fmt.Errorf("MCP server not found. Please ensure zypheron-ai/mcp_interface/server.py exists")
		}
	}

	// Check if dependencies are installed
	checkCmd := exec.Command(python3Path, "-c", "import fastmcp")
	if err := checkCmd.Run(); err != nil {
		fmt.Println("⚠️  MCP dependencies not installed.")
		fmt.Println("   Please run: pip install -r zypheron-ai/requirements-mcp.txt")
		fmt.Println("")
		return fmt.Errorf("missing MCP dependencies")
	}

	// Build command
	mcpCmd := exec.Command(python3Path, mcpServerPath, "--server", mcpServerURL)
	if mcpDebug {
		mcpCmd.Args = append(mcpCmd.Args, "--debug")
	}

	// Set edition environment variable
	mcpCmd.Env = append(os.Environ(), fmt.Sprintf("ZYPHERON_EDITION=%s", edition.Current().String()))
	
	// Set up output
	mcpCmd.Stdout = os.Stdout
	mcpCmd.Stderr = os.Stderr
	mcpCmd.Stdin = os.Stdin

	// Run the server
	fmt.Printf("Starting: %s\n", strings.Join(mcpCmd.Args, " "))
	fmt.Println("")
	
	if err := mcpCmd.Run(); err != nil {
		return fmt.Errorf("MCP server failed: %w", err)
	}

	return nil
}

func runMCPStop(cmd *cobra.Command, args []string) error {
	fmt.Println("⏹️  Stopping Zypheron MCP Server...")

	// Find and kill MCP server process
	var killCmd *exec.Cmd
	if runtime.GOOS == "windows" {
		killCmd = exec.Command("taskkill", "/F", "/IM", "python.exe", "/FI", "WINDOWTITLE eq *mcp*server*")
	} else {
		killCmd = exec.Command("pkill", "-f", "zypheron.*mcp.*server")
	}

	if err := killCmd.Run(); err != nil {
		return fmt.Errorf("failed to stop MCP server (may not be running): %w", err)
	}

	fmt.Println("✅ MCP server stopped")
	return nil
}

func runMCPStatus(cmd *cobra.Command, args []string) error {
	fmt.Println("🔍 Checking Zypheron MCP Server status...")
	fmt.Println("")

	// Check if process is running
	var psCmd *exec.Cmd
	if runtime.GOOS == "windows" {
		psCmd = exec.Command("tasklist", "/FI", "IMAGENAME eq python.exe")
	} else {
		psCmd = exec.Command("pgrep", "-f", "zypheron.*mcp.*server")
	}

	output, err := psCmd.Output()
	if err != nil || len(output) == 0 {
		fmt.Println("❌ MCP server is not running")
		fmt.Println("")
		fmt.Println("Start it with: zypheron mcp start")
		return nil
	}

	fmt.Println("✅ MCP server is running")
	
	// Try to show process details
	if runtime.GOOS != "windows" {
		detailCmd := exec.Command("ps", "aux")
		detailOutput, err := detailCmd.Output()
		if err == nil {
			lines := strings.Split(string(detailOutput), "\n")
			for _, line := range lines {
				if strings.Contains(line, "mcp") && strings.Contains(line, "server") {
					fmt.Println("")
					fmt.Println("Process details:")
					fmt.Println(line)
					break
				}
			}
		}
	}

	return nil
}

func runMCPConfig(cmd *cobra.Command, args []string) error {
	outputPath, _ := cmd.Flags().GetString("output")

	// Get absolute path to MCP server
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	execDir := filepath.Dir(execPath)
	mcpServerPath := filepath.Join(execDir, "..", "zypheron-ai", "mcp_interface", "server.py")
	
	// Try current working directory if not found
	if _, err := os.Stat(mcpServerPath); os.IsNotExist(err) {
		cwd, _ := os.Getwd()
		mcpServerPath = filepath.Join(cwd, "zypheron-ai", "mcp_interface", "server.py")
	}

	// Get absolute path
	absPath, err := filepath.Abs(mcpServerPath)
	if err != nil {
		absPath = mcpServerPath
	}

	// Generate configuration
	config := fmt.Sprintf(`{
  "mcpServers": {
    "zypheron-ai": {
      "command": "python3",
      "args": [
        "%s",
        "--server",
        "http://localhost:8080"
      ],
      "description": "Zypheron AI - AI-Powered Penetration Testing Platform with 30+ security tools",
      "timeout": 300,
      "alwaysAllow": []
    }
  }
}`, absPath)

	// Output configuration
	if outputPath != "" {
		if err := os.WriteFile(outputPath, []byte(config), 0644); err != nil {
			return fmt.Errorf("failed to write config file: %w", err)
		}
		fmt.Printf("✅ Configuration written to: %s\n", outputPath)
	} else {
		fmt.Println("📋 Zypheron MCP Configuration:")
		fmt.Println("")
		fmt.Println(config)
		fmt.Println("")
		fmt.Println("Usage Instructions:")
		fmt.Println("-------------------")
		fmt.Println("Claude Desktop:")
		fmt.Println("  Copy this to: ~/.config/Claude/claude_desktop_config.json")
		fmt.Println("")
		fmt.Println("Cursor:")
		fmt.Println("  Add this to Cursor settings under MCP servers")
		fmt.Println("")
		fmt.Println("VS Code Copilot:")
		fmt.Println("  Add this to .vscode/settings.json")
	}

	return nil
}

