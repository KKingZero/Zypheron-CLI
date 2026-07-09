package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/licensing"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/validation"
	"github.com/spf13/cobra"
)

// AutoPentCmd returns the autopent command
func AutoPentCmd() *cobra.Command {
	var (
		autopentObjective    string
		autopentAIProvider   string
		autopentResume       string
		autopentListSessions bool
		autopentSaveSession  bool
		autopentSessionID    string
		autopentAutonomous   bool // Full autonomous mode - AI makes all decisions
	)

	cmd := &cobra.Command{
		Use:   "autopent [target]",
		Short: "Run autonomous attack path execution",
		Long: `Execute semi-autonomous penetration testing with AI-powered attack path chaining.

AutoPent is a high-risk feature and is disabled by default. To enable it for
authorized testing, set ZYPHERON_ENABLE_AUTOPENT=1 before running the command.

This command launches the Phase 1 autonomous attack path engine that:
- Discovers attack paths to your objective
- Uses AI for intelligent decision making
- Requests approval for high-risk actions (unless --autonomous)
- Chains attacks across multiple hops
- Manages credentials discovered during execution
- Saves and resumes sessions

OPERATION MODES:
  Default (Interactive):
    - AI proposes actions, user approves major decisions
    - High-risk actions always require confirmation
    - Recommended for learning and controlled testing

  Autonomous (--autonomous):
    - AI makes ALL decisions automatically
    - No user prompts except critical safety gates
    - Use only in authorized, isolated environments
    - WARNING: May execute exploits without confirmation

Examples:
  # Interactive mode (default) - asks for approval
  zypheron autopent 192.168.1.100 --objective "reach database server"

  # Fully autonomous mode - AI decides everything
  zypheron autopent 192.168.1.100 --objective "reach database server" --autonomous

  # With custom AI provider
  zypheron autopent example.com --objective "obtain domain admin" --ai-provider claude

  # Resume previous session
  zypheron autopent --resume session_abc123

  # List saved sessions
  zypheron autopent --list-sessions`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Getenv("ZYPHERON_ENABLE_AUTOPENT") != "1" {
				return fmt.Errorf("autopent is a high-risk feature and is disabled by default; set ZYPHERON_ENABLE_AUTOPENT=1 only for authorized testing")
			}

			// License check - Autopent requires paid tier
			if err := licensing.RequireAutopent(); err != nil {
				if licErr, ok := err.(*licensing.FeatureLockedError); ok {
					fmt.Println(licErr.Message)
					return nil
				}
				return err
			}

			// Also check for cloud AI if using non-Ollama provider
			if autopentAIProvider != "" && autopentAIProvider != "ollama" {
				if err := licensing.RequireProviderAccess(autopentAIProvider); err != nil {
					if licErr, ok := err.(*licensing.FeatureLockedError); ok {
						fmt.Println(licErr.Message)
						return nil
					}
					return err
				}
			}

			fmt.Printf("\n%s\n", ui.Primary.Sprint("╔══════════════════════════════════════════╗"))
			fmt.Printf("%s\n", ui.Primary.Sprint("║  AUTONOMOUS ATTACK PATH ENGINE           ║"))
			fmt.Printf("%s\n\n", ui.Primary.Sprint("╚══════════════════════════════════════════╝"))

			// Show legal warning for exploitation mode (once per session)
			// This is shown for all autopent operations except listing sessions
			if !autopentListSessions {
				// Check if running interactively
				interactive := isInteractive(cmd)
				var acknowledged bool
				if interactive {
					acknowledged = ui.ShowExploitWarning()
				} else {
					// In non-interactive mode, check for --yes flag equivalent behavior
					// autopent doesn't have --yes flag, so we require interaction
					acknowledged = ui.ShowExploitWarningNonInteractive(false)
				}

				if !acknowledged {
					return nil // User declined, exit gracefully
				}
			}

			// Handle list sessions
			if autopentListSessions {
				return listAutoPentSessions()
			}

			// Handle resume
			if autopentResume != "" {
				return resumeAutoPentSession(autopentResume)
			}

			// Validate arguments for new session
			if len(args) == 0 {
				return fmt.Errorf("target is required (or use --resume to resume a session)")
			}

			target := args[0]

			if autopentObjective == "" {
				return fmt.Errorf("--objective is required (e.g., 'reach database server')")
			}

			// Print execution parameters
			fmt.Println(ui.InfoMsg("Configuration"))
			fmt.Printf("  Target:       %s\n", ui.Success.Sprint(target))
			fmt.Printf("  Objective:    %s\n", ui.Success.Sprint(autopentObjective))

			if autopentAIProvider != "" {
				fmt.Printf("  AI Provider:  %s\n", ui.Success.Sprint(autopentAIProvider))
			} else {
				fmt.Printf("  AI Provider:  %s\n", ui.Success.Sprint("auto (Claude → DeepSeek → OpenAI)"))
			}

			if autopentSessionID != "" {
				fmt.Printf("  Session ID:   %s\n", ui.Success.Sprint(autopentSessionID))
			}

			// Show operation mode
			if autopentAutonomous {
				fmt.Printf("  Mode:         %s\n", ui.Warning.Sprint("AUTONOMOUS (AI decides all)"))
				fmt.Println()
				fmt.Println(ui.WarningMsg("⚠️  AUTONOMOUS MODE ENABLED"))
				fmt.Println("   The AI will make ALL decisions without prompting.")
				fmt.Println("   Only critical safety gates will interrupt execution.")
				fmt.Println()
			} else {
				fmt.Printf("  Mode:         %s\n", ui.Success.Sprint("Interactive (user approves)"))
			}

			fmt.Println()

			// Check if Python AI engine is available
			fmt.Println(ui.InfoMsg("Checking Dependencies"))
			if err := checkAutoPentDependencies(); err != nil {
				return fmt.Errorf("dependency check failed: %w", err)
			}
			fmt.Println(ui.SuccessMsg("  ✓ Python AI engine available"))
			fmt.Println(ui.SuccessMsg("  ✓ Autonomous orchestrator available"))
			fmt.Println()

			// Execute autonomous attack path
			return executeAutoPent(target, autopentObjective, autopentAIProvider, autopentSessionID, autopentSaveSession, autopentAutonomous)
		},
	}

	cmd.Flags().StringVarP(&autopentObjective, "objective", "o", "", "Attack objective (e.g., 'reach database server', 'obtain domain admin')")
	cmd.Flags().StringVar(&autopentAIProvider, "ai-provider", "", "AI provider to use (claude, deepseek, openai, etc.)")
	cmd.Flags().StringVar(&autopentResume, "resume", "", "Resume a saved session by ID")
	cmd.Flags().BoolVar(&autopentListSessions, "list-sessions", false, "List all saved sessions")
	cmd.Flags().BoolVar(&autopentSaveSession, "save", false, "Save session on completion")
	cmd.Flags().StringVar(&autopentSessionID, "session-id", "", "Custom session ID")
	cmd.Flags().BoolVar(&autopentAutonomous, "autonomous", false, "Full autonomous mode - AI makes all decisions without prompting")

	return cmd
}

func getPythonPath() string {
	// Try venv Python first (preferred)
	projectRoot := getProjectRoot()
	venvPython := filepath.Join(projectRoot, "zypheron-ai", ".venv", "bin", "python3")

	if _, err := os.Stat(venvPython); err == nil {
		return venvPython
	}

	// Fallback to system Python
	return "python3"
}

func checkAutoPentDependencies() error {
	// Check if Python is available
	pythonPath := getPythonPath()
	pythonCmd := exec.Command(pythonPath, "--version")
	if err := pythonCmd.Run(); err != nil {
		return fmt.Errorf("python3 not found: %w", err)
	}

	// Check if autonomous orchestrator module exists
	projectRoot := getProjectRoot()
	orchestratorPath := filepath.Join(projectRoot, "zypheron-ai", "autopent", "autonomous_orchestrator.py")

	if _, err := os.Stat(orchestratorPath); os.IsNotExist(err) {
		return fmt.Errorf("autonomous orchestrator not found at: %s", orchestratorPath)
	}

	return nil
}

func executeAutoPent(target, objective, aiProvider, sessionID string, saveSession, autonomous bool) error {
	fmt.Println(ui.InfoMsg("Launching Autonomous Attack Path Engine"))

	// SECURITY: Validate inputs before passing to Python script
	if err := validation.ValidateTarget(target); err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	// Validate objective doesn't contain shell metacharacters
	if validation.ContainsShellMetachars(objective) {
		return fmt.Errorf("objective contains invalid characters (shell metacharacters not allowed)")
	}

	// Build Python script path
	projectRoot := getProjectRoot()
	runnerScript := filepath.Join(projectRoot, "zypheron-ai", "autopent", "run_autopent.py")

	// Check if runner exists, if not create it
	if _, err := os.Stat(runnerScript); os.IsNotExist(err) {
		if err := createAutoPentRunner(runnerScript); err != nil {
			return fmt.Errorf("failed to create autopent runner: %w", err)
		}
	}

	// Build command
	args := []string{runnerScript, "--target", target, "--objective", objective}

	if aiProvider != "" {
		args = append(args, "--ai-provider", aiProvider)
	}

	if sessionID != "" {
		args = append(args, "--session-id", sessionID)
	}

	if saveSession {
		args = append(args, "--save")
	}

	if autonomous {
		args = append(args, "--autonomous")
	}

	// Execute Python script with streaming output (use venv Python)
	pythonPath := getPythonPath()
	pythonCmd := exec.Command(pythonPath, args...)
	pythonCmd.Dir = filepath.Join(projectRoot, "zypheron-ai")
	pythonCmd.Stdout = os.Stdout
	pythonCmd.Stderr = os.Stderr
	pythonCmd.Stdin = os.Stdin // For interactive prompts

	// Set environment
	pythonCmd.Env = append(os.Environ(),
		"PYTHONUNBUFFERED=1", // Disable Python output buffering
	)

	fmt.Println("🚀 Starting autonomous execution...")
	fmt.Println("   (You will be prompted for approvals)")

	if err := pythonCmd.Run(); err != nil {
		return fmt.Errorf("autopent execution failed: %w", err)
	}

	return nil
}

func listAutoPentSessions() error {
	fmt.Println(ui.InfoMsg("Saved Sessions"))

	projectRoot := getProjectRoot()
	runnerScript := filepath.Join(projectRoot, "zypheron-ai", "autopent", "run_autopent.py")

	// Check if runner exists
	if _, err := os.Stat(runnerScript); os.IsNotExist(err) {
		if err := createAutoPentRunner(runnerScript); err != nil {
			return fmt.Errorf("failed to create autopent runner: %w", err)
		}
	}

	// Execute list command (use venv Python)
	pythonPath := getPythonPath()
	pythonCmd := exec.Command(pythonPath, runnerScript, "--list")
	pythonCmd.Dir = filepath.Join(projectRoot, "zypheron-ai")
	pythonCmd.Stdout = os.Stdout
	pythonCmd.Stderr = os.Stderr

	return pythonCmd.Run()
}

func resumeAutoPentSession(sessionID string) error {
	fmt.Println(ui.InfoMsg(fmt.Sprintf("Resuming Session: %s", sessionID)))

	projectRoot := getProjectRoot()
	runnerScript := filepath.Join(projectRoot, "zypheron-ai", "autopent", "run_autopent.py")

	// Execute resume command (use venv Python)
	pythonPath := getPythonPath()
	pythonCmd := exec.Command(pythonPath, runnerScript, "--resume", sessionID)
	pythonCmd.Dir = filepath.Join(projectRoot, "zypheron-ai")
	pythonCmd.Stdout = os.Stdout
	pythonCmd.Stderr = os.Stderr
	pythonCmd.Stdin = os.Stdin

	pythonCmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")

	return pythonCmd.Run()
}

func createAutoPentRunner(scriptPath string) error {
	// Create the Python runner script
	runnerContent := `#!/usr/bin/env python3
"""
Autonomous Penetration Testing Runner

CLI wrapper for the autonomous attack path orchestrator.
Called by the Go CLI: zypheron autopent
"""

import asyncio
import argparse
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from autopent.autonomous_orchestrator import AutonomousOrchestrator
from autopent.session_state import SessionStateManager


def main():
    parser = argparse.ArgumentParser(description="Autonomous Attack Path Execution")
    parser.add_argument("--target", help="Initial target")
    parser.add_argument("--objective", help="Attack objective")
    parser.add_argument("--ai-provider", help="AI provider to use")
    parser.add_argument("--session-id", help="Custom session ID")
    parser.add_argument("--save", action="store_true", help="Save session on completion")
    parser.add_argument("--resume", help="Resume session by ID")
    parser.add_argument("--list", action="store_true", help="List saved sessions")
    parser.add_argument("--autonomous", action="store_true", help="Full autonomous mode - AI decides all")

    args = parser.parse_args()

    # Handle list sessions
    if args.list:
        list_sessions()
        return

    # Handle resume
    if args.resume:
        resume_session(args.resume)
        return

    # Validate required args for new session
    if not args.target or not args.objective:
        print("Error: --target and --objective are required", file=sys.stderr)
        sys.exit(1)

    # Run new session
    asyncio.run(run_autopent(
        target=args.target,
        objective=args.objective,
        ai_provider=args.ai_provider,
        session_id=args.session_id,
        save=args.save,
        autonomous=args.autonomous
    ))


async def run_autopent(target, objective, ai_provider, session_id, save, autonomous=False):
    """Run autonomous attack path execution"""
    orchestrator = None
    try:
        # Create orchestrator
        orchestrator = AutonomousOrchestrator(
            objective=objective,
            initial_target=target,
            session_id=session_id,
            autonomous_mode=autonomous
        )

        # Show mode banner
        if autonomous:
            print("\n" + "="*60)
            print("🤖 AUTONOMOUS MODE - AI will make all decisions")
            print("   Press Ctrl+C at any time to interrupt")
            print("="*60 + "\n")

        # Execute
        results = await orchestrator.execute()

        # Save if requested
        if save or results['status'] == 'completed':
            orchestrator.save_session()
            print(f"\n💾 Session saved: {orchestrator.session_id}")
            print(f"   Resume with: zypheron autopent --resume {orchestrator.session_id}")

        # Print final status
        print(f"\n✓ Execution completed: {results['status']}")
        sys.exit(0 if results['status'] == 'completed' else 1)

    except KeyboardInterrupt:
        print("\n⚠️  Execution interrupted")
        if orchestrator:
            orchestrator.save_session()
            print(f"💾 Session saved: {orchestrator.session_id}")
        sys.exit(130)

    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


def list_sessions():
    """List all saved sessions"""
    state_mgr = SessionStateManager()
    sessions = state_mgr.list_sessions()

    if not sessions:
        print("\nNo saved sessions found.")
        return

    print(state_mgr.format_session_list(sessions))


def resume_session(session_id):
    """Resume a saved session - continue from checkpoint with credentials"""
    state_mgr = SessionStateManager()

    # Load session metadata first
    metadata = state_mgr.get_session_metadata(session_id)
    if not metadata:
        print(f"❌ Session not found: {session_id}")
        sys.exit(1)

    print(f"\n📂 Loading session: {session_id}")
    print(f"   Objective: {metadata.objective}")
    print(f"   Target: {metadata.initial_target}")
    print(f"   Progress: {metadata.completed_steps}/{metadata.total_steps} steps")
    print(f"   Status: {metadata.status}")
    print()

    # Load full session data
    session_data = state_mgr.resume_session(session_id)
    if not session_data:
        print(f"❌ Failed to load session data")
        sys.exit(1)

    attack_graph_data, credentials_data, approvals_data, additional = session_data

    # Show credential summary
    if credentials_data.get('vault'):
        cred_count = len(credentials_data['vault'])
        print(f"🔑 Loaded {cred_count} discovered credentials")
        for cred in credentials_data['vault'][:5]:  # Show first 5
            cred_type = cred.get('cred_type', 'unknown')
            target = cred.get('target', 'unknown')
            print(f"   - {cred_type} for {target}")
        if cred_count > 5:
            print(f"   ... and {cred_count - 5} more")
        print()

    # Run resume
    asyncio.run(run_resume(
        session_id=session_id,
        metadata=metadata,
        attack_graph_data=attack_graph_data,
        credentials_data=credentials_data,
        approvals_data=approvals_data,
        additional=additional
    ))


async def run_resume(session_id, metadata, attack_graph_data, credentials_data, approvals_data, additional):
    """Execute resume of a paused session"""
    orchestrator = None
    try:
        from autopent.attack_path_graph import AttackPathGraph
        from autopent.credential_vault import CredentialVault
        from autopent.approval_manager import ApprovalManager

        # Reconstruct components from saved state
        print("🔄 Reconstructing attack graph...")
        attack_graph = AttackPathGraph.from_dict(attack_graph_data)

        print("🔄 Restoring credential vault...")
        credential_vault = CredentialVault()
        credential_vault.restore_from_dict(credentials_data)

        print("🔄 Restoring approval state...")
        approval_manager = ApprovalManager()
        approval_manager.restore_from_dict(approvals_data)

        # Create orchestrator with restored state
        print("🔄 Creating orchestrator from checkpoint...")
        orchestrator = AutonomousOrchestrator(
            objective=metadata.objective,
            initial_target=metadata.initial_target,
            session_id=session_id,
            attack_graph=attack_graph,
            credential_vault=credential_vault,
            approval_manager=approval_manager,
            resume_mode=True
        )

        # Validate credentials before continuing
        print("\n🔍 Validating previously discovered credentials...")
        valid_count = await orchestrator.validate_credentials()
        print(f"   ✓ {valid_count} credentials still valid\n")

        # Continue execution from checkpoint
        print("▶️  Resuming execution from checkpoint...")
        print("=" * 60)

        results = await orchestrator.execute()

        # Save updated session
        orchestrator.save_session()
        print(f"\n💾 Session updated: {session_id}")

        # Print final status
        print(f"\n✓ Execution completed: {results['status']}")
        sys.exit(0 if results['status'] == 'completed' else 1)

    except KeyboardInterrupt:
        print("\n⚠️  Execution interrupted")
        if orchestrator:
            orchestrator.save_session()
            print(f"💾 Session saved: {session_id}")
        sys.exit(130)

    except Exception as e:
        print(f"\n❌ Resume failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
`

	return os.WriteFile(scriptPath, []byte(runnerContent), 0755)
}

func getProjectRoot() string {
	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
		// Fallback to current directory
		cwd, _ := os.Getwd()
		return filepath.Dir(cwd)
	}

	// Assume executable is in zypheron-go/ or zypheron-go/build/
	exeDir := filepath.Dir(exePath)

	// Check if we're in build directory
	if filepath.Base(exeDir) == "build" {
		exeDir = filepath.Dir(exeDir) // Go up one level
	}

	// Go up one more level to project root
	return filepath.Dir(exeDir)
}
