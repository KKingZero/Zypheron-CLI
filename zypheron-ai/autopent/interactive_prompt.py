"""
Interactive CLI Prompts - User interaction for decisions

Terminal-based prompts for user approval and decision making
"""

import sys
from typing import List, Optional, Dict, Any
from enum import Enum

from .approval_manager import ApprovalRequest, ApprovalDecision
from .credential_vault import CredentialUseRequest
from .ai_decision_engine import AIDecision


class PromptColors:
    """ANSI color codes for terminal"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # Colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

    # Backgrounds
    BG_RED = '\033[101m'
    BG_GREEN = '\033[102m'
    BG_YELLOW = '\033[103m'


class InteractivePrompt:
    """
    Interactive CLI prompts for user decisions

    Provides:
    - Approval prompts (with "allow for this session" option)
    - Credential use prompts
    - Error decision prompts
    - Path selection prompts
    """

    @staticmethod
    def prompt_for_approval(request: ApprovalRequest) -> ApprovalDecision:
        """
        Prompt user for approval of an action

        Args:
            request: ApprovalRequest to display

        Returns:
            User's ApprovalDecision
        """
        from .approval_manager import ApprovalManager

        # Display the request
        print(ApprovalManager().format_approval_request(request))

        # Show options
        print(f"\n{PromptColors.BOLD}Choose an option:{PromptColors.RESET}")
        print(f"  {PromptColors.GREEN}[1]{PromptColors.RESET} Approve (this action only)")
        print(f"  {PromptColors.CYAN}[2]{PromptColors.RESET} Approve for this session (all {request.category.value} actions)")
        print(f"  {PromptColors.YELLOW}[3]{PromptColors.RESET} Deny (skip this action)")
        print(f"  {PromptColors.RED}[4]{PromptColors.RESET} Abort (stop entire operation)")

        while True:
            try:
                choice = input(f"\n{PromptColors.BOLD}Your choice [1-4]:{PromptColors.RESET} ").strip()

                if choice == '1':
                    print(f"{PromptColors.GREEN}✓ Action approved{PromptColors.RESET}")
                    return ApprovalDecision.APPROVE_ONCE

                elif choice == '2':
                    print(f"{PromptColors.CYAN}✓ Approved for this session{PromptColors.RESET}")
                    return ApprovalDecision.APPROVE_SESSION

                elif choice == '3':
                    print(f"{PromptColors.YELLOW}✗ Action denied{PromptColors.RESET}")
                    return ApprovalDecision.DENY

                elif choice == '4':
                    confirm = input(
                        f"{PromptColors.RED}⚠️  Are you sure you want to ABORT? [y/N]:{PromptColors.RESET} "
                    ).strip().lower()
                    if confirm == 'y':
                        print(f"{PromptColors.RED}⚠️  Operation aborted by user{PromptColors.RESET}")
                        return ApprovalDecision.ABORT
                    else:
                        continue

                else:
                    print(f"{PromptColors.RED}Invalid choice. Please enter 1-4.{PromptColors.RESET}")

            except (KeyboardInterrupt, EOFError):
                print(f"\n{PromptColors.YELLOW}Operation interrupted by user{PromptColors.RESET}")
                return ApprovalDecision.ABORT

    @staticmethod
    def prompt_for_credential_use(
        request: CredentialUseRequest,
        vault: Any  # CredentialVault instance
    ) -> bool:
        """
        Prompt user for permission to use a credential

        Args:
            request: CredentialUseRequest
            vault: CredentialVault instance

        Returns:
            True if approved, False otherwise
        """
        # Display the request
        print(vault.format_use_request(request))

        # Show options
        print(f"\n{PromptColors.BOLD}Use this credential?{PromptColors.RESET}")
        print(f"  {PromptColors.GREEN}[Y]{PromptColors.RESET} Yes, use it")
        print(f"  {PromptColors.RED}[N]{PromptColors.RESET} No, skip")
        print(f"  {PromptColors.CYAN}[A]{PromptColors.RESET} Auto-approve this credential for this session")

        while True:
            try:
                choice = input(f"\n{PromptColors.BOLD}Your choice [Y/N/A]:{PromptColors.RESET} ").strip().lower()

                if choice in ['y', 'yes', '']:
                    print(f"{PromptColors.GREEN}✓ Credential approved for use{PromptColors.RESET}")
                    return True

                elif choice in ['n', 'no']:
                    print(f"{PromptColors.YELLOW}✗ Credential use denied{PromptColors.RESET}")
                    return False

                elif choice in ['a', 'auto']:
                    vault.session_auto_approve.add(request.cred_id)
                    print(f"{PromptColors.CYAN}✓ Credential auto-approved for this session{PromptColors.RESET}")
                    return True

                else:
                    print(f"{PromptColors.RED}Invalid choice. Please enter Y, N, or A.{PromptColors.RESET}")

            except (KeyboardInterrupt, EOFError):
                print(f"\n{PromptColors.YELLOW}Credential use denied (interrupted){PromptColors.RESET}")
                return False

    @staticmethod
    def prompt_for_error_decision(
        error: str,
        ai_decision: AIDecision,
        alternatives: List[str]
    ) -> str:
        """
        Prompt user for decision after an error

        Args:
            error: Error message
            ai_decision: AI's recommended decision
            alternatives: Alternative actions

        Returns:
            User's chosen action
        """
        print(f"\n{PromptColors.BG_RED}{PromptColors.WHITE} ERROR {PromptColors.RESET}")
        print(f"{PromptColors.RED}╔{'═'*68}╗{PromptColors.RESET}")
        print(f"{PromptColors.RED}║{PromptColors.RESET} {error[:66]:<66} {PromptColors.RED}║{PromptColors.RESET}")
        print(f"{PromptColors.RED}╚{'═'*68}╝{PromptColors.RESET}")

        # Show AI recommendation
        print(f"\n{PromptColors.CYAN}🤖 AI Recommendation:{PromptColors.RESET}")
        print(f"   {ai_decision.recommendation}")
        print(f"\n{PromptColors.DIM}Reasoning:{PromptColors.RESET}")
        print(f"   {ai_decision.reasoning}")
        print(f"\n{PromptColors.DIM}Confidence: {ai_decision.confidence:.0%}{PromptColors.RESET}")

        # Show alternatives
        print(f"\n{PromptColors.BOLD}Available Options:{PromptColors.RESET}")
        options = [ai_decision.recommendation] + alternatives
        for i, option in enumerate(options[:5], 1):  # Limit to 5 options
            marker = "★" if i == 1 else " "
            print(f"  {PromptColors.CYAN}[{i}]{PromptColors.RESET} {marker} {option}")

        print(f"  {PromptColors.RED}[A]{PromptColors.RESET} Abort operation")

        while True:
            try:
                choice = input(f"\n{PromptColors.BOLD}Your choice [1-{len(options)}/A]:{PromptColors.RESET} ").strip().lower()

                if choice in ['a', 'abort']:
                    confirm = input(
                        f"{PromptColors.RED}Abort entire operation? [y/N]:{PromptColors.RESET} "
                    ).strip().lower()
                    if confirm == 'y':
                        return "abort"
                    continue

                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(options):
                        selected = options[idx]
                        print(f"{PromptColors.GREEN}✓ Selected: {selected}{PromptColors.RESET}")
                        return selected
                    else:
                        print(f"{PromptColors.RED}Invalid choice.{PromptColors.RESET}")
                except ValueError:
                    print(f"{PromptColors.RED}Please enter a number or 'A'.{PromptColors.RESET}")

            except (KeyboardInterrupt, EOFError):
                print(f"\n{PromptColors.YELLOW}Operation aborted{PromptColors.RESET}")
                return "abort"

    @staticmethod
    def prompt_for_path_selection(
        objective: str,
        paths: List[List[str]],
        optimal_path_idx: int = 0
    ) -> int:
        """
        Prompt user to select an attack path

        Args:
            objective: Attack objective
            paths: List of available paths (each path is list of step descriptions)
            optimal_path_idx: Index of AI-recommended optimal path

        Returns:
            Index of selected path
        """
        print(f"\n{PromptColors.BOLD}{'='*70}{PromptColors.RESET}")
        print(f"{PromptColors.BOLD}ATTACK PATH SELECTION{PromptColors.RESET}")
        print(f"{PromptColors.BOLD}{'='*70}{PromptColors.RESET}")

        print(f"\n🎯 Objective: {objective}")
        print(f"\n📋 {len(paths)} attack paths found:\n")

        for i, path in enumerate(paths[:5], 1):  # Show top 5 paths
            marker = "★" if i - 1 == optimal_path_idx else " "
            label = " (AI Recommended)" if i - 1 == optimal_path_idx else ""

            print(f"{PromptColors.CYAN}[{i}]{PromptColors.RESET} {marker} Path {i}{PromptColors.YELLOW}{label}{PromptColors.RESET}")
            print(f"     Steps: {len(path)}")

            # Show first few steps
            for j, step in enumerate(path[:3], 1):
                print(f"      {j}. {step[:60]}")
            if len(path) > 3:
                print(f"      ... and {len(path) - 3} more steps")

            print()

        while True:
            try:
                choice = input(
                    f"{PromptColors.BOLD}Select path [1-{min(5, len(paths))}] "
                    f"(Enter for recommended):{PromptColors.RESET} "
                ).strip()

                if choice == '':
                    print(f"{PromptColors.GREEN}✓ Using AI-recommended path{PromptColors.RESET}")
                    return optimal_path_idx

                try:
                    idx = int(choice) - 1
                    if 0 <= idx < min(5, len(paths)):
                        print(f"{PromptColors.GREEN}✓ Path {idx + 1} selected{PromptColors.RESET}")
                        return idx
                    else:
                        print(f"{PromptColors.RED}Invalid choice.{PromptColors.RESET}")
                except ValueError:
                    print(f"{PromptColors.RED}Please enter a number.{PromptColors.RESET}")

            except (KeyboardInterrupt, EOFError):
                print(f"\n{PromptColors.YELLOW}Using default (recommended) path{PromptColors.RESET}")
                return optimal_path_idx

    @staticmethod
    def display_progress(
        current_step: int,
        total_steps: int,
        description: str,
        status: str = "running"
    ):
        """
        Display progress of current operation

        Args:
            current_step: Current step number
            total_steps: Total number of steps
            description: Description of current step
            status: Status (running, success, failed)
        """
        status_emoji = {
            'running': '⚡',
            'success': '✓',
            'failed': '✗',
            'pending': '○',
        }.get(status, '○')

        status_color = {
            'running': PromptColors.CYAN,
            'success': PromptColors.GREEN,
            'failed': PromptColors.RED,
            'pending': PromptColors.DIM,
        }.get(status, PromptColors.WHITE)

        progress_pct = (current_step / total_steps) * 100 if total_steps > 0 else 0

        print(
            f"{status_color}{status_emoji} [{current_step}/{total_steps}] "
            f"({progress_pct:.0f}%) {description}{PromptColors.RESET}"
        )

    @staticmethod
    def display_banner(text: str):
        """Display a banner message"""
        print(f"\n{PromptColors.BOLD}{PromptColors.CYAN}{'='*70}{PromptColors.RESET}")
        print(f"{PromptColors.BOLD}{PromptColors.CYAN}{text:^70}{PromptColors.RESET}")
        print(f"{PromptColors.BOLD}{PromptColors.CYAN}{'='*70}{PromptColors.RESET}\n")

    @staticmethod
    def display_summary(title: str, items: Dict[str, Any]):
        """Display a summary table"""
        print(f"\n{PromptColors.BOLD}{title}{PromptColors.RESET}")
        print(f"{PromptColors.DIM}{'─'*70}{PromptColors.RESET}")

        for key, value in items.items():
            print(f"  {key:.<30} {value}")

        print(f"{PromptColors.DIM}{'─'*70}{PromptColors.RESET}\n")
