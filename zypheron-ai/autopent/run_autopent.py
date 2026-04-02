#!/usr/bin/env python3
"""Autonomous Penetration Testing Runner.

CLI wrapper for the autonomous attack path orchestrator.
Called by the Go CLI: zypheron autopent
"""

import argparse
import asyncio
import os
import sys

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

    if args.list:
        list_sessions()
        return
    if args.resume:
        resume_session(args.resume)
        return
    if not args.target or not args.objective:
        print("Error: --target and --objective are required", file=sys.stderr)
        sys.exit(1)

    asyncio.run(
        run_autopent(
            target=args.target,
            objective=args.objective,
            session_id=args.session_id,
            save=args.save,
            autonomous=args.autonomous,
        )
    )


async def run_autopent(target, objective, session_id, save, autonomous=False):
    orchestrator = None
    try:
        orchestrator = AutonomousOrchestrator(
            objective=objective,
            initial_target=target,
            session_id=session_id,
            autonomous_mode=autonomous,
        )

        if autonomous:
            print("\n" + "=" * 60)
            print("AUTONOMOUS MODE - AI will make all decisions")
            print("Press Ctrl+C at any time to interrupt")
            print("=" * 60 + "\n")

        results = await orchestrator.execute()

        if save or results["status"] == "completed":
            orchestrator.save_session()
            print(f"\nSession saved: {orchestrator.session_id}")
            print(f"Resume with: zypheron autopent --resume {orchestrator.session_id}")

        print(f"\nExecution completed: {results['status']}")
        sys.exit(0 if results["status"] == "completed" else 1)
    except KeyboardInterrupt:
        print("\nExecution interrupted")
        if orchestrator:
            orchestrator.save_session()
            print(f"Session saved: {orchestrator.session_id}")
        sys.exit(130)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)


def list_sessions():
    state_mgr = SessionStateManager()
    sessions = state_mgr.list_sessions()
    if not sessions:
        print("\nNo saved sessions found.")
        return
    print(state_mgr.format_session_list(sessions))


def resume_session(session_id):
    state_mgr = SessionStateManager()
    metadata = state_mgr.get_session_metadata(session_id)
    if not metadata:
        print(f"Session not found: {session_id}")
        sys.exit(1)

    print(f"\nLoading session: {session_id}")
    print(f"  Objective: {metadata.objective}")
    print(f"  Target: {metadata.initial_target}")
    print(f"  Progress: {metadata.completed_steps}/{metadata.total_steps} steps")
    print(f"  Status: {metadata.status}")
    print()

    session_data = state_mgr.resume_session(session_id)
    if not session_data:
        print("Failed to load session data")
        sys.exit(1)

    attack_graph_data, credentials_data, approvals_data, additional = session_data
    asyncio.run(
        run_resume(
            session_id=session_id,
            metadata=metadata,
            attack_graph_data=attack_graph_data,
            credentials_data=credentials_data,
            approvals_data=approvals_data,
            additional=additional,
        )
    )


async def run_resume(session_id, metadata, attack_graph_data, credentials_data, approvals_data, additional):
    orchestrator = None
    try:
        from autopent.approval_manager import ApprovalManager
        from autopent.attack_path_graph import AttackPathGraph
        from autopent.credential_vault import CredentialVault

        attack_graph = AttackPathGraph.from_dict(attack_graph_data)
        credential_vault = CredentialVault()
        credential_vault.restore_from_dict(credentials_data)
        approval_manager = ApprovalManager()
        approval_manager.restore_from_dict(approvals_data)

        orchestrator = AutonomousOrchestrator(
            objective=metadata.objective,
            initial_target=metadata.initial_target,
            session_id=session_id,
            attack_graph=attack_graph,
            credential_vault=credential_vault,
            approval_manager=approval_manager,
            resume_mode=True,
        )
        results = await orchestrator.execute()
        print(f"\nExecution completed: {results['status']}")
        sys.exit(0 if results["status"] == "completed" else 1)
    except KeyboardInterrupt:
        print("\nExecution interrupted")
        if orchestrator:
            orchestrator.save_session()
        sys.exit(130)


if __name__ == "__main__":
    main()
