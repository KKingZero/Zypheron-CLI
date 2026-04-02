"""Regression tests for autopent runtime control flow."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from autopent.approval_manager import ApprovalDecision
from autopent.attack_path_graph import GraphEdge
from autopent.autonomous_orchestrator import AutonomousOrchestrator, OrchestratorStatus
from contracts.runtime import RiskCategory
from tasks.store import TaskStore


class TestAutopentRuntime:
    """Verify autopent approval and status behavior."""

    @pytest.mark.asyncio
    async def test_phase_execution_without_viable_path_fails(self, tmp_path):
        orchestrator = AutonomousOrchestrator(
            objective="reach database",
            initial_target="127.0.0.1",
            session_id="test-no-path",
        )
        orchestrator.task_store = TaskStore(str(tmp_path / "runtime.db"))
        orchestrator.attack_graph.get_optimal_path_to_objective = MagicMock(return_value=[])

        status = await orchestrator._phase_execution()

        assert status == OrchestratorStatus.FAILED

    @pytest.mark.asyncio
    async def test_non_tty_action_approval_times_out_to_abort(self, tmp_path):
        orchestrator = AutonomousOrchestrator(
            objective="obtain admin",
            initial_target="127.0.0.1",
            session_id="test-timeout",
        )
        orchestrator.task_store = TaskStore(str(tmp_path / "runtime.db"))
        request = SimpleNamespace(action_id="approval-1")
        orchestrator._wait_for_external_approval = AsyncMock(return_value=None)

        with patch("sys.stdin.isatty", return_value=False):
            decision = await orchestrator._resolve_action_approval(request)

        assert decision == ApprovalDecision.ABORT

    @pytest.mark.asyncio
    async def test_shared_tool_approve_session_persists(self, tmp_path):
        orchestrator = AutonomousOrchestrator(
            objective="obtain admin",
            initial_target="127.0.0.1",
            session_id="test-shared-session",
        )
        orchestrator.task_store = TaskStore(str(tmp_path / "runtime.db"))
        edge = GraphEdge(
            edge_id="edge-1",
            source_id="src",
            target_id="http://127.0.0.1/login",
            technique="T1190",
            tool="sqlmap",
            description="Exploit SQL Injection in login form",
            complexity="medium",
            detection_likelihood="high",
            success_probability=0.5,
        )
        approval_request = SimpleNamespace(
            risk_category=RiskCategory.HIGH,
        )
        policy_decision = SimpleNamespace(
            requires_approval=True,
            reason="shared tool approval required",
            approval_request=approval_request,
        )
        orchestrator._resolve_action_approval = AsyncMock(return_value=ApprovalDecision.APPROVE_SESSION)

        allowed, granted = await orchestrator._ensure_shared_tool_authorized(
            edge,
            policy_decision=policy_decision,
        )

        assert allowed is True
        assert granted is True
        assert orchestrator.task_store.has_session_approval(orchestrator.session_id, "sqlmap_scan")
