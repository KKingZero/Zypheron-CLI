"""Tests for the unified query engine."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from contracts.runtime import PolicyMode, RiskCategory, ToolResult, ToolSpec
from core.query_engine import QueryEngine, QueryRequest
from providers.base import AIMessage, AIResponse
from providers.manager import normalize_provider_name
from tasks.store import TaskStore


class TestQueryEngine:
    """Verify query-engine chat and tool behavior."""

    @pytest.mark.asyncio
    async def test_tool_routed_provider_query(self, tmp_path):
        """Provider questions should resolve through the typed tool registry."""
        engine = QueryEngine(task_store=TaskStore(str(tmp_path / "runtime.db")))
        request = QueryRequest(
            messages=[AIMessage(role="user", content="What configured providers do I have?")],
            policy_mode=PolicyMode.INTERACTIVE_SAFE,
        )

        with patch("tools.registry.list_configured_providers", return_value=["anthropic", "openai"]):
            response = await engine.execute(request)

        assert response.provider == "zypheron-query-engine"
        assert response.task_status.value == "completed"
        assert response.tool_results
        assert response.tool_results[0].tool_name == "list_configured_providers"
        assert "anthropic" in response.content

    @pytest.mark.asyncio
    async def test_chat_falls_back_to_ai_manager(self, tmp_path):
        """General chat should use the provider manager through the query engine."""
        engine = QueryEngine(task_store=TaskStore(str(tmp_path / "runtime.db")))
        request = QueryRequest(
            messages=[AIMessage(role="user", content="Explain SQL injection at a high level.")],
            provider="anthropic",
        )

        mock_response = AIResponse(
            content="SQL injection is a class of input-handling vulnerability.",
            provider="claude",
            model="claude-sonnet-test",
            tokens_used=42,
        )

        with patch("core.query_engine.ai_manager.chat", new=AsyncMock(return_value=mock_response)) as mock_chat:
            response = await engine.execute(request)

        mock_chat.assert_awaited_once()
        assert response.provider == "claude"
        assert response.model == "claude-sonnet-test"
        assert response.content.startswith("SQL injection")

    @pytest.mark.asyncio
    async def test_submit_approval_resumes_pending_tool(self, tmp_path):
        """Approval decisions should resume a waiting tool call."""
        engine = QueryEngine(task_store=TaskStore(str(tmp_path / "runtime.db")))
        session_id = "test-session"
        engine.task_store.set_session_scope(session_id, ["example.com"])
        request = QueryRequest(
            messages=[AIMessage(role="user", content="run nmap scan against example.com")],
            policy_mode=PolicyMode.INTERACTIVE_SAFE,
            session_id=session_id,
        )
        mock_tool = MagicMock()
        mock_tool.spec = ToolSpec(
            name="nmap_scan",
            description="scan",
            risk_category=RiskCategory.MEDIUM,
            requires_approval=True,
            read_only=True,
        )
        mock_tool.execute = AsyncMock(
            return_value=ToolResult(
                tool_name="nmap_scan",
                success=True,
                content="open ports: 80,443",
                data={"ports": [80, 443]},
            )
        )

        with patch("core.query_engine.tool_registry.get", return_value=mock_tool):
            pending = await engine.execute(request)
            resumed = await engine.submit_approval(
                task_id=pending.task_id,
                request_id=pending.approval_request.request_id,
                decision="approve_once",
            )

        assert pending.task_status.value == "waiting_approval"
        assert resumed.task_status.value == "completed"
        assert resumed.tool_results[0].tool_name == "nmap_scan"
        mock_tool.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_web_prompt_executes_multiple_real_tools(self, tmp_path):
        """Web-app prompts should compose multiple shared-tool executions."""
        engine = QueryEngine(task_store=TaskStore(str(tmp_path / "runtime.db")))
        session_id = "web-session"
        engine.task_store.set_session_scope(session_id, ["example.com"])
        request = QueryRequest(
            messages=[AIMessage(role="user", content="scan https://example.com for web vulnerabilities and fuzz directories")],
            policy_mode=PolicyMode.AUTONOMOUS_LAB,
            session_id=session_id,
        )

        tools = {}
        for name in ("httpx_probe", "ffuf_scan", "nuclei_scan", "nikto_scan"):
            mock_tool = MagicMock()
            mock_tool.spec = ToolSpec(
                name=name,
                description="scan",
                risk_category=RiskCategory.MEDIUM,
                requires_approval=True,
                read_only=True,
            )
            async def execute_side_effect(arguments, context, tool_name=name):
                target = arguments.get("target") or arguments.get("url")
                return ToolResult(
                    tool_name=tool_name,
                    success=True,
                    content=f"{tool_name} ok for {target}",
                    data={},
                )

            mock_tool.execute = AsyncMock(side_effect=execute_side_effect)
            tools[name] = mock_tool

        with patch("core.query_engine.tool_registry.get", side_effect=lambda name: tools.get(name)):
            response = await engine.execute(request)

        assert response.task_status.value == "completed"
        assert [result.tool_name for result in response.tool_results] == ["httpx_probe", "ffuf_scan", "nuclei_scan", "nikto_scan"]

    @pytest.mark.asyncio
    async def test_authenticated_prompt_without_session_requests_follow_up(self, tmp_path):
        """Authenticated testing must stop and ask for a session id when missing."""
        engine = QueryEngine(task_store=TaskStore(str(tmp_path / "runtime.db")))
        request = QueryRequest(
            messages=[AIMessage(role="user", content="run authenticated IDOR checks on https://example.com/api/users/1")],
            policy_mode=PolicyMode.INTERACTIVE_SAFE,
        )

        response = await engine.execute(request)

        assert response.task_status.value == "paused"
        assert "session_id" in response.content

    @pytest.mark.asyncio
    async def test_submit_approval_marks_failed_on_tool_exception(self, tmp_path):
        """Resumed tool exceptions should fail the task instead of stranding it."""
        store = TaskStore(str(tmp_path / "runtime.db"))
        engine = QueryEngine(task_store=store)
        session_id = "exception-session"
        store.set_session_scope(session_id, ["example.com"])
        request = QueryRequest(
            messages=[AIMessage(role="user", content="run nmap scan against example.com")],
            policy_mode=PolicyMode.INTERACTIVE_SAFE,
            session_id=session_id,
        )
        mock_tool = MagicMock()
        mock_tool.spec = ToolSpec(
            name="nmap_scan",
            description="scan",
            risk_category=RiskCategory.MEDIUM,
            requires_approval=True,
            read_only=True,
        )
        mock_tool.execute = AsyncMock(side_effect=RuntimeError("boom"))

        with patch("core.query_engine.tool_registry.get", return_value=mock_tool):
            pending = await engine.execute(request)
            with pytest.raises(RuntimeError, match="boom"):
                await engine.submit_approval(
                    task_id=pending.task_id,
                    request_id=pending.approval_request.request_id,
                    decision="approve_once",
                )

        task = store.get_task(pending.task_id)
        assert task is not None
        assert task.status.value == "failed"

    @pytest.mark.asyncio
    async def test_failed_tool_result_marks_task_failed(self, tmp_path):
        """ToolResult(success=False) should persist a failed task state."""
        engine = QueryEngine(task_store=TaskStore(str(tmp_path / "runtime.db")))
        session_id = "failed-session"
        engine.task_store.set_session_scope(session_id, ["example.com"])
        request = QueryRequest(
            messages=[AIMessage(role="user", content="run nmap scan against example.com")],
            policy_mode=PolicyMode.INTERACTIVE_SAFE,
            session_id=session_id,
        )
        mock_tool = MagicMock()
        mock_tool.spec = ToolSpec(
            name="nmap_scan",
            description="scan",
            risk_category=RiskCategory.MEDIUM,
            requires_approval=True,
            read_only=True,
        )
        mock_tool.execute = AsyncMock(
            return_value=ToolResult(
                tool_name="nmap_scan",
                success=False,
                content="",
                error="scan failed",
            )
        )

        with patch("core.query_engine.tool_registry.get", return_value=mock_tool):
            pending = await engine.execute(request)
            resumed = await engine.submit_approval(
                task_id=pending.task_id,
                request_id=pending.approval_request.request_id,
                decision="approve_once",
            )

        assert resumed.task_status.value == "failed"

    @pytest.mark.asyncio
    async def test_approve_session_persists_across_engine_restart(self, tmp_path):
        """Session approvals should survive a query-engine restart."""
        db_path = str(tmp_path / "runtime.db")
        request = QueryRequest(
            messages=[AIMessage(role="user", content="run nmap scan against example.com")],
            policy_mode=PolicyMode.INTERACTIVE_SAFE,
            session_id="session-1",
        )
        mock_tool = MagicMock()
        mock_tool.spec = ToolSpec(
            name="nmap_scan",
            description="scan",
            risk_category=RiskCategory.MEDIUM,
            requires_approval=True,
            read_only=True,
        )
        mock_tool.execute = AsyncMock(
            return_value=ToolResult(
                tool_name="nmap_scan",
                success=True,
                content="done",
            )
        )

        store = TaskStore(db_path)
        store.set_session_scope("session-1", ["example.com"])
        engine = QueryEngine(task_store=store)
        with patch("core.query_engine.tool_registry.get", return_value=mock_tool):
            pending = await engine.execute(request)
            await engine.submit_approval(
                task_id=pending.task_id,
                request_id=pending.approval_request.request_id,
                decision="approve_session",
            )

        restarted = QueryEngine(task_store=TaskStore(db_path))
        with patch("core.query_engine.tool_registry.get", return_value=mock_tool):
            response = await restarted.execute(request)

        assert response.task_status.value == "completed"
        assert response.approval_request is None

    def test_provider_alias_normalization(self):
        """Anthropic should normalize to the internal Claude provider name."""
        assert normalize_provider_name("anthropic") == "claude"
