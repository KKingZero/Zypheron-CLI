"""Tests for MCP shared-tool adapter behavior."""

from unittest.mock import AsyncMock, MagicMock, patch

from contracts.runtime import RiskCategory, ToolResult, ToolSpec
from mcp_interface.tools import ZypheronToolExecutor


class TestMCPSharedTools:
    """Ensure MCP prefers the shared registry where available."""

    def test_execute_shared_tool_runs_registry_tool(self):
        executor = ZypheronToolExecutor()
        mock_tool = MagicMock()
        mock_tool.spec = ToolSpec(
            name="list_available_providers",
            description="providers",
            risk_category=RiskCategory.LOW,
            requires_approval=False,
            read_only=True,
        )
        mock_tool.execute = AsyncMock(
            return_value=ToolResult(
                tool_name="list_available_providers",
                success=True,
                content="claude, openai",
                data={"providers": ["claude", "openai"]},
            )
        )

        with patch("mcp_interface.tools.tool_registry.get", return_value=mock_tool):
            result = executor.execute_shared_tool("list_available_providers", {})

        assert result is not None
        assert result["success"] is True
        assert result["shared"] is True
        assert "claude" in result["stdout"]

    def test_execute_shared_tool_returns_none_when_missing(self):
        executor = ZypheronToolExecutor()

        with patch("mcp_interface.tools.tool_registry.get", return_value=None):
            result = executor.execute_shared_tool("missing_tool", {})

        assert result is None

    def test_execute_shared_tool_requires_approval_before_running(self):
        executor = ZypheronToolExecutor()
        mock_tool = MagicMock()
        mock_tool.spec = ToolSpec(
            name="nmap_scan",
            description="scan",
            risk_category=RiskCategory.MEDIUM,
            requires_approval=True,
            read_only=True,
        )
        mock_tool.execute = AsyncMock()

        with patch("mcp_interface.tools.tool_registry.get", return_value=mock_tool):
            result = executor.execute_shared_tool("nmap_scan", {"target": "example.com"})

        assert result is not None
        assert result["success"] is False
        assert result["approval_required"] is True
        mock_tool.execute.assert_not_called()
