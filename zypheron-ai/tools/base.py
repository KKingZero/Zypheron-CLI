"""Base types for typed query-engine tools."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict

from contracts.runtime import ToolResult, ToolSpec


@dataclass
class ExecutionContext:
    """Context passed to tool execution."""

    session_id: str
    task_id: str
    policy_mode: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseTool(ABC):
    """Base class for unified query-engine tools."""

    spec: ToolSpec

    @abstractmethod
    async def execute(
        self,
        arguments: Dict[str, Any],
        context: ExecutionContext,
    ) -> ToolResult:
        """Execute the tool and return a normalized result."""

