"""Shared runtime contracts for query execution, tools, policy, and tasks."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


def utc_now_iso() -> str:
    """Return an ISO timestamp in UTC."""
    return datetime.now(timezone.utc).isoformat()


class PolicyMode(str, Enum):
    """Global runtime policy posture."""

    INTERACTIVE_SAFE = "interactive_safe"
    GUIDED_AUTO = "guided_auto"
    AUTONOMOUS_LAB = "autonomous_lab"
    READ_ONLY = "read_only"


class RiskCategory(str, Enum):
    """Risk level attached to a tool."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(str, Enum):
    """Persistent task lifecycle."""

    QUEUED = "queued"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


@dataclass
class ToolSpec:
    """Typed description of a query-engine tool."""

    name: str
    description: str
    input_schema: Dict[str, Any] = field(default_factory=dict)
    risk_category: RiskCategory = RiskCategory.LOW
    requires_approval: bool = False
    supports_streaming: bool = False
    read_only: bool = True


@dataclass
class ToolCall:
    """A planned tool invocation."""

    tool_name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    rationale: str = ""


@dataclass
class ToolResult:
    """A normalized tool execution result."""

    tool_name: str
    success: bool
    content: str
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class ToolProgressEvent:
    """Progress event emitted during tool execution."""

    task_id: str
    tool_name: str
    status: str
    message: str
    created_at: str = field(default_factory=utc_now_iso)


@dataclass
class ApprovalRequest:
    """Approval payload for risky runtime actions."""

    tool_name: str
    reason: str
    risk_category: RiskCategory
    arguments: Dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: f"approval-{uuid4().hex[:12]}")
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the approval request to a JSON-safe dict."""
        return {
            "tool_name": self.tool_name,
            "reason": self.reason,
            "risk_category": self.risk_category.value,
            "arguments": self.arguments,
            "request_id": self.request_id,
            "created_at": self.created_at,
        }


@dataclass
class ApprovalDecision:
    """Approval decision made by the operator or policy layer."""

    approved: bool
    mode: PolicyMode
    reason: str = ""
    decided_at: str = field(default_factory=utc_now_iso)


@dataclass
class TaskRecord:
    """Durable record for a chat or workflow task."""

    task_id: str
    kind: str
    status: TaskStatus
    session_id: str
    input_summary: str
    provider: str = ""
    model: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the task record to a plain dict."""
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class AuditEvent:
    """Append-only event emitted by the query runtime."""

    task_id: str
    event_type: str
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)


@dataclass
class QueryResponse:
    """Response returned from the query engine to the IPC layer."""

    content: str
    provider: str
    model: str
    tokens_used: Optional[int] = None
    session_id: str = ""
    task_id: str = ""
    task_status: TaskStatus = TaskStatus.COMPLETED
    tool_results: List[ToolResult] = field(default_factory=list)
    progress_events: List[ToolProgressEvent] = field(default_factory=list)
    approval_request: Optional[ApprovalRequest] = None

    def to_result(self) -> Dict[str, Any]:
        """Serialize to an IPC-safe result dict."""
        return {
            "content": self.content,
            "provider": self.provider,
            "model": self.model,
            "tokens_used": self.tokens_used,
            "session_id": self.session_id,
            "task_id": self.task_id,
            "task_status": self.task_status.value,
            "tool_results": [asdict(result) for result in self.tool_results],
            "progress_events": [asdict(event) for event in self.progress_events],
            "approval_request": self.approval_request.to_dict() if self.approval_request else None,
        }
