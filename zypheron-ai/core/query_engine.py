"""Unified Python-owned query engine for Zypheron chat and tool turns."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Dict, List, Optional
from uuid import uuid4

from loguru import logger

from contracts.runtime import (
    AuditEvent,
    PolicyMode,
    QueryResponse,
    TaskRecord,
    TaskStatus,
    ToolCall,
    ToolProgressEvent,
    ApprovalRequest,
)
from core.policy import authorize_tool_call
from providers.base import AIMessage
from providers.manager import ai_manager, normalize_provider_name
from tasks.store import TaskStore
from tools.base import ExecutionContext
from tools.registry import tool_registry


@dataclass
class QueryRequest:
    """Inputs accepted by the query engine."""

    messages: List[AIMessage]
    provider: Optional[str] = None
    model: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 4096
    session_id: Optional[str] = None
    task_id: Optional[str] = None
    policy_mode: PolicyMode = PolicyMode.INTERACTIVE_SAFE


class QueryEngine:
    """Owns chat turns, simple tool planning, policy, and task persistence."""

    def __init__(self, task_store: Optional[TaskStore] = None):
        self.task_store = task_store or TaskStore()
        self.task_store.recover_claimed_approvals()

    async def execute(self, request: QueryRequest) -> QueryResponse:
        """Execute a single query-engine turn."""
        session_id = request.session_id or f"session-{uuid4().hex[:12]}"
        task_id = request.task_id or f"task-{uuid4().hex[:12]}"
        latest_user = self._latest_user_message(request.messages)
        input_summary = latest_user.content[:200] if latest_user else "chat turn"

        task = TaskRecord(
            task_id=task_id,
            kind="chat_turn",
            status=TaskStatus.QUEUED,
            session_id=session_id,
            input_summary=input_summary,
            provider=normalize_provider_name(request.provider),
            model=request.model or "",
        )
        self.task_store.upsert_task(task)
        self.task_store.append_event(AuditEvent(task_id=task_id, event_type="task_queued"))

        task.status = TaskStatus.RUNNING
        self.task_store.upsert_task(task)
        self.task_store.append_event(AuditEvent(task_id=task_id, event_type="task_running"))

        tool_call = self._plan_tool_call(latest_user.content if latest_user else "")

        try:
            if tool_call:
                tool = tool_registry.get(tool_call.tool_name)
                if tool is not None:
                    approval_granted = self.task_store.has_session_approval(session_id, tool.spec.name)
                    decision = authorize_tool_call(
                        tool_spec=tool.spec,
                        policy_mode=request.policy_mode,
                        reason=tool_call.rationale or f"query engine selected {tool_call.tool_name}",
                        arguments=tool_call.arguments,
                        approval_granted=approval_granted,
                    )
                    if decision.requires_approval and decision.approval_request is not None:
                        task.status = TaskStatus.WAITING_APPROVAL
                        task.metadata.update({
                            "pending_tool_call": {
                                "tool_name": tool_call.tool_name,
                                "arguments": tool_call.arguments,
                                "rationale": tool_call.rationale,
                            },
                            "pending_approval_request": decision.approval_request.to_dict(),
                            "policy_mode": request.policy_mode.value,
                        })
                        self.task_store.upsert_task(task)
                        self.task_store.append_event(
                            AuditEvent(
                                task_id=task_id,
                                event_type="approval_required",
                                payload={
                                    "tool_name": tool.spec.name,
                                    "reason": decision.reason,
                                    "risk_category": tool.spec.risk_category.value,
                                    "request_id": decision.approval_request.request_id,
                                    "arguments": tool_call.arguments,
                                },
                            )
                        )
                        return QueryResponse(
                            content=(
                                f"The requested action needs approval before I can run "
                                f"`{tool.spec.name}` in {request.policy_mode.value} mode."
                            ),
                            provider="zypheron-query-engine",
                            model=request.model or "runtime-policy",
                            session_id=session_id,
                            task_id=task_id,
                            task_status=task.status,
                            approval_request=decision.approval_request,
                        )

                    if decision.allowed:
                        return await self._execute_tool_call(
                            task=task,
                            tool_call=tool_call,
                            policy_mode=request.policy_mode,
                            provider_model=request.model,
                        )

            provider = normalize_provider_name(request.provider)
            model = request.model
            ai_response = await ai_manager.chat(
                messages=request.messages,
                provider=provider,
                temperature=request.temperature,
                max_tokens=request.max_tokens,
                model=model,
            )
            task.provider = ai_response.provider
            task.model = ai_response.model
            task.status = TaskStatus.COMPLETED
            self.task_store.upsert_task(task)
            self.task_store.append_event(
                AuditEvent(
                    task_id=task_id,
                    event_type="assistant_response",
                    payload={
                        "provider": ai_response.provider,
                        "model": ai_response.model,
                    },
                )
            )
            return QueryResponse(
                content=ai_response.content,
                provider=ai_response.provider,
                model=ai_response.model,
                tokens_used=ai_response.tokens_used,
                session_id=session_id,
                task_id=task_id,
                task_status=task.status,
                progress_events=[],
            )
        except Exception as exc:
            logger.error(f"Query engine turn failed: {exc}")
            task.status = TaskStatus.FAILED
            task.metadata["error"] = str(exc)
            self.task_store.upsert_task(task)
            self.task_store.append_event(
                AuditEvent(
                    task_id=task_id,
                    event_type="task_failed",
                    payload={"error": str(exc)},
                )
            )
            raise

    async def submit_approval(
        self,
        task_id: str,
        request_id: str,
        decision: str,
    ) -> QueryResponse:
        """Resume or deny a waiting approval-gated task."""
        normalized_decision = (decision or "").strip().lower()
        if normalized_decision not in {"approve_once", "approve_session", "deny"}:
            raise ValueError(f"Unsupported approval decision: {decision}")

        task = self.task_store.get_task(task_id)
        if task is None:
            raise ValueError(f"Task not found: {task_id}")

        pending_request = task.metadata.get("pending_approval_request") or {}
        if pending_request.get("request_id") != request_id:
            raise ValueError("Approval request id does not match pending task")

        tool_call_data = task.metadata.get("pending_tool_call") or {}
        tool_call = ToolCall(
            tool_name=tool_call_data.get("tool_name", ""),
            arguments=tool_call_data.get("arguments", {}),
            rationale=tool_call_data.get("rationale", ""),
        )
        policy_mode = task.metadata.get("policy_mode", PolicyMode.INTERACTIVE_SAFE.value)

        self.task_store.append_event(
            AuditEvent(
                task_id=task_id,
                event_type="approval_decision",
                payload={
                    "request_id": request_id,
                    "decision": normalized_decision,
                },
            )
        )

        if normalized_decision == "deny":
            task.status = TaskStatus.ABORTED
            task.metadata.pop("pending_tool_call", None)
            task.metadata.pop("pending_approval_request", None)
            task.metadata.pop("approval_claimed", None)
            self.task_store.upsert_task(task)
            return QueryResponse(
                content=f"Denied `{tool_call.tool_name}`. The pending runtime action was not executed.",
                provider="zypheron-query-engine",
                model="runtime-policy",
                session_id=task.session_id,
                task_id=task.task_id,
                task_status=task.status,
            )

        if normalized_decision == "approve_session":
            self.task_store.add_session_approval(task.session_id, tool_call.tool_name)

        claimed_task = self.task_store.claim_pending_approval(task_id, request_id)
        try:
            return await self._execute_tool_call(
                task=claimed_task,
                tool_call=tool_call,
                policy_mode=PolicyMode(policy_mode),
                provider_model="tool-runtime",
                approval_granted=True,
            )
        except Exception as exc:
            logger.error(f"Approval-resumed tool execution failed: {exc}")
            claimed_task.status = TaskStatus.FAILED
            claimed_task.metadata["error"] = str(exc)
            claimed_task.metadata.pop("approval_claimed", None)
            self.task_store.upsert_task(claimed_task)
            self.task_store.append_event(
                AuditEvent(
                    task_id=task_id,
                    event_type="task_failed",
                    payload={"error": str(exc)},
                )
            )
            raise

    def _latest_user_message(self, messages: List[AIMessage]) -> Optional[AIMessage]:
        for message in reversed(messages):
            if message.role == "user":
                return message
        return messages[-1] if messages else None

    def _plan_tool_call(self, text: str) -> Optional[ToolCall]:
        query = (text or "").strip()
        lowered = query.lower()
        if not lowered:
            return None

        if lowered.startswith("remember ") or lowered.startswith("remember that "):
            value = query.split(" ", 1)[1].strip() if " " in query else query
            return ToolCall(
                tool_name="store_memory",
                arguments={
                    "key": f"note_{uuid4().hex[:8]}",
                    "value": value,
                    "tier": "session",
                },
                rationale="User explicitly asked Zypheron to remember information.",
            )

        if "what do you remember" in lowered or lowered.startswith("recall "):
            search_query = query
            for prefix in ("what do you remember about", "recall", "remember"):
                if lowered.startswith(prefix):
                    search_query = query[len(prefix):].strip() or query
                    break
            return ToolCall(
                tool_name="search_memory",
                arguments={"query": search_query, "limit": 5},
                rationale="User asked to retrieve stored memory.",
            )

        if "configured provider" in lowered or "configured providers" in lowered:
            return ToolCall(
                tool_name="list_configured_providers",
                arguments={},
                rationale="User asked which providers are configured.",
            )

        if "available provider" in lowered or "available providers" in lowered:
            return ToolCall(
                tool_name="list_available_providers",
                arguments={},
                rationale="User asked which providers are available.",
            )

        if "what providers" in lowered and "config" in lowered:
            return ToolCall(
                tool_name="list_configured_providers",
                arguments={},
                rationale="Provider configuration question matched configured providers tool.",
            )

        if "what providers" in lowered:
            return ToolCall(
                tool_name="list_available_providers",
                arguments={},
                rationale="Provider availability question matched provider listing tool.",
            )

        target = self._extract_target(query)
        if target:
            if "nmap" in lowered:
                return ToolCall(
                    tool_name="nmap_scan",
                    arguments={"target": target, "scan_type": "-sV"},
                    rationale="User explicitly requested an nmap scan.",
                )
            if "amass" in lowered:
                return ToolCall(
                    tool_name="amass_enum",
                    arguments={"domain": target, "mode": "enum"},
                    rationale="User explicitly requested amass enumeration.",
                )
            if "subfinder" in lowered:
                return ToolCall(
                    tool_name="subfinder_scan",
                    arguments={"domain": target, "silent": True, "all_sources": False},
                    rationale="User explicitly requested subfinder enumeration.",
                )
            if "gobuster" in lowered:
                return ToolCall(
                    tool_name="gobuster_scan",
                    arguments={"url": target, "mode": "dir", "wordlist": "/usr/share/wordlists/dirb/common.txt"},
                    rationale="User explicitly requested gobuster enumeration.",
                )
            if "httpx" in lowered:
                return ToolCall(
                    tool_name="httpx_probe",
                    arguments={"target": target, "probe": True, "tech_detect": True, "status_code": True, "threads": 50},
                    rationale="User explicitly requested httpx probing.",
                )
            if "ffuf" in lowered:
                return ToolCall(
                    tool_name="ffuf_scan",
                    arguments={"url": target, "wordlist": "/usr/share/wordlists/dirb/common.txt", "mode": "directory"},
                    rationale="User explicitly requested ffuf enumeration.",
                )

        return None

    def _render_tool_response(self, tool_result) -> str:
        if tool_result.tool_name == "store_memory":
            return "Stored that in Zypheron session memory."
        if tool_result.tool_name in {"list_available_providers", "list_configured_providers"}:
            providers = tool_result.data.get("providers", [])
            if providers:
                return f"{tool_result.tool_name.replace('_', ' ')}: {', '.join(providers)}"
            return tool_result.content
        if tool_result.tool_name == "search_memory":
            return tool_result.content
        return tool_result.content

    def _extract_target(self, text: str) -> Optional[str]:
        """Extract a simple URL/hostname/IP token from the user request."""
        match = re.search(r"(https?://[^\s]+|[A-Za-z0-9._-]+\.[A-Za-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})", text)
        if match:
            return match.group(1).rstrip(".,)")
        return None

    async def _execute_tool_call(
        self,
        task: TaskRecord,
        tool_call: ToolCall,
        policy_mode: PolicyMode,
        provider_model: Optional[str],
        approval_granted: bool = False,
    ) -> QueryResponse:
        """Execute a tool call and persist the runtime state."""
        tool = tool_registry.get(tool_call.tool_name)
        if tool is None:
            raise ValueError(f"Unknown tool: {tool_call.tool_name}")

        task.status = TaskStatus.RUNNING
        self.task_store.upsert_task(task)

        progress_events: List[ToolProgressEvent] = [
            ToolProgressEvent(
                task_id=task.task_id,
                tool_name=tool.spec.name,
                status="started",
                message=f"Executing {tool.spec.name}",
            )
        ]
        tool_result = await tool.execute(
            tool_call.arguments,
            ExecutionContext(
                session_id=task.session_id,
                task_id=task.task_id,
                policy_mode=policy_mode.value,
                metadata={"approval_granted": approval_granted},
            ),
        )
        progress_events.append(
            ToolProgressEvent(
                task_id=task.task_id,
                tool_name=tool.spec.name,
                status="completed" if tool_result.success else "failed",
                message=(
                    f"Completed {tool.spec.name}"
                    if tool_result.success
                    else f"Failed {tool.spec.name}"
                ),
            )
        )
        task.status = TaskStatus.COMPLETED if tool_result.success else TaskStatus.FAILED
        task.metadata.pop("pending_tool_call", None)
        task.metadata.pop("pending_approval_request", None)
        task.metadata.pop("approval_claimed", None)
        if not tool_result.success and tool_result.error:
            task.metadata["error"] = tool_result.error
        self.task_store.upsert_task(task)
        self.task_store.append_event(
            AuditEvent(
                task_id=task.task_id,
                event_type="tool_executed" if tool_result.success else "tool_failed",
                payload={
                    "tool_name": tool.spec.name,
                    "success": tool_result.success,
                },
            )
        )
        return QueryResponse(
            content=self._render_tool_response(tool_result),
            provider="zypheron-query-engine",
            model=provider_model or "tool-runtime",
            session_id=task.session_id,
            task_id=task.task_id,
            task_status=task.status,
            tool_results=[tool_result],
            progress_events=progress_events,
        )


query_engine = QueryEngine()
