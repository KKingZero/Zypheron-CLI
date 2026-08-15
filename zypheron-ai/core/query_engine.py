"""Unified Python-owned query engine for Zypheron chat and tool turns."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Any, Dict, List, Optional
from uuid import uuid4

from loguru import logger

from contracts.runtime import AuditEvent, PolicyMode, QueryResponse, RiskCategory, TaskRecord, TaskStatus, ToolCall, ToolProgressEvent
from core.mcp_client_config import load_selected_mcp_servers, unsupported_mcp_client_message
from core.policy import authorize_tool_call
from core.scope import normalize_scope_host, scope_match
from providers.base import AIMessage
from providers.capabilities import EFFORT_CAPABLE_PROVIDERS, validate_effort
from providers.manager import ai_manager, normalize_provider_name
from tasks.store import TaskStore
from tools.base import ExecutionContext
from tools.registry import tool_registry

_TARGET_ARG_KEYS = ("target", "url", "domain", "host")
_SCOPE_GATED_RISK = {RiskCategory.MEDIUM, RiskCategory.HIGH, RiskCategory.CRITICAL}


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
    effort: Optional[str] = None
    mcp_config: Optional[str] = None
    mcp: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class PlanOutcome:
    """Planning output for a single user turn."""

    tool_calls: List[ToolCall]
    follow_up: Optional[str] = None


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

        plan = self._plan_tool_calls(
            latest_user.content if latest_user else "",
            latest_user.metadata if latest_user else None,
        )

        try:
            if request.mcp:
                servers = load_selected_mcp_servers(request.mcp_config or "~/.config/zypheron/mcp.json", request.mcp)
                raise NotImplementedError(unsupported_mcp_client_message(servers))

            if plan.follow_up:
                task.status = TaskStatus.PAUSED
                task.metadata["follow_up"] = plan.follow_up
                self.task_store.upsert_task(task)
                return QueryResponse(
                    content=plan.follow_up,
                    provider="zypheron-query-engine",
                    model=request.model or "runtime-policy",
                    session_id=session_id,
                    task_id=task_id,
                    task_status=task.status,
                )

            if plan.tool_calls:
                return await self._execute_tool_calls(
                    task=task,
                    tool_calls=plan.tool_calls,
                    policy_mode=request.policy_mode,
                    provider_model=request.model,
                )

            provider = normalize_provider_name(request.provider)
            model = request.model
            if request.effort and provider not in EFFORT_CAPABLE_PROVIDERS:
                raise ValueError(f"effort is not supported with provider {provider}")
            provider_kwargs: Dict[str, Any] = {"model": model}
            if request.effort:
                provider_kwargs["effort"] = validate_effort(provider, request.effort)
            ai_response = await ai_manager.chat(
                messages=request.messages,
                provider=provider,
                temperature=request.temperature,
                max_tokens=request.max_tokens,
                **provider_kwargs,
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

        tool_calls = self._deserialize_tool_calls(task.metadata.get("pending_tool_calls") or [])
        tool_index = int(task.metadata.get("pending_tool_call_index", 0))
        if tool_index >= len(tool_calls):
            raise ValueError("Pending tool sequence is missing or corrupt")
        tool_call = tool_calls[tool_index]
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
            self._clear_pending_task_metadata(task)
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
            completed_results = self._deserialize_tool_results(claimed_task.metadata.get("completed_tool_results") or [])
            return await self._execute_tool_calls(
                task=claimed_task,
                tool_calls=tool_calls,
                policy_mode=PolicyMode(policy_mode),
                provider_model="tool-runtime",
                start_index=tool_index,
                approval_granted_index=tool_index,
                completed_results=completed_results,
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

    def _plan_tool_calls(self, text: str, metadata: Optional[Dict[str, Any]] = None) -> PlanOutcome:
        query = (text or "").strip()
        lowered = query.lower()
        if not lowered:
            return PlanOutcome(tool_calls=[])

        if lowered.startswith("remember ") or lowered.startswith("remember that "):
            value = query.split(" ", 1)[1].strip() if " " in query else query
            return PlanOutcome(
                tool_calls=[
                    ToolCall(
                        tool_name="store_memory",
                        arguments={
                            "key": f"note_{uuid4().hex[:8]}",
                            "value": value,
                            "tier": "session",
                        },
                        rationale="User explicitly asked Zypheron to remember information.",
                    )
                ]
            )

        if "what do you remember" in lowered or lowered.startswith("recall "):
            search_query = query
            for prefix in ("what do you remember about", "recall", "remember"):
                if lowered.startswith(prefix):
                    search_query = query[len(prefix):].strip() or query
                    break
            return PlanOutcome(
                tool_calls=[
                    ToolCall(
                        tool_name="search_memory",
                        arguments={"query": search_query, "limit": 5},
                        rationale="User asked to retrieve stored memory.",
                    )
                ]
            )

        if "configured provider" in lowered or "configured providers" in lowered:
            return PlanOutcome(
                tool_calls=[
                    ToolCall(
                        tool_name="list_configured_providers",
                        arguments={},
                        rationale="User asked which providers are configured.",
                    )
                ]
            )

        if "available provider" in lowered or "available providers" in lowered:
            return PlanOutcome(
                tool_calls=[
                    ToolCall(
                        tool_name="list_available_providers",
                        arguments={},
                        rationale="User asked which providers are available.",
                    )
                ]
            )

        if "what providers" in lowered and "config" in lowered:
            return PlanOutcome(
                tool_calls=[
                    ToolCall(
                        tool_name="list_configured_providers",
                        arguments={},
                        rationale="Provider configuration question matched configured providers tool.",
                    )
                ]
            )

        if "what providers" in lowered:
            return PlanOutcome(
                tool_calls=[
                    ToolCall(
                        tool_name="list_available_providers",
                        arguments={},
                        rationale="Provider availability question matched provider listing tool.",
                    )
                ]
            )

        target = self._extract_target(query)
        if target:
            auth_plan = self._plan_authenticated_scan(query, lowered, target, metadata or {})
            if auth_plan is not None:
                return auth_plan

            explicit_calls = self._plan_explicit_tool_calls(lowered, target)
            if explicit_calls:
                return PlanOutcome(tool_calls=explicit_calls)

            web_calls = self._plan_web_tool_calls(query, lowered, target)
            if web_calls:
                return PlanOutcome(tool_calls=web_calls)

        return PlanOutcome(tool_calls=[])

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
        evidence = tool_result.data.get("evidence", {})
        summary = evidence.get("summary")
        if summary:
            return summary
        return tool_result.content

    def _extract_target(self, text: str) -> Optional[str]:
        """Extract a simple URL/hostname/IP token from the user request."""
        match = re.search(r"(https?://[^\s]+|[A-Za-z0-9._-]+\.[A-Za-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})", text)
        if match:
            return match.group(1).rstrip(".,)")
        return None

    def _plan_authenticated_scan(
        self,
        query: str,
        lowered: str,
        target: str,
        metadata: Dict[str, Any],
    ) -> Optional[PlanOutcome]:
        auth_keywords = ("authenticated", "session", "cookie", "idor", "bola", "bfla", "authorization", "privilege")
        if not any(keyword in lowered for keyword in auth_keywords):
            return None

        session_id = self._extract_session_id(query, metadata)
        if not session_id:
            return PlanOutcome(
                tool_calls=[],
                follow_up=(
                    "Authenticated testing needs a stored `session_id`. "
                    "Provide one in the request metadata or include `session_id=<value>` in the prompt."
                ),
            )

        if "sql injection" in lowered or "sqli" in lowered:
            scan_type = "sql_injection"
        elif "idor" in lowered or "bola" in lowered:
            scan_type = "idor"
        else:
            scan_type = "broken_authorization"

        arguments: Dict[str, Any] = {
            "scan_type": scan_type,
            "session_id": session_id,
            "url": target,
            "method": str(metadata.get("method", "GET")).upper(),
            "data": metadata.get("data", ""),
            "headers": metadata.get("headers", {}),
            "required_role": metadata.get("required_role", "admin"),
            "actual_role": metadata.get("actual_role", "user"),
            "target_user_id": metadata.get("target_user_id"),
        }
        return PlanOutcome(
            tool_calls=[
                ToolCall(
                    tool_name="authenticated_web_scan",
                    arguments=arguments,
                    rationale=f"User requested authenticated {scan_type.replace('_', ' ')} testing.",
                )
            ]
        )

    def _plan_explicit_tool_calls(self, lowered: str, target: str) -> List[ToolCall]:
        calls: List[ToolCall] = []
        if "nmap" in lowered:
            calls.append(ToolCall("nmap_scan", {"target": target, "scan_type": "-sV"}, "User explicitly requested an nmap scan."))
        if "amass" in lowered:
            calls.append(ToolCall("amass_enum", {"domain": target, "mode": "enum"}, "User explicitly requested amass enumeration."))
        if "subfinder" in lowered:
            calls.append(ToolCall("subfinder_scan", {"domain": target, "silent": True, "all_sources": False}, "User explicitly requested subfinder enumeration."))
        if "gobuster" in lowered:
            calls.append(ToolCall("gobuster_scan", {"url": target, "mode": "dir", "wordlist": "/usr/share/wordlists/dirb/common.txt"}, "User explicitly requested gobuster enumeration."))
        if "httpx" in lowered:
            calls.append(ToolCall("httpx_probe", {"target": target, "probe": True, "tech_detect": True, "status_code": True, "threads": 50}, "User explicitly requested httpx probing."))
        if "ffuf" in lowered:
            calls.append(ToolCall("ffuf_scan", {"url": target, "wordlist": "/usr/share/wordlists/dirb/common.txt", "mode": "directory"}, "User explicitly requested ffuf enumeration."))
        if "nuclei" in lowered:
            calls.append(ToolCall("nuclei_scan", {"target": target}, "User explicitly requested nuclei scanning."))
        if "nikto" in lowered:
            calls.append(ToolCall("nikto_scan", {"target": target}, "User explicitly requested nikto scanning."))
        if "sqlmap" in lowered:
            calls.append(ToolCall("sqlmap_scan", {"url": target}, "User explicitly requested sqlmap scanning."))
        return calls

    def _plan_web_tool_calls(self, query: str, lowered: str, target: str) -> List[ToolCall]:
        looks_like_web = target.startswith("http://") or target.startswith("https://") or any(
            keyword in lowered for keyword in ("web", "url", "site", "endpoint", "api", "directory", "vuln", "vulnerability", "scan", "recon", "fuzz")
        )
        if not looks_like_web:
            return []

        calls: List[ToolCall] = [
            ToolCall(
                "httpx_probe",
                {"target": target, "probe": True, "tech_detect": True, "status_code": True, "threads": 50},
                "Probe the target and fingerprint the web stack before deeper testing.",
            )
        ]

        if any(keyword in lowered for keyword in ("fuzz", "directory", "content discovery", "paths", "dirbust")):
            calls.append(
                ToolCall(
                    "ffuf_scan",
                    {"url": target, "wordlist": "/usr/share/wordlists/dirb/common.txt", "mode": "directory"},
                    "User requested content discovery or directory fuzzing.",
                )
            )

        if any(keyword in lowered for keyword in ("subdomain", "subdomains", "recon")) and not target.startswith("http"):
            calls.insert(0, ToolCall("subfinder_scan", {"domain": target, "silent": True, "all_sources": False}, "Enumerate subdomains before probing the target."))

        if any(keyword in lowered for keyword in ("vuln", "vulnerability", "scan", "check", "test")):
            calls.append(ToolCall("nuclei_scan", {"target": target}, "Run template-based web vulnerability checks."))
            calls.append(ToolCall("nikto_scan", {"target": target}, "Run signature-based web server checks."))

        if any(keyword in lowered for keyword in ("sql injection", "sqli", "database")):
            calls.append(ToolCall("sqlmap_scan", {"url": target}, "Validate SQL injection exposure against the target URL."))

        deduped: List[ToolCall] = []
        seen = set()
        for call in calls:
            fingerprint = (call.tool_name, tuple(sorted(call.arguments.items())))
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            deduped.append(call)
        return deduped

    def _extract_session_id(self, text: str, metadata: Dict[str, Any]) -> Optional[str]:
        for key in ("session_id", "auth_session_id"):
            value = metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        match = re.search(r"session(?:_id)?\s*[:=]\s*([A-Za-z0-9._-]+)", text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    async def _execute_tool_calls(
        self,
        task: TaskRecord,
        tool_calls: List[ToolCall],
        policy_mode: PolicyMode,
        provider_model: Optional[str],
        start_index: int = 0,
        approval_granted_index: Optional[int] = None,
        completed_results: Optional[List[Any]] = None,
    ) -> QueryResponse:
        """Execute one or more tool calls and persist the runtime state."""
        task.status = TaskStatus.RUNNING
        self.task_store.upsert_task(task)

        progress_events: List[ToolProgressEvent] = []
        results = list(completed_results or [])

        for index in range(start_index, len(tool_calls)):
            tool_call = tool_calls[index]
            tool = tool_registry.get(tool_call.tool_name)
            if tool is None:
                raise ValueError(f"Unknown tool: {tool_call.tool_name}")

            scope_block_reason = self._scope_block_reason(task.session_id, tool, tool_call)
            if scope_block_reason is not None:
                task.status = TaskStatus.FAILED
                task.metadata["error"] = scope_block_reason
                self._clear_pending_task_metadata(task)
                self.task_store.upsert_task(task)
                self.task_store.append_event(
                    AuditEvent(
                        task_id=task.task_id,
                        event_type="scope_blocked",
                        payload={
                            "tool_name": tool.spec.name,
                            "reason": scope_block_reason,
                            "arguments": tool_call.arguments,
                        },
                    )
                )
                return QueryResponse(
                    content=scope_block_reason,
                    provider="zypheron-query-engine",
                    model=provider_model or "tool-runtime",
                    session_id=task.session_id,
                    task_id=task.task_id,
                    task_status=task.status,
                    tool_results=results,
                    progress_events=progress_events,
                )

            approval_granted = index == approval_granted_index or self.task_store.has_session_approval(task.session_id, tool.spec.name)
            decision = authorize_tool_call(
                tool_spec=tool.spec,
                policy_mode=policy_mode,
                reason=tool_call.rationale or f"query engine selected {tool_call.tool_name}",
                arguments=tool_call.arguments,
                approval_granted=approval_granted,
            )
            if decision.requires_approval and decision.approval_request is not None:
                task.status = TaskStatus.WAITING_APPROVAL
                task.metadata.update({
                    "pending_tool_calls": self._serialize_tool_calls(tool_calls),
                    "pending_tool_call_index": index,
                    "completed_tool_results": [asdict(result) for result in results],
                    "pending_approval_request": decision.approval_request.to_dict(),
                    "policy_mode": policy_mode.value,
                })
                self.task_store.upsert_task(task)
                self.task_store.append_event(
                    AuditEvent(
                        task_id=task.task_id,
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
                        f"I need approval before running `{tool.spec.name}` "
                        f"({index + 1}/{len(tool_calls)}) in {policy_mode.value} mode."
                    ),
                    provider="zypheron-query-engine",
                    model=provider_model or "runtime-policy",
                    session_id=task.session_id,
                    task_id=task.task_id,
                    task_status=task.status,
                    tool_results=results,
                    progress_events=progress_events,
                    approval_request=decision.approval_request,
                )

            tool_result, new_events = await self._run_tool_call(
                task=task,
                tool_call=tool_call,
                policy_mode=policy_mode,
                approval_granted=approval_granted,
            )
            results.append(tool_result)
            progress_events.extend(new_events)
            if not tool_result.success:
                task.status = TaskStatus.FAILED
                task.metadata["error"] = tool_result.error or tool_result.content
                self._clear_pending_task_metadata(task)
                self.task_store.upsert_task(task)
                return QueryResponse(
                    content=self._render_tool_sequence(results),
                    provider="zypheron-query-engine",
                    model=provider_model or "tool-runtime",
                    session_id=task.session_id,
                    task_id=task.task_id,
                    task_status=task.status,
                    tool_results=results,
                    progress_events=progress_events,
                )

        task.status = TaskStatus.COMPLETED
        self._clear_pending_task_metadata(task)
        self.task_store.upsert_task(task)
        return QueryResponse(
            content=self._render_tool_sequence(results),
            provider="zypheron-query-engine",
            model=provider_model or "tool-runtime",
            session_id=task.session_id,
            task_id=task.task_id,
            task_status=task.status,
            tool_results=results,
            progress_events=progress_events,
        )

    async def _run_tool_call(
        self,
        task: TaskRecord,
        tool_call: ToolCall,
        policy_mode: PolicyMode,
        approval_granted: bool = False,
    ) -> tuple[Any, List[ToolProgressEvent]]:
        tool = tool_registry.get(tool_call.tool_name)
        if tool is None:
            raise ValueError(f"Unknown tool: {tool_call.tool_name}")

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
        tool_result = self._annotate_tool_result(tool_result, tool_call)
        progress_events.append(
            ToolProgressEvent(
                task_id=task.task_id,
                tool_name=tool.spec.name,
                status="completed" if tool_result.success else "failed",
                message=f"Completed {tool.spec.name}" if tool_result.success else f"Failed {tool.spec.name}",
            )
        )
        self.task_store.append_event(
            AuditEvent(
                task_id=task.task_id,
                event_type="tool_executed" if tool_result.success else "tool_failed",
                payload={"tool_name": tool.spec.name, "success": tool_result.success},
            )
        )
        return tool_result, progress_events

    def _annotate_tool_result(self, tool_result, tool_call: ToolCall):
        data = dict(tool_result.data or {})
        evidence = {
            "tool": tool_result.tool_name,
            "target": tool_call.arguments.get("target") or tool_call.arguments.get("url") or tool_call.arguments.get("domain", ""),
            "summary": tool_result.content.strip() or tool_result.error or "",
            "findings": self._extract_findings(tool_result),
        }
        data["evidence"] = evidence
        tool_result.data = data
        return tool_result

    def _extract_findings(self, tool_result) -> List[Dict[str, Any]]:
        if tool_result.tool_name == "authenticated_web_scan":
            return tool_result.data.get("findings", [])

        findings: List[Dict[str, Any]] = []
        for raw_line in tool_result.content.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if tool_result.tool_name == "nuclei_scan":
                findings.append({"title": line, "severity": self._infer_severity(line), "evidence": line})
            elif tool_result.tool_name == "nikto_scan" and line.startswith("+"):
                findings.append({"title": line[1:].strip(), "severity": "medium", "evidence": line})
            elif tool_result.tool_name == "sqlmap_scan" and ("sql injection" in line.lower() or "is vulnerable" in line.lower()):
                findings.append({"title": line, "severity": "high", "evidence": line})
        return findings

    def _infer_severity(self, text: str) -> str:
        lowered = text.lower()
        for severity in ("critical", "high", "medium", "low", "info"):
            if severity in lowered:
                return severity
        return "medium"

    def _render_tool_sequence(self, tool_results: List[Any]) -> str:
        rendered = [self._render_tool_response(result) for result in tool_results if self._render_tool_response(result)]
        return "\n\n".join(rendered)

    def _scope_block_reason(self, session_id: str, tool, tool_call: ToolCall) -> Optional[str]:
        """Return a block-reason string if the tool call violates session scope."""
        if tool.spec.risk_category not in _SCOPE_GATED_RISK:
            return None

        target_value: Optional[str] = None
        for key in _TARGET_ARG_KEYS:
            value = tool_call.arguments.get(key)
            if isinstance(value, str) and value.strip():
                target_value = value.strip()
                break
        if target_value is None:
            return None

        scope_entries = self.task_store.get_session_scope(session_id)
        if not scope_entries:
            return (
                f"Refusing to run `{tool.spec.name}` (risk={tool.spec.risk_category.value}) "
                "because no in-scope hosts are configured for this session. "
                "Set scope first (e.g. via /scope add <host>)."
            )

        target_host = normalize_scope_host(target_value)
        if not target_host:
            return f"Refusing to run `{tool.spec.name}`: unable to parse host from {target_value!r}."

        if not scope_match(target_value, scope_entries):
            return (
                f"Refusing to run `{tool.spec.name}` against {target_host}: "
                f"target is outside session scope ({', '.join(sorted(scope_entries))})."
            )
        return None

    def _serialize_tool_calls(self, tool_calls: List[ToolCall]) -> List[Dict[str, Any]]:
        return [asdict(tool_call) for tool_call in tool_calls]

    def _deserialize_tool_calls(self, data: List[Dict[str, Any]]) -> List[ToolCall]:
        return [ToolCall(**item) for item in data]

    def _deserialize_tool_results(self, data: List[Dict[str, Any]]) -> List[Any]:
        from contracts.runtime import ToolResult
        return [ToolResult(**item) for item in data]

    def _clear_pending_task_metadata(self, task: TaskRecord) -> None:
        for key in (
            "pending_tool_calls",
            "pending_tool_call_index",
            "completed_tool_results",
            "pending_approval_request",
            "approval_claimed",
            "follow_up",
        ):
            task.metadata.pop(key, None)


query_engine = QueryEngine()
