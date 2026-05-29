"""Registry of typed query-engine tools."""

from __future__ import annotations

import shutil
import shlex
from typing import Dict, Iterable, List

from core.memory import MemoryTier, memory_manager
from core.secure_config import list_configured_providers
from providers.manager import ai_manager

from contracts.runtime import RiskCategory, ToolResult, ToolSpec
from tools.base import BaseTool, ExecutionContext
from mcp_interface.security import InputValidator, SecureCommandExecutor, CommandInjectionError


ALLOWED_NMAP_SCAN_FLAGS = {
    "-sS",
    "-sT",
    "-sU",
    "-sV",
    "-O",
    "-A",
    "-Pn",
    "-n",
}

ALLOWED_AMASS_MODES = {"enum", "intel", "track", "db"}
ALLOWED_GOBUSTER_MODES = {"dir"}
ALLOWED_FFUF_MODES = {"directory"}


def _parse_nmap_scan_type(scan_type: str) -> List[str]:
    """Allow only a narrow, explicit subset of nmap scan flags on the shared path."""
    if not scan_type.strip():
        return ["-sV"]
    flags = shlex.split(scan_type)
    if not flags:
        return ["-sV"]
    for flag in flags:
        if flag not in ALLOWED_NMAP_SCAN_FLAGS:
            raise ValueError(f"Unsupported shared nmap flag: {flag}")
    return flags


class ListAvailableProvidersTool(BaseTool):
    """Return providers currently available to the runtime."""

    spec = ToolSpec(
        name="list_available_providers",
        description="List AI providers currently available in the runtime.",
        input_schema={"type": "object", "properties": {}},
        risk_category=RiskCategory.LOW,
        requires_approval=False,
        read_only=True,
    )

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        providers = ai_manager.list_available_providers()
        return ToolResult(
            tool_name=self.spec.name,
            success=True,
            content=", ".join(providers) if providers else "No available providers.",
            data={"providers": providers},
        )


class ListConfiguredProvidersTool(BaseTool):
    """Return providers with configured credentials."""

    spec = ToolSpec(
        name="list_configured_providers",
        description="List providers that have credentials configured.",
        input_schema={"type": "object", "properties": {}},
        risk_category=RiskCategory.LOW,
        requires_approval=False,
        read_only=True,
    )

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        providers = list_configured_providers()
        return ToolResult(
            tool_name=self.spec.name,
            success=True,
            content=", ".join(providers) if providers else "No configured providers found.",
            data={"providers": providers},
        )


class StoreMemoryTool(BaseTool):
    """Persist a user note to Zypheron memory."""

    spec = ToolSpec(
        name="store_memory",
        description="Store a note in Zypheron session memory.",
        input_schema={
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "value": {"type": "string"},
                "tier": {"type": "string"},
            },
        },
        risk_category=RiskCategory.LOW,
        requires_approval=False,
        read_only=False,
    )

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        key = str(arguments.get("key", "note")).strip() or "note"
        value = str(arguments.get("value", "")).strip()
        tier_value = str(arguments.get("tier", MemoryTier.SESSION.value)).strip().lower()
        tier = MemoryTier(tier_value)
        memory_manager.store(
            tier=tier,
            context_id=context.session_id,
            key=key,
            value=value,
            metadata={"source": "query_engine", "task_id": context.task_id},
        )
        return ToolResult(
            tool_name=self.spec.name,
            success=True,
            content=f"Stored memory '{key}' in {tier.value} context.",
            data={"key": key, "tier": tier.value, "value": value},
        )


class SearchMemoryTool(BaseTool):
    """Search persisted Zypheron memory."""

    spec = ToolSpec(
        name="search_memory",
        description="Search previously stored Zypheron memory.",
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "tier": {"type": "string"},
                "limit": {"type": "integer"},
            },
        },
        risk_category=RiskCategory.LOW,
        requires_approval=False,
        read_only=True,
    )

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        query = str(arguments.get("query", "")).strip()
        tier_value = arguments.get("tier")
        tier = MemoryTier(str(tier_value).strip().lower()) if tier_value else None
        limit = int(arguments.get("limit", 5))
        matches = memory_manager.search(query=query, tier=tier, limit=limit)
        content = "No relevant memory found."
        if matches:
            rendered = []
            for match in matches:
                rendered.append(f"{match['key']}: {match['value']}")
            content = "\n".join(rendered)
        return ToolResult(
            tool_name=self.spec.name,
            success=True,
            content=content,
            data={"matches": matches},
        )


class ListSharedToolsTool(BaseTool):
    """List shared typed tools exposed by the runtime."""

    spec = ToolSpec(
        name="list_available_tools",
        description="List tools available through the shared runtime registry.",
        input_schema={"type": "object", "properties": {}},
        risk_category=RiskCategory.LOW,
        requires_approval=False,
        read_only=True,
    )

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        tools = [tool_spec.name for tool_spec in tool_registry.specs()]
        return ToolResult(
            tool_name=self.spec.name,
            success=True,
            content=", ".join(tools),
            data={
                "tools": [
                    {
                        "name": tool_spec.name,
                        "description": tool_spec.description,
                        "risk_category": tool_spec.risk_category.value,
                        "requires_approval": tool_spec.requires_approval,
                    }
                    for tool_spec in tool_registry.specs()
                ]
            },
        )


class CheckToolStatusTool(BaseTool):
    """Check availability of a local binary/tool."""

    spec = ToolSpec(
        name="check_tool_status",
        description="Check whether a local tool binary is installed and discoverable.",
        input_schema={"type": "object", "properties": {"tool_name": {"type": "string"}}},
        risk_category=RiskCategory.LOW,
        requires_approval=False,
        read_only=True,
    )

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        tool_name = str(arguments.get("tool_name", "")).strip()
        available = bool(shutil.which(tool_name))
        return ToolResult(
            tool_name=self.spec.name,
            success=True,
            content=f"{tool_name}: {'available' if available else 'not available'}",
            data={"tool": tool_name, "available": available},
        )


class NmapScanTool(BaseTool):
    """Shared nmap execution path used by MCP and future query steps."""

    spec = ToolSpec(
        name="nmap_scan",
        description="Run a validated nmap scan against a target.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "scan_type": {"type": "string"},
                "ports": {"type": "string"},
            },
        },
        risk_category=RiskCategory.MEDIUM,
        requires_approval=True,
        read_only=True,
    )

    def __init__(self):
        self.validator = InputValidator()
        self.executor = SecureCommandExecutor()

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        target = str(arguments.get("target", "")).strip()
        scan_type = str(arguments.get("scan_type", "-sV")).strip()
        ports = str(arguments.get("ports", "")).strip()

        if not self.validator.validate_target(target):
            return ToolResult(
                tool_name=self.spec.name,
                success=False,
                content="",
                error=f"Invalid target: {target}",
            )
        if ports and not self.validator.validate_port_spec(ports):
            return ToolResult(
                tool_name=self.spec.name,
                success=False,
                content="",
                error=f"Invalid port specification: {ports}",
            )
        try:
            scan_flags = _parse_nmap_scan_type(scan_type)
        except ValueError as exc:
            return ToolResult(
                tool_name=self.spec.name,
                success=False,
                content="",
                error=str(exc),
            )

        args = [target]
        args.extend(scan_flags)
        if ports:
            args.extend(["-p", ports])

        try:
            result = self.executor.execute_tool("nmap", args)
        except CommandInjectionError as exc:
            return ToolResult(
                tool_name=self.spec.name,
                success=False,
                content="",
                error=f"Security validation failed: {exc}",
            )

        return ToolResult(
            tool_name=self.spec.name,
            success=result.get("success", False),
            content=result.get("stdout", "") or result.get("stderr", ""),
            data=result,
            error=result.get("error"),
        )


class RustscanFastScanTool(BaseTool):
    """Shared rustscan execution path."""

    spec = ToolSpec(
        name="rustscan_fast_scan",
        description="Run a validated rustscan scan against a target.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "ports": {"type": "string"},
                "ulimit": {"type": "integer"},
                "batch_size": {"type": "integer"},
                "timeout": {"type": "integer"},
            },
        },
        risk_category=RiskCategory.MEDIUM,
        requires_approval=True,
        read_only=True,
    )

    def __init__(self):
        self.validator = InputValidator()
        self.executor = SecureCommandExecutor()

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        target = str(arguments.get("target", "")).strip()
        ports = str(arguments.get("ports", "")).strip()
        ulimit = int(arguments.get("ulimit", 5000))
        batch_size = int(arguments.get("batch_size", 4500))
        timeout = int(arguments.get("timeout", 1500))

        if not self.validator.validate_target(target):
            return ToolResult(
                tool_name=self.spec.name,
                success=False,
                content="",
                error=f"Invalid target: {target}",
            )
        if ports and not self.validator.validate_port_spec(ports):
            return ToolResult(
                tool_name=self.spec.name,
                success=False,
                content="",
                error=f"Invalid port specification: {ports}",
            )

        args = ["-a", target, "--ulimit", str(ulimit), "-b", str(batch_size), "-t", str(timeout)]
        if ports:
            args.extend(["-p", ports])

        try:
            result = self.executor.execute_tool("rustscan", args)
        except CommandInjectionError as exc:
            return ToolResult(
                tool_name=self.spec.name,
                success=False,
                content="",
                error=f"Security validation failed: {exc}",
            )

        return ToolResult(
            tool_name=self.spec.name,
            success=result.get("success", False),
            content=result.get("stdout", "") or result.get("stderr", ""),
            data=result,
            error=result.get("error"),
        )


class NucleiScanTool(BaseTool):
    """Shared nuclei execution path."""

    spec = ToolSpec(
        name="nuclei_scan",
        description="Run a validated nuclei scan against a target.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "severity": {"type": "string"},
                "tags": {"type": "string"},
                "template": {"type": "string"},
            },
        },
        risk_category=RiskCategory.MEDIUM,
        requires_approval=True,
        read_only=True,
    )

    def __init__(self):
        self.validator = InputValidator()
        self.executor = SecureCommandExecutor()

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        target = str(arguments.get("target", "")).strip()
        severity = str(arguments.get("severity", "")).strip()
        tags = str(arguments.get("tags", "")).strip()
        template = str(arguments.get("template", "")).strip()

        if not self.validator.validate_target(target):
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Invalid target: {target}")

        args = ["-u", target]
        if severity:
            args.extend(["-severity", severity])
        if tags:
            args.extend(["-tags", tags])
        if template:
            args.extend(["-t", template])

        try:
            result = self.executor.execute_tool("nuclei", args, timeout=600)
        except CommandInjectionError as exc:
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Security validation failed: {exc}")

        return ToolResult(
            tool_name=self.spec.name,
            success=result.get("success", False),
            content=result.get("stdout", "") or result.get("stderr", ""),
            data=result,
            error=result.get("error"),
        )


class NiktoScanTool(BaseTool):
    """Shared nikto execution path."""

    spec = ToolSpec(
        name="nikto_scan",
        description="Run a validated nikto web scan.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
            },
        },
        risk_category=RiskCategory.MEDIUM,
        requires_approval=True,
        read_only=True,
    )

    def __init__(self):
        self.validator = InputValidator()
        self.executor = SecureCommandExecutor()

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        target = str(arguments.get("target", "")).strip()
        if not self.validator.validate_target(target):
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Invalid target: {target}")

        args = ["-h", target]

        try:
            result = self.executor.execute_tool("nikto", args, timeout=600)
        except CommandInjectionError as exc:
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Security validation failed: {exc}")

        return ToolResult(
            tool_name=self.spec.name,
            success=result.get("success", False),
            content=result.get("stdout", "") or result.get("stderr", ""),
            data=result,
            error=result.get("error"),
        )


class SqlmapScanTool(BaseTool):
    """Shared sqlmap execution path."""

    spec = ToolSpec(
        name="sqlmap_scan",
        description="Run a validated sqlmap scan against a target URL.",
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "data": {"type": "string"},
            },
        },
        risk_category=RiskCategory.HIGH,
        requires_approval=True,
        read_only=False,
    )

    def __init__(self):
        self.validator = InputValidator()
        self.executor = SecureCommandExecutor()

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        url = str(arguments.get("url", "")).strip()
        data = str(arguments.get("data", "")).strip()
        if not self.validator.validate_target(url):
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Invalid target: {url}")

        args = ["-u", url, "--batch"]
        if data:
            args.extend(["--data", data])

        try:
            result = self.executor.execute_tool("sqlmap", args, timeout=900)
        except CommandInjectionError as exc:
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Security validation failed: {exc}")

        return ToolResult(
            tool_name=self.spec.name,
            success=result.get("success", False),
            content=result.get("stdout", "") or result.get("stderr", ""),
            data=result,
            error=result.get("error"),
        )


class AmassEnumTool(BaseTool):
    """Shared amass execution path for recon workflows."""

    spec = ToolSpec(
        name="amass_enum",
        description="Run validated amass enumeration against a domain.",
        input_schema={
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "mode": {"type": "string"},
            },
        },
        risk_category=RiskCategory.MEDIUM,
        requires_approval=True,
        read_only=True,
    )

    def __init__(self):
        self.validator = InputValidator()
        self.executor = SecureCommandExecutor()

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        domain = str(arguments.get("domain", "")).strip()
        mode = str(arguments.get("mode", "enum")).strip().lower()
        if not self.validator.validate_target(domain):
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Invalid domain: {domain}")
        if mode not in ALLOWED_AMASS_MODES:
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Unsupported amass mode: {mode}")

        result = self.executor.execute_tool("amass", [mode, "-d", domain], timeout=600)
        return ToolResult(
            tool_name=self.spec.name,
            success=result.get("success", False),
            content=result.get("stdout", "") or result.get("stderr", ""),
            data=result,
            error=result.get("error"),
        )


class SubfinderScanTool(BaseTool):
    """Shared subfinder execution path."""

    spec = ToolSpec(
        name="subfinder_scan",
        description="Run validated subfinder against a domain.",
        input_schema={
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "silent": {"type": "boolean"},
                "all_sources": {"type": "boolean"},
            },
        },
        risk_category=RiskCategory.MEDIUM,
        requires_approval=True,
        read_only=True,
    )

    def __init__(self):
        self.validator = InputValidator()
        self.executor = SecureCommandExecutor()

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        domain = str(arguments.get("domain", "")).strip()
        silent = bool(arguments.get("silent", True))
        all_sources = bool(arguments.get("all_sources", False))
        if not self.validator.validate_target(domain):
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Invalid domain: {domain}")

        args = ["-d", domain]
        if silent:
            args.append("-silent")
        if all_sources:
            args.append("-all")
        result = self.executor.execute_tool("subfinder", args, timeout=300)
        return ToolResult(
            tool_name=self.spec.name,
            success=result.get("success", False),
            content=result.get("stdout", "") or result.get("stderr", ""),
            data=result,
            error=result.get("error"),
        )


class GobusterScanTool(BaseTool):
    """Shared gobuster execution path."""

    spec = ToolSpec(
        name="gobuster_scan",
        description="Run validated gobuster enumeration.",
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "mode": {"type": "string"},
                "wordlist": {"type": "string"},
            },
        },
        risk_category=RiskCategory.MEDIUM,
        requires_approval=True,
        read_only=True,
    )

    def __init__(self):
        self.validator = InputValidator()
        self.executor = SecureCommandExecutor()

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        url = str(arguments.get("url", "")).strip()
        mode = str(arguments.get("mode", "dir")).strip().lower()
        wordlist = str(arguments.get("wordlist", "/usr/share/wordlists/dirb/common.txt")).strip()
        if not self.validator.validate_target(url):
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Invalid target: {url}")
        if mode not in ALLOWED_GOBUSTER_MODES:
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Unsupported gobuster mode: {mode}")
        if not self.validator.validate_file_path(wordlist):
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Invalid wordlist path: {wordlist}")

        args = [mode, "-u", url, "-w", wordlist]
        result = self.executor.execute_tool("gobuster", args, timeout=600)
        return ToolResult(
            tool_name=self.spec.name,
            success=result.get("success", False),
            content=result.get("stdout", "") or result.get("stderr", ""),
            data=result,
            error=result.get("error"),
        )


class HttpxProbeTool(BaseTool):
    """Shared httpx execution path."""

    spec = ToolSpec(
        name="httpx_probe",
        description="Run validated httpx probing and technology detection.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "probe": {"type": "boolean"},
                "tech_detect": {"type": "boolean"},
                "status_code": {"type": "boolean"},
                "threads": {"type": "integer"},
            },
        },
        risk_category=RiskCategory.MEDIUM,
        requires_approval=True,
        read_only=True,
    )

    def __init__(self):
        self.validator = InputValidator()
        self.executor = SecureCommandExecutor()

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        target = str(arguments.get("target", "")).strip()
        probe = bool(arguments.get("probe", True))
        tech_detect = bool(arguments.get("tech_detect", False))
        status_code = bool(arguments.get("status_code", False))
        if not self.validator.validate_bounded_int(arguments.get("threads", 50), minimum=1, maximum=200):
            return ToolResult(tool_name=self.spec.name, success=False, content="", error="threads must be between 1 and 200")
        threads = int(arguments.get("threads", 50))

        httpx_args = ["httpx", "-threads", str(threads)]
        if self.validator.validate_target(target):
            httpx_args.extend(["-u", target])
        elif self.validator.validate_file_path(target):
            httpx_args.extend(["-l", target])
        else:
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Invalid target: {target}")
        if not probe:
            httpx_args.append("-no-probe")
        if tech_detect:
            httpx_args.append("-tech-detect")
        if status_code:
            httpx_args.append("-status-code")

        result = self.executor.execute_tool(httpx_args[0], httpx_args[1:], timeout=300)
        return ToolResult(
            tool_name=self.spec.name,
            success=result.get("success", False),
            content=result.get("stdout", "") or result.get("stderr", ""),
            data=result,
            error=result.get("error"),
        )


class FfufScanTool(BaseTool):
    """Shared ffuf execution path."""

    spec = ToolSpec(
        name="ffuf_scan",
        description="Run validated ffuf web fuzzing.",
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "wordlist": {"type": "string"},
                "mode": {"type": "string"},
            },
        },
        risk_category=RiskCategory.MEDIUM,
        requires_approval=True,
        read_only=True,
    )

    def __init__(self):
        self.validator = InputValidator()
        self.executor = SecureCommandExecutor()

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        url = str(arguments.get("url", "")).strip()
        wordlist = str(arguments.get("wordlist", "/usr/share/wordlists/dirb/common.txt")).strip()
        mode = str(arguments.get("mode", "directory")).strip().lower()
        if not self.validator.validate_target(url):
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Invalid target: {url}")
        if mode not in ALLOWED_FFUF_MODES:
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Unsupported ffuf mode: {mode}")
        if not self.validator.validate_file_path(wordlist):
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Invalid wordlist path: {wordlist}")

        args = ["-u", url, "-w", wordlist]
        result = self.executor.execute_tool("ffuf", args, timeout=600)
        return ToolResult(
            tool_name=self.spec.name,
            success=result.get("success", False),
            content=result.get("stdout", "") or result.get("stderr", ""),
            data=result,
            error=result.get("error"),
        )


class AuthenticatedWebScanTool(BaseTool):
    """Run authenticated web checks through the shared runtime."""

    spec = ToolSpec(
        name="authenticated_web_scan",
        description="Run authenticated SQLi, IDOR, or authorization checks using a stored session.",
        input_schema={
            "type": "object",
            "properties": {
                "scan_type": {"type": "string"},
                "session_id": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "data": {"type": "string"},
                "headers": {"type": "object"},
                "required_role": {"type": "string"},
                "actual_role": {"type": "string"},
                "target_user_id": {"type": "string"},
            },
        },
        risk_category=RiskCategory.HIGH,
        requires_approval=True,
        read_only=False,
    )

    def __init__(self):
        from analysis.authenticated_scanner import AuthenticatedScanner
        from auth.session_manager import SessionManager

        self.validator = InputValidator()
        self.session_manager = SessionManager()
        self.scanner = AuthenticatedScanner(self.session_manager)

    async def execute(self, arguments: dict, context: ExecutionContext) -> ToolResult:
        scan_type = str(arguments.get("scan_type", "")).strip().lower()
        session_id = str(arguments.get("session_id", "")).strip()
        url = str(arguments.get("url", "")).strip()
        method = str(arguments.get("method", "GET")).strip().upper()
        data = str(arguments.get("data", "")).strip()
        headers = arguments.get("headers") or {}

        if not session_id:
            return ToolResult(tool_name=self.spec.name, success=False, content="", error="session_id is required for authenticated testing")
        if not self.validator.validate_target(url):
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Invalid target: {url}")
        if not isinstance(headers, dict):
            return ToolResult(tool_name=self.spec.name, success=False, content="", error="headers must be a dictionary")

        findings = []
        try:
            if scan_type == "sql_injection":
                findings = await self.scanner.test_sql_injection(
                    session_id=session_id,
                    targets=[{"url": url, "method": method, "data": data or None, "headers": headers}],
                )
            elif scan_type == "idor":
                findings = await self.scanner.test_idor(
                    session_id=session_id,
                    test_urls=[url],
                    target_user_id=arguments.get("target_user_id"),
                )
            elif scan_type == "broken_authorization":
                findings = await self.scanner.test_broken_authorization(
                    session_id=session_id,
                    api_endpoints=[{
                        "url": url,
                        "method": method,
                        "required_role": str(arguments.get("required_role", "admin")),
                        "actual_role": str(arguments.get("actual_role", "user")),
                    }],
                )
            else:
                return ToolResult(tool_name=self.spec.name, success=False, content="", error=f"Unsupported authenticated scan type: {scan_type}")
        except Exception as exc:
            return ToolResult(tool_name=self.spec.name, success=False, content="", error=str(exc))

        finding_dicts = [finding.to_dict() for finding in findings]
        if finding_dicts:
            summary = f"Validated {len(finding_dicts)} authenticated finding(s) against {url}."
        else:
            summary = f"No authenticated findings were validated against {url}."
        return ToolResult(
            tool_name=self.spec.name,
            success=True,
            content=summary,
            data={
                "scan_type": scan_type,
                "session_id": session_id,
                "url": url,
                "findings": finding_dicts,
            },
        )


class ToolRegistry:
    """Lookup and expose typed tool implementations."""

    def __init__(self, tools: Iterable[BaseTool] | None = None):
        self._tools: Dict[str, BaseTool] = {}
        for tool in tools or self._default_tools():
            self.register(tool)

    def _default_tools(self) -> List[BaseTool]:
        return [
            ListAvailableProvidersTool(),
            ListConfiguredProvidersTool(),
            StoreMemoryTool(),
            SearchMemoryTool(),
            ListSharedToolsTool(),
            CheckToolStatusTool(),
            NmapScanTool(),
            RustscanFastScanTool(),
            NucleiScanTool(),
            NiktoScanTool(),
            SqlmapScanTool(),
            AmassEnumTool(),
            SubfinderScanTool(),
            GobusterScanTool(),
            HttpxProbeTool(),
            FfufScanTool(),
            AuthenticatedWebScanTool(),
        ]

    def register(self, tool: BaseTool) -> None:
        self._tools[tool.spec.name] = tool

    def get(self, name: str) -> BaseTool | None:
        return self._tools.get(name)

    def specs(self) -> List[ToolSpec]:
        return [tool.spec for tool in self._tools.values()]

    def names(self) -> List[str]:
        return list(self._tools.keys())


tool_registry = ToolRegistry()
