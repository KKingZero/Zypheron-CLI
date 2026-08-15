"""MCP client configuration loading for chat turns."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class MCPServerConfig:
    label: str
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    server_url: Optional[str] = None
    allowed_tools: List[str] = field(default_factory=list)
    approval: str = "required"


def load_selected_mcp_servers(config_path: str, selections: List[Dict[str, Any]]) -> List[MCPServerConfig]:
    """Load and validate selected MCP server entries.

    The current runtime can parse common MCP JSON and distinguish stdio from
    remote servers, but it does not yet implement a provider tool-calling loop.
    Callers should surface the resulting NotImplementedError clearly.
    """
    if not selections:
        return []

    path = Path(config_path).expanduser()
    if not path.exists():
        raise ValueError(f"MCP config not found: {path}")

    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid MCP config JSON: {exc}") from exc

    servers = raw.get("mcpServers")
    if not isinstance(servers, dict):
        raise ValueError("MCP config must contain an object field named 'mcpServers'")

    selected: List[MCPServerConfig] = []
    for selection in selections:
        label = str(selection.get("label", "")).strip()
        if not label:
            raise ValueError("MCP selection is missing a server label")
        entry = servers.get(label)
        if not isinstance(entry, dict):
            raise ValueError(f"MCP server label not found in config: {label}")

        command = entry.get("command")
        server_url = entry.get("server_url") or entry.get("url")
        if not command and not server_url:
            raise ValueError(f"MCP server {label!r} must define command or server_url")

        args = entry.get("args", [])
        env = entry.get("env", {})
        allowed_tools = selection.get("allowed_tools") or entry.get("allowed_tools", [])
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise ValueError(f"MCP server {label!r} args must be a list of strings")
        if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
            raise ValueError(f"MCP server {label!r} env must be an object of string values")
        if not isinstance(allowed_tools, list) or not all(isinstance(tool, str) for tool in allowed_tools):
            raise ValueError(f"MCP server {label!r} allowed_tools must be a list of strings")

        selected.append(
            MCPServerConfig(
                label=label,
                command=str(command) if command else None,
                args=args,
                env=env,
                server_url=str(server_url) if server_url else None,
                allowed_tools=allowed_tools,
                approval=str(entry.get("approval", "required")),
            )
        )
    return selected


def unsupported_mcp_client_message(servers: List[MCPServerConfig]) -> str:
    """Build a precise runtime error for parsed-but-unsupported MCP client use."""
    remote = [server.label for server in servers if server.server_url]
    local = [server.label for server in servers if not server.server_url]
    parts = []
    if local:
        parts.append(f"stdio server(s): {', '.join(local)}")
    if remote:
        parts.append(f"remote HTTP/SSE server(s): {', '.join(remote)}")
    selected = "; ".join(parts) if parts else "no selected servers"
    return (
        "MCP client config parsing succeeded, but chat-time MCP tool execution is experimental "
        f"and not implemented yet for {selected}"
    )
