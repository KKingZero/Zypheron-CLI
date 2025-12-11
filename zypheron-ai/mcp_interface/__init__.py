"""
Zypheron MCP (Model Context Protocol) Integration Module

This module provides MCP server capabilities to expose Zypheron's security tools
to AI agents like Claude Desktop, Cursor, VS Code Copilot, and other MCP-compatible clients.

Features:
- 30+ integrated security tools via MCP protocol
- FastMCP server implementation
- Zypheron-branded visual theme
- Integration with existing tool execution infrastructure
- Authentication and security controls
"""

from mcp_interface.server import setup_mcp_server, main
from mcp_interface.client import ZypheronClient
from mcp_interface.colors import ZypheronColors
from mcp_interface.tools import ZypheronToolExecutor

__all__ = [
    'setup_mcp_server',
    'main',
    'ZypheronClient',
    'ZypheronColors',
    'ZypheronToolExecutor',
]

__version__ = '1.0.0'

