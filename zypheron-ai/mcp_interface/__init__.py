"""Zypheron MCP integration package.

Keep package initialization side-effect free so MCP helpers can be imported from
shared runtime modules without triggering import cycles.
"""

__all__ = ["__version__"]

__version__ = "2.0.0"
