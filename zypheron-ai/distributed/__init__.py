"""
Distributed Scanning Architecture

Enables multi-host coordination for large-scale security assessments.
"""

from .coordinator import ScanCoordinator, ScanTask, TaskStatus
from .agent import ScanAgent, AgentStatus
from .network import NetworkManager, AgentConnection

__all__ = [
    'ScanCoordinator',
    'ScanTask',
    'TaskStatus',
    'ScanAgent',
    'AgentStatus',
    'NetworkManager',
    'AgentConnection'
]

