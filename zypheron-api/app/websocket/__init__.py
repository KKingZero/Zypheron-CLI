"""WebSocket support for real-time scan event streaming.

Provides:
- Authenticated WebSocket connections
- License-aware feature access
- Real-time scan event broadcasting
- Rate limiting and connection management
"""

from app.websocket.broadcast import (
    broadcast_custom_event,
    broadcast_finding,
    broadcast_scan_completed,
    broadcast_scan_error,
    broadcast_scan_progress,
    broadcast_scan_started,
)
from app.websocket.events import ScanEvent, ScanEventType
from app.websocket.manager import ScanConnectionManager, scan_manager

__all__ = [
    "ScanConnectionManager",
    "ScanEvent",
    "ScanEventType",
    "scan_manager",
    "broadcast_scan_started",
    "broadcast_scan_progress",
    "broadcast_finding",
    "broadcast_scan_completed",
    "broadcast_scan_error",
    "broadcast_custom_event",
]
