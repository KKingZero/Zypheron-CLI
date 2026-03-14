"""Helper utilities for broadcasting scan events from anywhere in the application.

These functions can be imported and used by scan workers, routers, or background
tasks to send real-time updates to connected WebSocket clients.
"""

from typing import Any

from app.websocket.events import ScanEvent, ScanEventType, create_event
from app.websocket.manager import scan_manager


async def broadcast_scan_started(
    scan_id: str,
    target: str,
    scan_type: str,
    **kwargs: Any,
) -> None:
    """Broadcast that a scan has started.

    Args:
        scan_id: Unique scan identifier
        target: Scan target (URL, IP, etc.)
        scan_type: Type of scan (web, api, network, etc.)
        **kwargs: Additional scan metadata
    """
    data = {
        "scan_id": scan_id,
        "target": target,
        "scan_type": scan_type,
        **kwargs,
    }

    event = create_event(ScanEventType.SCAN_STARTED, data)
    await scan_manager.broadcast_scan_event(scan_id, event)


async def broadcast_scan_progress(
    scan_id: str,
    percent: int,
    message: str,
    phase: str | None = None,
    **kwargs: Any,
) -> None:
    """Broadcast scan progress update.

    Args:
        scan_id: Unique scan identifier
        percent: Progress percentage (0-100)
        message: Human-readable progress message
        phase: Current scan phase (port_scan, vulnerability_check, etc.)
        **kwargs: Additional progress data
    """
    data = {
        "scan_id": scan_id,
        "percent": percent,
        "message": message,
    }

    if phase:
        data["phase"] = phase

    data.update(kwargs)

    event = create_event(ScanEventType.SCAN_PROGRESS, data)
    await scan_manager.broadcast_scan_event(scan_id, event)


async def broadcast_finding(
    scan_id: str,
    vulnerability: dict[str, Any],
    severity: str,
    **kwargs: Any,
) -> None:
    """Broadcast a security finding.

    Args:
        scan_id: Unique scan identifier
        vulnerability: Vulnerability details dictionary
        severity: Severity level (critical, high, medium, low, info)
        **kwargs: Additional finding metadata
    """
    data = {
        "scan_id": scan_id,
        "vulnerability": vulnerability,
        "severity": severity,
        **kwargs,
    }

    event = create_event(ScanEventType.FINDING, data)
    await scan_manager.broadcast_scan_event(scan_id, event)


async def broadcast_scan_completed(
    scan_id: str,
    duration_seconds: float,
    findings_count: int,
    summary: dict[str, Any],
    **kwargs: Any,
) -> None:
    """Broadcast scan completion.

    Args:
        scan_id: Unique scan identifier
        duration_seconds: Total scan duration
        findings_count: Number of findings discovered
        summary: Scan summary with statistics
        **kwargs: Additional completion data
    """
    data = {
        "scan_id": scan_id,
        "duration_seconds": duration_seconds,
        "findings_count": findings_count,
        "summary": summary,
        **kwargs,
    }

    event = create_event(ScanEventType.SCAN_COMPLETED, data)
    await scan_manager.broadcast_scan_event(scan_id, event)


async def broadcast_scan_error(
    scan_id: str,
    error_message: str,
    error_type: str | None = None,
    **kwargs: Any,
) -> None:
    """Broadcast a scan error.

    Args:
        scan_id: Unique scan identifier
        error_message: Error description
        error_type: Type of error (network, authentication, etc.)
        **kwargs: Additional error context
    """
    data = {
        "scan_id": scan_id,
        "error": error_message,
    }

    if error_type:
        data["error_type"] = error_type

    data.update(kwargs)

    event = create_event(ScanEventType.SCAN_ERROR, data)
    await scan_manager.broadcast_scan_event(scan_id, event)


async def broadcast_custom_event(
    scan_id: str,
    event_type: ScanEventType,
    data: dict[str, Any],
) -> None:
    """Broadcast a custom event.

    Use this for any event type not covered by the specific helpers.

    Args:
        scan_id: Unique scan identifier
        event_type: Type of event to send
        data: Event data payload
    """
    event = create_event(event_type, data)
    await scan_manager.broadcast_scan_event(scan_id, event)
