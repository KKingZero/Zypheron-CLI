"""WebSocket event types and schemas for scan streaming.

Defines event types and data structures for real-time scan updates.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ScanEventType(str, Enum):
    """Types of events that can be sent over WebSocket."""

    CONNECTED = "connected"
    SCAN_STARTED = "scan_started"
    SCAN_PROGRESS = "scan_progress"
    FINDING = "finding"
    SCAN_COMPLETED = "scan_completed"
    SCAN_ERROR = "scan_error"
    PING = "ping"
    PONG = "pong"
    ERROR = "error"
    SUBSCRIBED = "subscribed"
    UNSUBSCRIBED = "unsubscribed"


class ScanEvent(BaseModel):
    """WebSocket event message structure.

    All events sent to clients follow this structure for consistency.
    """

    event: ScanEventType = Field(..., description="Event type")
    data: dict[str, Any] = Field(default_factory=dict, description="Event payload")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Event timestamp in UTC",
    )

    class Config:
        """Pydantic configuration."""

        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


class ClientCommand(BaseModel):
    """Command sent from client to server."""

    command: str = Field(..., description="Command type (subscribe, unsubscribe, ping)")
    scan_id: str | None = Field(None, description="Scan ID for subscription commands")
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional command data",
    )


def create_event(
    event_type: ScanEventType,
    data: dict[str, Any] | None = None,
) -> ScanEvent:
    """Helper to create a scan event.

    Args:
        event_type: Type of event
        data: Event payload data

    Returns:
        ScanEvent instance
    """
    return ScanEvent(
        event=event_type,
        data=data or {},
    )


def create_connected_event(user_id: int, connection_id: str) -> ScanEvent:
    """Create a connection success event.

    Args:
        user_id: Authenticated user ID
        connection_id: Unique connection identifier

    Returns:
        Connected event
    """
    return create_event(
        ScanEventType.CONNECTED,
        {
            "message": "WebSocket connected successfully",
            "user_id": user_id,
            "connection_id": connection_id,
        },
    )


def create_error_event(message: str, code: int | None = None) -> ScanEvent:
    """Create an error event.

    Args:
        message: Error message
        code: Optional error code

    Returns:
        Error event
    """
    data = {"message": message}
    if code:
        data["code"] = code
    return create_event(ScanEventType.ERROR, data)


def create_subscribed_event(scan_id: str) -> ScanEvent:
    """Create a subscription confirmation event.

    Args:
        scan_id: Scan ID that was subscribed to

    Returns:
        Subscribed event
    """
    return create_event(
        ScanEventType.SUBSCRIBED,
        {
            "scan_id": scan_id,
            "message": f"Subscribed to scan {scan_id}",
        },
    )


def create_unsubscribed_event(scan_id: str) -> ScanEvent:
    """Create an unsubscribe confirmation event.

    Args:
        scan_id: Scan ID that was unsubscribed from

    Returns:
        Unsubscribed event
    """
    return create_event(
        ScanEventType.UNSUBSCRIBED,
        {
            "scan_id": scan_id,
            "message": f"Unsubscribed from scan {scan_id}",
        },
    )


def create_pong_event() -> ScanEvent:
    """Create a pong response event.

    Returns:
        Pong event
    """
    return create_event(
        ScanEventType.PONG,
        {"message": "pong"},
    )
