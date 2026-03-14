"""WebSocket connection manager with authentication and license validation.

Manages authenticated WebSocket connections and scan event subscriptions.
"""

import json
import structlog
import uuid
from collections import defaultdict
from typing import DefaultDict

from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token
from app.models.license import License
from app.models.session import Session
from app.models.user import User
from app.routers.auth import hash_token
from app.schemas.license import get_tier_features
from app.websocket.events import (
    ClientCommand,
    ScanEvent,
    ScanEventType,
    create_connected_event,
    create_error_event,
    create_pong_event,
    create_subscribed_event,
    create_unsubscribed_event,
)
from app.websocket.rate_limiter import WebSocketRateLimiter, get_rate_limit_for_tier

logger = structlog.get_logger()


class ConnectionInfo:
    """Information about a WebSocket connection."""

    def __init__(
        self,
        websocket: WebSocket,
        user: User,
        license: License,
        connection_id: str,
    ):
        """Initialize connection info.

        Args:
            websocket: WebSocket connection
            user: Authenticated user
            license: User's license
            connection_id: Unique connection identifier
        """
        self.websocket = websocket
        self.user = user
        self.license = license
        self.connection_id = connection_id
        self.subscriptions: set[str] = set()  # Set of scan IDs


class ScanConnectionManager:
    """Manages authenticated WebSocket connections for scan streaming.

    Handles:
    - JWT authentication
    - License validation
    - Connection lifecycle
    - Scan subscriptions
    - Event broadcasting
    - Rate limiting
    """

    def __init__(self) -> None:
        """Initialize connection manager."""
        # Map user_id to list of ConnectionInfo objects
        self.user_connections: DefaultDict[int, list[ConnectionInfo]] = defaultdict(list)

        # Map scan_id to set of user_ids subscribed to that scan
        self.scan_subscriptions: DefaultDict[str, set[int]] = defaultdict(set)

        # Rate limiter for messages
        self.rate_limiter = WebSocketRateLimiter()

    async def authenticate(
        self,
        token: str,
        db: AsyncSession,
    ) -> tuple[User, License] | None:
        """Authenticate WebSocket connection using JWT token.

        Validates JWT token and retrieves user and license information.

        Args:
            token: JWT token from query parameter
            db: Database session

        Returns:
            Tuple of (User, License) if authentication succeeds, None otherwise
        """
        # Decode JWT token
        payload = decode_access_token(token)
        if not payload:
            logger.warning("Failed to decode JWT token")
            return None

        # Extract user_id from token subject
        user_id = payload.get("sub")
        if not user_id:
            logger.warning("Token missing subject claim")
            return None

        try:
            user_id_int = int(user_id)
        except (ValueError, TypeError):
            logger.warning(f"Invalid user_id in token: {user_id}")
            return None

        # Hash token for session lookup (same as REST API authentication)
        token_hash = hash_token(token)

        # Validate token exists in sessions table and is active
        stmt = select(Session).where(
            Session.token == token_hash,
            Session.is_active == True,  # noqa: E712
        )
        result = await db.execute(stmt)
        session = result.scalar_one_or_none()

        if not session or not session.is_valid():
            logger.warning(f"Invalid or expired session for user {user_id}")
            return None

        # Get user from database
        stmt = select(User).where(User.id == user_id_int)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            logger.warning(f"User {user_id} not found or inactive")
            return None

        # Get user's license
        stmt = (
            select(License)
            .where(License.user_id == user_id_int)
            .order_by(License.created_at.desc())
        )
        result = await db.execute(stmt)
        license = result.scalar_one_or_none()

        if not license:
            # Create default free license if none exists
            license = License(
                user_id=user_id_int,
                tier="free",
                status="active",
            )
            db.add(license)
            await db.commit()
            await db.refresh(license)
            logger.info(f"Created default free license for user {user_id}")

        # Update session activity
        session.update_activity()
        await db.commit()

        return user, license

    def validate_license_feature(self, license: License) -> tuple[bool, str | None]:
        """Validate that license has websocket_streaming feature enabled.

        Args:
            license: User's license to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if license is valid
        if not license.is_valid():
            return False, "License is not active or has expired"

        # Get tier features
        features = get_tier_features(license.tier)

        # Check if websocket_streaming is enabled for this tier
        if not features.features.get("websocket_streaming", False):
            return False, f"WebSocket streaming not available for {license.tier} tier"

        return True, None

    async def connect(
        self,
        websocket: WebSocket,
        user: User,
        license: License,
    ) -> str:
        """Accept and register a new WebSocket connection.

        Args:
            websocket: WebSocket connection to accept
            user: Authenticated user
            license: User's license

        Returns:
            Connection ID
        """
        await websocket.accept()

        # Generate unique connection ID
        connection_id = str(uuid.uuid4())

        # Create connection info
        conn_info = ConnectionInfo(
            websocket=websocket,
            user=user,
            license=license,
            connection_id=connection_id,
        )

        # Store connection
        self.user_connections[user.id].append(conn_info)

        logger.info(
            f"WebSocket connected: user={user.id}, "
            f"connection_id={connection_id}, tier={license.tier}"
        )

        return connection_id

    def disconnect(self, websocket: WebSocket, user_id: int) -> None:
        """Remove a WebSocket connection and clean up subscriptions.

        Args:
            websocket: WebSocket connection to remove
            user_id: User ID of the connection
        """
        if user_id not in self.user_connections:
            return

        # Find and remove the connection
        connections = self.user_connections[user_id]
        conn_to_remove = None

        for conn in connections:
            if conn.websocket == websocket:
                conn_to_remove = conn
                break

        if conn_to_remove:
            # Remove from scan subscriptions
            for scan_id in conn_to_remove.subscriptions:
                if scan_id in self.scan_subscriptions:
                    self.scan_subscriptions[scan_id].discard(user_id)
                    if not self.scan_subscriptions[scan_id]:
                        del self.scan_subscriptions[scan_id]

            # Remove connection
            connections.remove(conn_to_remove)

            logger.info(
                f"WebSocket disconnected: user={user_id}, "
                f"connection_id={conn_to_remove.connection_id}"
            )

        # Remove user entry if no more connections
        if not connections:
            del self.user_connections[user_id]
            # Clean up rate limiter
            self.rate_limiter.reset(user_id)

    async def send_event(
        self,
        websocket: WebSocket,
        event: ScanEvent,
    ) -> None:
        """Send an event to a specific WebSocket connection.

        Args:
            websocket: Target WebSocket connection
            event: Event to send
        """
        try:
            await websocket.send_text(event.model_dump_json())
        except Exception as e:
            logger.error(f"Error sending event to websocket: {e}")

    async def send_to_user(
        self,
        user_id: int,
        event: ScanEvent,
    ) -> None:
        """Send an event to all connections for a user.

        Args:
            user_id: Target user ID
            event: Event to send
        """
        if user_id not in self.user_connections:
            return

        for conn in self.user_connections[user_id]:
            await self.send_event(conn.websocket, event)

    async def subscribe_to_scan(
        self,
        user_id: int,
        scan_id: str,
        websocket: WebSocket,
    ) -> bool:
        """Subscribe a user to scan updates.

        Args:
            user_id: User ID to subscribe
            scan_id: Scan ID to subscribe to
            websocket: WebSocket connection

        Returns:
            True if subscription successful, False otherwise
        """
        if user_id not in self.user_connections:
            return False

        # Find the connection
        for conn in self.user_connections[user_id]:
            if conn.websocket == websocket:
                # Add to connection's subscriptions
                conn.subscriptions.add(scan_id)

                # Add to global scan subscriptions
                self.scan_subscriptions[scan_id].add(user_id)

                logger.info(f"User {user_id} subscribed to scan {scan_id}")
                return True

        return False

    async def unsubscribe_from_scan(
        self,
        user_id: int,
        scan_id: str,
        websocket: WebSocket,
    ) -> bool:
        """Unsubscribe a user from scan updates.

        Args:
            user_id: User ID to unsubscribe
            scan_id: Scan ID to unsubscribe from
            websocket: WebSocket connection

        Returns:
            True if unsubscription successful, False otherwise
        """
        if user_id not in self.user_connections:
            return False

        # Find the connection
        for conn in self.user_connections[user_id]:
            if conn.websocket == websocket:
                # Remove from connection's subscriptions
                conn.subscriptions.discard(scan_id)

                # Remove from global scan subscriptions
                if scan_id in self.scan_subscriptions:
                    self.scan_subscriptions[scan_id].discard(user_id)
                    if not self.scan_subscriptions[scan_id]:
                        del self.scan_subscriptions[scan_id]

                logger.info(f"User {user_id} unsubscribed from scan {scan_id}")
                return True

        return False

    async def broadcast_scan_event(
        self,
        scan_id: str,
        event: ScanEvent,
    ) -> None:
        """Broadcast an event to all subscribers of a scan.

        Args:
            scan_id: Scan ID to broadcast to
            event: Event to broadcast
        """
        if scan_id not in self.scan_subscriptions:
            logger.debug(f"No subscribers for scan {scan_id}")
            return

        subscriber_ids = self.scan_subscriptions[scan_id].copy()
        logger.debug(f"Broadcasting to {len(subscriber_ids)} subscribers of scan {scan_id}")

        for user_id in subscriber_ids:
            await self.send_to_user(user_id, event)

    def check_rate_limit(self, user_id: int, tier: str) -> bool:
        """Check if user is within rate limit for messages.

        Args:
            user_id: User ID to check
            tier: User's subscription tier

        Returns:
            True if allowed, False if rate limited
        """
        limit = get_rate_limit_for_tier(tier)
        return self.rate_limiter.is_allowed(user_id, limit, window_seconds=60)

    async def handle_client_command(
        self,
        websocket: WebSocket,
        user_id: int,
        command_data: dict,
    ) -> None:
        """Handle a command from the client.

        Args:
            websocket: WebSocket connection
            user_id: User ID sending the command
            command_data: Command data from client
        """
        try:
            command = ClientCommand.model_validate(command_data)
        except Exception as e:
            logger.warning(f"Invalid command format from user {user_id}: {e}")
            await self.send_event(
                websocket,
                create_error_event("Invalid command format"),
            )
            return

        # Handle different command types
        if command.command == "subscribe" and command.scan_id:
            success = await self.subscribe_to_scan(user_id, command.scan_id, websocket)
            if success:
                await self.send_event(
                    websocket,
                    create_subscribed_event(command.scan_id),
                )
            else:
                await self.send_event(
                    websocket,
                    create_error_event(f"Failed to subscribe to scan {command.scan_id}"),
                )

        elif command.command == "unsubscribe" and command.scan_id:
            success = await self.unsubscribe_from_scan(user_id, command.scan_id, websocket)
            if success:
                await self.send_event(
                    websocket,
                    create_unsubscribed_event(command.scan_id),
                )
            else:
                await self.send_event(
                    websocket,
                    create_error_event(f"Failed to unsubscribe from scan {command.scan_id}"),
                )

        elif command.command == "ping":
            await self.send_event(websocket, create_pong_event())

        else:
            logger.warning(f"Unknown command from user {user_id}: {command.command}")
            await self.send_event(
                websocket,
                create_error_event(f"Unknown command: {command.command}"),
            )


# Global connection manager instance
scan_manager = ScanConnectionManager()
