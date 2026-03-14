"""WebSocket client example and testing script.

Demonstrates how to connect to the Zypheron WebSocket API for real-time
scan event streaming.

Usage:
    python -m app.examples.websocket_client_test --token <jwt_token> --user-id <user_id>

Requirements:
    pip install websockets
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime
from typing import Any

try:
    import websockets
except ImportError:
    print("Error: websockets package not installed")
    print("Install with: pip install websockets")
    sys.exit(1)


class ScanWebSocketClient:
    """WebSocket client for Zypheron scan streaming."""

    def __init__(self, base_url: str, user_id: int, token: str):
        """Initialize client.

        Args:
            base_url: WebSocket base URL (e.g., ws://localhost:8000)
            user_id: User ID for connection
            token: JWT authentication token
        """
        self.base_url = base_url
        self.user_id = user_id
        self.token = token
        self.websocket = None
        self.subscribed_scans = set()

    def get_uri(self) -> str:
        """Get WebSocket URI with authentication.

        Returns:
            Full WebSocket URI with token parameter
        """
        return f"{self.base_url}/ws/scans/{self.user_id}?token={self.token}"

    async def connect(self) -> None:
        """Connect to WebSocket server."""
        uri = self.get_uri()
        print(f"Connecting to {uri[:50]}...")

        try:
            self.websocket = await websockets.connect(uri)
            print("Connected successfully!")
        except Exception as e:
            print(f"Connection failed: {e}")
            raise

    async def disconnect(self) -> None:
        """Disconnect from WebSocket server."""
        if self.websocket:
            await self.websocket.close()
            print("Disconnected")

    async def subscribe(self, scan_id: str) -> None:
        """Subscribe to a scan.

        Args:
            scan_id: Scan ID to subscribe to
        """
        if not self.websocket:
            raise RuntimeError("Not connected")

        command = {
            "command": "subscribe",
            "scan_id": scan_id,
        }

        await self.websocket.send(json.dumps(command))
        self.subscribed_scans.add(scan_id)
        print(f"Sent subscribe command for scan: {scan_id}")

    async def unsubscribe(self, scan_id: str) -> None:
        """Unsubscribe from a scan.

        Args:
            scan_id: Scan ID to unsubscribe from
        """
        if not self.websocket:
            raise RuntimeError("Not connected")

        command = {
            "command": "unsubscribe",
            "scan_id": scan_id,
        }

        await self.websocket.send(json.dumps(command))
        self.subscribed_scans.discard(scan_id)
        print(f"Sent unsubscribe command for scan: {scan_id}")

    async def ping(self) -> None:
        """Send ping keep-alive."""
        if not self.websocket:
            raise RuntimeError("Not connected")

        command = {"command": "ping"}
        await self.websocket.send(json.dumps(command))
        print("Sent ping")

    def format_event(self, event: dict[str, Any]) -> str:
        """Format event for display.

        Args:
            event: Event data

        Returns:
            Formatted string
        """
        event_type = event.get("event", "unknown")
        timestamp = event.get("timestamp", datetime.now().isoformat())
        data = event.get("data", {})

        lines = [
            f"\n{'='*60}",
            f"Event: {event_type}",
            f"Time: {timestamp}",
            f"{'-'*60}",
        ]

        # Format data based on event type
        if event_type == "connected":
            lines.append(f"Message: {data.get('message')}")
            lines.append(f"User ID: {data.get('user_id')}")
            lines.append(f"Connection ID: {data.get('connection_id')}")

        elif event_type == "scan_started":
            lines.append(f"Scan ID: {data.get('scan_id')}")
            lines.append(f"Target: {data.get('target')}")
            lines.append(f"Type: {data.get('scan_type')}")

        elif event_type == "scan_progress":
            lines.append(f"Scan ID: {data.get('scan_id')}")
            lines.append(f"Progress: {data.get('percent')}%")
            lines.append(f"Message: {data.get('message')}")
            if data.get('phase'):
                lines.append(f"Phase: {data.get('phase')}")

        elif event_type == "finding":
            lines.append(f"Scan ID: {data.get('scan_id')}")
            lines.append(f"Severity: {data.get('severity')}")
            vuln = data.get('vulnerability', {})
            lines.append(f"Vulnerability: {vuln.get('title', 'Unknown')}")
            if vuln.get('id'):
                lines.append(f"ID: {vuln.get('id')}")

        elif event_type == "scan_completed":
            lines.append(f"Scan ID: {data.get('scan_id')}")
            lines.append(f"Duration: {data.get('duration_seconds')}s")
            lines.append(f"Findings: {data.get('findings_count')}")
            summary = data.get('summary', {})
            if summary:
                lines.append("Summary:")
                for key, value in summary.items():
                    lines.append(f"  {key}: {value}")

        elif event_type == "error":
            lines.append(f"Error: {data.get('message')}")
            if data.get('code'):
                lines.append(f"Code: {data.get('code')}")

        elif event_type in ["subscribed", "unsubscribed"]:
            lines.append(f"Scan ID: {data.get('scan_id')}")
            lines.append(f"Message: {data.get('message')}")

        elif event_type == "pong":
            lines.append("Pong received")

        else:
            # Generic formatting for unknown event types
            lines.append(f"Data: {json.dumps(data, indent=2)}")

        lines.append(f"{'='*60}\n")
        return "\n".join(lines)

    async def listen(self) -> None:
        """Listen for events and display them."""
        if not self.websocket:
            raise RuntimeError("Not connected")

        print("\nListening for events... (Ctrl+C to stop)\n")

        try:
            async for message in self.websocket:
                try:
                    event = json.loads(message)
                    print(self.format_event(event))
                except json.JSONDecodeError:
                    print(f"Invalid JSON received: {message}")
        except websockets.exceptions.ConnectionClosed as e:
            print(f"\nConnection closed: {e.code} - {e.reason}")


async def run_interactive_client(base_url: str, user_id: int, token: str) -> None:
    """Run interactive WebSocket client.

    Args:
        base_url: WebSocket base URL
        user_id: User ID
        token: JWT token
    """
    client = ScanWebSocketClient(base_url, user_id, token)

    try:
        await client.connect()

        # Create tasks for listening and user input
        listen_task = asyncio.create_task(client.listen())

        print("\nCommands:")
        print("  subscribe <scan_id>  - Subscribe to a scan")
        print("  unsubscribe <scan_id> - Unsubscribe from a scan")
        print("  ping                  - Send ping")
        print("  quit                  - Exit")
        print()

        # Note: This is a simplified version. Real implementation would need
        # proper async input handling (e.g., using aioconsole)
        await listen_task

    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        await client.disconnect()


async def run_test_scenario(base_url: str, user_id: int, token: str) -> None:
    """Run automated test scenario.

    Args:
        base_url: WebSocket base URL
        user_id: User ID
        token: JWT token
    """
    client = ScanWebSocketClient(base_url, user_id, token)

    try:
        # Connect
        await client.connect()

        # Wait for connected event
        await asyncio.sleep(1)

        # Subscribe to a test scan
        test_scan_id = "test-scan-123"
        await client.subscribe(test_scan_id)

        # Send ping
        await asyncio.sleep(1)
        await client.ping()

        # Listen for 10 seconds
        print("\nListening for 10 seconds...")
        listen_task = asyncio.create_task(client.listen())

        await asyncio.sleep(10)

        # Unsubscribe
        await client.unsubscribe(test_scan_id)

        await asyncio.sleep(1)

        # Cancel listening
        listen_task.cancel()

    except KeyboardInterrupt:
        print("\nTest interrupted")
    except Exception as e:
        print(f"Test error: {e}")
    finally:
        await client.disconnect()


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Zypheron WebSocket client for scan streaming"
    )
    parser.add_argument(
        "--base-url",
        default="ws://localhost:8000",
        help="WebSocket base URL (default: ws://localhost:8000)",
    )
    parser.add_argument(
        "--user-id",
        type=int,
        required=True,
        help="User ID for authentication",
    )
    parser.add_argument(
        "--token",
        required=True,
        help="JWT authentication token",
    )
    parser.add_argument(
        "--mode",
        choices=["interactive", "test"],
        default="test",
        help="Client mode (default: test)",
    )

    args = parser.parse_args()

    print("Zypheron WebSocket Client")
    print("=" * 60)
    print(f"Base URL: {args.base_url}")
    print(f"User ID: {args.user_id}")
    print(f"Mode: {args.mode}")
    print("=" * 60)

    if args.mode == "interactive":
        asyncio.run(run_interactive_client(args.base_url, args.user_id, args.token))
    else:
        asyncio.run(run_test_scenario(args.base_url, args.user_id, args.token))


if __name__ == "__main__":
    main()
