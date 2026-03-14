"""Example: Integrating WebSocket broadcasting into a scan worker.

Demonstrates how to broadcast scan events from background workers or API endpoints.
"""

import asyncio
import uuid
from typing import Any

from app.websocket import (
    broadcast_finding,
    broadcast_scan_completed,
    broadcast_scan_error,
    broadcast_scan_progress,
    broadcast_scan_started,
)


async def simulate_vulnerability_scan(
    target: str,
    scan_type: str = "web",
) -> dict[str, Any]:
    """Simulate a vulnerability scan with WebSocket event broadcasting.

    This is an example of how to integrate WebSocket broadcasting into
    your actual scan worker implementation.

    Args:
        target: Target URL or system to scan
        scan_type: Type of scan to perform

    Returns:
        Scan results dictionary
    """
    # Generate unique scan ID
    scan_id = str(uuid.uuid4())

    try:
        # Broadcast scan start
        await broadcast_scan_started(
            scan_id=scan_id,
            target=target,
            scan_type=scan_type,
            initiated_by="user_123",  # Replace with actual user
        )

        # Simulate phases of scanning
        phases = [
            {"name": "port_scan", "message": "Scanning ports...", "percent": 10},
            {"name": "dns_lookup", "message": "Performing DNS lookups...", "percent": 20},
            {
                "name": "ssl_check",
                "message": "Checking SSL/TLS configuration...",
                "percent": 30,
            },
            {
                "name": "dependency_scan",
                "message": "Scanning dependencies...",
                "percent": 50,
            },
            {
                "name": "vulnerability_check",
                "message": "Checking for vulnerabilities...",
                "percent": 70,
            },
            {
                "name": "exploit_verification",
                "message": "Verifying exploitability...",
                "percent": 90,
            },
        ]

        findings = []

        for phase in phases:
            # Broadcast progress
            await broadcast_scan_progress(
                scan_id=scan_id,
                percent=phase["percent"],
                message=phase["message"],
                phase=phase["name"],
            )

            # Simulate work
            await asyncio.sleep(2)

            # Simulate finding vulnerabilities in some phases
            if phase["name"] == "dependency_scan":
                # Found a vulnerability
                vulnerability = {
                    "id": "CVE-2024-1234",
                    "title": "SQL Injection in authentication module",
                    "description": "User input is not properly sanitized in login form",
                    "affected_component": "login.php",
                    "cwe": "CWE-89",
                    "cvss_score": 8.5,
                    "remediation": "Use parameterized queries",
                }

                await broadcast_finding(
                    scan_id=scan_id,
                    vulnerability=vulnerability,
                    severity="high",
                )

                findings.append({"severity": "high", "vulnerability": vulnerability})

            elif phase["name"] == "ssl_check":
                # Found SSL issue
                vulnerability = {
                    "id": "SSL-WEAK-CIPHER",
                    "title": "Weak SSL cipher suite detected",
                    "description": "Server accepts deprecated TLS 1.0",
                    "affected_component": "TLS configuration",
                    "remediation": "Disable TLS 1.0 and 1.1",
                }

                await broadcast_finding(
                    scan_id=scan_id,
                    vulnerability=vulnerability,
                    severity="medium",
                )

                findings.append({"severity": "medium", "vulnerability": vulnerability})

        # Final progress
        await broadcast_scan_progress(
            scan_id=scan_id,
            percent=100,
            message="Scan complete, generating report...",
            phase="finalization",
        )

        await asyncio.sleep(1)

        # Calculate summary
        summary = {
            "critical": 0,
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
            "info": sum(1 for f in findings if f["severity"] == "info"),
        }

        # Broadcast completion
        await broadcast_scan_completed(
            scan_id=scan_id,
            duration_seconds=len(phases) * 2 + 1,  # Approximate duration
            findings_count=len(findings),
            summary=summary,
            report_url=f"https://api.zypheron.com/scans/{scan_id}/report",
        )

        return {
            "scan_id": scan_id,
            "target": target,
            "findings": findings,
            "summary": summary,
            "status": "completed",
        }

    except Exception as e:
        # Broadcast error
        await broadcast_scan_error(
            scan_id=scan_id,
            error_message=str(e),
            error_type=type(e).__name__,
        )

        raise


async def example_api_endpoint_integration(target: str) -> dict[str, Any]:
    """Example: Start scan from API endpoint with WebSocket notification.

    This demonstrates how to integrate WebSocket broadcasting into a
    FastAPI endpoint that starts a background scan.

    Args:
        target: Scan target

    Returns:
        API response dictionary
    """
    # Generate scan ID
    scan_id = str(uuid.uuid4())

    # Start scan in background
    # In production, use FastAPI BackgroundTasks or Celery
    asyncio.create_task(simulate_vulnerability_scan(target))

    # Immediately notify subscribers that scan started
    await broadcast_scan_started(
        scan_id=scan_id,
        target=target,
        scan_type="web",
        initiated_by="api",
    )

    # Return response to API caller
    return {
        "scan_id": scan_id,
        "status": "started",
        "message": "Scan started, subscribe to WebSocket for updates",
        "websocket_url": f"/ws/scans/{{user_id}}?token={{jwt_token}}",
    }


async def example_batch_scan_integration(targets: list[str]) -> list[dict[str, Any]]:
    """Example: Run multiple scans concurrently with WebSocket updates.

    Args:
        targets: List of targets to scan

    Returns:
        List of scan results
    """
    # Start all scans concurrently
    tasks = [simulate_vulnerability_scan(target) for target in targets]

    # Wait for all to complete
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    successful = []
    failed = []

    for result in results:
        if isinstance(result, Exception):
            failed.append({"error": str(result)})
        else:
            successful.append(result)

    return successful


# Example FastAPI router integration
"""
from fastapi import APIRouter, BackgroundTasks

router = APIRouter(prefix="/scans", tags=["Scans"])

@router.post("/start")
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser,
) -> dict:
    \"""Start a new vulnerability scan with WebSocket streaming.\"""

    scan_id = str(uuid.uuid4())

    # Add scan to background tasks
    background_tasks.add_task(
        simulate_vulnerability_scan,
        target=request.target,
        scan_type=request.scan_type,
    )

    # Broadcast start immediately
    await broadcast_scan_started(
        scan_id=scan_id,
        target=request.target,
        scan_type=request.scan_type,
        initiated_by=current_user.email,
    )

    return {
        "scan_id": scan_id,
        "status": "started",
        "message": "Scan queued, connect to WebSocket for real-time updates",
    }
"""


# CLI integration example
"""
import asyncio
import websockets
import json

async def cli_scan_with_streaming(target: str, token: str, user_id: int):
    \"""CLI command that starts scan and streams results.\"""

    # Connect to WebSocket
    uri = f"ws://api.zypheron.com/ws/scans/{user_id}?token={token}"

    async with websockets.connect(uri) as ws:
        # Start scan via API
        scan_id = await start_scan_api(target, token)

        # Subscribe to scan events
        await ws.send(json.dumps({
            "command": "subscribe",
            "scan_id": scan_id
        }))

        print(f"Scanning {target}...")

        # Listen for events
        async for message in ws:
            event = json.loads(message)

            if event["event"] == "scan_progress":
                percent = event["data"]["percent"]
                msg = event["data"]["message"]
                print(f"[{percent}%] {msg}")

            elif event["event"] == "finding":
                vuln = event["data"]["vulnerability"]
                severity = event["data"]["severity"]
                print(f"[{severity.upper()}] {vuln['title']}")

            elif event["event"] == "scan_completed":
                summary = event["data"]["summary"]
                print(f"Scan complete! Found {event['data']['findings_count']} issues")
                print(f"Summary: {summary}")
                break
"""


if __name__ == "__main__":
    # Run example scan
    print("Running example vulnerability scan with WebSocket broadcasting...")
    print("=" * 60)
    asyncio.run(simulate_vulnerability_scan("https://example.com"))
    print("\nExample completed!")
