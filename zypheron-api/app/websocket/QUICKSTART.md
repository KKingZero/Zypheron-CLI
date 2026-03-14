# WebSocket Quick Start Guide

## For Developers: Broadcasting Events

```python
from app.websocket import (
    broadcast_scan_started,
    broadcast_scan_progress,
    broadcast_finding,
    broadcast_scan_completed,
)

# In your scan worker or API endpoint
async def my_scan_function(scan_id: str):
    # Start
    await broadcast_scan_started(scan_id, "https://example.com", "web")

    # Progress
    await broadcast_scan_progress(scan_id, 50, "Scanning...", "port_scan")

    # Finding
    await broadcast_finding(
        scan_id,
        vulnerability={"title": "SQL Injection", "id": "CVE-2024-1234"},
        severity="high"
    )

    # Complete
    await broadcast_scan_completed(
        scan_id,
        duration_seconds=120,
        findings_count=5,
        summary={"high": 2, "medium": 3}
    )
```

## For Clients: Connecting

### JavaScript/TypeScript

```javascript
const ws = new WebSocket(
  `ws://localhost:8000/ws/scans/${userId}?token=${jwtToken}`
);

ws.onmessage = (event) => {
  const { event: eventType, data } = JSON.parse(event.data);

  switch(eventType) {
    case 'connected':
      // Subscribe to a scan
      ws.send(JSON.stringify({
        command: 'subscribe',
        scan_id: 'your-scan-uuid'
      }));
      break;

    case 'scan_progress':
      console.log(`Progress: ${data.percent}%`);
      break;

    case 'finding':
      console.log('Found:', data.vulnerability.title);
      break;

    case 'scan_completed':
      console.log('Done!', data.summary);
      break;
  }
};
```

### Python

```python
import asyncio
import json
import websockets

async def connect():
    uri = f"ws://localhost:8000/ws/scans/{user_id}?token={token}"

    async with websockets.connect(uri) as ws:
        # Subscribe
        await ws.send(json.dumps({
            "command": "subscribe",
            "scan_id": "your-scan-uuid"
        }))

        # Listen
        async for message in ws:
            event = json.loads(message)
            print(event['event'], event['data'])

asyncio.run(connect())
```

## Event Types

- `connected` - Connection established
- `scan_started` - Scan began
- `scan_progress` - Progress update (includes `percent`)
- `finding` - Vulnerability found
- `scan_completed` - Scan finished
- `scan_error` - Error occurred
- `pong` - Response to ping

## Commands to Server

```json
{"command": "subscribe", "scan_id": "uuid"}
{"command": "unsubscribe", "scan_id": "uuid"}
{"command": "ping"}
```

## Error Codes

- **4001**: Authentication failed
- **4002**: License required
- **4003**: Rate limited

## Rate Limits

- Free: 100 msg/min
- Starter: 200 msg/min
- Pro: 500 msg/min
- Enterprise: 1000 msg/min

## Testing

```bash
# Install test dependencies
pip install websockets

# Run test client
python -m app.examples.websocket_client_test \
  --user-id 123 \
  --token "your-jwt-token" \
  --mode test
```

## Common Issues

**Authentication Failed (4001)**
- Check JWT token is valid
- Verify user_id matches token
- Ensure session is active

**License Required (4002)**
- Check license is active
- Verify `websocket_streaming` feature enabled

**Connection Refused**
- Check server is running
- Verify WebSocket URL is correct
- Check firewall/proxy settings

## More Documentation

- Full documentation: `app/websocket/README.md`
- Implementation details: `WEBSOCKET_IMPLEMENTATION.md`
- Example client: `app/examples/websocket_client_test.py`
- Integration examples: `app/examples/scan_worker_integration.py`
