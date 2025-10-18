# COBRA AI Polyglot Architecture

## Overview

COBRA AI now uses a **polyglot architecture** to maximize performance, security, and functionality by leveraging the best language for each task:

- **Node.js/TypeScript** - Main backend and API orchestration
- **Python** - OSINT data gathering (leverages rich security ecosystem)
- **Rust** - High-performance port scanning and network probing

## Architecture Diagram

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Frontend      │────▶│  Node.js API    │────▶│  Python OSINT   │
│   (React)       │     │  (Port 3001)    │     │  (Port 8001)    │
└─────────────────┘     └────────┬────────┘     └─────────────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │  Rust Scanner   │
                        │  (Port 8002)    │
                        └─────────────────┘
```

## 1. Python OSINT Service

### Location
`backend/services/osint/osint_service.py`

### Features
- **Shodan API Integration** - Port/service discovery
- **Censys API Integration** - Certificate transparency
- **VirusTotal API Integration** - Malware/reputation checks
- **Wayback Machine** - Historical website data (FREE)
- **DNS History** - Historical DNS records
- **Have I Been Pwned** - Data breach information

### Setup
```bash
cd backend/services/osint
pip install -r requirements.txt
python osint_service.py
```

### Environment Variables
```env
OSINT_SERVICE_PORT=8001
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_id_here
CENSYS_API_SECRET=your_secret_here
VIRUSTOTAL_API_KEY=your_key_here
HIBP_API_KEY=your_key_here
```

### API Endpoints
- `GET /` - Service health check
- `POST /gather` - Gather OSINT data
- `GET /health` - Detailed health status

### Example Request
```json
POST http://localhost:8001/gather
{
  "target": "example.com",
  "tools": {
    "shodan": true,
    "wayback": true,
    "dnsHistory": true
  }
}
```

## 2. Rust Port Scanner

### Location
`backend/services/scanner/`

### Features
- **High-Performance Scanning** - Async Rust with Tokio
- **Multiple Scan Techniques**:
  - TCP Connect Scan
  - SYN Scan (requires privileges)
  - Timing Evasion
  - Banner Grabbing
- **Concurrent Scanning** - Up to 1000 ports simultaneously
- **Service Detection** - Identifies common services

### Setup
```bash
cd backend/services/scanner
cargo build --release
cargo run --release
```

### Environment Variables
```env
SCANNER_SERVICE_PORT=8002
```

### API Endpoints
- `GET /` - Service info
- `POST /scan` - Perform port scan
- `GET /health` - Health check

### Example Request
```json
POST http://localhost:8002/scan
{
  "target": "example.com",
  "ports": [80, 443, 22, 3306],
  "timeout_ms": 1000,
  "max_concurrent": 100,
  "techniques": {
    "syn_scan": false,
    "timing_evasion": true,
    "fragmentation": false
  }
}
```

## 3. Node.js Polyglot Service

### Location
`backend/src/services/polyglot.ts`

### Features
- **Service Orchestration** - Manages Python and Rust services
- **Automatic Fallback** - Uses Node.js implementation if services are down
- **Health Monitoring** - Checks service availability
- **Transparent Integration** - Existing code works without changes

### Key Functions
```typescript
// Gather OSINT data via Python service
await polyglotServices.gatherOSINT({
  target: "example.com",
  tools: { shodan: true, wayback: true }
})

// Scan ports via Rust service
await polyglotServices.scanPorts({
  target: "example.com",
  ports: [80, 443, 22],
  timeout_ms: 1000
})
```

## Performance Improvements

### Port Scanning
- **Before (Node.js)**: ~5-10 seconds for 1000 ports
- **After (Rust)**: ~0.5-2 seconds for 1000 ports
- **Improvement**: 5-10x faster

### OSINT Gathering
- **Before (Node.js)**: Limited mock data
- **After (Python)**: Real API integrations with concurrent requests
- **Improvement**: Real data from 6+ sources

### Memory Usage
- **Rust Scanner**: ~10MB for 10,000 concurrent connections
- **Python OSINT**: ~50MB with all APIs active
- **Node.js**: Reduced load, better resource allocation

## Security Benefits

1. **Memory Safety** - Rust prevents buffer overflows in port scanning
2. **Isolation** - Services run in separate processes
3. **Privilege Separation** - Only scanner needs elevated privileges for SYN scan
4. **API Key Management** - Centralized in environment variables

## Development Workflow

### Starting All Services

1. **Terminal 1 - Backend**:
```bash
cd backend
npm run dev
```

2. **Terminal 2 - Python OSINT**:
```bash
cd backend/services/osint
python osint_service.py
```

3. **Terminal 3 - Rust Scanner**:
```bash
cd backend/services/scanner
cargo run --release
```

### Docker Deployment (Future)
```yaml
version: '3.8'
services:
  backend:
    build: ./backend
    ports:
      - "3001:3001"
    depends_on:
      - osint
      - scanner
  
  osint:
    build: ./backend/services/osint
    ports:
      - "8001:8001"
    environment:
      - SHODAN_API_KEY=${SHODAN_API_KEY}
  
  scanner:
    build: ./backend/services/scanner
    ports:
      - "8002:8002"
    cap_add:
      - NET_RAW  # For SYN scanning
```

## Adding New Languages/Services

To add a new service in another language:

1. Create directory: `backend/services/[service-name]/`
2. Implement REST API with health check
3. Add to `polyglot.ts`:
```typescript
async checkNewService() {
  const health = await axios.get(`${NEW_SERVICE_URL}/health`)
  this.newServiceAvailable = health.status === 200
}
```
4. Create fallback implementation
5. Update this documentation

## Troubleshooting

### Python OSINT Service
```bash
# Check if running
curl http://localhost:8001/health

# Install missing dependencies
pip install -r requirements.txt

# Debug mode
python osint_service.py --debug
```

### Rust Scanner
```bash
# Check if running
curl http://localhost:8002/health

# Build errors
cargo clean
cargo build --release

# Permission errors (SYN scan)
# Run with sudo/admin privileges
```

### Service Communication
```bash
# Test from Node.js
curl http://localhost:3001/api/pentest/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","tests":["port-scan"]}'
```

## Future Enhancements

1. **gRPC Communication** - Replace REST with gRPC for better performance
2. **Service Mesh** - Use Istio/Linkerd for advanced routing
3. **More Languages**:
   - **Go** - Web crawling and fuzzing
   - **C++** - Packet crafting and low-level networking
   - **Ruby** - Metasploit integration
4. **Kubernetes Deployment** - Scale services independently
5. **Message Queue** - Use RabbitMQ/Kafka for async operations

## Contributing

When adding new polyglot services:
1. Follow the existing service structure
2. Implement health checks
3. Add comprehensive error handling
4. Document API endpoints
5. Create fallback implementations
6. Add to CI/CD pipeline 