# 📦 Dependencies & Quick Commands

## NPM Dependencies to Install

```bash
cd backend

# Production Dependencies
npm install --save \
  axios \
  semver \
  node-cache \
  bull \
  ioredis \
  dockerode \
  xml2js

# Development Dependencies  
npm install --save-dev \
  @types/semver \
  @types/node-cache \
  @types/bull \
  @types/ioredis \
  @types/dockerode \
  @types/xml2js
```

## Package.json Additions

Add to your `backend/package.json`:

```json
{
  "dependencies": {
    "axios": "^1.6.0",
    "semver": "^7.5.4",
    "node-cache": "^5.1.2",
    "bull": "^4.11.5",
    "ioredis": "^5.3.2",
    "dockerode": "^4.0.0",
    "xml2js": "^0.6.2"
  },
  "devDependencies": {
    "@types/semver": "^7.5.4",
    "@types/node-cache": "^4.2.5",
    "@types/bull": "^4.10.0",
    "@types/ioredis": "^5.0.0",
    "@types/dockerode": "^3.3.23",
    "@types/xml2js": "^0.4.14"
  }
}
```

---

## Quick Command Reference

### Setup Commands
```bash
# Full automated installation
./install-pentest-fixes.sh

# Start Redis
docker run -d --name cobra-redis -p 6379:6379 redis:alpine

# Build Kali container
docker build -f Dockerfile.kali-pentest -t cobra-ai-kali-pentest:latest .

# Check Docker containers
docker ps | grep cobra
```

### Verification Commands
```bash
# Check Redis
docker exec cobra-redis redis-cli ping
# Should return: PONG

# Check Kali image
docker images | grep cobra-ai-kali-pentest

# Test NVD API
node -e "
const { getNVDClient } = require('./backend/src/services/nvdClient');
const client = getNVDClient();
client.getCVE('CVE-2021-44228').then(cve => {
  console.log('✅ NVD API working!');
  console.log('CVE:', cve.id);
}).catch(err => console.error('❌ Error:', err));
"
```

### Service Management
```bash
# Start all services
docker-compose up -d  # If using docker-compose
# OR
cd backend && npm start

# Stop services
docker stop cobra-redis
docker stop $(docker ps -q --filter ancestor=cobra-ai-kali-pentest)

# View logs
docker logs cobra-redis
tail -f backend/logs/combined.log

# Clean up
docker system prune -a --volumes
```

### Development Commands
```bash
# Watch mode (if configured)
cd backend && npm run dev

# Run tests
npm test

# Lint code
npm run lint

# Build frontend
cd frontend && npm run build
```

---

## Environment Variables

Create or update `backend/.env`:

```bash
# Required
NVD_API_KEY=your_nvd_api_key_here
REDIS_URL=redis://localhost:6379
DOCKER_HOST=unix:///var/run/docker.sock

# Optional (for enhanced features)
OPENAI_API_KEY=your_openai_key_for_embeddings
OLLAMA_URL=http://localhost:11434

# Database (if not already set)
DATABASE_URL=postgresql://user:pass@localhost:5432/cobra_ai

# AI Services (existing)
ANTHROPIC_API_KEY=your_claude_key
GOOGLE_API_KEY=your_gemini_key
```

---

## Docker Commands

### Kali Container Management
```bash
# Build with no cache (if updates needed)
docker build --no-cache -f Dockerfile.kali-pentest -t cobra-ai-kali-pentest:latest .

# Run interactive shell in Kali container
docker run -it cobra-ai-kali-pentest:latest /bin/bash

# Execute tool in container
docker run --rm cobra-ai-kali-pentest:latest nmap --version

# Check container resource usage
docker stats cobra-ai-kali-pentest
```

### Redis Commands
```bash
# Connect to Redis CLI
docker exec -it cobra-redis redis-cli

# Check keys
docker exec cobra-redis redis-cli KEYS "*"

# Monitor commands
docker exec cobra-redis redis-cli MONITOR

# Get Redis info
docker exec cobra-redis redis-cli INFO
```

---

## Monitoring & Debugging

### Check Service Health
```bash
# Backend API
curl http://localhost:3000/health

# Redis
docker exec cobra-redis redis-cli ping

# Check active jobs
curl http://localhost:3000/api/jobs/stats

# Check threat intel status
curl http://localhost:3000/api/threat-intel/stats
```

### View Logs
```bash
# Backend logs
tail -f backend/logs/combined.log
tail -f backend/logs/error.log
tail -f backend/logs/audit.log

# Redis logs
docker logs -f cobra-redis

# Docker container logs
docker logs -f $(docker ps -q --filter ancestor=cobra-ai-kali-pentest)
```

### Performance Monitoring
```bash
# Memory usage
docker stats --no-stream

# Process monitoring
ps aux | grep node

# Network connections
netstat -an | grep 3000
netstat -an | grep 6379
```

---

## Troubleshooting Quick Fixes

### Redis Connection Issues
```bash
# Restart Redis
docker restart cobra-redis

# Check if port is in use
lsof -i :6379

# Clear Redis data (WARNING: deletes all cached data)
docker exec cobra-redis redis-cli FLUSHALL
```

### Docker Issues
```bash
# Clean up stopped containers
docker container prune

# Clean up unused images
docker image prune -a

# Rebuild from scratch
docker system prune -a --volumes
docker build -f Dockerfile.kali-pentest -t cobra-ai-kali-pentest:latest .
```

### Node Module Issues
```bash
# Clean install
rm -rf node_modules package-lock.json
npm install

# Clear npm cache
npm cache clean --force
```

### Permission Issues
```bash
# Docker socket permissions
sudo chmod 666 /var/run/docker.sock

# Log directory permissions
sudo chown -R $USER:$USER backend/logs
sudo chown -R $USER:$USER backend/data
```

---

## Performance Tuning

### Redis Configuration
```bash
# Set max memory
docker exec cobra-redis redis-cli CONFIG SET maxmemory 2gb
docker exec cobra-redis redis-cli CONFIG SET maxmemory-policy allkeys-lru

# Enable persistence
docker exec cobra-redis redis-cli CONFIG SET save "900 1 300 10 60 10000"
```

### Node.js Optimization
```bash
# Increase heap size (add to package.json scripts)
"start": "node --max-old-space-size=4096 server.js"

# Enable worker threads
NODE_OPTIONS="--max-old-space-size=4096 --experimental-worker" npm start
```

### Database Optimization
```sql
-- Run in PostgreSQL
VACUUM ANALYZE;
REINDEX DATABASE cobra_ai;

-- Add indexes (if not already present)
CREATE INDEX CONCURRENTLY idx_vulnerabilities_created_at ON vulnerabilities(created_at DESC);
CREATE INDEX CONCURRENTLY idx_scan_results_severity ON scan_results(severity);
```

---

## Useful Aliases

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
# Cobra AI shortcuts
alias cobra-start='cd ~/Downloads/"Cobra-AI-webapp (1)"/Cobra-AI-webapp && ./install-pentest-fixes.sh'
alias cobra-logs='tail -f ~/Downloads/"Cobra-AI-webapp (1)"/Cobra-AI-webapp/backend/logs/combined.log'
alias cobra-redis='docker exec -it cobra-redis redis-cli'
alias cobra-status='docker ps | grep cobra && redis-cli -h localhost ping'
alias cobra-clean='docker stop cobra-redis && docker system prune -f'
```

---

## Testing Checklist

### ✅ Pre-Deployment Tests

```bash
# 1. Redis connectivity
docker exec cobra-redis redis-cli ping

# 2. NVD API
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"

# 3. Backend health
curl http://localhost:3000/health

# 4. WebSocket connection
wscat -c ws://localhost:3000/pentest/test-session

# 5. Job queue
curl http://localhost:3000/api/jobs/stats

# 6. Docker execution
docker run --rm cobra-ai-kali-pentest:latest nmap --version

# 7. ML similarity (if OpenAI key set)
# Test via API endpoint

# 8. Threat intelligence
curl http://localhost:3000/api/threat-intel/recent

# 9. Learning system
# Check if data directory exists and is writable
ls -la backend/data/learning/

# 10. Frontend build
cd frontend && npm run build
```

---

## Quick Reference Card

| Task | Command |
|------|---------|
| **Install** | `./install-pentest-fixes.sh` |
| **Start Redis** | `docker run -d --name cobra-redis -p 6379:6379 redis:alpine` |
| **Start Backend** | `cd backend && npm start` |
| **View Logs** | `tail -f backend/logs/combined.log` |
| **Check Status** | `docker ps \| grep cobra` |
| **Test NVD** | See test command above |
| **Clean Up** | `docker stop cobra-redis && docker system prune -f` |
| **Rebuild Kali** | `docker build -f Dockerfile.kali-pentest -t cobra-ai-kali-pentest:latest .` |
| **Redis CLI** | `docker exec -it cobra-redis redis-cli` |
| **Get NVD Key** | Visit: https://nvd.nist.gov/developers/request-an-api-key |

---

## Support & Resources

### Documentation
- Main guide: `PENTEST_SYSTEM_FIXES_COMPLETE.md`
- Quick start: `QUICK_START_GUIDE.md`
- Optimization: `ULTIMATE_OPTIMIZATION_PLAN.md`
- Summary: `COMPLETE_SYSTEM_SUMMARY.md`

### External Resources
- NVD API: https://nvd.nist.gov/developers
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities
- OWASP Top 10: https://owasp.org/Top10/
- Docker Docs: https://docs.docker.com/
- Bull Queue: https://optimalbits.github.io/bull/
- Redis: https://redis.io/documentation

---

**Ready to go! Run `./install-pentest-fixes.sh` to start! 🚀**

