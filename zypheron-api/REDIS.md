# Redis

Redis is an optional dependency used for rate limiting, caching, and session storage. The API works without Redis; rate limiting is simply disabled.

## Quick Start

```bash
# Start Redis via Docker Compose
docker-compose --profile cache up -d redis

# Or standalone Docker
docker run -d -p 6379:6379 --name zypheron-redis redis:7-alpine

# Or install locally
brew install redis && brew services start redis          # macOS
sudo apt install redis-server && sudo systemctl start redis  # Ubuntu
```

## Configuration

Add to `.env`:

```bash
REDIS_ENABLED=true
REDIS_URL=redis://:zypheron_redis_password@localhost:6379/0
REDIS_PASSWORD=zypheron_redis_password
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
```

For Docker networking, use `REDIS_HOST=redis` instead of `localhost`.

For production with TLS:

```bash
REDIS_URL=rediss://default:PASSWORD@HOST:PORT
REDIS_SSL=true
```

## Docker Compose Details

- **Image:** redis:7-alpine
- **Container:** zypheron-redis
- **Port:** 6379
- **Volume:** `redis_data` (persistent)
- **Password:** `zypheron_redis_password` (change in production)
- **Memory limit:** 256MB with LRU eviction
- **Persistence:** AOF (everysec) + RDB snapshots

## Common Commands

```bash
# Access Redis CLI
docker exec -it zypheron-redis redis-cli -a zypheron_redis_password

# Or from host
redis-cli -h localhost -p 6379 -a zypheron_redis_password
```

```
PING                          # Test connection
INFO memory                   # Memory stats
DBSIZE                        # Number of keys
KEYS *                        # List all keys (dev only)
GET key                       # Get value
SETEX key 3600 value          # Set with TTL
TTL key                       # Check TTL
DEL key                       # Delete key
FLUSHALL                      # Clear all data (CAUTION)
MONITOR                       # Watch commands in real-time
SLOWLOG GET 10                # Recent slow queries
CLIENT LIST                   # Connected clients
```

## Python Connection

```python
import redis.asyncio as aioredis
from app.core.config import settings

# Via URL
redis_client = aioredis.from_url(
    settings.REDIS_URL,
    encoding="utf-8",
    decode_responses=True
)

# Via parameters
redis_client = aioredis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    password=settings.REDIS_PASSWORD,
    decode_responses=True
)

await redis_client.ping()
```

## Use Cases in Zypheron API

**Rate Limiting** (sliding window with sorted sets):
```python
key = f"rate_limit:{user_id}:{window}"
current = await redis_client.incr(key)
if current == 1:
    await redis_client.expire(key, window_seconds)
```

**Caching** (API responses):
```python
await redis_client.setex(f"cache:{key}", 3600, json.dumps(data))
cached = await redis_client.get(f"cache:{key}")
```

**Session Storage:**
```python
await redis_client.setex(f"session:{session_id}", 1800, json.dumps(data))
```

## Backup / Restore

```bash
# Backup
docker exec zypheron-redis redis-cli -a zypheron_redis_password SAVE
docker cp zypheron-redis:/data/dump.rdb ./redis-backup.rdb

# Restore
docker-compose stop redis
docker cp ./redis-backup.rdb zypheron-redis:/data/dump.rdb
docker-compose start redis
```

## Monitoring

```bash
docker-compose ps redis                    # Check status
docker-compose logs -f redis               # View logs
docker inspect zypheron-redis --format='{{.State.Health.Status}}'  # Health
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Connection refused | `docker-compose ps redis` / restart |
| Auth failed | Check REDIS_PASSWORD matches docker-compose.yml |
| High memory | Check `INFO memory`, adjust maxmemory |
| Slow queries | `SLOWLOG GET 10` to identify |

## Production Checklist

- Change default password to a strong random value
- Use TLS (`rediss://` scheme)
- Do not expose port 6379 publicly
- Set appropriate `maxmemory` for workload
- Set up automated backups
- Consider Redis Sentinel or Cluster for HA
