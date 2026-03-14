# Redis Integration for Zypheron API

This document describes the Redis configuration for the Zypheron API project.

## Overview

Redis has been integrated into the Zypheron API Docker Compose stack for caching and rate limiting functionality. The service runs automatically when you start the Docker Compose stack.

## Configuration Details

### Redis Service Specifications

- **Image:** redis:7-alpine
- **Container Name:** zypheron-redis
- **Port:** 6379 (exposed to host)
- **Network:** zypheron-network (shared with PostgreSQL and other services)

### Persistence Configuration

Redis is configured with multiple persistence strategies for data durability:

#### AOF (Append Only File)
- **Enabled:** Yes
- **Sync Strategy:** `everysec` - fsync every second (good balance between performance and durability)
- **Purpose:** Logs every write operation for crash recovery

#### RDB Snapshots
Redis also performs periodic snapshots:
- Every 60 seconds if at least 1000 keys changed
- Every 300 seconds (5 minutes) if at least 100 keys changed
- Every 3600 seconds (1 hour) if at least 1 key changed

### Memory Management

- **Max Memory:** 256MB
- **Eviction Policy:** `allkeys-lru` (Least Recently Used)
- When max memory is reached, Redis will evict the least recently used keys across all keys

### Security

- **Password Protection:** Enabled
- **Default Password:** `zypheron_redis_password`
- **Important:** Change the password in production by updating:
  - `docker-compose.yml`: `command` section and `REDIS_PASSWORD` environment variable
  - `.env`: `REDIS_PASSWORD` and `REDIS_URL`

### Health Check

The Redis service includes a health check that runs every 10 seconds:
- **Test Command:** `redis-cli -a <password> ping`
- **Interval:** 10 seconds
- **Timeout:** 5 seconds
- **Retries:** 5
- **Start Period:** 10 seconds

## Environment Variables

The following environment variables are available in `.env`:

```bash
# Redis Configuration
REDIS_ENABLED=true
REDIS_URL=redis://:zypheron_redis_password@redis:6379/0
REDIS_PASSWORD=zypheron_redis_password
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=0
```

### Environment Variable Descriptions

- **REDIS_ENABLED:** Enable/disable Redis functionality in the API
- **REDIS_URL:** Full connection URL (includes password)
- **REDIS_PASSWORD:** Redis authentication password
- **REDIS_HOST:** Redis hostname (use `redis` for Docker, `localhost` for local dev)
- **REDIS_PORT:** Redis port number
- **REDIS_DB:** Redis database number (0-15)

## Usage

### Starting the Stack

Start all services (including Redis):
```bash
docker-compose up -d
```

Start specific services:
```bash
docker-compose up -d postgres redis
```

### Accessing Redis CLI

Connect to Redis from the host:
```bash
redis-cli -h localhost -p 6379 -a zypheron_redis_password
```

Connect to Redis inside the container:
```bash
docker exec -it zypheron-redis redis-cli -a zypheron_redis_password
```

### Common Redis Commands

```bash
# Ping the server
PING

# Check memory usage
INFO memory

# Get all keys (use with caution in production)
KEYS *

# Get a specific key
GET key_name

# Set a key with expiration
SETEX key_name 3600 "value"

# Check key TTL
TTL key_name

# Get database statistics
INFO stats

# Monitor real-time commands
MONITOR
```

### Monitoring

Check Redis service health:
```bash
docker-compose ps redis
```

View Redis logs:
```bash
docker-compose logs -f redis
```

Check Redis memory and performance stats:
```bash
docker exec -it zypheron-redis redis-cli -a zypheron_redis_password INFO
```

## Data Persistence

Redis data is persisted in a Docker volume named `redis_data`:

### View Volume Information
```bash
docker volume inspect zypheron-api_redis_data
```

### Backup Redis Data

1. Create a backup:
```bash
# Trigger a save operation
docker exec -it zypheron-redis redis-cli -a zypheron_redis_password SAVE

# Copy the dump file
docker cp zypheron-redis:/data/dump.rdb ./backup-dump.rdb
docker cp zypheron-redis:/data/appendonly.aof ./backup-appendonly.aof
```

2. Restore from backup:
```bash
# Stop Redis
docker-compose stop redis

# Copy backup files to volume
docker cp ./backup-dump.rdb zypheron-redis:/data/dump.rdb
docker cp ./backup-appendonly.aof zypheron-redis:/data/appendonly.aof

# Start Redis
docker-compose start redis
```

## Integration with API

The API service can connect to Redis using the environment variables. Example Python connection:

```python
import redis.asyncio as redis
from app.core.config import settings

# Create Redis connection
redis_client = redis.from_url(
    settings.REDIS_URL,
    encoding="utf-8",
    decode_responses=True
)

# Or using individual parameters
redis_client = redis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    password=settings.REDIS_PASSWORD,
    decode_responses=True
)
```

## Use Cases

### 1. Caching
Cache frequently accessed data to reduce database load:
```python
# Cache API responses
await redis_client.setex(f"cache:{cache_key}", 3600, json.dumps(data))
cached = await redis_client.get(f"cache:{cache_key}")
```

### 2. Rate Limiting
Implement rate limiting per user/API key:
```python
# Rate limit example
key = f"rate_limit:{user_id}:{window}"
current = await redis_client.incr(key)
if current == 1:
    await redis_client.expire(key, window_seconds)
if current > limit:
    raise RateLimitExceeded()
```

### 3. Session Storage
Store user sessions:
```python
# Store session
await redis_client.setex(f"session:{session_id}", 3600, session_data)
```

### 4. Pub/Sub Messaging
Real-time messaging between services:
```python
# Publisher
await redis_client.publish("notifications", message)

# Subscriber
pubsub = redis_client.pubsub()
await pubsub.subscribe("notifications")
```

## Performance Tuning

### For High-Traffic Scenarios

Modify the Redis configuration in `docker-compose.yml`:

```yaml
command: >
  redis-server
  --appendonly yes
  --appendfsync no  # Better performance, less durability
  --maxmemory 512mb  # Increase memory limit
  --maxmemory-policy allkeys-lru
  --tcp-backlog 511
  --timeout 0
  --tcp-keepalive 300
```

### For Maximum Durability

```yaml
command: >
  redis-server
  --appendonly yes
  --appendfsync always  # Sync after every write (slower but safest)
  --maxmemory 256mb
  --maxmemory-policy noeviction  # Don't evict keys, fail writes instead
```

## Troubleshooting

### Connection Issues

1. Check if Redis is running:
```bash
docker-compose ps redis
```

2. Test Redis connectivity:
```bash
docker exec -it zypheron-redis redis-cli -a zypheron_redis_password PING
```

3. Check Redis logs:
```bash
docker-compose logs redis
```

### Memory Issues

1. Check memory usage:
```bash
docker exec -it zypheron-redis redis-cli -a zypheron_redis_password INFO memory
```

2. Clear all data (CAUTION):
```bash
docker exec -it zypheron-redis redis-cli -a zypheron_redis_password FLUSHALL
```

3. Remove specific keys:
```bash
docker exec -it zypheron-redis redis-cli -a zypheron_redis_password DEL key_name
```

### Performance Issues

1. Monitor slow queries:
```bash
docker exec -it zypheron-redis redis-cli -a zypheron_redis_password SLOWLOG GET 10
```

2. Check connected clients:
```bash
docker exec -it zypheron-redis redis-cli -a zypheron_redis_password CLIENT LIST
```

## Security Best Practices

1. **Change Default Password:** Update `REDIS_PASSWORD` in production
2. **Network Isolation:** Redis is only accessible within the Docker network
3. **Don't Expose Port:** For production, remove the ports mapping if Redis doesn't need external access
4. **Use TLS:** For production, consider enabling TLS encryption
5. **Regular Backups:** Implement automated backup strategy
6. **Monitor Access:** Regularly review Redis logs for suspicious activity

## Production Recommendations

1. **Increase Memory:** Adjust `maxmemory` based on your caching needs
2. **Use Dedicated Host:** For high traffic, run Redis on a dedicated server
3. **Enable Monitoring:** Use Redis monitoring tools (RedisInsight, Grafana)
4. **Set Up Replication:** Configure Redis Sentinel or Redis Cluster for high availability
5. **Implement Backup Strategy:** Automate daily backups of Redis data
6. **Use Strong Password:** Generate a cryptographically secure password
7. **Tune Persistence:** Choose between RDB, AOF, or both based on durability requirements
8. **Connection Pooling:** Use connection pools in your application

## Additional Resources

- [Redis Official Documentation](https://redis.io/documentation)
- [Redis Best Practices](https://redis.io/topics/best-practices)
- [Redis Persistence](https://redis.io/topics/persistence)
- [Redis Security](https://redis.io/topics/security)
- [Redis Monitoring](https://redis.io/topics/monitoring)
