# Redis Quick Reference - Zypheron API

Quick reference for common Redis operations in the Zypheron project.

## Connection Info

```bash
Host: redis (Docker) / localhost (local)
Port: 6379
Password: zypheron_redis_password
Database: 0
```

## Docker Commands

```bash
# Start Redis
docker compose up -d redis

# Stop Redis
docker compose stop redis

# Restart Redis
docker compose restart redis

# View logs
docker compose logs -f redis

# Check status
docker compose ps redis

# Access CLI
docker exec -it zypheron-redis redis-cli -a zypheron_redis_password
```

## Redis CLI Commands

```bash
# Basic operations
PING                                    # Test connection
INFO                                    # Server info
INFO memory                             # Memory stats
INFO stats                              # Statistics
DBSIZE                                  # Number of keys
MONITOR                                 # Watch commands in real-time

# Key operations
SET key value                           # Set a key
GET key                                 # Get a key
DEL key                                 # Delete a key
EXISTS key                              # Check if key exists
EXPIRE key 3600                         # Set expiration (seconds)
TTL key                                 # Time to live
KEYS pattern                            # Find keys (use with caution)
SCAN 0 MATCH pattern COUNT 100          # Iterate keys (safer)

# String operations
SETEX key 3600 value                    # Set with expiration
MSET key1 val1 key2 val2               # Set multiple
MGET key1 key2                          # Get multiple
INCR counter                            # Increment
DECR counter                            # Decrement
APPEND key value                        # Append to string

# Hash operations
HSET user:1 name "John"                 # Set hash field
HGET user:1 name                        # Get hash field
HGETALL user:1                          # Get all fields
HMSET user:1 name "John" email "j@e.com" # Set multiple fields
HDEL user:1 field                       # Delete field

# List operations
LPUSH queue task                        # Push to left
RPUSH queue task                        # Push to right
LPOP queue                              # Pop from left
RPOP queue                              # Pop from right
LLEN queue                              # List length
LRANGE queue 0 -1                       # Get all items

# Set operations
SADD set member                         # Add to set
SREM set member                         # Remove from set
SMEMBERS set                            # Get all members
SISMEMBER set member                    # Check membership
SCARD set                               # Set size

# Sorted Set operations
ZADD leaderboard 100 user1              # Add with score
ZRANGE leaderboard 0 -1                 # Get range
ZRANK leaderboard user1                 # Get rank
ZSCORE leaderboard user1                # Get score

# Pub/Sub
SUBSCRIBE channel                       # Subscribe
PUBLISH channel message                 # Publish
UNSUBSCRIBE channel                     # Unsubscribe
```

## Python Connection

```python
import redis.asyncio as aioredis
import os

# Method 1: URL
redis_client = aioredis.from_url(
    os.getenv("REDIS_URL"),
    encoding="utf-8",
    decode_responses=True
)

# Method 2: Parameters
redis_client = aioredis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    db=int(os.getenv("REDIS_DB", 0)),
    password=os.getenv("REDIS_PASSWORD"),
    decode_responses=True
)

# Test connection
await redis_client.ping()
```

## Common Patterns

### Caching
```python
# Set cache
cache_key = f"cache:api:user:{user_id}"
await redis_client.setex(cache_key, 3600, json.dumps(data))

# Get cache
cached = await redis_client.get(cache_key)
if cached:
    data = json.loads(cached)
```

### Rate Limiting
```python
# Sliding window rate limit
window = 60  # seconds
limit = 100  # requests

key = f"rate:{user_id}:{int(time.time() / window)}"
count = await redis_client.incr(key)
if count == 1:
    await redis_client.expire(key, window)

if count > limit:
    raise RateLimitExceeded()
```

### Session Storage
```python
# Store session
session_key = f"session:{session_id}"
await redis_client.setex(
    session_key,
    1800,  # 30 minutes
    json.dumps(session_data)
)

# Get session
session = await redis_client.get(session_key)
if session:
    data = json.loads(session)
```

### Distributed Lock
```python
# Acquire lock
lock_key = f"lock:{resource_id}"
acquired = await redis_client.set(
    lock_key,
    "locked",
    nx=True,  # Only if not exists
    ex=10     # Expire in 10 seconds
)

if acquired:
    try:
        # Do work
        pass
    finally:
        # Release lock
        await redis_client.delete(lock_key)
```

### Queue
```python
# Add to queue
await redis_client.rpush("task_queue", json.dumps(task))

# Process queue
while True:
    task_json = await redis_client.lpop("task_queue")
    if not task_json:
        break
    task = json.loads(task_json)
    # Process task
```

### Pub/Sub
```python
# Publisher
await redis_client.publish("notifications", json.dumps(message))

# Subscriber
pubsub = redis_client.pubsub()
await pubsub.subscribe("notifications")

async for message in pubsub.listen():
    if message['type'] == 'message':
        data = json.loads(message['data'])
        # Handle message
```

## Environment Variables

```bash
# .env file
REDIS_ENABLED=true
REDIS_URL=redis://:zypheron_redis_password@redis:6379/0
REDIS_PASSWORD=zypheron_redis_password
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=0
```

## Testing

```bash
# Test script
./scripts/test-redis.sh

# Python examples
python scripts/redis-example.py

# Manual test
docker exec zypheron-redis redis-cli -a zypheron_redis_password PING
```

## Monitoring

```bash
# Memory usage
docker exec zypheron-redis redis-cli -a zypheron_redis_password INFO memory | grep used_memory_human

# Connected clients
docker exec zypheron-redis redis-cli -a zypheron_redis_password CLIENT LIST

# Slow queries
docker exec zypheron-redis redis-cli -a zypheron_redis_password SLOWLOG GET 10

# Commands per second
docker exec zypheron-redis redis-cli -a zypheron_redis_password INFO stats | grep instantaneous_ops_per_sec
```

## Backup & Restore

```bash
# Backup
docker exec zypheron-redis redis-cli -a zypheron_redis_password SAVE
docker cp zypheron-redis:/data/dump.rdb ./redis-backup.rdb

# Restore
docker compose stop redis
docker cp ./redis-backup.rdb zypheron-redis:/data/dump.rdb
docker compose start redis
```

## Troubleshooting

```bash
# Check if running
docker compose ps redis

# View logs
docker compose logs --tail=100 redis

# Test connection
docker exec zypheron-redis redis-cli -a zypheron_redis_password PING

# Check health
docker inspect zypheron-redis --format='{{.State.Health.Status}}'

# Restart
docker compose restart redis

# Full reset (deletes all data)
docker compose down -v
docker compose up -d
```

## Performance Tips

1. Use pipelines for multiple operations
2. Prefer SCAN over KEYS in production
3. Set appropriate expiration on cached data
4. Use connection pooling
5. Monitor memory usage regularly
6. Use appropriate data structures (Hash vs String)
7. Consider read replicas for high read loads

## Security Checklist

- [ ] Change default password in production
- [ ] Use TLS for production connections
- [ ] Don't expose port 6379 publicly
- [ ] Implement network-level access controls
- [ ] Regular security audits
- [ ] Monitor for suspicious activity
- [ ] Keep Redis updated

## Production Checklist

- [ ] Update REDIS_PASSWORD to strong random value
- [ ] Configure appropriate maxmemory for workload
- [ ] Set up automated backups
- [ ] Implement monitoring and alerting
- [ ] Configure Redis persistence strategy
- [ ] Test disaster recovery procedures
- [ ] Document runbooks for common issues
- [ ] Set up Redis Sentinel for HA (if needed)

## Useful Links

- [Redis Commands](https://redis.io/commands)
- [Redis Data Types](https://redis.io/topics/data-types)
- [Redis Best Practices](https://redis.io/topics/best-practices)
- [redis-py Async Docs](https://redis.readthedocs.io/en/stable/)

---

For detailed documentation, see `REDIS_SETUP.md`
