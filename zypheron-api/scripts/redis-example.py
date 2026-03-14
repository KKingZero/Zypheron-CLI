#!/usr/bin/env python3
"""
Redis Connection Example for Zypheron API

This script demonstrates how to connect to Redis and perform common operations.
It can be used for testing Redis connectivity and as a reference for integration.

Usage:
    python scripts/redis-example.py
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from typing import Optional

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    import redis.asyncio as aioredis
except ImportError:
    print("Error: redis package not installed")
    print("Install it with: pip install redis")
    sys.exit(1)


class RedisExample:
    """Example class demonstrating Redis operations for Zypheron API."""

    def __init__(self):
        """Initialize Redis connection from environment variables."""
        self.redis_url = os.getenv(
            "REDIS_URL",
            "redis://:zypheron_redis_password@localhost:6379/0"
        )
        self.redis_host = os.getenv("REDIS_HOST", "localhost")
        self.redis_port = int(os.getenv("REDIS_PORT", "6379"))
        self.redis_password = os.getenv("REDIS_PASSWORD", "zypheron_redis_password")
        self.redis_db = int(os.getenv("REDIS_DB", "0"))
        self.client: Optional[aioredis.Redis] = None

    async def connect(self) -> bool:
        """
        Establish connection to Redis.

        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            # Method 1: Connect using URL
            self.client = aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=5
            )

            # Test connection
            await self.client.ping()
            print(f"✓ Connected to Redis at {self.redis_host}:{self.redis_port}")
            return True

        except aioredis.ConnectionError as e:
            print(f"✗ Failed to connect to Redis: {e}")
            return False
        except Exception as e:
            print(f"✗ Unexpected error connecting to Redis: {e}")
            return False

    async def disconnect(self):
        """Close Redis connection."""
        if self.client:
            await self.client.close()
            print("✓ Disconnected from Redis")

    async def example_basic_operations(self):
        """Demonstrate basic Redis operations."""
        print("\n" + "=" * 50)
        print("Basic Operations Example")
        print("=" * 50)

        # SET and GET
        await self.client.set("user:1:name", "John Doe")
        name = await self.client.get("user:1:name")
        print(f"GET user:1:name = {name}")

        # SET with expiration (5 minutes)
        await self.client.setex("session:abc123", 300, "user_data")
        ttl = await self.client.ttl("session:abc123")
        print(f"TTL session:abc123 = {ttl} seconds")

        # Increment counter
        await self.client.incr("page_views")
        views = await self.client.get("page_views")
        print(f"Page views = {views}")

        # Multiple operations
        await self.client.mset({
            "user:1:email": "john@example.com",
            "user:1:role": "admin"
        })
        user_data = await self.client.mget("user:1:name", "user:1:email", "user:1:role")
        print(f"User data = {user_data}")

    async def example_caching(self):
        """Demonstrate caching patterns."""
        print("\n" + "=" * 50)
        print("Caching Example")
        print("=" * 50)

        cache_key = "api:vulnerabilities:CVE-2024-1234"
        cache_ttl = 3600  # 1 hour

        # Simulate API response
        api_response = {
            "id": "CVE-2024-1234",
            "severity": "HIGH",
            "description": "Example vulnerability",
            "published": datetime.now().isoformat()
        }

        # Cache the response
        await self.client.setex(
            cache_key,
            cache_ttl,
            json.dumps(api_response)
        )
        print(f"✓ Cached response for {cache_key}")

        # Retrieve from cache
        cached_data = await self.client.get(cache_key)
        if cached_data:
            data = json.loads(cached_data)
            print(f"✓ Retrieved from cache: {data['id']}")

        # Check cache hit/miss pattern
        keys = await self.client.keys("api:*")
        print(f"Total cached API responses: {len(keys)}")

    async def example_rate_limiting(self):
        """Demonstrate rate limiting implementation."""
        print("\n" + "=" * 50)
        print("Rate Limiting Example")
        print("=" * 50)

        user_id = "user123"
        window = 60  # 60 second window
        limit = 10  # 10 requests per minute

        rate_key = f"rate_limit:{user_id}:{datetime.now().minute}"

        # Simulate multiple requests
        for i in range(12):
            # Increment request counter
            count = await self.client.incr(rate_key)

            # Set expiration on first request
            if count == 1:
                await self.client.expire(rate_key, window)

            # Check if limit exceeded
            if count <= limit:
                print(f"Request {i+1}: ✓ Allowed (count: {count}/{limit})")
            else:
                print(f"Request {i+1}: ✗ Rate limit exceeded (count: {count}/{limit})")

    async def example_session_management(self):
        """Demonstrate session storage."""
        print("\n" + "=" * 50)
        print("Session Management Example")
        print("=" * 50)

        session_id = "sess_abc123xyz"
        session_ttl = 1800  # 30 minutes

        session_data = {
            "user_id": "user123",
            "email": "user@example.com",
            "role": "admin",
            "created_at": datetime.now().isoformat(),
            "last_activity": datetime.now().isoformat()
        }

        # Store session
        session_key = f"session:{session_id}"
        await self.client.setex(
            session_key,
            session_ttl,
            json.dumps(session_data)
        )
        print(f"✓ Created session: {session_id}")

        # Retrieve session
        stored_session = await self.client.get(session_key)
        if stored_session:
            session = json.loads(stored_session)
            print(f"✓ Session user: {session['email']}")

        # Update session activity
        session_data["last_activity"] = datetime.now().isoformat()
        await self.client.setex(session_key, session_ttl, json.dumps(session_data))
        print(f"✓ Updated session activity")

        # Check remaining TTL
        ttl = await self.client.ttl(session_key)
        print(f"Session expires in {ttl} seconds")

    async def example_pub_sub(self):
        """Demonstrate pub/sub messaging."""
        print("\n" + "=" * 50)
        print("Pub/Sub Messaging Example")
        print("=" * 50)

        channel = "notifications"

        # Create subscriber
        pubsub = self.client.pubsub()
        await pubsub.subscribe(channel)
        print(f"✓ Subscribed to channel: {channel}")

        # Publish message
        message = json.dumps({
            "type": "alert",
            "message": "New vulnerability detected",
            "timestamp": datetime.now().isoformat()
        })
        await self.client.publish(channel, message)
        print(f"✓ Published message to {channel}")

        # Receive message (with timeout)
        try:
            received = await asyncio.wait_for(pubsub.get_message(ignore_subscribe_messages=True), timeout=2.0)
            if received and received['type'] == 'message':
                data = json.loads(received['data'])
                print(f"✓ Received: {data['message']}")
        except asyncio.TimeoutError:
            print("No messages received (timeout)")

        await pubsub.unsubscribe(channel)
        await pubsub.close()

    async def example_lists(self):
        """Demonstrate list operations for queues."""
        print("\n" + "=" * 50)
        print("List/Queue Example")
        print("=" * 50)

        queue_key = "task_queue"

        # Add tasks to queue
        tasks = ["scan:repo1", "scan:repo2", "scan:repo3"]
        for task in tasks:
            await self.client.rpush(queue_key, task)
        print(f"✓ Added {len(tasks)} tasks to queue")

        # Get queue length
        queue_length = await self.client.llen(queue_key)
        print(f"Queue length: {queue_length}")

        # Process tasks
        while await self.client.llen(queue_key) > 0:
            task = await self.client.lpop(queue_key)
            print(f"Processing task: {task}")

        print("✓ All tasks processed")

    async def example_sets(self):
        """Demonstrate set operations for unique collections."""
        print("\n" + "=" * 50)
        print("Set Operations Example")
        print("=" * 50)

        # Track unique users
        await self.client.sadd("active_users", "user1", "user2", "user3")
        user_count = await self.client.scard("active_users")
        print(f"Active users: {user_count}")

        # Check membership
        is_active = await self.client.sismember("active_users", "user1")
        print(f"Is user1 active? {is_active}")

        # Get all members
        users = await self.client.smembers("active_users")
        print(f"All active users: {users}")

    async def example_hashes(self):
        """Demonstrate hash operations for structured data."""
        print("\n" + "=" * 50)
        print("Hash Operations Example")
        print("=" * 50)

        user_key = "user:profile:1"

        # Store user profile
        await self.client.hset(user_key, mapping={
            "name": "John Doe",
            "email": "john@example.com",
            "role": "admin",
            "api_key": "sk_test_123",
            "tier": "pro"
        })
        print(f"✓ Stored user profile")

        # Get specific field
        email = await self.client.hget(user_key, "email")
        print(f"User email: {email}")

        # Get all fields
        profile = await self.client.hgetall(user_key)
        print(f"Full profile: {profile}")

        # Update field
        await self.client.hset(user_key, "tier", "enterprise")
        print("✓ Updated user tier")

    async def cleanup_test_data(self):
        """Clean up all test data created by examples."""
        print("\n" + "=" * 50)
        print("Cleanup")
        print("=" * 50)

        patterns = [
            "user:*",
            "session:*",
            "api:*",
            "rate_limit:*",
            "task_queue",
            "active_users",
            "page_views"
        ]

        total_deleted = 0
        for pattern in patterns:
            keys = await self.client.keys(pattern)
            if keys:
                deleted = await self.client.delete(*keys)
                total_deleted += deleted

        print(f"✓ Cleaned up {total_deleted} test keys")

    async def get_redis_info(self):
        """Display Redis server information."""
        print("\n" + "=" * 50)
        print("Redis Server Information")
        print("=" * 50)

        info = await self.client.info()

        print(f"Redis Version: {info.get('redis_version')}")
        print(f"Connected Clients: {info.get('connected_clients')}")
        print(f"Used Memory: {info.get('used_memory_human')}")
        print(f"Total Commands: {info.get('total_commands_processed')}")
        print(f"Total Connections: {info.get('total_connections_received')}")

        # Database stats
        db_info = await self.client.info('keyspace')
        if 'db0' in db_info:
            db_stats = db_info['db0']
            print(f"Database 0 Keys: {db_stats.get('keys', 0)}")


async def main():
    """Run all Redis examples."""
    print("=" * 50)
    print("Zypheron Redis Integration Examples")
    print("=" * 50)

    example = RedisExample()

    # Connect to Redis
    if not await example.connect():
        print("\nFailed to connect to Redis. Make sure:")
        print("1. Docker Compose is running: docker-compose up -d redis")
        print("2. Environment variables are set correctly")
        return

    try:
        # Run all examples
        await example.example_basic_operations()
        await example.example_caching()
        await example.example_rate_limiting()
        await example.example_session_management()
        await example.example_lists()
        await example.example_sets()
        await example.example_hashes()
        await example.example_pub_sub()

        # Show server info
        await example.get_redis_info()

        # Cleanup
        await example.cleanup_test_data()

        print("\n" + "=" * 50)
        print("All examples completed successfully!")
        print("=" * 50)

    except Exception as e:
        print(f"\n✗ Error running examples: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Disconnect
        await example.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
