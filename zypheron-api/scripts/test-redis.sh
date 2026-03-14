#!/bin/bash

# Redis Connection Test Script for Zypheron API
# This script tests the Redis connection and basic operations

set -e

REDIS_PASSWORD="${REDIS_PASSWORD:-zypheron_redis_password}"
REDIS_HOST="${REDIS_HOST:-localhost}"
REDIS_PORT="${REDIS_PORT:-6379}"

echo "=========================================="
echo "Zypheron Redis Connection Test"
echo "=========================================="
echo ""

# Check if redis-cli is available
if ! command -v redis-cli &> /dev/null; then
    echo "Error: redis-cli is not installed."
    echo "Using Docker to test Redis connection instead..."
    echo ""

    # Test using docker exec
    echo "1. Testing Redis connection..."
    if docker exec zypheron-redis redis-cli -a "$REDIS_PASSWORD" PING > /dev/null 2>&1; then
        echo "   ✓ Redis is responding to PING"
    else
        echo "   ✗ Redis is not responding"
        exit 1
    fi

    echo ""
    echo "2. Testing SET/GET operations..."
    docker exec zypheron-redis redis-cli -a "$REDIS_PASSWORD" SET test_key "Hello from Zypheron" > /dev/null 2>&1
    TEST_VALUE=$(docker exec zypheron-redis redis-cli -a "$REDIS_PASSWORD" GET test_key 2>&1 | grep -v "Warning")
    if [ "$TEST_VALUE" = "Hello from Zypheron" ]; then
        echo "   ✓ SET/GET operations working"
    else
        echo "   ✗ SET/GET operations failed"
        exit 1
    fi

    echo ""
    echo "3. Cleaning up test data..."
    docker exec zypheron-redis redis-cli -a "$REDIS_PASSWORD" DEL test_key > /dev/null 2>&1
    echo "   ✓ Test key deleted"

    echo ""
    echo "4. Getting Redis info..."
    docker exec zypheron-redis redis-cli -a "$REDIS_PASSWORD" INFO server | grep "redis_version"

    echo ""
    echo "=========================================="
    echo "All tests passed! ✓"
    echo "Redis is ready for use."
    echo "=========================================="
    exit 0
fi

# If redis-cli is available locally
echo "1. Testing Redis connection to $REDIS_HOST:$REDIS_PORT..."
if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" PING > /dev/null 2>&1; then
    echo "   ✓ Redis is responding to PING"
else
    echo "   ✗ Redis is not responding"
    echo "   Make sure Redis is running: docker-compose up -d redis"
    exit 1
fi

echo ""
echo "2. Testing SET/GET operations..."
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" SET test_key "Hello from Zypheron" > /dev/null 2>&1
TEST_VALUE=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" GET test_key 2>&1 | grep -v "Warning")
if [ "$TEST_VALUE" = "Hello from Zypheron" ]; then
    echo "   ✓ SET/GET operations working"
else
    echo "   ✗ SET/GET operations failed"
    exit 1
fi

echo ""
echo "3. Testing key expiration..."
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" SETEX temp_key 5 "expires in 5 seconds" > /dev/null 2>&1
TTL=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" TTL temp_key 2>&1 | grep -v "Warning")
if [ "$TTL" -gt 0 ] && [ "$TTL" -le 5 ]; then
    echo "   ✓ Key expiration working (TTL: ${TTL}s)"
else
    echo "   ✗ Key expiration failed"
fi

echo ""
echo "4. Cleaning up test data..."
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" DEL test_key > /dev/null 2>&1
echo "   ✓ Test keys deleted"

echo ""
echo "5. Getting Redis statistics..."
echo ""
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" INFO stats 2>&1 | grep -v "Warning" | grep "total_connections_received\|total_commands_processed\|keyspace"

echo ""
echo "6. Getting memory info..."
echo ""
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" INFO memory 2>&1 | grep -v "Warning" | grep "used_memory_human\|maxmemory_human"

echo ""
echo "=========================================="
echo "All tests passed! ✓"
echo "Redis is ready for use."
echo "=========================================="
echo ""
echo "Useful commands:"
echo "  - Connect: redis-cli -h $REDIS_HOST -p $REDIS_PORT -a $REDIS_PASSWORD"
echo "  - Monitor: docker-compose logs -f redis"
echo "  - Stats: docker exec zypheron-redis redis-cli -a $REDIS_PASSWORD INFO"
echo ""
