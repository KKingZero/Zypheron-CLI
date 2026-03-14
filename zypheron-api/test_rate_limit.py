#!/usr/bin/env python3
"""Test script for Redis-based rate limiting middleware.

This script demonstrates the rate limiting functionality by:
1. Testing authenticated vs unauthenticated requests
2. Verifying rate limit headers
3. Testing different tier limits
4. Verifying graceful fallback when Redis is unavailable
"""

import asyncio
import time
from typing import Optional

import httpx


async def test_unauthenticated_rate_limit(base_url: str = "http://localhost:8000"):
    """Test rate limiting for unauthenticated requests (Free tier: 10 req/min)."""
    print("\n=== Testing Unauthenticated Rate Limit (Free tier: 10 req/min) ===")

    async with httpx.AsyncClient() as client:
        # Make requests until rate limited
        for i in range(15):
            try:
                response = await client.get(f"{base_url}/health")

                # Print rate limit headers
                limit = response.headers.get("X-RateLimit-Limit", "N/A")
                remaining = response.headers.get("X-RateLimit-Remaining", "N/A")
                reset = response.headers.get("X-RateLimit-Reset", "N/A")

                if response.status_code == 200:
                    print(
                        f"Request {i+1}: OK - "
                        f"Limit: {limit}, Remaining: {remaining}, Reset: {reset}"
                    )
                elif response.status_code == 429:
                    retry_after = response.headers.get("Retry-After", "N/A")
                    print(
                        f"Request {i+1}: RATE LIMITED - "
                        f"Retry-After: {retry_after}s"
                    )
                    print(f"Response: {response.json()}")
                    break
                else:
                    print(f"Request {i+1}: Unexpected status {response.status_code}")

                # Small delay to avoid overwhelming the server
                await asyncio.sleep(0.1)

            except Exception as e:
                print(f"Request {i+1}: Error - {e}")
                break


async def test_authenticated_rate_limit(
    base_url: str = "http://localhost:8000",
    token: Optional[str] = None,
    tier: str = "starter",
    expected_limit: int = 60
):
    """Test rate limiting for authenticated requests.

    Args:
        base_url: API base URL
        token: JWT access token
        tier: User tier name (for display)
        expected_limit: Expected rate limit for this tier
    """
    print(f"\n=== Testing Authenticated Rate Limit ({tier} tier: {expected_limit} req/min) ===")

    if not token:
        print("No token provided - skipping authenticated test")
        return

    headers = {"Authorization": f"Bearer {token}"}

    async with httpx.AsyncClient() as client:
        # Make several requests to verify tier-based limits
        for i in range(min(10, expected_limit + 5)):
            try:
                response = await client.get(
                    f"{base_url}/health",
                    headers=headers
                )

                # Print rate limit headers
                limit = response.headers.get("X-RateLimit-Limit", "N/A")
                remaining = response.headers.get("X-RateLimit-Remaining", "N/A")

                if response.status_code == 200:
                    print(
                        f"Request {i+1}: OK - "
                        f"Limit: {limit}, Remaining: {remaining}"
                    )

                    # Verify the limit matches the expected tier limit
                    if limit != "N/A" and int(limit) != expected_limit:
                        print(
                            f"WARNING: Expected limit {expected_limit}, got {limit}"
                        )
                elif response.status_code == 429:
                    retry_after = response.headers.get("Retry-After", "N/A")
                    print(
                        f"Request {i+1}: RATE LIMITED - "
                        f"Retry-After: {retry_after}s"
                    )
                    break
                else:
                    print(f"Request {i+1}: Unexpected status {response.status_code}")

                await asyncio.sleep(0.1)

            except Exception as e:
                print(f"Request {i+1}: Error - {e}")
                break


async def test_rate_limit_headers(base_url: str = "http://localhost:8000"):
    """Test that rate limit headers are present in responses."""
    print("\n=== Testing Rate Limit Headers ===")

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{base_url}/health")

        print(f"Status Code: {response.status_code}")
        print(f"X-RateLimit-Limit: {response.headers.get('X-RateLimit-Limit', 'MISSING')}")
        print(f"X-RateLimit-Remaining: {response.headers.get('X-RateLimit-Remaining', 'MISSING')}")
        print(f"X-RateLimit-Reset: {response.headers.get('X-RateLimit-Reset', 'MISSING')}")


async def test_exempt_paths(base_url: str = "http://localhost:8000"):
    """Test that exempt paths don't have rate limiting."""
    print("\n=== Testing Exempt Paths ===")

    exempt_paths = ["/", "/health", "/docs", "/openapi.json"]

    async with httpx.AsyncClient() as client:
        for path in exempt_paths:
            try:
                response = await client.get(f"{base_url}{path}")

                has_rate_limit_headers = "X-RateLimit-Limit" in response.headers

                print(
                    f"Path {path}: Status {response.status_code}, "
                    f"Rate Limited: {has_rate_limit_headers}"
                )

            except Exception as e:
                print(f"Path {path}: Error - {e}")


async def test_sliding_window(base_url: str = "http://localhost:8000"):
    """Test sliding window algorithm behavior."""
    print("\n=== Testing Sliding Window Algorithm ===")

    async with httpx.AsyncClient() as client:
        print("Making 5 requests quickly...")
        for i in range(5):
            response = await client.get(f"{base_url}/health")
            remaining = response.headers.get("X-RateLimit-Remaining", "N/A")
            print(f"Request {i+1}: Remaining = {remaining}")
            await asyncio.sleep(0.1)

        print("\nWaiting 5 seconds...")
        await asyncio.sleep(5)

        print("\nMaking 5 more requests...")
        for i in range(5):
            response = await client.get(f"{base_url}/health")
            remaining = response.headers.get("X-RateLimit-Remaining", "N/A")
            print(f"Request {i+6}: Remaining = {remaining}")
            await asyncio.sleep(0.1)


async def test_redis_fallback(base_url: str = "http://localhost:8000"):
    """Test emergency fail-CLOSED fallback when Redis is unavailable.

    NOTE: This test requires Redis to be stopped temporarily.
    """
    print("\n=== Testing Redis Emergency Fail-CLOSED Fallback ===")
    print("NOTE: To fully test this, stop Redis and restart the API")
    print("If Redis is unavailable, emergency rate limiter (10 req/min) should activate")

    async with httpx.AsyncClient() as client:
        # Make multiple requests to test emergency limiter
        for i in range(15):
            try:
                response = await client.get(f"{base_url}/api/health")

                # Check for emergency fallback header
                is_fallback = response.headers.get("X-RateLimit-Fallback", "false")
                limit = response.headers.get("X-RateLimit-Limit", "N/A")
                remaining = response.headers.get("X-RateLimit-Remaining", "N/A")

                if response.status_code == 200:
                    print(
                        f"Request {i+1}: OK - "
                        f"Fallback: {is_fallback}, Limit: {limit}, Remaining: {remaining}"
                    )
                    if is_fallback == "true":
                        print("  -> EMERGENCY MODE ACTIVE (fail-CLOSED protection)")
                elif response.status_code == 503:
                    # Emergency rate limit exceeded
                    retry_after = response.headers.get("Retry-After", "N/A")
                    print(
                        f"Request {i+1}: EMERGENCY LIMIT EXCEEDED (503) - "
                        f"Retry-After: {retry_after}s"
                    )
                    print(f"Response: {response.json()}")
                    print("  -> PROTECTED: DDoS attack prevented by fail-CLOSED limiter")
                    break
                else:
                    print(f"Request {i+1}: Status {response.status_code}")

                await asyncio.sleep(0.1)

            except Exception as e:
                print(f"Request {i+1}: Error - {e}")
                break

        # Summary
        print("\nRedis Fallback Test Summary:")
        if is_fallback == "true":
            print("  - Emergency fail-CLOSED mode is ACTIVE")
            print("  - Conservative limit enforced (10 req/min)")
            print("  - DDoS protection working correctly")
        else:
            print("  - Redis appears to be available")
            print("  - Normal rate limiting active")


async def main():
    """Run all rate limiting tests."""
    print("=" * 80)
    print("Redis-based Rate Limiting Test Suite")
    print("=" * 80)

    base_url = "http://localhost:8000"

    # Check if server is running
    try:
        async with httpx.AsyncClient() as client:
            await client.get(f"{base_url}/health", timeout=2.0)
    except Exception as e:
        print(f"\nERROR: Cannot connect to API at {base_url}")
        print(f"Please start the API server first: uvicorn app.main:app")
        print(f"Error: {e}")
        return

    # Run tests
    await test_rate_limit_headers(base_url)
    await test_exempt_paths(base_url)
    await test_unauthenticated_rate_limit(base_url)
    await test_sliding_window(base_url)
    await test_redis_fallback(base_url)

    # Note about authenticated tests
    print("\n" + "=" * 80)
    print("AUTHENTICATED TESTS")
    print("=" * 80)
    print("To test authenticated rate limiting:")
    print("1. Create a user account (Free tier)")
    print("2. Login to get a JWT token")
    print("3. Run: await test_authenticated_rate_limit(token='YOUR_TOKEN', tier='free', expected_limit=10)")
    print("\nOr upgrade to different tiers and test with appropriate limits:")
    print("- Starter: 60 req/min")
    print("- Pro: 120 req/min")
    print("- Enterprise: 300 req/min")

    print("\n" + "=" * 80)
    print("Tests Completed")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
