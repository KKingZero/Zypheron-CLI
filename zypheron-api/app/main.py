"""Main FastAPI application for Zypheron API.

Entry point for the API server with:
- Database initialization
- CORS middleware
- Router registration
- WebSocket support for real-time scan updates
- Health check endpoint
"""

import json
import logging
import structlog
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from app.core.config import get_settings
from app.core.database import close_db, get_db, init_db
from app.core.redis_client import close_redis_client, get_redis_client
from app.middleware.metrics import MetricsMiddleware
from app.middleware.rate_limiter import RateLimitMiddleware
from app.routers import (
    ai_proxy_router,
    auth_router,
    byok_router,
    devices_router,
    license_router,
    teams_router,
    tokens_router,
)
from app.routers.webhooks import router as webhooks_router
from app.websocket.events import create_connected_event, create_error_event
from app.websocket.manager import scan_manager

settings = get_settings()

# Configure structlog for the entire application.
# Uses JSON rendering in production for log aggregation tools (Datadog, ELK, etc.)
# and colored console output in development for readability.
_is_production = settings.environment not in ("development", "testing")

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.dev.ConsoleRenderer()
        if not _is_production
        else structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

# Also configure stdlib logging to route through structlog so that third-party
# libraries (uvicorn, sqlalchemy, etc.) emit structured logs in the same format.
logging.basicConfig(
    format="%(message)s",
    level=logging.INFO if not settings.debug else logging.DEBUG,
)

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager.

    Handles startup and shutdown events:
    - Startup: Initialize database tables and Redis connection
    - Shutdown: Close database and Redis connections

    Args:
        app: FastAPI application instance

    Yields:
        None during application runtime
    """
    # Startup: Initialize database
    print("🚀 Initializing database...")
    await init_db()
    print("✅ Database initialized")

    # Startup: Initialize Redis connection (if enabled or URL provided)
    if settings.redis_enabled or settings.redis_url:
        print("🚀 Initializing Redis connection...")
        try:
            await get_redis_client()
            print("✅ Redis connection established")
        except Exception as e:
            print(f"⚠️  Redis connection failed: {e}")
            print("⚠️  Rate limiting will be disabled")

    yield

    # Shutdown: Close Redis connections
    if settings.redis_enabled or settings.redis_url:
        print("🔄 Closing Redis connections...")
        await close_redis_client()
        print("✅ Redis connections closed")

    # Shutdown: Close database connections
    print("🔄 Closing database connections...")
    await close_db()
    print("✅ Database connections closed")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Zypheron API - AI-powered vulnerability scanning and security analysis",
    lifespan=lifespan,
    debug=settings.debug,
)


# Configure CORS middleware
# Allow all origins ONLY in explicit development mode
# SECURITY: environment defaults to "development" — ensure ENVIRONMENT=production in prod
if settings.environment == "development":
    logger.warning("CORS: allowing all origins (development mode)")
allowed_origins = ["*"] if settings.environment == "development" else settings.cors_allowed_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add rate limiting middleware (before routers)
# This should be added after CORS but before route handlers
app.add_middleware(RateLimitMiddleware)

# Add Prometheus metrics middleware
app.add_middleware(MetricsMiddleware)


# Register routers
app.include_router(auth_router)
app.include_router(devices_router)
app.include_router(license_router)
app.include_router(tokens_router)
app.include_router(ai_proxy_router)
app.include_router(byok_router)
app.include_router(teams_router)
app.include_router(webhooks_router)


# Prometheus metrics endpoint (restricted access)
@app.get("/metrics", tags=["Monitoring"], include_in_schema=False)
async def metrics_endpoint(request: Request):
    """Prometheus metrics scrape endpoint.

    Restricted to private IPs and/or bearer token for security.
    """
    from fastapi.responses import Response

    client_ip = request.client.host if request.client else ""
    is_private_ip = client_ip in ("127.0.0.1", "::1") or client_ip.startswith(
        ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
         "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
         "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.")
    )

    # Check bearer token if configured
    token_valid = False
    if settings.metrics_secret_token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token_valid = auth_header[7:] == settings.metrics_secret_token

    # Allow if: private IP, OR valid token
    if not is_private_ip and not token_valid:
        raise HTTPException(status_code=404)

    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


# Health check endpoint with component checks
@app.get("/health", tags=["Health"])
async def health_check() -> dict:
    """Health check endpoint with component status.

    Returns:
        Dictionary with status, version, and component health
    """
    import time as _time

    components = {}

    # Database check
    try:
        from app.core.database import async_session_maker
        async with async_session_maker() as session:
            from sqlalchemy import text
            await session.execute(text("SELECT 1"))
        components["database"] = "healthy"
    except Exception as e:
        components["database"] = "unhealthy"

    # Redis check
    try:
        redis_client = await get_redis_client()
        if redis_client and redis_client.is_available:
            components["redis"] = "healthy"
        else:
            components["redis"] = "unavailable"
    except Exception:
        components["redis"] = "unavailable"

    # Stripe check
    if settings.stripe_secret_key:
        components["stripe"] = "configured"
    else:
        components["stripe"] = "not_configured"

    # Cache stats
    try:
        from app.services.cache import get_cache_service
        cache = get_cache_service()
        cache_stats = await cache.get_stats()
        components["cache"] = {
            "backend": cache_stats.get("backend", "unknown"),
            "size": cache_stats.get("size", 0),
            "hit_rate": cache_stats.get("metrics", {}).get("hit_rate_percent", 0),
        }
    except Exception:
        components["cache"] = "unavailable"

    # AI proxy provider health
    try:
        from app.routers.ai_proxy import _load_balancer
        if _load_balancer:
            components["ai_providers"] = _load_balancer.get_pool_stats()
        else:
            components["ai_providers"] = "not_initialized"
    except Exception:
        components["ai_providers"] = "unavailable"

    overall = "healthy" if components.get("database") == "healthy" else "degraded"

    return {
        "status": overall,
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "components": components,
    }


# Root endpoint
@app.get("/", tags=["Root"])
async def root() -> dict:
    """Root endpoint with API information.

    Returns:
        Dictionary with API metadata and links
    """
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health",
        "message": "Welcome to Zypheron API - AI-powered vulnerability scanning",
    }


# WebSocket endpoint for real-time scan updates
@app.websocket("/ws/scans/{user_id}")
async def websocket_scan_updates(
    websocket: WebSocket,
    user_id: int,
    token: str,
    db: AsyncSession = Depends(get_db),
) -> None:
    """WebSocket endpoint for authenticated real-time vulnerability scan updates.

    Provides real-time streaming of scan events to CLI clients with full
    authentication and license validation.

    Authentication:
    - Requires JWT token via query parameter: ?token=<jwt>
    - Validates token and verifies user_id matches
    - Checks for active license and websocket_streaming feature

    Protocol:
    - Client connects: /ws/scans/{user_id}?token=<jwt>
    - Server validates and sends connected event
    - Client sends commands:
      - {"command": "subscribe", "scan_id": "uuid"} - Subscribe to scan
      - {"command": "unsubscribe", "scan_id": "uuid"} - Unsubscribe
      - {"command": "ping"} - Keep-alive ping
    - Server broadcasts scan events:
      - {"event": "scan_started", "data": {...}}
      - {"event": "scan_progress", "data": {"percent": 50, ...}}
      - {"event": "finding", "data": {"vulnerability": {...}}}
      - {"event": "scan_completed", "data": {...}}

    Rate Limiting:
    - Free tier: 100 messages/minute
    - Starter: 200 messages/minute
    - Pro: 500 messages/minute
    - Enterprise: 1000 messages/minute

    Error Codes:
    - 4001: Authentication failed
    - 4002: License validation failed
    - 4003: Rate limit exceeded

    Args:
        websocket: WebSocket connection
        user_id: User identifier for authentication verification
        token: JWT token for authentication
        db: Database session

    Example:
        # JavaScript client
        const ws = new WebSocket('ws://localhost:8000/ws/scans/123?token=eyJ...');

        ws.onopen = () => {
            // Subscribe to a scan
            ws.send(JSON.stringify({
                command: 'subscribe',
                scan_id: 'scan-uuid-here'
            }));
        };

        ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            console.log('Event:', message.event, message.data);
        };
    """
    # Authenticate the connection
    auth_result = await scan_manager.authenticate(token, db)

    if not auth_result:
        # Authentication failed - send error and close
        logger.warning(f"WebSocket authentication failed for user_id={user_id}")
        await websocket.accept()  # Must accept before sending/closing
        await scan_manager.send_event(
            websocket,
            create_error_event("Authentication failed", 4001),
        )
        await websocket.close(code=4001, reason="Authentication failed")
        return

    user, license = auth_result

    # Verify user_id matches token
    if user.id != user_id:
        logger.warning(
            f"WebSocket user_id mismatch: token={user.id}, path={user_id}"
        )
        await websocket.accept()
        await scan_manager.send_event(
            websocket,
            create_error_event("User ID mismatch", 4001),
        )
        await websocket.close(code=4001, reason="User ID mismatch")
        return

    # Validate license has websocket_streaming feature
    is_valid, error_msg = scan_manager.validate_license_feature(license)
    if not is_valid:
        logger.warning(
            f"WebSocket license validation failed for user {user_id}: {error_msg}"
        )
        await websocket.accept()
        await scan_manager.send_event(
            websocket,
            create_error_event(error_msg or "License validation failed", 4002),
        )
        await websocket.close(code=4002, reason=error_msg or "License validation failed")
        return

    # Accept connection and register
    connection_id = await scan_manager.connect(websocket, user, license)

    # Send connected event
    await scan_manager.send_event(
        websocket,
        create_connected_event(user.id, connection_id),
    )

    try:
        # Message handling loop
        while True:
            # Receive message from client
            data = await websocket.receive_text()

            # Check rate limit
            if not scan_manager.check_rate_limit(user.id, license.tier):
                logger.warning(f"Rate limit exceeded for user {user.id}")
                await scan_manager.send_event(
                    websocket,
                    create_error_event("Rate limit exceeded", 4003),
                )
                # Optionally close connection on rate limit
                # await websocket.close(code=4003, reason="Rate limit exceeded")
                continue

            # Parse and handle command
            try:
                command_data = json.loads(data)
                await scan_manager.handle_client_command(
                    websocket,
                    user.id,
                    command_data,
                )
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON from user {user.id}: {data}")
                await scan_manager.send_event(
                    websocket,
                    create_error_event("Invalid JSON format"),
                )

    except WebSocketDisconnect:
        scan_manager.disconnect(websocket, user.id)
        logger.info(f"WebSocket disconnected for user: {user.id}")
    except Exception as e:
        logger.error(f"WebSocket error for user {user.id}: {e}", exc_info=True)
        scan_manager.disconnect(websocket, user.id)


# Exception handlers
@app.exception_handler(404)
async def not_found_handler(request, exc) -> JSONResponse:
    """Custom 404 handler.

    Args:
        request: FastAPI request object
        exc: Exception that was raised

    Returns:
        JSON response with error details
    """
    return JSONResponse(
        status_code=404,
        content={
            "error": "Not Found",
            "message": "The requested resource was not found",
            "path": str(request.url),
        },
    )


@app.exception_handler(500)
async def internal_error_handler(request, exc) -> JSONResponse:
    """Custom 500 handler.

    Args:
        request: FastAPI request object
        exc: Exception that was raised

    Returns:
        JSON response with error details
    """
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "detail": str(exc) if settings.debug else None,
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level="info" if settings.debug else "warning",
    )
