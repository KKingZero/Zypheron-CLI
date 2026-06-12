"""Token quota checking middleware for AI request endpoints.

Intercepts requests to AI endpoints and validates that the user has sufficient
token quota before processing the request. Returns 429 Too Many Requests with
upgrade prompt if quota is exceeded.
"""

import hashlib
import structlog
from typing import Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session_maker
from app.models.session import Session
from app.models.user import User
from app.services.token_tracking import TokenTrackingService

logger = structlog.get_logger()


def hash_token(token: str) -> str:
    """SHA-256 hash of a bearer token, matching routers.auth.hash_token (C-02).

    Defined locally to avoid importing the whole routers package from a
    middleware module (import-order coupling). Sessions store this hash, so the
    middleware must hash before looking a session up.
    """
    return hashlib.sha256(token.encode()).hexdigest()

# AI endpoints that require token quota checking.
# SECURITY (M-10): these must match the ACTUAL router mount points. The AI proxy
# router is mounted at "/ai" (ai_proxy.py: APIRouter(prefix="/ai")) with no
# global "/api" prefix, so the previous "/api/ai/" entries never matched and the
# middleware never fired. BYOK endpoints ("/byok") use the user's own API key and
# do not consume platform token quota, so they are intentionally excluded.
AI_ENDPOINTS = [
    "/ai/",  # All AI proxy endpoints (platform-metered)
]


class TokenQuotaMiddleware:
    """Middleware to check token quota before processing AI requests.

    Validates that authenticated users have sufficient token quota before
    allowing AI API calls. Unauthenticated requests bypass this check.
    """

    def __init__(self, app):
        """Initialize the middleware.

        Args:
            app: FastAPI application instance
        """
        self.app = app

    async def __call__(self, request: Request, call_next: Callable) -> Response:
        """Process the request and check token quota if needed.

        Args:
            request: Incoming request
            call_next: Next middleware or route handler

        Returns:
            Response from the next handler or 429 if quota exceeded
        """
        # Check if this is an AI endpoint that requires quota checking
        if not self._is_ai_endpoint(request.url.path):
            # Not an AI endpoint, proceed normally
            return await call_next(request)

        # Only check quota for authenticated users
        user = await self._get_user_from_request(request)

        if not user:
            # Unauthenticated request, let it proceed (auth middleware will handle)
            return await call_next(request)

        # Check if user has quota.
        # Availability: fail OPEN on unexpected quota-service errors so a bug
        # here cannot take down every AI request with a 500. A genuine
        # over-quota result still returns 429 below.
        try:
            async with async_session_maker() as db:
                service = TokenTrackingService(db)
                has_quota = await service.check_quota(user.id)
                quota_info = None if has_quota else await service.get_quota_info(user.id)
        except Exception as e:
            logger.error(f"Quota check failed open: {e}")
            return await call_next(request)

        if not has_quota:
            # Quota exceeded, return 429 with upgrade message
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "quota_exceeded",
                    "message": "Monthly token quota exceeded",
                    "details": {
                        "tier": quota_info["tier"],
                        "tokens_used": quota_info["tokens_used"],
                        "token_limit": quota_info["token_limit"],
                        "period_end": quota_info["period_end"],
                    },
                    "upgrade_message": self._get_upgrade_message(quota_info["tier"]),
                },
                headers={
                    "X-RateLimit-Limit": str(quota_info["token_limit"]),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": quota_info["period_end"] or "",
                    "Retry-After": self._calculate_retry_after(quota_info["period_end"]),
                },
            )

        # Quota available, proceed with request
        return await call_next(request)

    def _is_ai_endpoint(self, path: str) -> bool:
        """Check if the request path is an AI endpoint.

        Args:
            path: Request URL path

        Returns:
            True if the path is an AI endpoint, False otherwise
        """
        return any(path.startswith(endpoint) for endpoint in AI_ENDPOINTS)

    async def _get_user_from_request(self, request: Request) -> User | None:
        """Extract and validate user from request authorization header.

        Args:
            request: Incoming request

        Returns:
            User object if authenticated, None otherwise
        """
        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        token = auth_header.replace("Bearer ", "")

        # SECURITY (C-02): sessions store the SHA-256 hash of the token, not the
        # raw token. Hash before lookup or the comparison never matches and quota
        # checks are silently skipped. Mirrors get_current_user in routers/auth.
        token_hash = hash_token(token)

        # Validate token and get user
        try:
            async with async_session_maker() as db:
                # Check if session exists and is active
                stmt = select(Session).where(
                    Session.token == token_hash,
                    Session.is_active == True,
                )
                result = await db.execute(stmt)
                session = result.scalar_one_or_none()

                if not session or not session.is_valid():
                    return None

                # Get user
                stmt = select(User).where(User.id == session.user_id)
                result = await db.execute(stmt)
                user = result.scalar_one_or_none()

                if not user or not user.is_active:
                    return None

                return user

        except Exception as e:
            logger.error(f"Error getting user from request: {e}")
            return None

    def _get_upgrade_message(self, tier: str) -> str:
        """Get upgrade message based on current tier.

        Args:
            tier: User's current subscription tier

        Returns:
            Upgrade message with call to action
        """
        if tier == "free":
            return (
                "You've reached your free tier limit. "
                "Upgrade to Starter ($9/month) for 1,000,000 tokens/month, "
                "or enable BYOK to use your own API keys."
            )
        elif tier == "starter":
            return (
                "You've reached your Starter tier limit. "
                "Upgrade to Pro ($29/month) for 3,000,000 tokens/month "
                "and priority support."
            )
        elif tier == "pro":
            return (
                "You've reached your Pro tier limit. "
                "Contact us for Enterprise pricing with shared pools "
                "and custom limits."
            )
        elif tier == "enterprise":
            return (
                "Your enterprise pool has reached its monthly limit. "
                "Contact your account manager to increase your quota."
            )
        else:
            return "Token quota exceeded. Please contact support."

    def _calculate_retry_after(self, period_end: str | None) -> str:
        """Calculate Retry-After header value.

        Args:
            period_end: ISO format period end timestamp

        Returns:
            Retry-After value in seconds as string
        """
        if not period_end:
            return "3600"  # Default to 1 hour

        try:
            from datetime import datetime, timezone

            end_date = datetime.fromisoformat(period_end.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            delta = end_date - now

            # Return seconds until period end (minimum 0)
            return str(max(0, int(delta.total_seconds())))

        except Exception:
            return "3600"  # Default to 1 hour on error


def add_token_quota_middleware(app):
    """Add token quota middleware to the FastAPI application.

    Args:
        app: FastAPI application instance
    """
    app.middleware("http")(TokenQuotaMiddleware(app))
