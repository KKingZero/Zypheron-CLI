"""Prometheus metrics middleware for automatic HTTP request tracking.

Auto-tracks request count, duration, and status code for all endpoints.
"""

import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.services.metrics import http_request_duration, http_requests_total


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware to collect Prometheus metrics for HTTP requests."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Track request metrics.

        Args:
            request: Incoming HTTP request
            call_next: Next middleware/route handler

        Returns:
            HTTP response with metrics recorded
        """
        method = request.method
        # Normalize path to avoid cardinality explosion
        path = self._normalize_path(request.url.path)

        start_time = time.time()

        try:
            response = await call_next(request)
            status_code = str(response.status_code)
        except Exception:
            status_code = "500"
            raise
        finally:
            duration = time.time() - start_time
            http_requests_total.labels(
                method=method,
                endpoint=path,
                status_code=status_code,
            ).inc()
            http_request_duration.labels(
                method=method,
                endpoint=path,
            ).observe(duration)

        return response

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalize URL path to prevent high-cardinality labels.

        Replaces dynamic path segments (numeric IDs, UUIDs) with placeholders.

        Args:
            path: Raw URL path

        Returns:
            Normalized path string
        """
        parts = path.strip("/").split("/")
        normalized = []
        for part in parts:
            # Replace numeric IDs
            if part.isdigit():
                normalized.append("{id}")
            # Replace UUID-like segments
            elif len(part) == 36 and part.count("-") == 4:
                normalized.append("{uuid}")
            else:
                normalized.append(part)
        return "/" + "/".join(normalized) if normalized else "/"
