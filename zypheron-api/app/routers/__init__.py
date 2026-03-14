"""API routers for Zypheron endpoints.

All routers use async handlers and proper dependency injection.
"""

from app.routers.ai_proxy import router as ai_proxy_router
from app.routers.auth import router as auth_router
from app.routers.byok import router as byok_router
from app.routers.devices import router as devices_router
from app.routers.license import router as license_router
from app.routers.teams import router as teams_router
from app.routers.tokens import router as tokens_router

__all__ = [
    "auth_router",
    "devices_router",
    "license_router",
    "tokens_router",
    "ai_proxy_router",
    "byok_router",
    "teams_router",
]
