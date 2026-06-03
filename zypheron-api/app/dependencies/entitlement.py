"""Dashboard entitlement gate — the web dashboard is the $499/mo platform tier.

Access rule (seat model): a firm is the paying entity. A user may use a firm's
dashboard when the FIRM OWNER holds an active plan that exposes the
`web_dashboard` feature (the $499 "Mid" plan and Enterprise do), or a
free-access grant / developer access. Solo users act in their own personal
firm, so the check collapses to their own subscription.

Entitlement is read from Supabase via the canonical `get_user_access_level`
RPC. Results are cached briefly in-process to avoid an RPC per finding sync.
"""

from __future__ import annotations

import time

from fastapi import Depends, HTTPException, status

from app.core.config import get_settings
from app.core.supabase_client import SupabaseService, get_supabase_service
from app.dependencies.firm import (
    SupabaseUser,
    require_firm_membership,
    verify_supabase_jwt,
)

settings = get_settings()

_CACHE_TTL = 60.0  # seconds
_user_cache: dict[str, tuple[float, bool]] = {}
_firm_owner_cache: dict[str, tuple[float, str | None]] = {}


def _feature_granted(features: object) -> bool:
    if not isinstance(features, dict):
        return False
    if features.get("all_features") is True:  # free grant shape
        return True
    return bool(features.get(settings.dashboard_required_feature))


async def user_has_dashboard_access(user_id: str, sb: SupabaseService) -> bool:
    """True if this user's own entitlement exposes the dashboard feature."""
    now = time.time()
    cached = _user_cache.get(user_id)
    if cached and now - cached[0] < _CACHE_TTL:
        return cached[1]

    granted = False
    try:
        rows = await sb.rpc("get_user_access_level", {"user_uuid": user_id})
        row = rows[0] if isinstance(rows, list) and rows else rows
        if isinstance(row, dict) and row.get("has_access"):
            granted = _feature_granted(row.get("features"))
    except Exception:
        granted = False

    # developer_access on the profile is an explicit override.
    if not granted:
        try:
            profs = await sb.select(
                "profiles", columns="developer_access",
                filters={"id": f"eq.{user_id}"}, limit=1,
            )
            if profs and profs[0].get("developer_access"):
                granted = True
        except Exception:
            pass

    _user_cache[user_id] = (now, granted)
    return granted


async def _firm_owner_id(firm_id: str, sb: SupabaseService) -> str | None:
    now = time.time()
    cached = _firm_owner_cache.get(firm_id)
    if cached and now - cached[0] < _CACHE_TTL:
        return cached[1]
    rows = await sb.select(
        "firm_members", columns="user_id",
        filters={"firm_id": f"eq.{firm_id}", "role": "eq.owner"}, limit=1,
    )
    owner = rows[0]["user_id"] if rows else None
    _firm_owner_cache[firm_id] = (now, owner)
    return owner


async def firm_has_dashboard_access(firm_id: str, sb: SupabaseService) -> bool:
    """True if the firm's owner is entitled (seats inherit firm entitlement)."""
    owner = await _firm_owner_id(firm_id, sb)
    if not owner:
        return False
    return await user_has_dashboard_access(owner, sb)


def _denied() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail="The Zypheron web dashboard requires the $499/mo platform plan.",
    )


async def require_dashboard_user(
    user: SupabaseUser = Depends(verify_supabase_jwt),
    sb: SupabaseService = Depends(get_supabase_service),
) -> SupabaseUser:
    """Gate an action on the CALLER's own entitlement (e.g. creating a firm)."""
    if not await user_has_dashboard_access(user.id, sb):
        raise _denied()
    return user


async def require_dashboard_firm(
    firm_id: str, user: SupabaseUser, sb: SupabaseService
) -> str:
    """Assert membership AND that the firm (its owner) is entitled. Returns role."""
    role = await require_firm_membership(firm_id, user, sb)
    if not await firm_has_dashboard_access(firm_id, sb):
        raise _denied()
    return role
