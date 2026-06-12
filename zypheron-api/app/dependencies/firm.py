"""Dashboard auth dependencies (app.zypheron.net).

Identity for the dashboard + desktop sync is the SUPABASE user (UUID `sub`),
NOT this API's own integer-keyed CLI user. So these dependencies decode the
Supabase-minted JWT and resolve the caller's firm membership. They are kept
fully separate from app.routers.auth.get_current_user (which validates this
API's SQLite-session tokens) to avoid mixing the two identity systems.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from jose import JWTError, jwt

from app.core.config import get_settings
from app.core.supabase_client import SupabaseService, get_supabase_service

settings = get_settings()


@dataclass
class SupabaseUser:
    """The verified Supabase identity behind a dashboard/sync request."""

    id: str  # auth.users UUID (the JWT `sub`)
    email: str | None


@dataclass
class FirmContext:
    """A verified user plus the firm they are acting within."""

    user: SupabaseUser
    firm_id: str
    role: str


def _bearer_token(request: Request) -> str:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return auth_header[len("Bearer "):]


async def verify_supabase_jwt(request: Request) -> SupabaseUser:
    """Decode + validate a Supabase access token, returning the user identity."""
    if not settings.supabase_jwt_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Dashboard auth is not configured (SUPABASE_JWT_SECRET unset)",
        )

    token = _bearer_token(request)
    try:
        # Supabase signs access tokens HS256 with the project JWT secret and
        # sets aud="authenticated". Pin the algorithm (no alg=none / RS256
        # confusion), the issuer, and REQUIRE exp/sub/aud so a token missing an
        # expiry cannot live forever.
        decode_kwargs = {
            "algorithms": ["HS256"],
            "audience": "authenticated",
            "options": {
                "require": ["exp", "sub", "aud"],
                "verify_exp": True,
                "verify_aud": True,
            },
        }
        if settings.supabase_url:
            decode_kwargs["issuer"] = f"{settings.supabase_url.rstrip('/')}/auth/v1"
            decode_kwargs["options"]["verify_iss"] = True
        payload = jwt.decode(token, settings.supabase_jwt_secret, **decode_kwargs)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    sub = payload.get("sub")
    if not sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject",
        )
    return SupabaseUser(id=sub, email=payload.get("email"))


async def _resolve_or_provision_firm(
    user: SupabaseUser, sb: SupabaseService
) -> tuple[str, str]:
    """Return (firm_id, role) for the user, provisioning a personal firm if none.

    Auto-provisioning a personal firm on first contact lets a single operator
    use the dashboard immediately; multi-seat firms add members via the firms
    router. The user becomes 'owner' of their bootstrap firm.
    """
    memberships = await sb.select(
        "firm_members",
        columns="firm_id,role",
        filters={"user_id": f"eq.{user.id}"},
        order="created_at.asc",
        limit=1,
    )
    if memberships:
        m = memberships[0]
        return m["firm_id"], m["role"]

    # Provision a personal firm. The partial unique index
    # (uniq_personal_firm_per_user) makes this idempotent under concurrent
    # first-contact requests: on conflict we re-read the winner's firm instead
    # of creating a duplicate, so a user can never amass extra personal firms.
    firm_name = (user.email.split("@")[0] if user.email else "My") + "'s Firm"
    try:
        created = await sb.insert(
            "firms",
            {"name": firm_name, "created_by": user.id, "is_personal": True},
        )
        firm_id = created[0]["id"]
    except Exception:
        # Unique-violation from the partial index (lost the race) — re-read the
        # winning personal firm rather than creating a duplicate.
        existing = await sb.select(
            "firms",
            columns="id",
            filters={"created_by": f"eq.{user.id}", "is_personal": "is.true"},
            limit=1,
        )
        if not existing:
            raise
        firm_id = existing[0]["id"]

    await sb.upsert(
        "firm_members",
        {"firm_id": firm_id, "user_id": user.id, "role": "owner"},
        on_conflict="firm_id,user_id",
        returning=False,
    )
    return firm_id, "owner"


async def get_firm_context(
    user: SupabaseUser = Depends(verify_supabase_jwt),
    sb: SupabaseService = Depends(get_supabase_service),
) -> FirmContext:
    """Resolve the firm the caller is acting within (auto-provision if needed)."""
    firm_id, role = await _resolve_or_provision_firm(user, sb)
    return FirmContext(user=user, firm_id=firm_id, role=role)


async def require_firm_membership(
    firm_id: str,
    user: SupabaseUser,
    sb: SupabaseService,
) -> str:
    """Assert the user belongs to firm_id; return their role. Raises 403 if not.

    Used by routers that take a firm-scoped resource id and must confirm the
    caller is entitled to it (defense in depth on top of the service-role
    client which bypasses RLS).
    """
    rows = await sb.select(
        "firm_members",
        columns="role",
        filters={"user_id": f"eq.{user.id}", "firm_id": f"eq.{firm_id}"},
        limit=1,
    )
    if not rows:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of this firm",
        )
    return rows[0]["role"]
