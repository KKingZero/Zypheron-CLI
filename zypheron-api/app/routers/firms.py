"""Firm / team collaboration + engagement management (dashboard).

Supabase-UUID identity (verify_supabase_jwt). All writes go through the
service-role Supabase client, so EVERY handler re-checks firm membership in
application code. Invites are opsec-grade: hashed, single-use + expiring by
default, optionally email-bound; the raw token is shown exactly once.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.config import get_settings
from app.core.supabase_client import SupabaseService, get_supabase_service
from app.dependencies.entitlement import (
    firm_has_dashboard_access,
    require_dashboard_firm,
    require_dashboard_user,
)
from app.dependencies.firm import (
    SupabaseUser,
    require_firm_membership,
    verify_supabase_jwt,
)
from app.schemas.firms import (
    AcceptResponse,
    EngagementCreate,
    EngagementListResponse,
    EngagementResponse,
    FirmCreate,
    FirmMember,
    FirmResponse,
    InviteCreate,
    InviteListResponse,
    InviteMeta,
    InviteResponse,
    MemberListResponse,
)

settings = get_settings()
router = APIRouter(prefix="/api", tags=["Firms"])


@router.get("/me/dashboard-access")
async def dashboard_access(
    user: SupabaseUser = Depends(verify_supabase_jwt),
    sb: SupabaseService = Depends(get_supabase_service),
) -> dict:
    """Lightweight gate check for the frontend. has_access true if the user is
    entitled directly OR belongs to any firm whose owner is entitled (seat)."""
    from app.dependencies.entitlement import user_has_dashboard_access

    if await user_has_dashboard_access(user.id, sb):
        return {"has_access": True}
    rows = await sb.select(
        "firm_members", columns="firm_id", filters={"user_id": f"eq.{user.id}"},
    )
    for r in rows:
        if await firm_has_dashboard_access(r["firm_id"], sb):
            return {"has_access": True}
    return {"has_access": False}


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


async def _require_admin(firm_id: str, user: SupabaseUser, sb: SupabaseService) -> str:
    # Asserts membership + firm entitlement ($499 platform), then admin role.
    role = await require_dashboard_firm(firm_id, user, sb)
    if role not in ("owner", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requires owner or admin role",
        )
    return role


# ---- Firms --------------------------------------------------------------
@router.post("/firms", response_model=FirmResponse)
async def create_firm(
    body: FirmCreate,
    user: SupabaseUser = Depends(require_dashboard_user),
    sb: SupabaseService = Depends(get_supabase_service),
) -> FirmResponse:
    payload = {"name": body.name, "created_by": user.id, "is_personal": False}
    if body.brand_color:
        payload["brand_color"] = body.brand_color
    created = await sb.insert("firms", payload)
    firm = created[0]
    await sb.insert(
        "firm_members",
        {"firm_id": firm["id"], "user_id": user.id, "role": "owner"},
        returning=False,
    )
    return FirmResponse(
        id=firm["id"], name=firm["name"], role="owner",
        is_personal=firm.get("is_personal", False),
        logo_url=firm.get("logo_url"), brand_color=firm.get("brand_color"),
    )


@router.get("/firms", response_model=list[FirmResponse])
async def list_firms(
    user: SupabaseUser = Depends(verify_supabase_jwt),
    sb: SupabaseService = Depends(get_supabase_service),
) -> list[FirmResponse]:
    rows = await sb.select(
        "firm_members",
        columns="role,firms(id,name,is_personal,logo_url,brand_color)",
        filters={"user_id": f"eq.{user.id}"},
    )
    out: list[FirmResponse] = []
    for r in rows:
        firm = r.get("firms") or {}
        if not firm:
            continue
        out.append(FirmResponse(
            id=firm["id"], name=firm["name"], role=r["role"],
            is_personal=firm.get("is_personal", False),
            logo_url=firm.get("logo_url"), brand_color=firm.get("brand_color"),
        ))
    return out


# ---- Members ------------------------------------------------------------
@router.get("/firms/{firm_id}/members", response_model=MemberListResponse)
async def list_members(
    firm_id: str,
    user: SupabaseUser = Depends(verify_supabase_jwt),
    sb: SupabaseService = Depends(get_supabase_service),
) -> MemberListResponse:
    await require_firm_membership(firm_id, user, sb)
    rows = await sb.select(
        "firm_members",
        columns="user_id,role,created_at",
        filters={"firm_id": f"eq.{firm_id}"},
    )
    # Resolve emails from profiles (firm_members.user_id has no PostgREST FK to profiles).
    ids = [r["user_id"] for r in rows]
    emails: dict[str, str] = {}
    if ids:
        id_list = ",".join(ids)
        profs = await sb.select(
            "profiles", columns="id,email", filters={"id": f"in.({id_list})"}
        )
        emails = {p["id"]: p.get("email") for p in profs}
    members = [
        FirmMember(
            user_id=r["user_id"], role=r["role"],
            email=emails.get(r["user_id"]), created_at=r.get("created_at"),
        )
        for r in rows
    ]
    return MemberListResponse(members=members)


@router.delete(
    "/firms/{firm_id}/members/{member_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def remove_member(
    firm_id: str,
    member_id: str,
    user: SupabaseUser = Depends(verify_supabase_jwt),
    sb: SupabaseService = Depends(get_supabase_service),
) -> None:
    await _require_admin(firm_id, user, sb)
    # Never allow removing an owner via this endpoint (prevents orphaning a firm).
    target = await sb.select(
        "firm_members", columns="role",
        filters={"firm_id": f"eq.{firm_id}", "user_id": f"eq.{member_id}"}, limit=1,
    )
    if target and target[0]["role"] == "owner":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove the firm owner",
        )
    await sb.delete(
        "firm_members",
        filters={"firm_id": f"eq.{firm_id}", "user_id": f"eq.{member_id}"},
    )


# ---- Invites ------------------------------------------------------------
@router.post("/firms/{firm_id}/invites", response_model=InviteResponse)
async def create_invite(
    firm_id: str,
    body: InviteCreate,
    user: SupabaseUser = Depends(verify_supabase_jwt),
    sb: SupabaseService = Depends(get_supabase_service),
) -> InviteResponse:
    await _require_admin(firm_id, user, sb)
    raw = secrets.token_urlsafe(32)
    expires_at = _now() + timedelta(days=body.expires_in_days)
    created = await sb.insert("firm_invites", {
        "firm_id": firm_id,
        "token_hash": _hash_token(raw),
        "role": body.role,
        "email": body.email,
        "max_uses": body.max_uses,
        "expires_at": expires_at.isoformat(),
        "created_by": user.id,
    })
    inv = created[0]
    return InviteResponse(
        id=inv["id"],
        accept_url=f"{settings.webapp_url.rstrip('/')}/join/{raw}",
        token=raw,
        role=body.role,
        expires_at=expires_at,
    )


@router.get("/firms/{firm_id}/invites", response_model=InviteListResponse)
async def list_invites(
    firm_id: str,
    user: SupabaseUser = Depends(verify_supabase_jwt),
    sb: SupabaseService = Depends(get_supabase_service),
) -> InviteListResponse:
    await _require_admin(firm_id, user, sb)
    rows = await sb.select(
        "firm_invites",
        columns="id,role,email,max_uses,used_count,expires_at,revoked_at",
        filters={"firm_id": f"eq.{firm_id}"},
        order="created_at.desc",
    )
    return InviteListResponse(invites=[InviteMeta(**r) for r in rows])


@router.delete(
    "/firms/{firm_id}/invites/{invite_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def revoke_invite(
    firm_id: str,
    invite_id: str,
    user: SupabaseUser = Depends(verify_supabase_jwt),
    sb: SupabaseService = Depends(get_supabase_service),
) -> None:
    await _require_admin(firm_id, user, sb)
    await sb.update(
        "firm_invites",
        {"revoked_at": _now().isoformat()},
        filters={"id": f"eq.{invite_id}", "firm_id": f"eq.{firm_id}"},
        returning=False,
    )


@router.post("/firms/invites/{token}/accept", response_model=AcceptResponse)
async def accept_invite(
    token: str,
    user: SupabaseUser = Depends(verify_supabase_jwt),
    sb: SupabaseService = Depends(get_supabase_service),
) -> AcceptResponse:
    rows = await sb.select(
        "firm_invites",
        columns="id,firm_id,role,email,max_uses,used_count,expires_at,revoked_at",
        filters={"token_hash": f"eq.{_hash_token(token)}"},
        limit=1,
    )
    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid invite")
    inv = rows[0]

    if inv.get("revoked_at"):
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Invite revoked")
    if inv["used_count"] >= inv["max_uses"]:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Invite already used")
    if datetime.fromisoformat(inv["expires_at"]) < _now():
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Invite expired")
    if inv.get("email") and (user.email or "").lower() != inv["email"].lower():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This invite is bound to a different email",
        )

    firm_id = inv["firm_id"]
    # The firm being joined must itself be entitled ($499 platform). Seats
    # inherit the firm's entitlement; joining a non-paying firm is pointless
    # and is blocked here.
    if not await firm_has_dashboard_access(firm_id, sb):
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="This firm does not have an active platform plan.",
        )
    # Idempotent join (unique firm_id,user_id). Only count a use when a NEW
    # membership is created, so re-clicking the link doesn't burn a use.
    existing = await sb.select(
        "firm_members", columns="role",
        filters={"firm_id": f"eq.{firm_id}", "user_id": f"eq.{user.id}"}, limit=1,
    )
    if existing:
        return AcceptResponse(firm_id=firm_id, role=existing[0]["role"])

    await sb.insert(
        "firm_members",
        {"firm_id": firm_id, "user_id": user.id, "role": inv["role"]},
        returning=False,
    )
    await sb.update(
        "firm_invites",
        {"used_count": inv["used_count"] + 1},
        filters={"id": f"eq.{inv['id']}"},
        returning=False,
    )
    return AcceptResponse(firm_id=firm_id, role=inv["role"])


# ---- Engagements --------------------------------------------------------
@router.post("/engagements", response_model=EngagementResponse)
async def create_engagement(
    body: EngagementCreate,
    user: SupabaseUser = Depends(verify_supabase_jwt),
    sb: SupabaseService = Depends(get_supabase_service),
) -> EngagementResponse:
    await require_dashboard_firm(body.firm_id, user, sb)
    created = await sb.insert("engagements", {
        "firm_id": body.firm_id,
        "name": body.name,
        "client_name": body.client_name,
        "target": body.target,
        "created_by": user.id,
    })
    e = created[0]
    return EngagementResponse(
        id=e["id"], firm_id=e["firm_id"], name=e["name"],
        client_name=e.get("client_name"), target=e.get("target"),
        status=e.get("status", "active"),
    )


@router.get("/firms/{firm_id}/engagements", response_model=EngagementListResponse)
async def list_engagements(
    firm_id: str,
    user: SupabaseUser = Depends(verify_supabase_jwt),
    sb: SupabaseService = Depends(get_supabase_service),
) -> EngagementListResponse:
    await require_firm_membership(firm_id, user, sb)
    rows = await sb.select(
        "engagements",
        columns="id,firm_id,name,client_name,target,status",
        filters={"firm_id": f"eq.{firm_id}"},
        order="created_at.desc",
    )
    return EngagementListResponse(
        engagements=[EngagementResponse(**r) for r in rows]
    )
