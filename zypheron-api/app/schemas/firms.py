"""Schemas for firm/team collaboration (dashboard, Supabase-UUID identity).

Distinct from schemas/teams.py (which is int-keyed for the CLI world). These
back the multi-account collaboration model: a firm groups accounts, and
engagements belong to a firm.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field

FirmRole = Literal["owner", "admin", "member"]
InviteRole = Literal["admin", "member"]


class FirmCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    brand_color: str | None = Field(None, max_length=16)


class FirmResponse(BaseModel):
    id: str
    name: str
    role: FirmRole
    is_personal: bool = False
    logo_url: str | None = None
    brand_color: str | None = None


class FirmMember(BaseModel):
    user_id: str
    email: str | None = None
    role: FirmRole
    created_at: datetime | None = None


class MemberListResponse(BaseModel):
    members: list[FirmMember]


class InviteCreate(BaseModel):
    role: InviteRole = "member"
    email: EmailStr | None = None       # optional bind
    max_uses: int = Field(1, ge=1, le=50)
    expires_in_days: int = Field(7, ge=1, le=90)


class InviteResponse(BaseModel):
    """Returned ONCE on creation — carries the raw token. Never re-fetchable."""

    id: str
    accept_url: str
    token: str
    role: InviteRole
    expires_at: datetime


class InviteMeta(BaseModel):
    """Listing shape — no raw token, no hash."""

    id: str
    role: InviteRole
    email: str | None
    max_uses: int
    used_count: int
    expires_at: datetime
    revoked_at: datetime | None


class InviteListResponse(BaseModel):
    invites: list[InviteMeta]


class AcceptResponse(BaseModel):
    firm_id: str
    role: FirmRole


class EngagementCreate(BaseModel):
    firm_id: str
    name: str = Field(..., min_length=1, max_length=160)
    client_name: str | None = None
    target: str | None = None


class EngagementResponse(BaseModel):
    id: str
    firm_id: str
    name: str
    client_name: str | None = None
    target: str | None = None
    status: str = "active"


class EngagementListResponse(BaseModel):
    engagements: list[EngagementResponse]
