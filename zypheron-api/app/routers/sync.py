"""Desktop -> dashboard sync ingestion (/api/sync/*).

The Electron desktop app pushes findings here (fire-and-forget, with a local
retry outbox) as testers work. Writes land in Supabase Postgres via the
service-role client; the browser dashboard then sees them live through Supabase
realtime. Idempotent: a finding is keyed by desktop_vuln_id and only overwritten
when the incoming row is at least as new as the stored one, so retries are safe.
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, status

from app.core.supabase_client import SupabaseService, get_supabase_service
from app.dependencies.entitlement import firm_has_dashboard_access
from app.dependencies.firm import (
    FirmContext,
    SupabaseUser,
    _resolve_or_provision_firm,
    get_firm_context,
    require_firm_membership,
    verify_supabase_jwt,
)
from app.schemas.sync import (
    EvidenceSignRequest,
    EvidenceSignResponse,
    FindingSync,
    SyncResult,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/api/sync", tags=["Sync"])

EVIDENCE_BUCKET = "evidence"

_SAFE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".txt", ".log", ".json", ".pcap", ".bin"}


def _safe_leaf_name(filename: str) -> str:
    """Derive a non-traversable storage leaf from a client-supplied filename.

    The client filename is untrusted (could be '../<other_firm>/x'), so we keep
    only the basename, allowlist the charset, and prefix a random component so
    one finding's uploads cannot overwrite each other or anything else.
    """
    base = os.path.basename(filename or "")
    _, ext = os.path.splitext(base)
    ext = ext.lower() if ext.lower() in _SAFE_EXT else ".bin"
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", base[: len(base) - len(ext)]).strip("._-")
    stem = stem[:64] or "file"
    return f"{uuid.uuid4().hex}_{stem}{ext}"


def _epoch_ms_to_iso(ms: int | None) -> str | None:
    if ms is None:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()


async def _upsert_engagement(
    sb: SupabaseService, firm_id: str, finding: FindingSync, user_id: str
) -> str:
    eng = finding.engagement
    rows = await sb.upsert(
        "engagements",
        {
            "firm_id": firm_id,
            "desktop_project_id": eng.desktop_project_id,
            "name": eng.name,
            "client_name": eng.client_name,
            "target": eng.target,
            "status": eng.status,
            "created_by": user_id,
        },
        on_conflict="firm_id,desktop_project_id",
    )
    return rows[0]["id"]


@router.post("/findings", response_model=SyncResult)
async def sync_finding(
    finding: FindingSync,
    user: SupabaseUser = Depends(verify_supabase_jwt),
    sb: SupabaseService = Depends(get_supabase_service),
) -> SyncResult:
    """Upsert one finding from the desktop. Idempotent per (firm, desktop_vuln_id).

    Collaboration mode (engagement_id set) routes the finding into a shared firm
    engagement after verifying membership; solo mode upserts a per-project
    engagement into the caller's personal firm.
    """
    if finding.engagement_id:
        # Collaboration: target an existing shared engagement.
        eng_rows = await sb.select(
            "engagements",
            columns="id,firm_id",
            filters={"id": f"eq.{finding.engagement_id}"},
            limit=1,
        )
        if not eng_rows:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target engagement not found",
            )
        firm_id = eng_rows[0]["firm_id"]
        await require_firm_membership(firm_id, user, sb)
    else:
        if finding.engagement is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="engagement_id or engagement block is required",
            )
        firm_id, _ = await _resolve_or_provision_firm(user, sb)

    # Entitlement gate: the dashboard is the $499/mo platform tier. Findings only
    # sync into firms whose owner holds an active platform plan (seats inherit).
    if not await firm_has_dashboard_access(firm_id, sb):
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="The Zypheron web dashboard requires the $499/mo platform plan.",
        )

    incoming_updated = _epoch_ms_to_iso(finding.updated_at)

    # Staleness guard: if the stored row is newer, skip (safe-retry semantics).
    existing = await sb.select(
        "findings",
        columns="id,engagement_id,updated_at",
        filters={"desktop_vuln_id": f"eq.{finding.desktop_vuln_id}",
                 "firm_id": f"eq.{firm_id}"},
        limit=1,
    )
    if existing and incoming_updated:
        stored_updated = existing[0].get("updated_at")
        if stored_updated and stored_updated > incoming_updated:
            return SyncResult(
                finding_id=existing[0]["id"],
                engagement_id=existing[0]["engagement_id"],
                action="skipped_stale",
            )

    if finding.engagement_id:
        engagement_id = finding.engagement_id
    else:
        engagement_id = await _upsert_engagement(sb, firm_id, finding, user.id)

    row = {
        "engagement_id": engagement_id,
        "firm_id": firm_id,
        "desktop_vuln_id": finding.desktop_vuln_id,
        "scan_id": finding.scan_id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "category": finding.category,
        "cwe_id": finding.cwe_id,
        "cvss_score": finding.cvss_score,
        "url": finding.url,
        "parameter": finding.parameter,
        "method": finding.method,
        "request": finding.request,
        "response": finding.response,
        "recommendation": finding.recommendation,
        "references": finding.references,
        "status": finding.status,
        "discovered_at": _epoch_ms_to_iso(finding.discovered_at),
    }
    if incoming_updated:
        row["updated_at"] = incoming_updated

    result = await sb.upsert("findings", row, on_conflict="firm_id,desktop_vuln_id")
    finding_row = result[0]
    finding_id = finding_row["id"]

    # Defense in depth: the upsert must never return a row owned by another
    # firm. If a schema regression ever widened the conflict target, this stops
    # a cross-tenant clobber from being treated as success.
    if finding_row.get("firm_id") != firm_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Finding ownership conflict",
        )

    # Inline evidence (poc text, inline payloads) — file blobs go via /evidence.
    if finding.evidence:
        await _sync_inline_evidence(sb, firm_id, finding_id, finding)

    return SyncResult(
        finding_id=finding_id,
        engagement_id=engagement_id,
        action="updated" if existing else "created",
    )


async def _sync_inline_evidence(
    sb: SupabaseService, firm_id: str, finding_id: str, finding: FindingSync
) -> None:
    """Persist small inline evidence (poc / payloads) attached to the finding.

    Replaces existing inline rows for this finding so repeated syncs do not
    accumulate duplicates. File-backed evidence (screenshots) is registered
    separately through /evidence after upload.
    """
    ev = finding.evidence
    if ev is None:
        return
    await sb.delete(
        "finding_evidence",
        filters={"finding_id": f"eq.{finding_id}",
                 "kind": "in.(poc,payload)",
                 "storage_path": "is.null"},
    )
    inline_rows: list[dict] = []
    if ev.proof_of_concept:
        inline_rows.append({
            "finding_id": finding_id, "firm_id": firm_id,
            "kind": "poc", "inline_text": ev.proof_of_concept,
        })
    for payload in ev.payloads:
        inline_rows.append({
            "finding_id": finding_id, "firm_id": firm_id,
            "kind": "payload", "inline_text": payload,
        })
    if inline_rows:
        await sb.insert("finding_evidence", inline_rows, returning=False)


@router.post("/evidence", response_model=EvidenceSignResponse)
async def sign_evidence_upload(
    req: EvidenceSignRequest,
    ctx: FirmContext = Depends(get_firm_context),
    sb: SupabaseService = Depends(get_supabase_service),
) -> EvidenceSignResponse:
    """Return a signed URL the desktop PUTs an evidence file to, and register it."""
    findings = await sb.select(
        "findings",
        columns="id",
        filters={"desktop_vuln_id": f"eq.{req.finding_desktop_vuln_id}",
                 "firm_id": f"eq.{ctx.firm_id}"},
        limit=1,
    )
    if not findings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found for evidence upload",
        )
    finding_id = findings[0]["id"]
    storage_path = f"{ctx.firm_id}/{finding_id}/{_safe_leaf_name(req.filename)}"

    signed = await sb.create_signed_upload_url(EVIDENCE_BUCKET, storage_path)

    await sb.insert(
        "finding_evidence",
        {
            "finding_id": finding_id,
            "firm_id": ctx.firm_id,
            "kind": req.kind,
            "storage_path": storage_path,
            "sha256": req.sha256,
            "mime": req.mime,
        },
        returning=False,
    )

    token = signed.get("token") if isinstance(signed, dict) else None
    upload_url = signed.get("url") if isinstance(signed, dict) else ""
    return EvidenceSignResponse(
        upload_url=upload_url, storage_path=storage_path, token=token
    )
