"""Schemas for the desktop -> dashboard sync contract (/api/sync/*).

The desktop app (Electron) pushes findings here as they are created/updated in
its local SQLite. Field names mirror the desktop `Vulnerability` /
`VulnerabilityEvidence` types (electron/types/database.ts) so the mapping is 1:1.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
FindingStatus = Literal["open", "confirmed", "false_positive", "fixed", "accepted"]


class EvidencePayload(BaseModel):
    """Desktop VulnerabilityEvidence — small text kept inline, files referenced."""

    proof_of_concept: str | None = None
    screenshots: list[str] = Field(default_factory=list)  # storage paths or local refs
    logs: list[str] = Field(default_factory=list)
    payloads: list[str] = Field(default_factory=list)


class EngagementSync(BaseModel):
    """Parent project/engagement, upserted lazily on first finding."""

    desktop_project_id: str
    name: str
    client_name: str | None = None
    target: str | None = None
    status: Literal["active", "paused", "completed", "archived"] = "active"


class FindingSync(BaseModel):
    """A single desktop vulnerability pushed to the dashboard.

    Two modes:
    - Collaboration: `engagement_id` set -> the finding joins an existing shared
      firm engagement (caller must be a member of that engagement's firm).
    - Solo: `engagement_id` omitted -> `engagement` block is upserted into the
      caller's auto-provisioned personal firm (per-project engagement).
    """

    desktop_vuln_id: str
    engagement_id: str | None = None       # explicit shared dashboard engagement
    engagement: EngagementSync | None = None
    scan_id: str | None = None
    title: str
    description: str | None = None
    severity: Severity = "info"
    category: str | None = None
    cwe_id: str | None = None
    cvss_score: float | None = None
    url: str | None = None
    parameter: str | None = None
    method: str | None = None
    request: str | None = None
    response: str | None = None
    recommendation: str | None = None
    references: list[str] = Field(default_factory=list)
    status: FindingStatus = "open"
    evidence: EvidencePayload | None = None
    # epoch millis from desktop; converted to ISO before storage
    discovered_at: int | None = None
    updated_at: int | None = None


class SyncResult(BaseModel):
    finding_id: str
    engagement_id: str
    action: Literal["created", "updated", "skipped_stale"]


class EvidenceSignRequest(BaseModel):
    finding_desktop_vuln_id: str
    kind: Literal["poc", "screenshot", "log", "payload"]
    filename: str
    sha256: str | None = None
    mime: str | None = None


class EvidenceSignResponse(BaseModel):
    upload_url: str
    storage_path: str
    token: str | None = None
