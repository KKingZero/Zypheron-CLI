"""Supabase service-role client for the dashboard webapp (app.zypheron.net).

Dashboard data (firms, engagements, findings, collab, reports, portal, ROI)
lives in Supabase Postgres so the browser can use Supabase realtime + RLS.
This API writes to those tables through the PostgREST REST endpoint using the
service_role key, which BYPASSES RLS — so every call here must enforce
firm-scoping in application code (never expose this client to a browser).

Why PostgREST over a second asyncpg pool: the project's primary SQLAlchemy
engine points at the API's own SQLite/Postgres for CLI auth + licensing.
Talking to Supabase over REST keeps the dashboard store fully decoupled and
avoids a second connection pool / migration surface.
"""

from __future__ import annotations

from typing import Any

import httpx

from app.core.config import get_settings

settings = get_settings()


class SupabaseConfigError(RuntimeError):
    """Raised when Supabase service credentials are not configured."""


def _base_url() -> str:
    if not settings.supabase_url:
        raise SupabaseConfigError("SUPABASE_URL is not configured")
    return settings.supabase_url.rstrip("/")


def _service_key() -> str:
    if not settings.supabase_service_key:
        raise SupabaseConfigError("SUPABASE_SERVICE_KEY is not configured")
    return settings.supabase_service_key


def _rest_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    key = _service_key()
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    if extra:
        headers.update(extra)
    return headers


class SupabaseService:
    """Thin async PostgREST + Storage client scoped to the service role."""

    def __init__(self, timeout: float = 15.0) -> None:
        self._timeout = timeout

    # ---- PostgREST ------------------------------------------------------
    async def select(
        self,
        table: str,
        *,
        columns: str = "*",
        filters: dict[str, str] | None = None,
        order: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, str] = {"select": columns}
        if filters:
            params.update(filters)
        if order:
            params["order"] = order
        if limit:
            params["limit"] = str(limit)
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.get(
                f"{_base_url()}/rest/v1/{table}",
                headers=_rest_headers(),
                params=params,
            )
            resp.raise_for_status()
            return resp.json()

    async def insert(
        self,
        table: str,
        rows: dict[str, Any] | list[dict[str, Any]],
        *,
        returning: bool = True,
    ) -> list[dict[str, Any]]:
        prefer = "return=representation" if returning else "return=minimal"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{_base_url()}/rest/v1/{table}",
                headers=_rest_headers({"Prefer": prefer}),
                json=rows,
            )
            resp.raise_for_status()
            return resp.json() if returning else []

    async def upsert(
        self,
        table: str,
        rows: dict[str, Any] | list[dict[str, Any]],
        *,
        on_conflict: str,
        returning: bool = True,
    ) -> list[dict[str, Any]]:
        """Insert-or-update on a conflict target (e.g. a unique column)."""
        prefer = "resolution=merge-duplicates,"
        prefer += "return=representation" if returning else "return=minimal"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{_base_url()}/rest/v1/{table}",
                headers=_rest_headers({"Prefer": prefer}),
                params={"on_conflict": on_conflict},
                json=rows,
            )
            resp.raise_for_status()
            return resp.json() if returning else []

    async def update(
        self,
        table: str,
        patch: dict[str, Any],
        *,
        filters: dict[str, str],
        returning: bool = True,
    ) -> list[dict[str, Any]]:
        prefer = "return=representation" if returning else "return=minimal"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.patch(
                f"{_base_url()}/rest/v1/{table}",
                headers=_rest_headers({"Prefer": prefer}),
                params=filters,
                json=patch,
            )
            resp.raise_for_status()
            return resp.json() if returning else []

    async def delete(self, table: str, *, filters: dict[str, str]) -> None:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.delete(
                f"{_base_url()}/rest/v1/{table}",
                headers=_rest_headers(),
                params=filters,
            )
            resp.raise_for_status()

    async def rpc(self, fn: str, params: dict[str, Any]) -> Any:
        """Call a Postgres function via PostgREST RPC (service role)."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{_base_url()}/rest/v1/rpc/{fn}",
                headers=_rest_headers(),
                json=params,
            )
            resp.raise_for_status()
            return resp.json()

    # ---- Storage --------------------------------------------------------
    async def create_signed_upload_url(
        self, bucket: str, path: str
    ) -> dict[str, Any]:
        """Return a one-time signed URL the desktop can PUT an evidence file to."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{_base_url()}/storage/v1/object/upload/sign/{bucket}/{path}",
                headers=_rest_headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def create_signed_download_url(
        self, bucket: str, path: str, expires_in: int = 3600
    ) -> str:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{_base_url()}/storage/v1/object/sign/{bucket}/{path}",
                headers=_rest_headers(),
                json={"expiresIn": expires_in},
            )
            resp.raise_for_status()
            signed = resp.json().get("signedURL", "")
            return f"{_base_url()}/storage/v1{signed}"


_service: SupabaseService | None = None


def get_supabase_service() -> SupabaseService:
    """Singleton accessor for the Supabase service client."""
    global _service
    if _service is None:
        _service = SupabaseService()
    return _service
