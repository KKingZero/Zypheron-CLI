"""Shared scope/host matching helpers for ROE enforcement."""

from __future__ import annotations

from typing import Iterable, Optional
from urllib.parse import urlparse


def normalize_scope_host(value: str) -> Optional[str]:
    """Reduce a scope entry or target to a comparable lowercase host."""
    if not value:
        return None
    candidate = value.strip().lower()
    if not candidate:
        return None
    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or ""
    else:
        candidate = candidate.split("/", 1)[0]
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[1]
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1:candidate.index("]")]
    elif ":" in candidate and candidate.count(":") == 1:
        candidate = candidate.split(":", 1)[0]
    candidate = candidate.rstrip(".")
    return candidate or None


def scope_match(target: str, entries: Iterable[str]) -> bool:
    """Return True when ``target``'s host matches any entry by suffix."""
    host = normalize_scope_host(target)
    if host is None:
        return False
    for entry in entries:
        scope_host = normalize_scope_host(entry)
        if not scope_host:
            continue
        if host == scope_host or host.endswith("." + scope_host):
            return True
    return False
