"""Provider capability constants and validation helpers."""

from __future__ import annotations

from typing import Optional


OPENAI_EFFORT_VALUES = {"none", "minimal", "low", "medium", "high", "xhigh"}
CLAUDE_EFFORT_VALUES = {"low", "medium", "high", "xhigh", "max"}
EFFORT_CAPABLE_PROVIDERS = {"openai", "claude"}


def validate_effort(provider: str, effort: Optional[str]) -> Optional[str]:
    """Return normalized effort or raise a provider-specific ValueError."""
    if not effort:
        return None

    normalized = str(effort).lower()
    if provider == "openai":
        if normalized in OPENAI_EFFORT_VALUES:
            return normalized
        raise ValueError("Invalid OpenAI effort. Allowed: none, minimal, low, medium, high, xhigh")

    if provider == "claude":
        if normalized in CLAUDE_EFFORT_VALUES:
            return normalized
        raise ValueError("Invalid Claude effort. Allowed: low, medium, high, xhigh, max")

    raise ValueError(f"effort is not supported with provider {provider}")
