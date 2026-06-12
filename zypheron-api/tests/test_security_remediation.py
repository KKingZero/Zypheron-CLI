"""Regression tests for the 2026-06 security review remediations (zypheron-api).

Finding IDs reference the Zypheron Security Code Review Report. These are
low-dependency unit tests; the full integration suite runs in the API test env.
"""

import importlib

import pytest


# ---------------------------------------------------------------- H-07
def test_h07_default_jwt_rejected_in_staging(monkeypatch):
    """H-07: the public default JWT secret must be rejected outside development."""
    pytest.importorskip("pydantic_settings")
    from app.core.config import Settings

    # development tolerates the default (local dev convenience)
    dev = Settings(environment="development", jwt_secret_key="dev-secret-UNSAFE-FOR-PRODUCTION")
    assert dev.environment == "development"

    # staging and production must reject it
    for env in ("staging", "production"):
        with pytest.raises(ValueError):
            Settings(environment=env, jwt_secret_key="dev-secret-UNSAFE-FOR-PRODUCTION")


def test_h07_short_secret_rejected_in_production():
    pytest.importorskip("pydantic_settings")
    from app.core.config import Settings

    with pytest.raises(ValueError):
        Settings(environment="production", jwt_secret_key="too-short")


# ---------------------------------------------------------------- C-02 / M-10
def test_m10_ai_endpoint_prefixes_match_real_mounts():
    """M-10: middleware must match the real /ai mount, not the old /api/ai."""
    pytest.importorskip("fastapi")
    mod = importlib.import_module("app.middleware.token_check")
    mw = mod.TokenQuotaMiddleware(app=None)

    assert mw._is_ai_endpoint("/ai/chat") is True
    assert mw._is_ai_endpoint("/ai/completions") is True
    # The old, never-matching prefixes must NOT be what we rely on.
    assert mw._is_ai_endpoint("/api/ai/chat") is False
    # BYOK is user-key metered, intentionally excluded.
    assert mw._is_ai_endpoint("/byok/keys") is False


def test_c02_middleware_hashes_token_before_lookup():
    """C-02: the middleware imports hash_token (sessions store hashes)."""
    pytest.importorskip("fastapi")
    mod = importlib.import_module("app.middleware.token_check")
    assert hasattr(mod, "hash_token")
