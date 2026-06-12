"""Regression tests for the 2026-06 security review remediations (Medium+).

Each test maps to a finding ID from the Zypheron Security Code Review Report.
"""

from __future__ import annotations

import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest


# ---------------------------------------------------------------- C-05 / C-06 / M-03
from auth.authorization import (
    AuthorizationValidator,
    AuthorizationScope,
    AuthorizationError,
)


def _validator(tmp_path: Path) -> AuthorizationValidator:
    return AuthorizationValidator(scope_dir=str(tmp_path / "scopes"))


def test_c05_no_token_means_no_scope(tmp_path):
    """C-05: _find_scope must NOT fall back to the first loaded scope."""
    v = _validator(tmp_path)
    v.active_scopes["tok-A"] = AuthorizationScope(
        authorization_id="tok-A",
        client_name="ClientA",
        signed_by="me",
        signed_date=datetime.now(timezone.utc) - timedelta(days=1),
        expires=datetime.now(timezone.utc) + timedelta(days=1),
    )
    assert v._find_scope(None) is None
    assert v._find_scope("tok-A") is not None
    assert v._find_scope("nonexistent") is None


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX only")
def test_c06_rejects_group_readable_scope_file(tmp_path):
    """C-06: scope files with group/other access are refused."""
    v = _validator(tmp_path)
    bad = tmp_path / "bad.yaml"
    bad.write_text("authorization: {}\nscope: {}\n")
    bad.chmod(0o644)
    with pytest.raises(AuthorizationError):
        v._verify_scope_file_perms(bad)

    bad.chmod(0o600)
    # Should not raise now.
    v._verify_scope_file_perms(bad)


def test_m03_timezone_aware_expiry_does_not_crash():
    """M-03: naive scope datetimes must not break aware comparisons."""
    naive_future = datetime.now() + timedelta(days=1)
    naive_past = datetime.now() - timedelta(days=1)
    valid = AuthorizationScope(
        authorization_id="x", client_name="c", signed_by="s",
        signed_date=naive_past, expires=naive_future,
    )
    assert valid.is_valid() is True
    assert valid.is_expired() is False

    expired = AuthorizationScope(
        authorization_id="y", client_name="c", signed_by="s",
        signed_date=naive_past, expires=naive_past,
    )
    assert expired.is_expired() is True


# ---------------------------------------------------------------- H-04
from auth.test_accounts import TestAccountManager


def test_h04_password_not_written_to_disk(tmp_path):
    """H-04: test-account JSON must not contain the plaintext password."""
    mgr = TestAccountManager(storage_dir=str(tmp_path))
    acct = mgr.create_account(target_url="http://t.local", role="user")
    assert acct is not None and acct.password

    json_path = tmp_path / f"{acct.account_id}.json"
    contents = json_path.read_text()
    assert acct.password not in contents

    # Password is resolvable via the keyring-backed accessor.
    assert mgr.get_password(acct.account_id) == acct.password


# ---------------------------------------------------------------- M-07
from autopent.credential_vault import Credential, CredentialType, CredentialSource


def test_m07_credential_not_a_plain_attribute():
    """M-07: secret resolves via get_secret(); to_dict() never serialises it."""
    cred = Credential(
        cred_id="c1",
        username="admin",
        credential="SuperSecret123",
        credential_type=CredentialType.PASSWORD,
        source=CredentialSource.DISCOVERED,
    )
    assert cred.get_secret() == "SuperSecret123"
    assert "credential" not in cred.to_dict()
    assert "SuperSecret123" not in str(cred.to_dict())


# ---------------------------------------------------------------- M-01
from autopent.session_state import write_session_file, read_session_file, _hmac_path
from autopent.session_state import SessionStateManager


def test_m01_session_integrity_roundtrip(tmp_path):
    f = tmp_path / "s.json"
    write_session_file(f, {"hello": "world"})
    assert read_session_file(f) == {"hello": "world"}


def test_m01_tampered_session_rejected(tmp_path):
    f = tmp_path / "s.json"
    write_session_file(f, {"hello": "world"})
    f.write_text('{"hello": "tampered"}')  # mutate payload, sidecar now stale
    assert read_session_file(f) is None


def test_m01_missing_sidecar_rejected(tmp_path):
    f = tmp_path / "s.json"
    write_session_file(f, {"hello": "world"})
    _hmac_path(f).unlink()
    assert read_session_file(f) is None


def _dummy_session_parts():
    edge = SimpleNamespace(successful=True)
    attack_graph = SimpleNamespace(
        objective="validate persistence",
        initial_target="127.0.0.1",
        edges={"e1": edge},
        to_dict=lambda: {"objective": "validate persistence"},
    )
    vault = SimpleNamespace(
        credentials={},
        session_auto_approve=set(),
        get_vault_summary=lambda: {},
    )
    approvals = SimpleNamespace(
        denied_actions=set(),
        get_session_approvals=lambda: [],
        get_approval_summary=lambda: {},
    )
    return attack_graph, vault, approvals


def test_autopent_session_ids_reject_traversal(tmp_path):
    mgr = SessionStateManager(state_dir=str(tmp_path / "sessions"))
    graph, vault, approvals = _dummy_session_parts()

    with pytest.raises(ValueError):
        mgr.save_session("../../x", graph, vault, approvals)
    with pytest.raises(ValueError):
        mgr.load_session("../x")
    with pytest.raises(ValueError):
        mgr.delete_session("../x")
    with pytest.raises(ValueError):
        mgr.auto_save("../x", graph, vault, approvals)
    with pytest.raises(ValueError):
        mgr.get_session_metadata("../x")

    assert not (tmp_path / "x.json").exists()
    assert not (tmp_path / "x.autosave.json").exists()


def test_autopent_valid_session_id_roundtrip_and_private_files(tmp_path):
    mgr = SessionStateManager(state_dir=str(tmp_path / "sessions"))
    graph, vault, approvals = _dummy_session_parts()
    session_id = "session-abc_123.1"

    session_file = mgr.save_session(session_id, graph, vault, approvals)
    assert session_file == tmp_path / "sessions" / f"{session_id}.json"
    assert mgr.load_session(session_id)["metadata"]["session_id"] == session_id
    assert mgr.delete_session(session_id) is True
    assert not session_file.exists()
    assert not _hmac_path(session_file).exists()


@pytest.mark.skipif(not hasattr(os, "stat"), reason="POSIX-style mode checks only")
def test_session_file_and_hmac_are_owner_only(tmp_path):
    f = tmp_path / "s.json"
    write_session_file(f, {"hello": "world"})
    for path in (f, _hmac_path(f)):
        assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0


from core.loot import LootManager


def test_loot_manager_rejects_traversal_session_id(tmp_path, monkeypatch):
    monkeypatch.setenv("ZYPHERON_STATE_DIR", str(tmp_path / "state"))
    with pytest.raises(ValueError):
        LootManager("../../x")
    with pytest.raises(ValueError):
        LootManager.load_session_meta("../x")
    assert not (tmp_path / "x").exists()


def test_loot_manager_valid_session_stays_under_base(tmp_path, monkeypatch):
    monkeypatch.setenv("ZYPHERON_STATE_DIR", str(tmp_path / "state"))
    session_dir = LootManager("valid-session").init("127.0.0.1")
    base = tmp_path / "state" / "loot"
    assert session_dir.resolve().is_relative_to(base.resolve())
    assert (base / "valid-session" / "session.json").exists()
    assert LootManager.load_session_meta("valid-session")["session_id"] == "valid-session"


from autopent.credential_vault import CredentialVault


def test_m07_credential_display_and_logs_are_fully_redacted(caplog):
    secret = "SuperSecret123"
    vault = CredentialVault()
    vault.add_credential(
        "cred-redact",
        "admin",
        secret,
        CredentialType.PASSWORD,
        CredentialSource.DISCOVERED,
    )

    cred = vault.get_credential("cred-redact")
    assert cred is not None
    display = cred.display_name()
    assert "<redacted>" in display
    assert secret not in display
    assert secret[:8] not in display

    request = vault.create_use_request(
        "cred-redact",
        "127.0.0.1",
        "SSH login",
        "ssh",
    )
    formatted = vault.format_use_request(request)
    assert secret not in formatted
    assert secret[:8] not in formatted

    with caplog.at_level("INFO"):
        vault.record_use("cred-redact", "127.0.0.1", True)
    logs = "\n".join(record.getMessage() for record in caplog.records)
    assert secret not in logs
    assert secret[:8] not in logs


@pytest.mark.skipif(not hasattr(os, "stat"), reason="POSIX-style mode checks only")
def test_generated_secret_keys_are_owner_only(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("ZYPHERON_CLUSTER_SECRET", raising=False)

    write_session_file(tmp_path / "session.json", {"x": "y"})

    from auth.session_manager import SessionManager
    from distributed.network import get_cluster_secret

    SessionManager(storage_dir=str(tmp_path / "auth-sessions"))
    get_cluster_secret()

    key_paths = [
        tmp_path / ".zypheron" / "session.key",
        tmp_path / ".zypheron" / "cluster.secret",
        tmp_path / "auth-sessions" / "sessions.key",
    ]
    for path in key_paths:
        assert path.exists()
        assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0


# ---------------------------------------------------------------- C-04
import asyncio


def _agent():
    pytest.importorskip("psutil")  # distributed.agent imports psutil
    from distributed.agent import ScanAgent, AgentConfig
    return ScanAgent(AgentConfig(coordinator_host="127.0.0.1"))


def test_c04_rejects_dangerous_target():
    agent = _agent()
    res = asyncio.run(agent._execute_generic("nmap", "evil.com; rm -rf /", {}))
    assert "error" in res
    assert "Rejected" in res["error"] or "Dangerous" in res["error"]


def test_c04_rejects_dangerous_tool_name():
    agent = _agent()
    res = asyncio.run(agent._execute_generic("nmap; cat /etc/passwd", "127.0.0.1", {}))
    assert "error" in res
    assert "Rejected tool" in res["error"] or "Dangerous" in res["error"]
    # the injected command must never reach the argv
    assert "passwd" not in str(res.get("stdout", ""))
