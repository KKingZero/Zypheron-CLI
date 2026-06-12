"""Focused scanner safety tests."""

from __future__ import annotations

import asyncio
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.authenticated_scanner import AuthenticatedScanner
from api_testing.api_scanner import APIScanner
from api_testing.graphql_introspection import GraphQLScanner
from api_testing.scope import ScannerScope
from api_testing.swagger_parser import SwaggerParser


def test_spa_discovery_ignores_cross_host_absolute_urls_when_not_scoped():
    scanner = APIScanner()

    verdict = asyncio.run(
        scanner._classify_endpoint(
            "https://app.example.com",
            "https://api.other.test/v1/users",
        )
    )

    assert verdict["kind"] == "ignore"
    assert verdict["reason"] == "out-of-scope"


def test_spa_discovery_allows_cross_host_absolute_urls_when_scoped():
    scanner = APIScanner(scope_hosts=["api.other.test"])

    with patch("api_testing.scope.socket.getaddrinfo", return_value=[]):
        verdict = asyncio.run(
            scanner._classify_endpoint(
                "https://app.example.com",
                "https://api.other.test/v1/users",
            )
        )

    assert verdict["kind"] == "backend"
    assert verdict["url"] == "https://api.other.test/v1/users"


def test_private_targets_require_private_opt_in_and_scope_membership():
    blocked = ScannerScope(
        base_url="https://app.example.com",
        scope_hosts=["127.0.0.1"],
        allow_private_targets=False,
    )
    allowed = ScannerScope(
        base_url="https://app.example.com",
        scope_hosts=["127.0.0.1"],
        allow_private_targets=True,
    )
    unscoped = ScannerScope(
        base_url="https://app.example.com",
        scope_hosts=["internal.example.com"],
        allow_private_targets=True,
    )

    assert blocked.validate_url("http://127.0.0.1:8080/admin") is False
    assert allowed.validate_url("http://127.0.0.1:8080/admin") is True
    assert unscoped.validate_url("http://127.0.0.1:8080/admin") is False


def test_no_scope_context_denies_public_targets():
    scope = ScannerScope()

    assert scope.validate_url("https://api.example.com/v1/users") is False


def test_hostname_resolving_to_private_address_is_blocked_by_default():
    scope = ScannerScope(base_url="https://internal.example.com")
    resolved_private = [(None, None, None, None, ("127.0.0.1", 0))]

    with patch("api_testing.scope.socket.getaddrinfo", return_value=resolved_private):
        assert scope.validate_url("https://internal.example.com/admin") is False


def test_swagger_rejects_out_of_scope_url_before_fetching():
    with patch("api_testing.swagger_parser.requests.get") as mock_get:
        parser = SwaggerParser(
            "https://api.other.test/openapi.json",
            base_url="https://app.example.com",
        )

    assert parser.spec is None
    mock_get.assert_not_called()


def test_graphql_rejects_out_of_scope_url_before_posting():
    scanner = GraphQLScanner(
        "https://api.other.test/graphql",
        base_url="https://app.example.com",
    )

    with patch("api_testing.graphql_introspection.requests.post") as mock_post:
        assert scanner.introspect() is False

    mock_post.assert_not_called()


def test_authenticated_sqlmap_log_summary_redacts_sensitive_headers():
    scanner = AuthenticatedScanner()
    cmd = [
        "sqlmap",
        "-u",
        "https://api.example.com/search?q=1",
        "--headers",
        "Authorization: Bearer abc.def.ghi\nCookie: sessionid=secret; theme=dark\nX-Trace: token=secret",
        "--batch",
    ]

    summary = scanner._sanitize_sqlmap_command(
        cmd,
        method="GET",
        url="https://api.example.com/search?q=1",
        timeout=180,
    )

    assert "abc.def.ghi" not in summary
    assert "sessionid=secret" not in summary
    assert "token=secret" not in summary
    assert "Authorization: <redacted>" in summary
    assert "Cookie: <redacted>" in summary
    assert "token=<redacted>" in summary
    assert "tool=sqlmap" in summary
    assert "target=api.example.com/search" in summary


def test_authenticated_idor_skips_out_of_scope_url_before_requesting():
    session = MagicMock()
    session.get = MagicMock()
    session_manager = MagicMock()
    session_manager.create_requests_session.return_value = session
    scanner = AuthenticatedScanner(
        session_manager=session_manager,
        base_url="https://app.example.com",
    )

    vulns = asyncio.run(
        scanner.test_idor(
            session_id="session-1",
            test_urls=["https://api.other.test/users?id=1"],
        )
    )

    assert vulns == []
    session.get.assert_not_called()
