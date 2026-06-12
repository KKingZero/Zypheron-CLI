"""Shared URL scope checks for API and web scanners."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse


PRIVATE_HOSTNAMES = {"localhost", "localhost.localdomain"}


@dataclass
class ScannerScope:
    """Validate scanner URLs against base host, explicit scope, and private policy."""

    base_url: str | None = None
    scope_hosts: Iterable[str] | None = None
    allow_private_targets: bool = False
    _scope_hosts: set[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._scope_hosts = {
            self._normalize_scope_entry(entry)
            for entry in (self.scope_hosts or [])
            if str(entry).strip()
        }

    @property
    def base_host(self) -> str:
        if not self.base_url:
            return ""
        return self._normalize_host(urlparse(self.base_url).hostname or "")

    def validate_url(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False

        host = self._normalize_host(parsed.hostname)
        in_scope = self.is_in_scope_host(host)
        if not in_scope:
            return False

        if self.is_private_host(host):
            return self.allow_private_targets

        return True

    def is_in_scope_url(self, url: str) -> bool:
        return self.validate_url(url)

    def is_in_scope_host(self, host: str) -> bool:
        normalized = self._normalize_host(host)
        if not self.base_host and not self._scope_hosts:
            return False

        if normalized and normalized == self.base_host:
            return True

        for entry in self._scope_hosts:
            if entry.startswith("*."):
                suffix = entry[1:]
                if normalized == entry[2:] or normalized.endswith(suffix):
                    return True
            elif normalized == entry:
                return True

        return False

    @staticmethod
    def is_private_host(host: str) -> bool:
        normalized = ScannerScope._normalize_host(host)
        if normalized in PRIVATE_HOSTNAMES:
            return True
        try:
            ip = ipaddress.ip_address(normalized.strip("[]"))
        except ValueError:
            return ScannerScope._host_resolves_private(normalized)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or str(ip) == "169.254.169.254"
        )

    @staticmethod
    def _normalize_scope_entry(entry: str) -> str:
        value = str(entry).strip().lower()
        if "://" in value:
            value = urlparse(value).hostname or value
        return ScannerScope._normalize_host(value)

    @staticmethod
    def _normalize_host(host: str) -> str:
        return host.strip().lower().rstrip(".")

    @staticmethod
    def _host_resolves_private(host: str) -> bool:
        try:
            records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError:
            return True

        for record in records:
            address = record[4][0]
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                return True
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or str(ip) == "169.254.169.254"
            ):
                return True

        return False
