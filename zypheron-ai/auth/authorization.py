"""
Authorization and Scope Validation System

This module enforces authorization requirements for all pentesting operations.
NO security testing is allowed without explicit written authorization.
"""

import os
import stat
import yaml
import json
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import ipaddress
from dataclasses import dataclass, field
from loguru import logger


@dataclass
class AuthorizationScope:
    """Authorization scope document"""
    authorization_id: str
    client_name: str
    signed_by: str
    signed_date: datetime
    expires: datetime
    targets: List[Dict[str, str]] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)
    restrictions: List[str] = field(default_factory=list)
    permitted_actions: List[str] = field(default_factory=list)
    prohibited_actions: List[str] = field(default_factory=list)
    signature: Optional[str] = None

    @staticmethod
    def _as_aware(dt: datetime) -> datetime:
        """Coerce a datetime to UTC-aware (treat naive values as UTC)."""
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    def is_expired(self) -> bool:
        """Check if authorization has expired"""
        return datetime.now(timezone.utc) > self._as_aware(self.expires)

    def is_valid(self) -> bool:
        """Check if authorization is currently valid"""
        if self.is_expired():
            return False
        if datetime.now(timezone.utc) < self._as_aware(self.signed_date):
            return False  # Not yet valid
        return True


class AuthorizationError(Exception):
    """Raised when authorization is denied"""
    pass


class ScopeViolation(AuthorizationError):
    """Raised when target is out of scope"""
    pass


class AuthorizationValidator:
    """
    Validates all pentesting operations against authorized scope

    Features:
    - Scope document management
    - Target validation
    - Action authorization
    - Digital signature verification
    - Audit logging integration
    """

    def __init__(self, scope_dir: str = None):
        """
        Initialize authorization validator

        Args:
            scope_dir: Directory containing scope documents
        """
        if scope_dir is None:
            scope_dir = str(Path.home() / ".zypheron" / "scopes")

        self.scope_dir = Path(scope_dir)
        self.scope_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        self.active_scopes: Dict[str, AuthorizationScope] = {}
        self._load_scopes()

    def _load_scopes(self):
        """Load all scope documents from directory"""
        for scope_file in self.scope_dir.glob("*.yaml"):
            try:
                scope = self._load_scope_file(scope_file)
                if scope.is_valid():
                    self.active_scopes[scope.authorization_id] = scope
                    logger.info(f"Loaded valid scope: {scope.authorization_id}")
                else:
                    logger.warning(f"Scope expired or invalid: {scope.authorization_id}")
            except Exception as e:
                logger.error(f"Failed to load scope {scope_file}: {e}")

    @staticmethod
    def _verify_scope_file_perms(path: Path) -> None:
        """
        Enforce OS-level integrity guard on a scope document.

        The `signature` field in scope YAML is ADVISORY ONLY and is never
        cryptographically verified (see C-06). The real control preventing a
        local user from forging an authorization scope is file ownership and
        permissions: the file must be owned by the current user and must not be
        readable/writable by group or other. Reject anything else.
        """
        st = path.stat()
        # POSIX-only ownership/permission enforcement.
        if hasattr(os, "geteuid"):
            if st.st_uid != os.geteuid():
                raise AuthorizationError(
                    f"Refusing scope file not owned by current user: {path}"
                )
            if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise AuthorizationError(
                    f"Refusing scope file with group/other access "
                    f"(must be 0600): {path}. Run: chmod 600 {path}"
                )

    def _load_scope_file(self, path: Path) -> AuthorizationScope:
        """Load scope from YAML file"""
        # SECURITY (C-06): the signature field is advisory; OS file permissions
        # are the enforced integrity control.
        self._verify_scope_file_perms(path)

        with open(path) as f:
            data = yaml.safe_load(f)

        auth_data = data['authorization']
        scope_data = data['scope']
        safety = data.get('safety_settings', {})

        return AuthorizationScope(
            authorization_id=auth_data['id'],
            client_name=auth_data['client'],
            signed_by=auth_data['signed_by'],
            signed_date=self._parse_scope_datetime(auth_data['signed_date']),
            expires=self._parse_scope_datetime(auth_data['expires']),
            targets=scope_data.get('targets', []),
            exclusions=scope_data.get('exclusions', []),
            restrictions=scope_data.get('restrictions', []),
            permitted_actions=safety.get('permitted_actions', []),
            prohibited_actions=safety.get('prohibited_actions', []),
            signature=auth_data.get('signature')
        )

    @staticmethod
    def _parse_scope_datetime(value) -> datetime:
        """Parse a scope timestamp as timezone-aware (assume UTC if naive)."""
        if isinstance(value, datetime):
            dt = value
        else:
            dt = datetime.fromisoformat(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    async def validate_target(self, target: str, auth_token: str = None) -> bool:
        """
        Validate target is in authorized scope

        Args:
            target: Target to test (IP, domain, CIDR)
            auth_token: Authorization token (uses active if None)

        Returns:
            True if authorized

        Raises:
            AuthorizationError: If not authorized
            ScopeViolation: If target not in scope
        """
        from core.audit_logger import get_audit_logger

        # Find applicable scope
        scope = self._find_scope(auth_token)
        if not scope:
            audit = get_audit_logger()
            audit.log_authorization_check(
                target=target,
                authorization_token=auth_token or "none",
                result="denied",
                reason="No valid authorization found"
            )
            raise AuthorizationError(
                "No valid authorization found.\n"
                "You must have written authorization before testing any systems.\n"
                "Create a scope document: zypheron auth create-scope"
            )

        # Check if expired
        if scope.is_expired():
            audit = get_audit_logger()
            audit.log_authorization_check(
                target=target,
                authorization_token=scope.authorization_id,
                result="denied",
                reason=f"Authorization expired on {scope.expires}"
            )
            raise AuthorizationError(f"Authorization expired on {scope.expires}")

        # Check exclusions first
        if self._is_excluded(target, scope):
            audit = get_audit_logger()
            audit.log_authorization_check(
                target=target,
                authorization_token=scope.authorization_id,
                result="denied",
                reason="Target is explicitly excluded"
            )
            raise ScopeViolation(f"Target {target} is explicitly excluded from scope")

        # Check if in scope
        if not self._is_in_scope(target, scope):
            audit = get_audit_logger()
            audit.log_authorization_check(
                target=target,
                authorization_token=scope.authorization_id,
                result="denied",
                reason="Target not in authorized scope"
            )
            raise ScopeViolation(
                f"Target {target} is NOT in authorized scope.\n"
                f"Authorization: {scope.authorization_id}\n"
                f"In-scope targets: {self._format_targets(scope.targets)}"
            )

        # Log successful authorization
        audit = get_audit_logger()
        audit.log_authorization_check(
            target=target,
            authorization_token=scope.authorization_id,
            result="granted",
            reason=None
        )

        return True

    async def validate_action(self, action: str, target: str, auth_token: str = None) -> Tuple[bool, bool]:
        """
        Validate if action is permitted

        Args:
            action: Action to perform (e.g., 'sql_injection', 'port_scan')
            target: Target of action
            auth_token: Authorization token

        Returns:
            (is_permitted, requires_confirmation)

        Raises:
            AuthorizationError: If action is prohibited
        """
        scope = self._find_scope(auth_token)
        if not scope:
            raise AuthorizationError("No valid authorization")

        # Check if target is in scope first
        await self.validate_target(target, auth_token)

        # Check prohibited actions
        if action in scope.prohibited_actions:
            raise AuthorizationError(
                f"Action '{action}' is explicitly prohibited by authorization scope"
            )

        # Check if confirmation required
        # (This would be configured in scope document)
        requires_confirmation = action in ['sql_injection', 'command_injection', 'file_upload']

        return True, requires_confirmation

    def _find_scope(self, auth_token: str = None) -> Optional[AuthorizationScope]:
        """
        Find applicable authorization scope.

        SECURITY (C-05): an explicit auth_token is REQUIRED. The previous
        behaviour silently fell back to the first loaded valid scope when no
        token was supplied, which could authorise testing against a target
        covered by an unrelated scope. We now refuse to guess: no token means
        no scope (callers raise AuthorizationError).
        """
        if not auth_token:
            logger.warning(
                "Authorization check with no auth_token; refusing silent "
                "scope fallback (C-05)."
            )
            return None
        return self.active_scopes.get(auth_token)

    def _is_in_scope(self, target: str, scope: AuthorizationScope) -> bool:
        """Check if target matches any scope entry"""
        for scope_target in scope.targets:
            if self._matches_scope_entry(target, scope_target):
                return True
        return False

    def _is_excluded(self, target: str, scope: AuthorizationScope) -> bool:
        """Check if target is in exclusion list"""
        for exclusion in scope.exclusions:
            if self._target_matches(target, exclusion):
                return True
        return False

    def _matches_scope_entry(self, target: str, scope_entry: Dict[str, str]) -> bool:
        """Check if target matches scope entry"""
        entry_type = scope_entry.get('type')
        entry_value = scope_entry.get('value')

        if entry_type == 'domain':
            return self._match_domain(target, entry_value)
        elif entry_type == 'ip_range':
            return self._match_ip_range(target, entry_value)
        elif entry_type == 'specific_host':
            return target == entry_value

        return False

    def _match_domain(self, target: str, pattern: str) -> bool:
        """Match domain with wildcard support"""
        if pattern.startswith('*.'):
            suffix = pattern[2:]
            return target.endswith(suffix) or target == suffix
        return target == pattern

    def _match_ip_range(self, target: str, cidr: str) -> bool:
        """Match IP against CIDR range"""
        try:
            target_ip = ipaddress.ip_address(target)
            network = ipaddress.ip_network(cidr)
            return target_ip in network
        except ValueError:
            return False

    def _target_matches(self, target: str, pattern: str) -> bool:
        """Check if target matches pattern (for exclusions)"""
        # Try exact match
        if target == pattern:
            return True

        # Try as domain suffix
        if target.endswith(f".{pattern}"):
            return True

        # Try as IP in range
        try:
            target_ip = ipaddress.ip_address(target)
            network = ipaddress.ip_network(pattern)
            return target_ip in network
        except ValueError:
            pass

        return False

    def _format_targets(self, targets: List[Dict]) -> str:
        """Format targets for display"""
        formatted = []
        for t in targets[:5]:  # Show first 5
            formatted.append(f"{t.get('type')}: {t.get('value')}")
        if len(targets) > 5:
            formatted.append(f"... and {len(targets) - 5} more")
        return ", ".join(formatted)

    def list_active_scopes(self) -> List[Dict]:
        """List all active authorization scopes"""
        scopes = []
        for scope in self.active_scopes.values():
            if scope.is_valid():
                scopes.append({
                    'id': scope.authorization_id,
                    'client': scope.client_name,
                    'expires': scope.expires.isoformat(),
                    'targets': len(scope.targets),
                    'restrictions': len(scope.restrictions)
                })
        return scopes


# Global authorization validator instance
_auth_validator = None


def get_auth_validator() -> AuthorizationValidator:
    """Get global authorization validator"""
    global _auth_validator
    if _auth_validator is None:
        _auth_validator = AuthorizationValidator()
    return _auth_validator
