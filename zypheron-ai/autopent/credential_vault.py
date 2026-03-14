"""
Credential Vault - Secure credential storage and management

Per user requirement: Prompt for approval before using each credential
"""

import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class CredentialType(Enum):
    """Types of credentials"""
    PASSWORD = "password"
    HASH = "hash"  # NTLM, SHA, etc.
    SSH_KEY = "ssh_key"
    API_KEY = "api_key"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    COOKIE = "cookie"


class CredentialSource(Enum):
    """How the credential was obtained"""
    DISCOVERED = "discovered"  # Found during pentest
    PROVIDED = "provided"  # User-provided
    CRACKED = "cracked"  # Cracked from hash
    CAPTURED = "captured"  # Network capture


@dataclass
class Credential:
    """Represents a discovered or provided credential"""
    cred_id: str
    username: str
    credential: str  # The actual password/hash/key (encrypted in real impl)
    credential_type: CredentialType
    source: CredentialSource

    # Context
    source_host: Optional[str] = None
    discovered_at: datetime = field(default_factory=datetime.now)
    discovered_by: Optional[str] = None  # Tool that found it

    # Usage tracking
    used_count: int = 0
    successful_uses: int = 0
    failed_uses: int = 0
    last_used: Optional[datetime] = None

    # Targets where this credential works
    valid_targets: Set[str] = field(default_factory=set)
    invalid_targets: Set[str] = field(default_factory=set)

    # Metadata
    notes: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'cred_id': self.cred_id,
            'username': self.username,
            'type': self.credential_type.value,
            'source': self.source.value,
            'source_host': self.source_host,
            'discovered_at': self.discovered_at.isoformat(),
            'used_count': self.used_count,
            'successful_uses': self.successful_uses,
            'success_rate': (
                self.successful_uses / self.used_count if self.used_count > 0 else 0.0
            ),
            'valid_targets': list(self.valid_targets),
            'tags': self.tags,
        }

    def display_name(self) -> str:
        """Get display-friendly name"""
        cred_preview = self.credential[:8] + "..." if len(self.credential) > 8 else self.credential
        return f"{self.username}:{cred_preview} ({self.credential_type.value})"

    def is_valid(self) -> bool:
        """Check if credential is still valid (not expired, etc.)"""
        # For now, credentials don't expire - in real impl would check age, etc.
        # Could add expiry_at field and check against it
        return True

    @property
    def target(self) -> str:
        """Get the primary target for this credential"""
        return self.source_host or "unknown"

    @property
    def cred_type(self) -> str:
        """Get credential type as string"""
        return self.credential_type.value

    @staticmethod
    def from_dict(data: Dict) -> 'Credential':
        """Reconstruct Credential from dictionary"""
        return Credential(
            cred_id=data['cred_id'],
            username=data['username'],
            credential=data.get('credential', '***'),  # May be redacted
            credential_type=CredentialType(data['type']),
            source=CredentialSource(data['source']),
            source_host=data.get('source_host'),
            discovered_at=datetime.fromisoformat(data['discovered_at']) if data.get('discovered_at') else datetime.now(),
            used_count=data.get('used_count', 0),
            successful_uses=data.get('successful_uses', 0),
            failed_uses=data.get('failed_uses', 0),
            valid_targets=set(data.get('valid_targets', [])),
            invalid_targets=set(data.get('invalid_targets', [])),
            tags=data.get('tags', []),
        )


@dataclass
class CredentialUseRequest:
    """Request to use a credential"""
    cred_id: str
    target: str
    purpose: str  # e.g., "SSH login", "SMB authentication", etc.
    tool: str
    risk_level: str = "medium"


@dataclass
class CredentialUseResponse:
    """Response to credential use request"""
    approved: bool
    cred_id: str
    target: str
    response_at: datetime = field(default_factory=datetime.now)


class CredentialVault:
    """
    Secure credential storage and management

    Features:
    - Store discovered credentials
    - Track usage and success rates
    - Prompt user before each use (per requirement)
    - Learn which credentials work on which targets
    """

    def __init__(self):
        self.credentials: Dict[str, Credential] = {}
        self.use_history: List[CredentialUseResponse] = []

        # Auto-approved uses for this session (user can enable)
        self.session_auto_approve: Set[str] = set()  # Set of cred_ids

    def add_credential(
        self,
        cred_id: str,
        username: str,
        credential: str,
        credential_type: CredentialType,
        source: CredentialSource,
        source_host: Optional[str] = None,
        discovered_by: Optional[str] = None
    ) -> Credential:
        """
        Add a credential to the vault

        Args:
            cred_id: Unique identifier
            username: Username/account name
            credential: The credential value (password, hash, key, etc.)
            credential_type: Type of credential
            source: How it was obtained
            source_host: Host where it was discovered
            discovered_by: Tool that discovered it

        Returns:
            Credential object
        """
        cred = Credential(
            cred_id=cred_id,
            username=username,
            credential=credential,
            credential_type=credential_type,
            source=source,
            source_host=source_host,
            discovered_by=discovered_by,
        )

        self.credentials[cred_id] = cred

        logger.info(
            f"🔑 Credential added: {username} ({credential_type.value}) "
            f"from {source_host or 'unknown'}"
        )

        return cred

    def get_credential(self, cred_id: str) -> Optional[Credential]:
        """Get a credential by ID"""
        return self.credentials.get(cred_id)

    def list_credentials(
        self,
        credential_type: Optional[CredentialType] = None,
        source: Optional[CredentialSource] = None
    ) -> List[Credential]:
        """
        List credentials with optional filters

        Args:
            credential_type: Filter by type
            source: Filter by source

        Returns:
            List of matching credentials
        """
        creds = list(self.credentials.values())

        if credential_type:
            creds = [c for c in creds if c.credential_type == credential_type]

        if source:
            creds = [c for c in creds if c.source == source]

        # Sort by success rate
        creds.sort(
            key=lambda c: (c.successful_uses / c.used_count if c.used_count > 0 else 0),
            reverse=True
        )

        return creds

    def find_credentials_for_target(
        self,
        target: str,
        credential_type: Optional[CredentialType] = None
    ) -> List[Credential]:
        """
        Find credentials that might work for a target

        Prioritizes:
        1. Credentials known to work on this target
        2. Credentials from the same host
        3. Credentials with high success rates

        Args:
            target: Target host/service
            credential_type: Optional type filter

        Returns:
            List of credentials, sorted by likelihood of success
        """
        candidates = []

        for cred in self.credentials.values():
            # Filter by type if specified
            if credential_type and cred.credential_type != credential_type:
                continue

            # Skip if known to fail on this target
            if target in cred.invalid_targets:
                continue

            # Calculate score
            score = 0.0

            # Known to work on this target
            if target in cred.valid_targets:
                score += 10.0

            # From same host
            if cred.source_host == target:
                score += 5.0

            # Success rate
            if cred.used_count > 0:
                success_rate = cred.successful_uses / cred.used_count
                score += success_rate * 3.0

            # Prefer recently successful credentials
            if cred.successful_uses > 0:
                score += 1.0

            candidates.append((score, cred))

        # Sort by score
        candidates.sort(key=lambda x: x[0], reverse=True)

        return [cred for _, cred in candidates]

    def record_use(
        self,
        cred_id: str,
        target: str,
        success: bool
    ):
        """
        Record credential usage

        Args:
            cred_id: Credential ID
            target: Target where it was used
            success: Whether the use was successful
        """
        cred = self.credentials.get(cred_id)
        if not cred:
            logger.warning(f"Attempted to record use of unknown credential: {cred_id}")
            return

        # Update usage stats
        cred.used_count += 1
        cred.last_used = datetime.now()

        if success:
            cred.successful_uses += 1
            cred.valid_targets.add(target)
            logger.info(f"✓ Credential {cred.display_name()} worked on {target}")
        else:
            cred.failed_uses += 1
            cred.invalid_targets.add(target)
            logger.debug(f"✗ Credential {cred.display_name()} failed on {target}")

    def create_use_request(
        self,
        cred_id: str,
        target: str,
        purpose: str,
        tool: str
    ) -> Optional[CredentialUseRequest]:
        """
        Create a request to use a credential

        Args:
            cred_id: Credential to use
            target: Target host/service
            purpose: What the credential will be used for
            tool: Tool that will use it

        Returns:
            CredentialUseRequest or None if credential not found
        """
        cred = self.get_credential(cred_id)
        if not cred:
            return None

        # Determine risk level
        risk_level = "medium"
        if target in cred.valid_targets:
            risk_level = "low"  # We know it works
        elif cred.failed_uses > cred.successful_uses:
            risk_level = "high"  # Track record is poor

        return CredentialUseRequest(
            cred_id=cred_id,
            target=target,
            purpose=purpose,
            tool=tool,
            risk_level=risk_level,
        )

    def format_use_request(
        self,
        request: CredentialUseRequest
    ) -> str:
        """
        Format credential use request for display

        Returns:
            Formatted string for terminal
        """
        cred = self.get_credential(request.cred_id)
        if not cred:
            return "Unknown credential"

        lines = []
        lines.append("\n" + "="*70)
        lines.append("CREDENTIAL USE REQUEST")
        lines.append("="*70)

        lines.append(f"\n🔑 Credential: {cred.display_name()}")
        lines.append(f"👤 Username: {cred.username}")
        lines.append(f"📦 Type: {cred.credential_type.value}")
        lines.append(f"📍 Source: {cred.source.value}")
        if cred.source_host:
            lines.append(f"🖥️  Source Host: {cred.source_host}")

        lines.append(f"\n🎯 Target: {request.target}")
        lines.append(f"🎬 Purpose: {request.purpose}")
        lines.append(f"🔧 Tool: {request.tool}")

        # Usage statistics
        if cred.used_count > 0:
            success_rate = (cred.successful_uses / cred.used_count) * 100
            lines.append(f"\n📊 Usage Statistics:")
            lines.append(f"   Times Used: {cred.used_count}")
            lines.append(f"   Success Rate: {success_rate:.0f}% ({cred.successful_uses}/{cred.used_count})")

        # Known validity
        if request.target in cred.valid_targets:
            lines.append(f"\n✓ This credential is KNOWN TO WORK on this target")
        elif request.target in cred.invalid_targets:
            lines.append(f"\n✗ This credential is KNOWN TO FAIL on this target")

        # Risk
        risk_emoji = {
            'low': '🟢',
            'medium': '🟡',
            'high': '🔴'
        }.get(request.risk_level, '⚪')

        lines.append(f"\n⚠️  Risk: {risk_emoji} {request.risk_level.upper()}")

        lines.append("\n" + "="*70)

        return "\n".join(lines)

    def requires_approval(self, cred_id: str) -> bool:
        """
        Check if credential use requires approval

        Per user requirement: Always prompt (unless session auto-approve enabled)

        Args:
            cred_id: Credential ID

        Returns:
            True if approval required
        """
        # Check session auto-approve
        if cred_id in self.session_auto_approve:
            return False

        # Always require approval (per user requirement)
        return True

    def get_vault_summary(self) -> Dict:
        """Get summary of vault contents"""
        return {
            'total_credentials': len(self.credentials),
            'by_type': {
                cred_type.value: sum(
                    1 for c in self.credentials.values()
                    if c.credential_type == cred_type
                )
                for cred_type in CredentialType
            },
            'by_source': {
                source.value: sum(
                    1 for c in self.credentials.values()
                    if c.source == source
                )
                for source in CredentialSource
            },
            'total_uses': sum(c.used_count for c in self.credentials.values()),
            'successful_uses': sum(c.successful_uses for c in self.credentials.values()),
        }

    def restore_from_dict(self, data: Dict) -> None:
        """
        Restore vault state from saved dictionary

        Args:
            data: Dictionary containing vault data from session save
        """
        # Restore credentials
        vault_data = data.get('vault', [])
        for cred_data in vault_data:
            try:
                cred = Credential.from_dict(cred_data)
                self.credentials[cred.cred_id] = cred
            except Exception as e:
                logger.warning(f"Failed to restore credential: {e}")

        # Restore session auto-approve list
        self.session_auto_approve = set(data.get('session_auto_approve', []))

        logger.info(f"🔑 Restored {len(self.credentials)} credentials from session")
