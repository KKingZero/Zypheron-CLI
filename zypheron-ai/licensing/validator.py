"""
License validation for Zypheron AI engine.

Reads the shared SQLite database that stores license and session information.
This database is shared between CLI, Electron app, and Python AI engine.
"""

import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional
from loguru import logger

from .exceptions import (
    FeatureLockedError,
    InsufficientTokensError,
    NotAuthenticatedError,
    LicenseExpiredError
)


class Tier(str, Enum):
    FREE = "free"
    STARTER = "starter"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class Feature(str, Enum):
    CLOUD_AI = "cloud_ai"
    AUTOPENT = "autopent"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploitation"
    TEAMS = "teams"
    COMPLIANCE = "compliance"
    AUDIT_LOGS = "audit_logs"
    API_ACCESS = "api_access"
    SSO = "sso"


# Feature requirements per tier
TIER_FEATURES = {
    Tier.FREE: [],
    Tier.STARTER: [Feature.CLOUD_AI, Feature.AUTOPENT, Feature.EXPLOITATION, Feature.POST_EXPLOIT],
    Tier.PRO: [Feature.CLOUD_AI, Feature.AUTOPENT, Feature.EXPLOITATION, Feature.POST_EXPLOIT],
    Tier.ENTERPRISE: [
        Feature.CLOUD_AI, Feature.AUTOPENT, Feature.EXPLOITATION, Feature.POST_EXPLOIT,
        Feature.TEAMS, Feature.COMPLIANCE, Feature.AUDIT_LOGS, Feature.API_ACCESS, Feature.SSO
    ],
}

# Token limits per tier
TIER_TOKEN_LIMITS = {
    Tier.FREE: 0,
    Tier.STARTER: 1_000_000,
    Tier.PRO: 3_000_000,
    Tier.ENTERPRISE: 15_000_000,
}

# Cloud AI providers that require paid tier
CLOUD_PROVIDERS = {
    "claude", "anthropic",
    "openai", "gpt",
    "gemini", "google",
    "deepseek",
    "grok", "xai",
    "kimi", "moonshot",
}


@dataclass
class License:
    """Represents a user's license state."""
    user_id: str = ""
    email: str = ""
    tier: Tier = Tier.FREE
    features: List[Feature] = field(default_factory=list)
    tokens_remaining: int = 0
    tokens_used: int = 0
    tokens_limit: int = 0
    reset_date: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    issued_at: Optional[datetime] = None
    device_id: str = ""
    team_id: Optional[str] = None
    team_role: Optional[str] = None
    offline_days: int = 30

    def has_feature(self, feature: Feature) -> bool:
        """Check if license includes a specific feature."""
        # Check direct feature list
        if feature in self.features:
            return True
        # Check tier defaults
        return feature in TIER_FEATURES.get(self.tier, [])

    def is_paid(self) -> bool:
        """Check if this is a paid tier."""
        return self.tier in (Tier.STARTER, Tier.PRO, Tier.ENTERPRISE)

    @classmethod
    def free_tier(cls) -> 'License':
        """Return a default free tier license."""
        return cls(tier=Tier.FREE)


class LicenseValidator:
    """
    Validates licenses by reading from the shared SQLite database.

    The database is created by the CLI/Electron app and stored at:
    ~/.zypheron/zypheron.db
    """

    _instance: Optional['LicenseValidator'] = None
    _license: Optional[License] = None

    def __new__(cls):
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._db_path = self._get_db_path()
        self._load_license()

    @staticmethod
    def _get_db_path() -> Path:
        """Get path to the shared SQLite database."""
        home = Path.home()
        return home / ".zypheron" / "zypheron.db"

    def _load_license(self):
        """Load license from SQLite database."""
        if not self._db_path.exists():
            logger.debug("License database not found, using free tier")
            self._license = License.free_tier()
            return

        try:
            conn = sqlite3.connect(str(self._db_path))
            cursor = conn.cursor()

            # Load license cache
            cursor.execute("SELECT license_json FROM license_cache WHERE id = 1")
            row = cursor.fetchone()

            if row:
                data = json.loads(row[0])
                self._license = License(
                    user_id=data.get("user_id", ""),
                    email=data.get("email", ""),
                    tier=Tier(data.get("tier", "free")),
                    features=[Feature(f) for f in data.get("features", []) if f in Feature.__members__.values()],
                    tokens_remaining=data.get("tokens_remaining", 0),
                    tokens_used=data.get("tokens_used", 0),
                    tokens_limit=data.get("tokens_limit", 0),
                    reset_date=datetime.fromisoformat(data["reset_date"]) if data.get("reset_date") else None,
                    expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
                    issued_at=datetime.fromisoformat(data["issued_at"]) if data.get("issued_at") else None,
                    device_id=data.get("device_id", ""),
                    team_id=data.get("team_id"),
                    team_role=data.get("team_role"),
                    offline_days=data.get("offline_days", 30),
                )
                logger.info(f"Loaded license: tier={self._license.tier}, tokens={self._license.tokens_remaining}")
            else:
                self._license = License.free_tier()

            conn.close()
        except Exception as e:
            logger.error(f"Failed to load license: {e}")
            self._license = License.free_tier()

    @property
    def license(self) -> License:
        """Get current license."""
        if self._license is None:
            self._load_license()
        return self._license or License.free_tier()

    def reload(self):
        """Reload license from database."""
        self._load_license()

    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return self.license.user_id != "" and self.license.email != ""

    def has_feature(self, feature: Feature) -> bool:
        """Check if current license includes a feature."""
        return self.license.has_feature(feature)

    def require_feature(self, feature: Feature) -> None:
        """
        Require a feature, raising FeatureLockedError if not available.

        Args:
            feature: The feature to require

        Raises:
            FeatureLockedError: If feature is not available in current tier
        """
        if not self.has_feature(feature):
            raise FeatureLockedError(
                feature=feature.value,
                required_tier=self._min_tier_for_feature(feature).value,
                current_tier=self.license.tier.value
            )

    def require_cloud_ai(self) -> None:
        """Require cloud AI access."""
        self.require_feature(Feature.CLOUD_AI)

    def require_autopent(self) -> None:
        """Require autopent access."""
        self.require_feature(Feature.AUTOPENT)

    def require_exploitation(self) -> None:
        """Require exploitation access."""
        self.require_feature(Feature.EXPLOITATION)

    def require_provider(self, provider: str) -> None:
        """
        Check if a specific AI provider can be used.

        Args:
            provider: The provider name (e.g., "claude", "ollama")

        Raises:
            FeatureLockedError: If cloud AI is required but not available
        """
        if self.is_cloud_provider(provider):
            self.require_cloud_ai()

    def require_tokens(self, estimated: int) -> None:
        """
        Check if enough tokens are available.

        Args:
            estimated: Estimated tokens needed

        Raises:
            InsufficientTokensError: If token balance is too low
        """
        if self.license.tokens_remaining < estimated:
            raise InsufficientTokensError(
                required=estimated,
                available=self.license.tokens_remaining,
                reset_date=self.license.reset_date.isoformat() if self.license.reset_date else None
            )

    def deduct_tokens(self, tokens: int, action: str = "ai_request", provider: str = None) -> None:
        """
        Deduct tokens from balance and record usage.

        Args:
            tokens: Number of tokens to deduct
            action: Description of the action
            provider: AI provider used
        """
        if not self._db_path.exists():
            return

        try:
            conn = sqlite3.connect(str(self._db_path))
            cursor = conn.cursor()

            # Update license cache
            if self._license:
                self._license.tokens_remaining -= tokens
                self._license.tokens_used += tokens

                # Update in database
                cursor.execute(
                    "SELECT license_json FROM license_cache WHERE id = 1"
                )
                row = cursor.fetchone()
                if row:
                    data = json.loads(row[0])
                    data["tokens_remaining"] = self._license.tokens_remaining
                    data["tokens_used"] = self._license.tokens_used
                    cursor.execute(
                        "UPDATE license_cache SET license_json = ?, cached_at = CURRENT_TIMESTAMP WHERE id = 1",
                        (json.dumps(data),)
                    )

            # Record usage
            cursor.execute(
                "INSERT INTO token_usage (action, tokens, provider, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                (action, tokens, provider or "")
            )

            conn.commit()
            conn.close()
            logger.debug(f"Deducted {tokens} tokens, remaining: {self._license.tokens_remaining if self._license else 0}")
        except Exception as e:
            logger.error(f"Failed to deduct tokens: {e}")

    @staticmethod
    def is_cloud_provider(provider: str) -> bool:
        """Check if provider is a cloud AI provider (requires paid tier)."""
        return provider.lower() in CLOUD_PROVIDERS

    @staticmethod
    def _min_tier_for_feature(feature: Feature) -> Tier:
        """Get minimum tier required for a feature."""
        if feature in (Feature.CLOUD_AI, Feature.AUTOPENT, Feature.EXPLOITATION, Feature.POST_EXPLOIT):
            return Tier.STARTER
        if feature in (Feature.TEAMS, Feature.COMPLIANCE, Feature.AUDIT_LOGS, Feature.API_ACCESS, Feature.SSO):
            return Tier.ENTERPRISE
        return Tier.FREE

    def is_license_valid(self) -> bool:
        """Check if cached license is still valid."""
        if self.license.tier == Tier.FREE:
            return True

        # Check expiration
        if self.license.expires_at and datetime.now() > self.license.expires_at:
            return False

        # Check offline duration
        if self.license.offline_days != -1 and self.license.issued_at:
            from datetime import timedelta
            offline_deadline = self.license.issued_at + timedelta(days=self.license.offline_days)
            if datetime.now() > offline_deadline:
                return False

        return True

    def get_available_features(self) -> List[str]:
        """Get list of available features for current tier."""
        return [f.value for f in TIER_FEATURES.get(self.license.tier, [])]

    def can_use_provider(self, provider: str) -> bool:
        """Check if a provider can be used without raising an error."""
        if not self.is_cloud_provider(provider):
            return True  # Local providers always allowed
        return self.has_feature(Feature.CLOUD_AI)


# Singleton instance
_validator: Optional[LicenseValidator] = None


def get_validator() -> LicenseValidator:
    """Get the singleton license validator instance."""
    global _validator
    if _validator is None:
        _validator = LicenseValidator()
    return _validator


def require_cloud_ai():
    """Convenience function to require cloud AI access."""
    get_validator().require_cloud_ai()


def require_autopent():
    """Convenience function to require autopent access."""
    get_validator().require_autopent()


def require_exploitation():
    """Convenience function to require exploitation access."""
    get_validator().require_exploitation()


def require_provider(provider: str):
    """Convenience function to require provider access."""
    get_validator().require_provider(provider)


def can_use_provider(provider: str) -> bool:
    """Check if a provider can be used."""
    return get_validator().can_use_provider(provider)


def deduct_tokens(tokens: int, action: str = "ai_request", provider: str = None):
    """Convenience function to deduct tokens."""
    get_validator().deduct_tokens(tokens, action, provider)
