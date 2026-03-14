"""User model for authentication and authorization.

Supports both email/password and GitHub OAuth authentication.
Tracks subscription tier for feature access control.
"""

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.device import Device
    from app.models.device_code import DeviceCode
    from app.models.license import License
    from app.models.session import Session
    from app.models.token_usage import TokenUsage
    from app.models.user_api_key import UserAPIKey


class User(Base):
    """User account model.

    Attributes:
        id: Primary key
        email: User email address (unique, indexed for fast lookups)
        password_hash: Hashed password (nullable for OAuth-only users)
        github_id: GitHub user ID for OAuth (unique, indexed)
        github_username: GitHub username for display
        github_avatar_url: GitHub profile picture URL
        tier: Subscription tier (free, starter, pro, enterprise)
        is_active: Account status flag
        is_verified: Email verification status
        created_at: Account creation timestamp
        updated_at: Last update timestamp
        last_login: Last successful login timestamp
    """

    __tablename__ = "users"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Authentication fields
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # GitHub OAuth fields
    github_id: Mapped[str | None] = mapped_column(String(100), unique=True, index=True, nullable=True)
    github_username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    github_avatar_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Subscription and status
    tier: Mapped[str] = mapped_column(
        String(20),
        default="free",
        nullable=False,
        index=True,  # Index for filtering by tier
    )
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(default=False, nullable=False)

    # Account lockout protection (AUTH-H3)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,  # Index for checking locked accounts
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    last_login: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships - use TYPE_CHECKING to avoid circular imports
    devices: Mapped[list["Device"]] = relationship(
        "Device",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",  # Eager load devices with user
    )
    device_codes: Mapped[list["DeviceCode"]] = relationship(
        "DeviceCode",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    licenses: Mapped[list["License"]] = relationship(
        "License",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    sessions: Mapped[list["Session"]] = relationship(
        "Session",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    token_usage: Mapped[list["TokenUsage"]] = relationship(
        "TokenUsage",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="noload",  # Don't eager load usage data (can be large)
    )
    api_keys: Mapped[list["UserAPIKey"]] = relationship(
        "UserAPIKey",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",  # Eager load API keys (small dataset)
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, tier={self.tier})>"

    def update_last_login(self) -> None:
        """Update the last login timestamp to current UTC time."""
        self.last_login = datetime.now(timezone.utc)

    def is_locked(self) -> bool:
        """Check if the account is currently locked due to failed login attempts.

        Returns:
            True if account is locked, False otherwise
        """
        if self.locked_until is None:
            return False
        return datetime.now(timezone.utc) < self.locked_until

    def record_failed_login(self, max_attempts: int = 5, lockout_minutes: int = 15) -> bool:
        """Record a failed login attempt and lock account if threshold reached.

        Args:
            max_attempts: Number of failed attempts before lockout (default 5)
            lockout_minutes: Duration of lockout in minutes (default 15)

        Returns:
            True if account is now locked, False otherwise
        """
        from datetime import timedelta

        self.failed_login_attempts += 1

        if self.failed_login_attempts >= max_attempts:
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
            return True

        return False

    def reset_failed_logins(self) -> None:
        """Reset failed login counter on successful login."""
        self.failed_login_attempts = 0
        self.locked_until = None

    def get_lockout_remaining_seconds(self) -> int:
        """Get remaining seconds until lockout expires.

        Returns:
            Seconds remaining, or 0 if not locked
        """
        if self.locked_until is None:
            return 0
        remaining = (self.locked_until - datetime.now(timezone.utc)).total_seconds()
        return max(0, int(remaining))
