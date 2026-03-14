"""Session model for authentication token management.

Tracks active user sessions with JWT tokens.
Supports token invalidation and session expiry.
"""

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.user import User


class Session(Base):
    """User session model for JWT token tracking.

    Each session represents an active authentication token.
    Sessions can be invalidated for logout functionality.

    Attributes:
        id: Primary key
        user_id: Foreign key to user account
        token: JWT access token (hashed for security)
        device_uuid: Optional device identifier for device-specific sessions
        ip_address: IP address of session creation (for security auditing)
        user_agent: Browser/client user agent string
        is_active: Session validity flag
        expires_at: Session expiration timestamp (null for no expiry)
        created_at: Session creation timestamp
        last_activity: Last API activity timestamp
    """

    __tablename__ = "sessions"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Foreign key to user
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,  # Index for fast user session lookups
    )

    # Token and device tracking
    token: Mapped[str] = mapped_column(
        String(500),
        unique=True,
        index=True,
        nullable=False,
    )
    device_uuid: Mapped[str | None] = mapped_column(
        String(255),
        index=True,
        nullable=True,
    )

    # Security and audit fields
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)  # IPv6 max length
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Session status
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False, index=True)

    # Expiration (null means no expiry until logout)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,  # Index for expiration cleanup queries
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    last_activity: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="sessions")

    def __repr__(self) -> str:
        return f"<Session(id={self.id}, user_id={self.user_id}, active={self.is_active})>"

    def is_valid(self) -> bool:
        """Check if the session is currently valid.

        Returns:
            True if session is active and not expired, False otherwise
        """
        if not self.is_active:
            return False

        if self.expires_at is None:
            return True  # No expiry set

        return datetime.now(timezone.utc) < self.expires_at

    def invalidate(self) -> None:
        """Invalidate this session (logout)."""
        self.is_active = False

    def update_activity(self) -> None:
        """Update the last activity timestamp to current UTC time."""
        self.last_activity = datetime.now(timezone.utc)
