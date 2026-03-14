"""Device Code model for OAuth 2.0 Device Authorization Grant flow.

This model implements the device code flow (RFC 8628) for authenticating
devices that have limited input capabilities or lack a browser.

Flow:
1. Device requests a device code and user code
2. User enters the user code on a separate device with a browser
3. Device polls the token endpoint with the device code
4. Once user approves, device receives access token
"""

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.user import User


class DeviceCode(Base):
    """Device Code model for OAuth 2.0 Device Authorization Grant.

    Attributes:
        id: Primary key
        device_code: Secret code used by the device to poll for authorization
        user_code: Short code displayed to the user for entering on another device
        device_info: JSON field storing device metadata (OS, version, hardware, etc.)
        user_id: Foreign key to the user who authorized the device (null until authorized)
        status: Current status of the device code (pending, authorized, expired, denied)
        expires_at: Timestamp when the device code expires
        created_at: Timestamp when the device code was created
        updated_at: Timestamp when the device code was last updated
        authorized_at: Timestamp when the user authorized the device
    """

    __tablename__ = "device_codes"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Device code (secret, used by device to poll)
    device_code: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
        comment="Secret code used by device to poll for authorization",
    )

    # User code (short, user-friendly code for manual entry)
    user_code: Mapped[str] = mapped_column(
        String(20),
        unique=True,
        index=True,
        nullable=False,
        comment="Short code displayed to user for manual entry",
    )

    # Device information (stored as JSON for flexibility)
    device_info: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
        comment="Device metadata: OS, version, hardware ID, etc.",
    )

    # User relationship (null until authorized)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Status tracking
    # pending: Waiting for user authorization
    # authorized: User has authorized the device
    # expired: Device code has expired
    # denied: User explicitly denied the authorization
    status: Mapped[str] = mapped_column(
        String(20),
        default="pending",
        nullable=False,
        index=True,
        comment="Status: pending, authorized, expired, denied",
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
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Expiration time for the device code",
    )
    authorized_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when user authorized the device",
    )

    # Relationship to User (device owner after authorization)
    user: Mapped["User | None"] = relationship(
        "User",
        back_populates="device_codes",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return (
            f"<DeviceCode(id={self.id}, user_code={self.user_code}, "
            f"status={self.status}, user_id={self.user_id})>"
        )

    def is_expired(self) -> bool:
        """Check if the device code has expired."""
        # Handle SQLite returning timezone-naive datetimes
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > expires

    def is_pending(self) -> bool:
        """Check if the device code is still pending authorization."""
        return self.status == "pending" and not self.is_expired()

    def is_authorized(self) -> bool:
        """Check if the device code has been authorized."""
        return self.status == "authorized" and self.user_id is not None

    def authorize(self, user_id: int) -> None:
        """Authorize this device code for a specific user.

        Args:
            user_id: The ID of the user authorizing the device
        """
        self.user_id = user_id
        self.status = "authorized"
        self.authorized_at = datetime.now(timezone.utc)

    def deny(self) -> None:
        """Deny authorization for this device code."""
        self.status = "denied"
        self.updated_at = datetime.now(timezone.utc)

    def mark_expired(self) -> None:
        """Mark this device code as expired."""
        self.status = "expired"
        self.updated_at = datetime.now(timezone.utc)

    @staticmethod
    def generate_expiration(minutes: int = 10) -> datetime:
        """Generate expiration timestamp.

        Args:
            minutes: Number of minutes until expiration (default: 10)

        Returns:
            Expiration datetime in UTC
        """
        return datetime.now(timezone.utc) + timedelta(minutes=minutes)
