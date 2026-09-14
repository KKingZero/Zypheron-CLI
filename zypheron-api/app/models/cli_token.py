"""Opaque CLI access tokens for Zypheron-hosted cloud inference."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.user import User


class CLIToken(Base):
    """Revocable opaque token used by the open-source CLI.

    Raw token values are only returned at creation time. The database stores a
    SHA-256 hash so a database leak does not expose usable CLI credentials.
    """

    __tablename__ = "cli_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(100), default="Zypheron CLI", nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    user: Mapped["User"] = relationship("User", back_populates="cli_tokens")

    def is_valid(self) -> bool:
        """Return true when the token is not revoked or expired."""
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None and datetime.now(timezone.utc) >= self.expires_at:
            return False
        return True

    def mark_used(self) -> None:
        """Update token activity timestamp."""
        self.last_used_at = datetime.now(timezone.utc)
