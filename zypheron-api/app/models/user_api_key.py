"""User API Key model for BYOK (Bring Your Own Key) feature.

Securely stores user-provided API keys for AI providers with encryption.
"""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.user import User


# Supported AI providers for BYOK
ProviderType = Literal["openai", "anthropic", "gemini", "deepseek", "grok", "ollama"]


class UserAPIKey(Base):
    """User-provided API keys for BYOK functionality.

    Stores encrypted API keys that users bring for AI providers.
    When a user has a valid BYOK key, they bypass token limits and
    use their own API key directly.

    Attributes:
        id: Primary key
        user_id: Foreign key to users table
        provider: AI provider name (openai, anthropic, gemini, deepseek, grok)
        encrypted_key: Fernet-encrypted API key (never store plaintext)
        key_masked: Last 4 characters for display (e.g., "sk-...xyz1")
        is_valid: Validation status (checked via test API call)
        last_validated_at: Timestamp of last successful validation
        last_used_at: Timestamp of last usage in API request
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """

    __tablename__ = "user_api_keys"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # User identification (foreign key to users table)
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Provider information
    provider: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    # Encrypted API key (stored using Fernet symmetric encryption)
    # SECURITY: Never store plaintext API keys
    encrypted_key: Mapped[str] = mapped_column(
        Text,  # Encrypted keys can be longer than 255 chars
        nullable=False,
    )

    # Masked key for display (e.g., "sk-...xyz1" or "...xyz1")
    # Shows only the last 4 characters for user reference
    key_masked: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    # Validation status
    is_valid: Mapped[bool] = mapped_column(
        nullable=False,
        default=False,
    )

    # Last validation timestamp
    last_validated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Last usage timestamp (updated when key is used in API proxy)
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationship to User model
    user: Mapped["User"] = relationship(
        "User",
        back_populates="api_keys",
        lazy="selectin",
    )

    # Composite indexes for efficient queries
    __table_args__ = (
        # Ensure one key per provider per user (composite unique constraint)
        Index("idx_user_provider_unique", "user_id", "provider", unique=True),
        # Query keys by validation status
        Index("idx_user_valid", "user_id", "is_valid"),
    )

    def __repr__(self) -> str:
        return (
            f"<UserAPIKey(id={self.id}, user_id={self.user_id}, "
            f"provider={self.provider}, valid={self.is_valid})>"
        )

    def mark_as_valid(self) -> None:
        """Mark the API key as validated and update timestamp."""
        self.is_valid = True
        self.last_validated_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

    def mark_as_invalid(self) -> None:
        """Mark the API key as invalid."""
        self.is_valid = False
        self.updated_at = datetime.now(timezone.utc)

    def update_last_used(self) -> None:
        """Update the last_used_at timestamp to current time."""
        self.last_used_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

    @staticmethod
    def mask_key(key: str) -> str:
        """Create a masked version of the API key showing only last 4 chars.

        Args:
            key: Full API key to mask

        Returns:
            Masked key in format "...last4" (e.g., "...xyz1")
        """
        if len(key) <= 4:
            return "****"
        return f"...{key[-4:]}"
