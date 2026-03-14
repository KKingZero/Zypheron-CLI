"""Database models for token usage tracking.

Tracks token consumption per user per provider for billing and quota enforcement.
"""

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.user import User


class TokenUsage(Base):
    """Token usage records for tracking consumption and enforcing quotas.

    Each record represents a single API call with token usage information.
    Indexed for efficient querying by user, time period, and provider.
    """

    __tablename__ = "token_usage"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # User identification (foreign key to users table)
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Token consumption (normalized with provider cost multiplier)
    tokens_used: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Detailed token tracking (raw counts before multiplier)
    prompt_tokens: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
        comment="Raw prompt tokens before cost multiplier",
    )
    completion_tokens: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
        comment="Raw completion tokens before cost multiplier",
    )

    # Provider tracking (openai, anthropic, grok, deepseek)
    provider: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    # Model used (gpt-4, claude-3-opus, etc.)
    model: Mapped[str] = mapped_column(String(100), nullable=False)

    # Cache key for deduplication (SHA-256 hash of prompt)
    prompt_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    # Metadata
    endpoint: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="token_usage",
        lazy="noload",
    )

    # Composite indexes for common queries
    __table_args__ = (
        # Query usage by user and time period (for quota checks)
        Index("idx_user_created", "user_id", "created_at"),

        # Query usage by user, provider, and time (for analytics)
        Index("idx_user_provider_created", "user_id", "provider", "created_at"),

        # Query by prompt hash (for cache hit detection)
        Index("idx_prompt_hash", "prompt_hash"),
    )

    def __repr__(self) -> str:
        return (
            f"<TokenUsage(id={self.id}, user_id={self.user_id}, "
            f"tokens={self.tokens_used}, provider={self.provider})>"
        )


class UserQuota(Base):
    """User quota and tier information for quick quota checks.

    Denormalized table for fast quota lookups without aggregating TokenUsage.
    Updated periodically and on each token consumption.
    """

    __tablename__ = "user_quota"

    # Primary key (user_id for fast lookups)
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )

    # Subscription tier (free, starter, pro, enterprise)
    tier: Mapped[str] = mapped_column(String(20), nullable=False, default="free")

    # Current billing period
    period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    # Token usage in current period
    tokens_used_period: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    # Token limit for current tier
    token_limit: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # BYOK (Bring Your Own Key) flag
    byok_enabled: Mapped[bool] = mapped_column(nullable=False, default=False)

    # Enterprise pool tracking (for shared quotas)
    enterprise_pool_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    # Timestamps
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return (
            f"<UserQuota(user_id={self.user_id}, tier={self.tier}, "
            f"used={self.tokens_used_period}/{self.token_limit})>"
        )
