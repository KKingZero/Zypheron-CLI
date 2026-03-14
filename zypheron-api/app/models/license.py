"""License model for subscription and billing management.

Integrates with Stripe for payment processing and subscription lifecycle.
Tracks subscription status and validity period.
"""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.user import User


class License(Base):
    """Subscription license model.

    Manages subscription tiers and billing through Stripe integration.
    One active license per user (current model, can be extended for multi-license).

    Tiers:
    - free: BYOK only, 1 device, no API keys provided
    - starter: 1M tokens/month, 2 devices, 60 req/min
    - pro: 3M tokens/month, 3 devices, 120 req/min
    - enterprise: 15M tokens/5 users, 500 devices, 300 req/min

    Attributes:
        id: Primary key
        user_id: Foreign key to user account
        tier: Subscription tier
        stripe_customer_id: Stripe customer identifier
        stripe_subscription_id: Stripe subscription identifier
        stripe_price_id: Stripe price identifier (for the plan)
        status: Subscription status (active, canceled, past_due, incomplete, etc.)
        valid_from: Subscription start date
        valid_until: Subscription end date (null for active subscriptions)
        cancel_at_period_end: Flag for scheduled cancellation
        created_at: License creation timestamp
        updated_at: Last update timestamp
    """

    __tablename__ = "licenses"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Foreign key to user
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Subscription tier
    tier: Mapped[str] = mapped_column(
        String(20),
        default="free",
        nullable=False,
        index=True,
    )

    # Stripe integration fields
    stripe_customer_id: Mapped[str | None] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=True,
    )
    stripe_subscription_id: Mapped[str | None] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=True,
    )
    stripe_price_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Billing interval (monthly or annual)
    billing_interval: Mapped[str] = mapped_column(
        String(20),
        default="monthly",
        nullable=False,
    )

    # Subscription status
    # Possible values: active, canceled, incomplete, incomplete_expired,
    # past_due, paused, trialing, unpaid
    status: Mapped[str] = mapped_column(
        String(50),
        default="active",
        nullable=False,
        index=True,
    )

    # Validity period
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    valid_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,  # Null means active subscription with no end date
    )

    # Cancellation flag
    cancel_at_period_end: Mapped[bool] = mapped_column(default=False, nullable=False)

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

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="licenses")

    def __repr__(self) -> str:
        return f"<License(id={self.id}, user_id={self.user_id}, tier={self.tier}, status={self.status})>"

    def is_valid(self) -> bool:
        """Check if the license is currently valid.

        Returns:
            True if status is active and not expired, False otherwise
        """
        if self.status != "active":
            return False

        if self.valid_until is None:
            return True  # Active with no end date

        from datetime import timezone
        return datetime.now(timezone.utc) < self.valid_until

    def is_enterprise(self) -> bool:
        """Check if this is an enterprise license."""
        return self.tier == "enterprise"

    def is_paid(self) -> bool:
        """Check if this is a paid tier."""
        return self.tier in ["starter", "pro", "enterprise"]
