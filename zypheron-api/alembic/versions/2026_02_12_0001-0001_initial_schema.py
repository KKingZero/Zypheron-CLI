"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-02-12

Creates all tables for Zypheron API:
  - users
  - devices
  - device_codes
  - sessions
  - user_api_keys
  - token_usage
  - user_quota
  - licenses
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- users ---
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=True),
        sa.Column("github_id", sa.String(length=100), nullable=True),
        sa.Column("github_username", sa.String(length=100), nullable=True),
        sa.Column("github_avatar_url", sa.String(length=500), nullable=True),
        sa.Column("tier", sa.String(length=20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("is_verified", sa.Boolean(), nullable=False),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_users_id"), "users", ["id"], unique=False)
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.create_index(op.f("ix_users_github_id"), "users", ["github_id"], unique=True)
    op.create_index(op.f("ix_users_tier"), "users", ["tier"], unique=False)
    op.create_index(op.f("ix_users_locked_until"), "users", ["locked_until"], unique=False)

    # --- devices ---
    op.create_table(
        "devices",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("device_uuid", sa.String(length=255), nullable=False),
        sa.Column("device_name", sa.String(length=255), nullable=False),
        sa.Column("platform", sa.String(length=50), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_devices_id"), "devices", ["id"], unique=False)
    op.create_index(op.f("ix_devices_user_id"), "devices", ["user_id"], unique=False)
    op.create_index(op.f("ix_devices_device_uuid"), "devices", ["device_uuid"], unique=True)

    # --- device_codes ---
    op.create_table(
        "device_codes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column(
            "device_code",
            sa.String(length=255),
            nullable=False,
            comment="Secret code used by device to poll for authorization",
        ),
        sa.Column(
            "user_code",
            sa.String(length=20),
            nullable=False,
            comment="Short code displayed to user for manual entry",
        ),
        sa.Column(
            "device_info",
            sa.JSON(),
            nullable=True,
            comment="Device metadata: OS, version, hardware ID, etc.",
        ),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            comment="Status: pending, authorized, expired, denied",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
            comment="Expiration time for the device code",
        ),
        sa.Column(
            "authorized_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="Timestamp when user authorized the device",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_device_codes_id"), "device_codes", ["id"], unique=False)
    op.create_index(
        op.f("ix_device_codes_device_code"), "device_codes", ["device_code"], unique=True
    )
    op.create_index(
        op.f("ix_device_codes_user_code"), "device_codes", ["user_code"], unique=True
    )
    op.create_index(op.f("ix_device_codes_user_id"), "device_codes", ["user_id"], unique=False)
    op.create_index(op.f("ix_device_codes_status"), "device_codes", ["status"], unique=False)
    op.create_index(
        op.f("ix_device_codes_expires_at"), "device_codes", ["expires_at"], unique=False
    )

    # --- sessions ---
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token", sa.String(length=500), nullable=False),
        sa.Column("device_uuid", sa.String(length=255), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=500), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "last_activity",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_sessions_id"), "sessions", ["id"], unique=False)
    op.create_index(op.f("ix_sessions_user_id"), "sessions", ["user_id"], unique=False)
    op.create_index(op.f("ix_sessions_token"), "sessions", ["token"], unique=True)
    op.create_index(op.f("ix_sessions_device_uuid"), "sessions", ["device_uuid"], unique=False)
    op.create_index(op.f("ix_sessions_is_active"), "sessions", ["is_active"], unique=False)
    op.create_index(op.f("ix_sessions_expires_at"), "sessions", ["expires_at"], unique=False)

    # --- user_api_keys ---
    op.create_table(
        "user_api_keys",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("encrypted_key", sa.Text(), nullable=False),
        sa.Column("key_masked", sa.String(length=50), nullable=False),
        sa.Column("is_valid", sa.Boolean(), nullable=False),
        sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_user_api_keys_user_id"), "user_api_keys", ["user_id"], unique=False)
    op.create_index(
        op.f("ix_user_api_keys_provider"), "user_api_keys", ["provider"], unique=False
    )
    # Composite indexes from __table_args__
    op.create_index(
        "idx_user_provider_unique",
        "user_api_keys",
        ["user_id", "provider"],
        unique=True,
    )
    op.create_index(
        "idx_user_valid",
        "user_api_keys",
        ["user_id", "is_valid"],
        unique=False,
    )

    # --- token_usage ---
    op.create_table(
        "token_usage",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("tokens_used", sa.BigInteger(), nullable=False),
        sa.Column(
            "prompt_tokens",
            sa.BigInteger(),
            nullable=False,
            comment="Raw prompt tokens before cost multiplier",
        ),
        sa.Column(
            "completion_tokens",
            sa.BigInteger(),
            nullable=False,
            comment="Raw completion tokens before cost multiplier",
        ),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("prompt_hash", sa.String(length=64), nullable=True),
        sa.Column("endpoint", sa.String(length=100), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_token_usage_user_id"), "token_usage", ["user_id"], unique=False)
    op.create_index(op.f("ix_token_usage_provider"), "token_usage", ["provider"], unique=False)
    op.create_index(
        op.f("ix_token_usage_prompt_hash"), "token_usage", ["prompt_hash"], unique=False
    )
    # Composite indexes from __table_args__
    op.create_index(
        "idx_user_created",
        "token_usage",
        ["user_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "idx_user_provider_created",
        "token_usage",
        ["user_id", "provider", "created_at"],
        unique=False,
    )
    op.create_index(
        "idx_prompt_hash",
        "token_usage",
        ["prompt_hash"],
        unique=False,
    )

    # --- user_quota ---
    op.create_table(
        "user_quota",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("tier", sa.String(length=20), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tokens_used_period", sa.BigInteger(), nullable=False),
        sa.Column("token_limit", sa.BigInteger(), nullable=False),
        sa.Column("byok_enabled", sa.Boolean(), nullable=False),
        sa.Column("enterprise_pool_id", sa.String(length=36), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )

    # --- licenses ---
    op.create_table(
        "licenses",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("tier", sa.String(length=20), nullable=False),
        sa.Column("stripe_customer_id", sa.String(length=255), nullable=True),
        sa.Column("stripe_subscription_id", sa.String(length=255), nullable=True),
        sa.Column("stripe_price_id", sa.String(length=255), nullable=True),
        sa.Column("billing_interval", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column(
            "valid_from",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_at_period_end", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_licenses_id"), "licenses", ["id"], unique=False)
    op.create_index(op.f("ix_licenses_user_id"), "licenses", ["user_id"], unique=False)
    op.create_index(op.f("ix_licenses_tier"), "licenses", ["tier"], unique=False)
    op.create_index(
        op.f("ix_licenses_stripe_customer_id"),
        "licenses",
        ["stripe_customer_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_licenses_stripe_subscription_id"),
        "licenses",
        ["stripe_subscription_id"],
        unique=True,
    )
    op.create_index(op.f("ix_licenses_status"), "licenses", ["status"], unique=False)


def downgrade() -> None:
    op.drop_table("licenses")
    op.drop_table("user_quota")
    op.drop_table("token_usage")
    op.drop_table("user_api_keys")
    op.drop_table("sessions")
    op.drop_table("device_codes")
    op.drop_table("devices")
    op.drop_table("users")
