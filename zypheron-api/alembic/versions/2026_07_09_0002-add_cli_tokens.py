"""add cli tokens

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-09
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "cli_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_cli_tokens_id"), "cli_tokens", ["id"], unique=False)
    op.create_index(op.f("ix_cli_tokens_user_id"), "cli_tokens", ["user_id"], unique=False)
    op.create_index(op.f("ix_cli_tokens_token_hash"), "cli_tokens", ["token_hash"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_cli_tokens_token_hash"), table_name="cli_tokens")
    op.drop_index(op.f("ix_cli_tokens_user_id"), table_name="cli_tokens")
    op.drop_index(op.f("ix_cli_tokens_id"), table_name="cli_tokens")
    op.drop_table("cli_tokens")
