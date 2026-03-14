#!/usr/bin/env python3
"""Database migration: Add prompt_tokens and completion_tokens to TokenUsage table.

This migration adds detailed token tracking fields to the token_usage table
to support separate tracking of prompt and completion tokens, which is
required for the enhanced token synchronization system.

Changes:
- Add prompt_tokens column (BigInteger, default 0)
- Add completion_tokens column (BigInteger, default 0)

Migration is idempotent - safe to run multiple times.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import BigInteger, Column, MetaData, Table, text
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import get_settings

settings = get_settings()


async def check_column_exists(engine, table_name: str, column_name: str) -> bool:
    """Check if a column exists in a table.

    Args:
        engine: SQLAlchemy async engine
        table_name: Name of the table
        column_name: Name of the column

    Returns:
        True if column exists, False otherwise
    """
    async with engine.begin() as conn:
        if settings.database_type == "sqlite":
            # SQLite: Check PRAGMA table_info
            result = await conn.execute(text(f"PRAGMA table_info({table_name})"))
            columns = [row[1] for row in result.fetchall()]
            return column_name in columns
        else:
            # PostgreSQL: Check information_schema
            result = await conn.execute(
                text(
                    """
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = :table_name
                    AND column_name = :column_name
                    """
                ),
                {"table_name": table_name, "column_name": column_name},
            )
            return result.fetchone() is not None


async def add_column_if_not_exists(
    engine,
    table_name: str,
    column_name: str,
    column_type: str,
    default_value: str = "0",
) -> bool:
    """Add a column to a table if it doesn't exist.

    Args:
        engine: SQLAlchemy async engine
        table_name: Name of the table
        column_name: Name of the column to add
        column_type: SQL column type (e.g., "BIGINT")
        default_value: Default value for the column

    Returns:
        True if column was added, False if it already existed
    """
    # Check if column already exists
    if await check_column_exists(engine, table_name, column_name):
        print(f"✓ Column {table_name}.{column_name} already exists, skipping")
        return False

    # Add column
    async with engine.begin() as conn:
        if settings.database_type == "sqlite":
            # SQLite: Use ALTER TABLE ADD COLUMN
            await conn.execute(
                text(
                    f"""
                    ALTER TABLE {table_name}
                    ADD COLUMN {column_name} {column_type} NOT NULL DEFAULT {default_value}
                    """
                )
            )
        else:
            # PostgreSQL: Use ALTER TABLE ADD COLUMN with comment
            await conn.execute(
                text(
                    f"""
                    ALTER TABLE {table_name}
                    ADD COLUMN {column_name} {column_type} NOT NULL DEFAULT {default_value}
                    """
                )
            )
            # Add column comment
            comment = (
                "Raw prompt tokens before cost multiplier"
                if "prompt" in column_name
                else "Raw completion tokens before cost multiplier"
            )
            await conn.execute(
                text(
                    f"""
                    COMMENT ON COLUMN {table_name}.{column_name}
                    IS '{comment}'
                    """
                )
            )

        print(f"✓ Added column {table_name}.{column_name}")
        return True


async def migrate():
    """Run the migration."""
    print("Starting migration: Add prompt_tokens and completion_tokens to TokenUsage")
    print(f"Database type: {settings.database_type}")

    # Get database URL
    if settings.database_type == "postgresql":
        database_url = settings.postgres_url
    else:
        database_url = settings.database_url

    if not database_url:
        print("ERROR: Database URL not configured")
        sys.exit(1)

    print(f"Database URL: {database_url.split('@')[-1] if '@' in database_url else database_url}")

    # Create engine
    engine = create_async_engine(database_url, echo=False)

    try:
        # Add prompt_tokens column
        added_prompt = await add_column_if_not_exists(
            engine=engine,
            table_name="token_usage",
            column_name="prompt_tokens",
            column_type="BIGINT",
            default_value="0",
        )

        # Add completion_tokens column
        added_completion = await add_column_if_not_exists(
            engine=engine,
            table_name="token_usage",
            column_name="completion_tokens",
            column_type="BIGINT",
            default_value="0",
        )

        if added_prompt or added_completion:
            print("\n✓ Migration completed successfully!")
            print("\nNext steps:")
            print("1. Restart the API server to use the new schema")
            print("2. New token usage records will include prompt/completion breakdown")
            print("3. Existing records will have 0 for both fields (acceptable)")
        else:
            print("\n✓ Migration already applied, no changes needed")

        # Verify the schema
        print("\nVerifying schema...")
        async with engine.begin() as conn:
            if settings.database_type == "sqlite":
                result = await conn.execute(text("PRAGMA table_info(token_usage)"))
                columns = result.fetchall()
                print("\ntoken_usage columns:")
                for col in columns:
                    print(f"  - {col[1]} ({col[2]})")
            else:
                result = await conn.execute(
                    text(
                        """
                        SELECT column_name, data_type, column_default
                        FROM information_schema.columns
                        WHERE table_name = 'token_usage'
                        ORDER BY ordinal_position
                        """
                    )
                )
                columns = result.fetchall()
                print("\ntoken_usage columns:")
                for col in columns:
                    print(f"  - {col[0]} ({col[1]}) DEFAULT {col[2]}")

    except Exception as e:
        print(f"\n✗ Migration failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
    finally:
        await engine.dispose()


def main():
    """Entry point for migration script."""
    asyncio.run(migrate())


if __name__ == "__main__":
    main()
