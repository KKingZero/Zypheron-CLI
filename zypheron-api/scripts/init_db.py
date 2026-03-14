#!/usr/bin/env python3
"""Database initialization script.

This script initializes the database by creating all tables defined in SQLAlchemy models.
It can be run standalone or imported and called from other scripts.

Usage:
    python scripts/init_db.py [--drop]

Options:
    --drop    Drop all existing tables before creating new ones (DESTRUCTIVE!)
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path so we can import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text

from app.core.config import get_settings
from app.core.database import Base, engine, get_database_url


async def drop_tables() -> None:
    """Drop all existing tables.

    WARNING: This is destructive and will delete all data!
    """
    print("WARNING: Dropping all existing tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    print("All tables dropped successfully.")


async def create_tables() -> None:
    """Create all tables defined in SQLAlchemy models."""
    print("Creating database tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("All tables created successfully.")


async def verify_tables() -> None:
    """Verify that tables were created successfully."""
    print("\nVerifying tables...")
    async with engine.begin() as conn:
        # Get list of tables
        if get_settings().database_type == "postgresql":
            query = text(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                ORDER BY table_name;
                """
            )
        else:
            # SQLite
            query = text(
                """
                SELECT name FROM sqlite_master
                WHERE type='table'
                ORDER BY name;
                """
            )

        result = await conn.execute(query)
        tables = [row[0] for row in result]

    if tables:
        print(f"Found {len(tables)} tables:")
        for table in tables:
            print(f"  - {table}")
    else:
        print("No tables found!")

    # Check expected tables
    expected_tables = [
        "users",
        "devices",
        "device_codes",
        "licenses",
        "sessions",
        "token_usage",
        "user_quota",
    ]

    missing_tables = [t for t in expected_tables if t not in tables]
    if missing_tables:
        print(f"\nWARNING: Missing expected tables: {', '.join(missing_tables)}")
    else:
        print("\nAll expected tables found!")


async def main() -> None:
    """Main initialization function."""
    settings = get_settings()
    db_url = get_database_url()

    print("=" * 70)
    print("Zypheron Database Initialization")
    print("=" * 70)
    print(f"Environment: {settings.environment}")
    print(f"Database Type: {settings.database_type}")
    print(f"Database URL: {db_url}")
    print("=" * 70)

    # Check for --drop flag
    drop_first = "--drop" in sys.argv

    try:
        if drop_first:
            confirm = input("\nAre you sure you want to DROP all tables? (yes/no): ")
            if confirm.lower() != "yes":
                print("Aborted.")
                return
            await drop_tables()

        await create_tables()
        await verify_tables()

        print("\n" + "=" * 70)
        print("Database initialization completed successfully!")
        print("=" * 70)

    except Exception as e:
        print(f"\nERROR: Database initialization failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
    finally:
        # Close database connections
        await engine.dispose()


if __name__ == "__main__":
    # Import all models to ensure they're registered with Base.metadata
    # This must be done before creating tables
    from app.models import (  # noqa: F401
        Device,
        DeviceCode,
        License,
        Session,
        TokenUsage,
        User,
        UserQuota,
    )

    asyncio.run(main())
