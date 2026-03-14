"""Alembic environment configuration for async SQLAlchemy.

Supports both SQLite (aiosqlite) and PostgreSQL (asyncpg) based on app settings.
Database URL is resolved dynamically from app.core.config at runtime, matching
the same logic used by the application in app.core.database.get_database_url().
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.core.config import get_settings
from app.core.database import Base, get_database_url

# Import all model modules so that Base.metadata is fully populated
# with every table before Alembic inspects it for autogenerate.
from app.models.user import User  # noqa: F401
from app.models.device import Device  # noqa: F401
from app.models.device_code import DeviceCode  # noqa: F401
from app.models.session import Session  # noqa: F401
from app.models.user_api_key import UserAPIKey  # noqa: F401
from app.models.token_usage import TokenUsage, UserQuota  # noqa: F401
from app.models.license import License  # noqa: F401

# Alembic Config object -- provides access to values in alembic.ini
config = context.config

# Load app settings
settings = get_settings()

# Dynamically override the sqlalchemy.url from app settings.
# This uses the same resolution logic as the application itself:
#   - PostgreSQL URL when database_type == "postgresql" and postgres_url is set
#   - SQLite URL otherwise (default for development)
database_url = get_database_url()
config.set_main_option("sqlalchemy.url", database_url)

# Interpret the config file for Python logging if present
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# MetaData object for autogenerate support -- contains all registered models
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Generates SQL scripts without connecting to the database.
    This is useful for generating migration SQL to review or apply manually.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Execute migrations within a connection context.

    This is called synchronously by run_sync() inside the async engine flow.
    """
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        render_as_batch=True,  # Required for SQLite ALTER TABLE support
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in 'online' mode with an async engine.

    Creates a throwaway async engine (NullPool) for the migration,
    runs the migration synchronously within the async connection,
    then disposes the engine.
    """
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    Delegates to the async migration runner since the project uses
    async SQLAlchemy drivers (asyncpg for PostgreSQL, aiosqlite for SQLite).
    """
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
