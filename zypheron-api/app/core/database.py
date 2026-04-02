"""Database connection and session management.

Supports SQLite by default and optional self-hosted PostgreSQL.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

settings = get_settings()


class Base(DeclarativeBase):
    """Base class for all database models."""

    pass


def get_database_url() -> str:
    """Get the appropriate database URL based on configuration."""
    if settings.database_type == "postgresql" and settings.postgres_url:
        return settings.postgres_url
    return settings.database_url


def get_engine_config() -> dict:
    """Get database engine configuration based on database type.

    Returns optimized connection pool settings for PostgreSQL and
    basic settings for SQLite.
    """
    db_url = get_database_url()
    base_config = {
        "echo": settings.debug,
        "pool_pre_ping": True,  # Verify connections before using
    }

    # PostgreSQL-specific configuration
    if settings.database_type == "postgresql":
        return {
            **base_config,
            "pool_size": 10,  # Number of connections to maintain
            "max_overflow": 20,  # Additional connections when pool is full
            "pool_timeout": 30,  # Timeout for getting a connection (seconds)
            "pool_recycle": 3600,  # Recycle connections after 1 hour
            "connect_args": {
                "server_settings": {
                    "application_name": "zypheron-api",
                    "jit": "off",  # Disable JIT for faster query planning in dev
                },
                "command_timeout": 60,  # Query timeout (seconds)
                "timeout": 10,  # Connection timeout (seconds)
            },
        }

    # SQLite configuration (simpler, no connection pooling)
    return {
        **base_config,
        "connect_args": {"check_same_thread": False},
    }


# Create async engine with appropriate configuration
engine = create_async_engine(
    get_database_url(),
    **get_engine_config(),
)

# Session factory
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for getting database sessions."""
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Close database connections."""
    await engine.dispose()


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """Context manager for database sessions (for non-FastAPI use)."""
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
