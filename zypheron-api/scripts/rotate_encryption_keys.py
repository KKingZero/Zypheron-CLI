#!/usr/bin/env python3
"""Script to rotate encryption keys for BYOK API keys.

This script re-encrypts all stored API keys with the current encryption key version.
Useful when rotating keys to a new version.

Usage:
    python scripts/rotate_encryption_keys.py [--dry-run] [--batch-size N]

Options:
    --dry-run       Show what would be rotated without making changes
    --batch-size N  Process N keys per batch (default: 100)

Environment Requirements:
    - All old key versions must be available (BYOK_ENCRYPTION_KEY_V1, V2, etc.)
    - New current key must be set (BYOK_ENCRYPTION_KEY_CURRENT or highest version)

Security Notes:
    - Keeps old keys available during rotation to prevent data loss
    - Re-encrypts incrementally to handle large datasets
    - Verifies decryption before committing changes
"""

import argparse
import asyncio
import structlog
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import async_sessionmaker, engine, init_db
from app.core.encryption import get_encryption_service
from app.models.user_api_key import UserAPIKey

logger = structlog.get_logger()


async def rotate_encryption_keys(
    session: AsyncSession,
    dry_run: bool = False,
    batch_size: int = 100,
) -> dict[str, int]:
    """Re-encrypt all API keys with the current key version.

    Args:
        session: Database session
        dry_run: If True, only report what would be done without making changes
        batch_size: Number of keys to process per batch

    Returns:
        Dictionary with rotation statistics
    """
    service = get_encryption_service()
    stats = {
        "total": 0,
        "needs_rotation": 0,
        "rotated": 0,
        "already_current": 0,
        "errors": 0,
    }

    logger.info(f"Starting encryption key rotation (dry_run={dry_run})")
    logger.info(f"Current encryption version: {service.current_version}")
    logger.info(f"Available key versions: {service.available_versions}")

    # Fetch all user API keys
    stmt = select(UserAPIKey)
    result = await session.execute(stmt)
    keys = result.scalars().all()

    stats["total"] = len(keys)
    logger.info(f"Found {stats['total']} API keys to check")

    # Process keys in batches
    batch = []
    for user_key in keys:
        try:
            # Check if re-encryption is needed
            if service.needs_re_encryption(user_key.encrypted_key):
                stats["needs_rotation"] += 1

                if not dry_run:
                    # Decrypt with old version
                    plaintext = service.decrypt(user_key.encrypted_key)

                    # Re-encrypt with current version
                    new_encrypted = service.encrypt(plaintext)

                    # Verify new encryption works before saving
                    verification = service.decrypt(new_encrypted)
                    if verification != plaintext:
                        logger.error(
                            f"Verification failed for user_id={user_key.user_id}, "
                            f"provider={user_key.provider}"
                        )
                        stats["errors"] += 1
                        continue

                    # Update the encrypted key
                    user_key.encrypted_key = new_encrypted
                    batch.append(user_key)
                    stats["rotated"] += 1

                    logger.debug(
                        f"Rotated key for user_id={user_key.user_id}, "
                        f"provider={user_key.provider}"
                    )

                    # Commit in batches
                    if len(batch) >= batch_size:
                        await session.commit()
                        logger.info(f"Committed batch of {len(batch)} keys")
                        batch.clear()
                else:
                    logger.info(
                        f"Would rotate: user_id={user_key.user_id}, "
                        f"provider={user_key.provider}"
                    )
            else:
                stats["already_current"] += 1
                logger.debug(
                    f"Already current: user_id={user_key.user_id}, "
                    f"provider={user_key.provider}"
                )

        except Exception as e:
            logger.error(
                f"Error processing key for user_id={user_key.user_id}, "
                f"provider={user_key.provider}: {e}"
            )
            stats["errors"] += 1

    # Commit remaining keys
    if batch and not dry_run:
        await session.commit()
        logger.info(f"Committed final batch of {len(batch)} keys")

    return stats


async def main() -> int:
    """Main entry point for key rotation script."""
    parser = argparse.ArgumentParser(
        description="Rotate encryption keys for BYOK API keys"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be rotated without making changes",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Number of keys to process per batch (default: 100)",
    )
    args = parser.parse_args()

    # Validate settings
    settings = get_settings()
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Database: {settings.database_type}")

    # Initialize database
    try:
        async with engine.begin() as conn:
            await init_db(conn)
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return 1

    # Initialize encryption service to validate configuration
    try:
        service = get_encryption_service()
        logger.info(f"Encryption service initialized successfully")
        logger.info(f"Current version: {service.current_version}")
        logger.info(f"Available versions: {service.available_versions}")
    except Exception as e:
        logger.error(f"Failed to initialize encryption service: {e}")
        return 1

    # Perform key rotation
    try:
        async with async_sessionmaker() as session:
            stats = await rotate_encryption_keys(
                session,
                dry_run=args.dry_run,
                batch_size=args.batch_size,
            )

        # Report results
        logger.info("=" * 60)
        logger.info("Key Rotation Summary")
        logger.info("=" * 60)
        logger.info(f"Total keys checked:      {stats['total']}")
        logger.info(f"Already current version: {stats['already_current']}")
        logger.info(f"Needed rotation:         {stats['needs_rotation']}")
        logger.info(f"Successfully rotated:    {stats['rotated']}")
        logger.info(f"Errors:                  {stats['errors']}")
        logger.info("=" * 60)

        if args.dry_run:
            logger.info("DRY RUN - No changes were made")
        elif stats["errors"] > 0:
            logger.warning(f"Completed with {stats['errors']} errors")
            return 1
        else:
            logger.info("Rotation completed successfully")

        return 0

    except Exception as e:
        logger.error(f"Key rotation failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
