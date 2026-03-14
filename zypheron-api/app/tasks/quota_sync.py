"""Background task for syncing Redis quota cache with database.

This task ensures consistency between Redis (fast quota checks) and PostgreSQL
(persistent storage) by periodically syncing the quota values.

Critical for:
  - Redis restarts (quota data is ephemeral)
  - Data integrity verification
  - Handling reservation expirations
"""

import asyncio
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.core.redis_client import get_redis_client
from app.models.token_usage import UserQuota
from app.services.token_reservation import TokenReservationService

logger = structlog.get_logger()

# Sync interval (5 minutes)
SYNC_INTERVAL_SECONDS = 300


async def sync_quota_to_redis(db: AsyncSession) -> int:
    """Sync all user quotas from database to Redis.

    This ensures Redis quota cache matches database reality, handling cases where:
      - Redis was restarted (data lost)
      - Reservations expired but weren't finalized
      - Manual database adjustments were made

    Args:
        db: Database session

    Returns:
        Number of quotas synced

    Raises:
        Exception: On database or Redis errors (logged, not raised to caller)
    """
    try:
        reservation_service = TokenReservationService()

        # Get all user quotas from database
        stmt = select(UserQuota)
        result = await db.execute(stmt)
        quotas = result.scalars().all()

        synced_count = 0
        for quota in quotas:
            try:
                # Get current Redis value
                redis_usage = await reservation_service.get_current_usage(quota.user_id)

                # Sync database value to Redis
                # This overwrites Redis with authoritative DB value
                await reservation_service.sync_quota_from_db(
                    user_id=quota.user_id,
                    db_usage=quota.tokens_used_period,
                )

                # Log if there was a discrepancy
                if redis_usage != quota.tokens_used_period:
                    logger.warning(
                        "quota_sync_discrepancy",
                        user_id=quota.user_id,
                        redis_usage=redis_usage,
                        db_usage=quota.tokens_used_period,
                        difference=abs(redis_usage - quota.tokens_used_period),
                    )

                synced_count += 1

            except Exception as e:
                logger.error(
                    "quota_sync_failed_for_user",
                    user_id=quota.user_id,
                    error=str(e),
                    error_type=type(e).__name__,
                )
                # Continue syncing other users

        logger.info(
            "quota_sync_completed",
            users_synced=synced_count,
            total_users=len(quotas),
        )

        return synced_count

    except Exception as e:
        logger.error(
            "quota_sync_task_error",
            error=str(e),
            error_type=type(e).__name__,
        )
        raise


async def periodic_quota_sync():
    """Background task that periodically syncs database quotas to Redis.

    Runs indefinitely with configurable interval. Handles errors gracefully
    to ensure continuous operation.

    Interval: 5 minutes (configurable via SYNC_INTERVAL_SECONDS)
    """
    logger.info(
        "quota_sync_task_started",
        interval_seconds=SYNC_INTERVAL_SECONDS,
    )

    while True:
        try:
            # Create database session for this sync cycle
            async with AsyncSessionLocal() as db:
                start_time = datetime.now(timezone.utc)

                # Perform sync
                synced_count = await sync_quota_to_redis(db)

                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

                logger.info(
                    "quota_sync_cycle_completed",
                    users_synced=synced_count,
                    elapsed_seconds=round(elapsed, 2),
                )

        except Exception as e:
            logger.error(
                "quota_sync_cycle_error",
                error=str(e),
                error_type=type(e).__name__,
                message="Will retry on next cycle",
            )

        # Wait before next sync
        await asyncio.sleep(SYNC_INTERVAL_SECONDS)


async def sync_single_user_quota(user_id: int) -> bool:
    """Sync a single user's quota from database to Redis.

    Useful for on-demand syncing after manual database updates.

    Args:
        user_id: User ID to sync

    Returns:
        True if synced successfully, False otherwise
    """
    try:
        async with AsyncSessionLocal() as db:
            # Get user quota
            stmt = select(UserQuota).where(UserQuota.user_id == user_id)
            result = await db.execute(stmt)
            quota = result.scalar_one_or_none()

            if not quota:
                logger.warning(
                    "quota_not_found_for_sync",
                    user_id=user_id,
                )
                return False

            # Sync to Redis
            reservation_service = TokenReservationService()
            await reservation_service.sync_quota_from_db(
                user_id=user_id,
                db_usage=quota.tokens_used_period,
            )

            logger.info(
                "single_user_quota_synced",
                user_id=user_id,
                tokens_used=quota.tokens_used_period,
                token_limit=quota.token_limit,
            )

            return True

    except Exception as e:
        logger.error(
            "single_user_sync_error",
            user_id=user_id,
            error=str(e),
        )
        return False


async def cleanup_expired_reservations():
    """Clean up expired reservations from Redis.

    Redis automatically handles TTL expiration, but this task ensures
    we log and track expired reservations for monitoring.

    Note: This is mostly for observability - Redis TTL handles actual cleanup.
    """
    try:
        redis_client = await get_redis_client()
        if not redis_client.is_available or not redis_client._client:
            logger.warning("redis_unavailable_for_cleanup")
            return

        # Scan for expired reservation keys
        # Pattern: token_reservation:{user_id}:{uuid}
        pattern = "token_reservation:*"

        cursor = 0
        expired_count = 0

        if hasattr(redis_client._client, 'scan'):
            while True:
                cursor, keys = await redis_client._client.scan(
                    cursor=cursor,
                    match=pattern,
                    count=100,
                )

                for key in keys:
                    # Check TTL
                    ttl = await redis_client.ttl(key)
                    if ttl == -2:  # Key doesn't exist (expired)
                        expired_count += 1

                if cursor == 0:
                    break

        if expired_count > 0:
            logger.info(
                "expired_reservations_cleaned",
                count=expired_count,
            )

    except Exception as e:
        logger.error(
            "cleanup_task_error",
            error=str(e),
        )


# Startup hook
async def start_background_tasks():
    """Start all background tasks.

    Call this from FastAPI startup event.
    """
    # Start quota sync task
    asyncio.create_task(periodic_quota_sync())

    logger.info("background_tasks_started")
