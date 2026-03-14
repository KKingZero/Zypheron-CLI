"""Webhook handlers for external service integrations.

Currently supports:
- Stripe payment webhooks for subscription lifecycle events

SECURITY: Webhook signature verification is critical.
- All requests must have valid Stripe signatures
- Invalid signatures return 400 (not 200) to prevent replay attacks
- Infrastructure errors return 500 for retry
- Business logic errors return 200 to acknowledge receipt
"""

import structlog
from collections import OrderedDict
from typing import Any

import stripe
from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.redis_client import get_redis_client
from app.services.stripe_service import StripeService

settings = get_settings()
logger = structlog.get_logger()

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

# In-memory fallback for idempotency when Redis is unavailable.
# Uses OrderedDict to evict oldest entries instead of dropping all history.
_processed_events: OrderedDict[str, bool] = OrderedDict()
_MAX_INMEMORY_EVENTS = 10000
_EVICT_COUNT = 2000  # Evict oldest 2000 when at capacity


def _add_to_inmemory_events(event_id: str) -> None:
    """Add event to in-memory idempotency store, evicting oldest entries if at capacity."""
    if len(_processed_events) >= _MAX_INMEMORY_EVENTS:
        # Evict oldest entries instead of clearing all
        for _ in range(_EVICT_COUNT):
            if _processed_events:
                _processed_events.popitem(last=False)
    _processed_events[event_id] = True


class WebhookProcessingError(Exception):
    """Raised when webhook processing encounters a recoverable error."""

    def __init__(self, message: str, should_retry: bool = True):
        super().__init__(message)
        self.should_retry = should_retry


@router.post("/stripe")
async def stripe_webhook(request: Request) -> dict[str, Any]:
    """Handle Stripe webhook events.

    Verifies webhook signature and dispatches to appropriate handler.

    Supported events:
    - customer.subscription.created: New subscription created
    - customer.subscription.updated: Subscription changed (renewal, upgrade, etc.)
    - customer.subscription.deleted: Subscription cancelled
    - invoice.payment_failed: Payment failed (sets grace period)
    - invoice.payment_succeeded: Payment succeeded (clears past_due)

    Args:
        request: FastAPI request object with webhook payload

    Returns:
        Success acknowledgment

    Raises:
        HTTPException: If webhook verification fails or processing error occurs
    """
    # Check if Stripe is configured
    if not settings.stripe_secret_key or not settings.stripe_webhook_secret:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Stripe webhooks not configured. Set STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET.",
        )

    # Get raw body for signature verification
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not sig_header:
        logger.error("Missing stripe-signature header")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing stripe-signature header",
        )

    # Verify webhook signature
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.stripe_webhook_secret
        )
    except ValueError as e:
        # Invalid payload
        logger.error(f"Invalid webhook payload: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid payload",
        )
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        logger.error(f"Invalid webhook signature: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid signature",
        )

    # Extract event type and data
    event_type: str = event["type"]
    event_id: str = event["id"]
    event_data: dict[str, Any] = event["data"]["object"]

    logger.info(f"Received Stripe webhook: {event_type} (id: {event_id})")

    # Idempotency check: skip duplicate events
    redis_key = f"webhook:processed:{event_id}"
    already_processed = False

    try:
        redis_client = await get_redis_client()
        if redis_client and redis_client.is_available and hasattr(redis_client, "_client") and redis_client._client:
            existing = await redis_client._client.get(redis_key)
            if existing:
                already_processed = True
    except Exception:
        # Redis unavailable — use in-memory fallback
        if event_id in _processed_events:
            already_processed = True

    if already_processed:
        logger.info(f"Skipping duplicate webhook: {event_type} (id: {event_id})")
        return {"status": "success", "event_type": event_type, "duplicate": True}

    # Get database session
    async for db in get_db():
        try:
            stripe_service = StripeService(db)

            # Dispatch to appropriate handler
            if event_type == "customer.subscription.created":
                await stripe_service.handle_subscription_created(event_data)

            elif event_type == "customer.subscription.updated":
                await stripe_service.handle_subscription_updated(event_data)

            elif event_type == "customer.subscription.deleted":
                await stripe_service.handle_subscription_deleted(event_data)

            elif event_type == "invoice.payment_failed":
                await stripe_service.handle_invoice_payment_failed(event_data)

            elif event_type == "invoice.payment_succeeded":
                await stripe_service.handle_invoice_payment_succeeded(event_data)

            else:
                # Unhandled event type - log but don't error
                logger.info(f"Unhandled webhook event type: {event_type}")

            logger.info(f"Successfully processed webhook: {event_type}")

            # Mark event as processed for idempotency
            try:
                redis_client = await get_redis_client()
                if redis_client and redis_client.is_available and hasattr(redis_client, "_client") and redis_client._client:
                    await redis_client._client.setex(redis_key, 48 * 3600, "1")  # 48h TTL
                else:
                    # In-memory fallback — evict oldest entries, not all
                    _add_to_inmemory_events(event_id)
            except Exception as idempotency_err:
                # In-memory fallback on Redis error
                logger.warning(f"Failed to store idempotency key: {idempotency_err}")
                _add_to_inmemory_events(event_id)

        except SQLAlchemyError as e:
            # SECURITY: Database errors should trigger Stripe retry
            # Return 500 so Stripe will retry the webhook later
            logger.error(f"Database error processing webhook {event_type}: {e}")
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database error - please retry",
            )

        except WebhookProcessingError as e:
            # Business logic error - check if retry is appropriate
            logger.error(f"Webhook processing error {event_type}: {e}")
            if e.should_retry:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=str(e),
                )
            # Non-retryable business error - acknowledge receipt but log
            logger.warning(f"Non-retryable webhook error for {event_type}: {e}")

        except stripe.error.StripeError as e:
            # Stripe API errors during processing - should retry
            logger.error(f"Stripe API error processing webhook {event_type}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Stripe API error - please retry",
            )

        except Exception as e:
            # Unexpected error - log but acknowledge to prevent infinite retries
            # This handles business logic errors that shouldn't trigger retries
            logger.error(
                f"Unexpected error processing webhook {event_type}: {e}",
                exc_info=True,
            )
            # Return 200 to acknowledge - manual investigation needed
            # This prevents Stripe from retrying forever for data issues

        finally:
            # Ensure database session is closed
            await db.close()

    # Return 200 to acknowledge receipt
    return {"status": "success", "event_type": event_type}
