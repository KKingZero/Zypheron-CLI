# Stripe Integration - Phase 4 Documentation

## Overview

This document describes the Stripe payment integration for Zypheron API, implemented in Phase 4. The integration handles subscription lifecycle management, webhook processing, and payment grace periods.

## Architecture

### Components

1. **StripeService** (`app/services/stripe_service.py`)
   - Core service handling all Stripe API interactions
   - Manages customers, subscriptions, and checkout sessions
   - Processes webhook events

2. **Webhooks Router** (`app/routers/webhooks.py`)
   - Receives and verifies Stripe webhook events
   - Dispatches events to appropriate handlers

3. **License Router** (`app/routers/license.py`)
   - Updated endpoints for subscription management
   - Integrates with StripeService

4. **Configuration** (`app/core/config.py`)
   - Stripe API keys and settings
   - Price ID mappings
   - Grace period configuration

## Configuration

### Environment Variables

Add these to your `.env` file (see `.env.example`):

```bash
# Stripe API Keys
STRIPE_SECRET_KEY=sk_test_...                    # Required
STRIPE_WEBHOOK_SECRET=whsec_...                  # Required for webhooks
STRIPE_PUBLISHABLE_KEY=pk_test_...               # Optional (for frontend)

# Price IDs - Map to subscription tiers
STRIPE_PRICE_ID_STARTER=price_...                # Starter tier price
STRIPE_PRICE_ID_PRO=price_...                    # Pro tier price
STRIPE_PRICE_ID_ENTERPRISE=price_...             # Enterprise tier price

# Grace Period
STRIPE_PAYMENT_GRACE_PERIOD_DAYS=3               # Default: 3 days
```

### Stripe Dashboard Setup

#### 1. Create Products and Prices

Go to: https://dashboard.stripe.com/products

Create three products:
- **Zypheron Starter** - $9/month (or your pricing)
- **Zypheron Pro** - $29/month
- **Zypheron Enterprise** - $99/month

Copy the price IDs (e.g., `price_1ABC...`) and add to your `.env` file.

#### 2. Configure Webhook Endpoint

Go to: https://dashboard.stripe.com/webhooks

Add endpoint:
- **URL**: `https://your-api-domain.com/webhooks/stripe`
- **Events to listen to**:
  - `customer.subscription.created`
  - `customer.subscription.updated`
  - `customer.subscription.deleted`
  - `invoice.payment_failed`
  - `invoice.payment_succeeded`

Copy the webhook signing secret and add to `.env` as `STRIPE_WEBHOOK_SECRET`.

## Features

### Subscription Lifecycle Management

#### 1. Upgrade to Paid Tier

**Endpoint**: `POST /license/upgrade/{tier}`

**Parameters**:
- `tier`: Target tier (starter, pro, enterprise)
- `success_url`: Redirect URL after successful payment
- `cancel_url`: Redirect URL if user cancels

**Flow**:
1. Creates or retrieves Stripe customer
2. Creates Stripe Checkout session
3. Returns checkout URL for frontend redirect
4. User completes payment on Stripe
5. Webhook updates license automatically

**Example**:
```bash
curl -X POST "http://localhost:8000/license/upgrade/pro" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "success_url": "http://localhost:3000/success",
    "cancel_url": "http://localhost:3000/cancel"
  }'
```

**Response**:
```json
{
  "checkout_url": "https://checkout.stripe.com/c/pay/cs_test_...",
  "tier": "pro",
  "message": "Checkout session created for pro tier"
}
```

#### 2. Refresh Subscription

**Endpoint**: `POST /license/refresh`

**Flow**:
1. Fetches latest subscription data from Stripe
2. Updates local license status, tier, and validity
3. Returns updated license

**Use Cases**:
- Manual sync after subscription changes
- Verify current subscription status
- Check for renewal or cancellation

#### 3. Cancel Subscription

**Endpoint**: `POST /license/cancel?cancel_immediately=false`

**Parameters**:
- `cancel_immediately`: Boolean (default: false)
  - `false`: Cancel at period end (user keeps access until renewal date)
  - `true`: Cancel immediately with prorated refund

**Flow**:
1. Updates subscription in Stripe
2. Sets `cancel_at_period_end` flag or cancels immediately
3. Returns updated license

### Webhook Event Handlers

#### 1. subscription.created

**Triggered**: When new subscription is created (after checkout)

**Actions**:
- Creates or updates license record
- Sets subscription tier
- Updates user tier
- Sets validity period

#### 2. subscription.updated

**Triggered**: When subscription is modified (renewal, upgrade, downgrade)

**Actions**:
- Updates license status and tier
- Detects renewals and resets token usage
- Clears `past_due` status if payment succeeds
- Logs tier changes

**Renewal Detection**:
- Compares old and new `current_period_end`
- If period advanced and status is active → renewal
- Resets token usage via `TokenTrackingService.reset_period_usage()`

#### 3. subscription.deleted

**Triggered**: When subscription is cancelled/expires

**Actions**:
- Downgrades user to free tier
- Sets status to "canceled"
- Updates quota to free tier limits (BYOK only)

#### 4. invoice.payment_failed

**Triggered**: When payment fails

**Actions**:
- Sets status to "past_due"
- Grants grace period (default: 3 days)
- User retains access during grace period

**Grace Period**:
```python
grace_period_end = now + timedelta(days=STRIPE_PAYMENT_GRACE_PERIOD_DAYS)
license.valid_until = grace_period_end
```

#### 5. invoice.payment_succeeded

**Triggered**: When payment succeeds (including after failed payment)

**Actions**:
- Clears `past_due` status
- Restores full access

## StripeService API

### Customer Management

```python
stripe_service = StripeService(db)

# Get or create customer
customer_id = await stripe_service.get_or_create_customer(user)
```

### Checkout Sessions

```python
checkout_url = await stripe_service.create_checkout_session(
    user=user,
    tier="pro",
    success_url="http://localhost:3000/success",
    cancel_url="http://localhost:3000/cancel"
)
```

### Subscription Management

```python
# Refresh from Stripe
updated_license = await stripe_service.refresh_subscription(license)

# Cancel subscription
updated_license = await stripe_service.cancel_subscription(
    license=license,
    immediately=False  # Cancel at period end
)
```

### Webhook Handlers

```python
# Called automatically by webhook endpoint
await stripe_service.handle_subscription_created(subscription_data)
await stripe_service.handle_subscription_updated(subscription_data)
await stripe_service.handle_subscription_deleted(subscription_data)
await stripe_service.handle_invoice_payment_failed(invoice_data)
await stripe_service.handle_invoice_payment_succeeded(invoice_data)
```

## Database Schema

### License Model Updates

The `License` model already includes all necessary Stripe fields:

```python
class License(Base):
    # Stripe integration fields
    stripe_customer_id: str | None          # Stripe customer ID
    stripe_subscription_id: str | None      # Stripe subscription ID
    stripe_price_id: str | None             # Current price ID

    # Subscription status
    status: str                              # active, canceled, past_due, etc.
    cancel_at_period_end: bool              # Scheduled cancellation flag
    valid_until: datetime | None            # Expiration or grace period end
```

## Error Handling

### Stripe API Errors

All StripeService methods catch and log `stripe.error.StripeError`:

```python
try:
    customer = stripe.Customer.create(...)
except stripe.error.StripeError as e:
    logger.error(f"Failed to create Stripe customer: {e}")
    raise
```

### Webhook Failures

Webhook endpoint returns 200 even on processing errors to prevent retries:

```python
try:
    await stripe_service.handle_subscription_created(event_data)
    logger.info(f"Successfully processed webhook: {event_type}")
except Exception as e:
    logger.error(f"Error processing webhook {event_type}: {e}")
    # Still return 200 - log for monitoring
```

### Configuration Errors

Operations fail gracefully when Stripe is not configured:

```python
if not settings.stripe_secret_key:
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Stripe integration not configured."
    )
```

## Testing

### Local Testing with Stripe CLI

1. **Install Stripe CLI**: https://stripe.com/docs/stripe-cli

2. **Login**:
```bash
stripe login
```

3. **Forward webhooks to local server**:
```bash
stripe listen --forward-to localhost:8000/webhooks/stripe
```

4. **Trigger test events**:
```bash
# Test subscription created
stripe trigger customer.subscription.created

# Test payment failed
stripe trigger invoice.payment_failed

# Test payment succeeded
stripe trigger invoice.payment_succeeded
```

### Test Cards

Use Stripe test cards: https://stripe.com/docs/testing

- **Success**: 4242 4242 4242 4242
- **Decline**: 4000 0000 0000 0002
- **Requires authentication**: 4000 0025 0000 3155

## Security

### Webhook Signature Verification

All webhooks are verified using the webhook secret:

```python
event = stripe.Webhook.construct_event(
    payload,
    sig_header,
    settings.stripe_webhook_secret
)
```

Invalid signatures return 400 Bad Request.

### API Key Security

- Secret keys stored in environment variables (never committed)
- Keys validated on service initialization
- All Stripe API calls use HTTPS

## Monitoring and Logging

### Logging Levels

- **INFO**: Successful operations (customer created, subscription updated)
- **WARNING**: Payment failures, grace period triggers
- **ERROR**: API errors, webhook processing failures

### Key Events to Monitor

1. **Payment failures**: Track `invoice.payment_failed` events
2. **Downgrades**: Monitor `subscription.deleted` for churn
3. **Webhook errors**: Alert on processing failures
4. **Grace period expirations**: Track users in `past_due` status

### Example Log Messages

```
INFO: Created Stripe customer: cus_ABC123 for user 42
INFO: Created checkout session cs_test_XYZ for user 42, tier pro
INFO: Subscription renewed for user 42
WARNING: Payment failed for user 42. Grace period until 2025-12-24T00:00:00Z
ERROR: Failed to create Stripe customer: Invalid API Key provided
```

## Deployment Checklist

### Development
- [ ] Copy `.env.example` to `.env`
- [ ] Add Stripe test keys (sk_test_, pk_test_)
- [ ] Create test products and prices in Stripe Dashboard
- [ ] Configure webhook endpoint in Stripe Dashboard
- [ ] Test with Stripe CLI

### Production
- [ ] Replace test keys with live keys (sk_live_, pk_live_)
- [ ] Update price IDs to production prices
- [ ] Configure production webhook endpoint
- [ ] Enable webhook signature verification
- [ ] Set up monitoring and alerting
- [ ] Test end-to-end payment flow
- [ ] Document runbook for payment issues

## API Endpoints Summary

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/license/upgrade/{tier}` | POST | Create checkout session | Yes |
| `/license/refresh` | POST | Sync with Stripe | Yes |
| `/license/cancel` | POST | Cancel subscription | Yes |
| `/webhooks/stripe` | POST | Receive Stripe events | No (signature) |

## Migration Notes

This implementation is backward compatible:
- Free tier users continue to work without Stripe
- Existing licenses without Stripe IDs remain valid
- Stripe integration is optional (feature flag)

## Support Resources

- **Stripe Documentation**: https://stripe.com/docs
- **Webhook Events**: https://stripe.com/docs/api/events
- **Subscription Lifecycle**: https://stripe.com/docs/billing/subscriptions/overview
- **Testing**: https://stripe.com/docs/testing

## Troubleshooting

### Common Issues

**1. Webhook not receiving events**
- Verify webhook URL is publicly accessible
- Check webhook signing secret matches `.env`
- Ensure endpoint returns 200 status

**2. Price ID not found**
- Verify price IDs in `.env` match Stripe Dashboard
- Check price is active in Stripe
- Ensure using correct API mode (test vs live)

**3. Payment failures not triggering grace period**
- Verify `invoice.payment_failed` webhook is configured
- Check grace period setting in `.env`
- Review webhook processing logs

**4. Token usage not resetting on renewal**
- Verify `subscription.updated` webhook is triggered
- Check renewal detection logic in logs
- Ensure `TokenTrackingService.reset_period_usage()` is called

## Future Enhancements

- [ ] Metered billing for token usage
- [ ] Proration on mid-cycle upgrades/downgrades
- [ ] Subscription pause/resume
- [ ] Multiple payment methods
- [ ] Invoice history API
- [ ] Subscription analytics dashboard
- [ ] Automatic failed payment retry
- [ ] Dunning management (reminder emails)

## Contact

For issues or questions:
- Review logs in `app/services/stripe_service.py` and `app/routers/webhooks.py`
- Check Stripe Dashboard for subscription/payment status
- Verify webhook delivery in Stripe Dashboard > Webhooks
