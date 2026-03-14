# Stripe Webhook Configuration

## Overview

Zypheron uses Stripe webhooks to synchronize subscription state. The webhook endpoint at `POST /webhooks/stripe` handles subscription lifecycle events.

## Required Webhook Events

Configure these events in the Stripe Dashboard under **Developers > Webhooks**:

| Event | Purpose |
|-------|---------|
| `customer.subscription.created` | Activate license after checkout |
| `customer.subscription.updated` | Handle plan changes, renewals |
| `customer.subscription.deleted` | Downgrade to free tier |
| `invoice.payment_succeeded` | Confirm payment, extend validity |
| `invoice.payment_failed` | Start grace period, notify user |

## Webhook URL

- **Production**: `https://api.zypheron.net/webhooks/stripe`
- **Staging**: `https://staging-api.zypheron.net/webhooks/stripe`
- **Local dev**: `http://localhost:8000/webhooks/stripe`

## Environment Variables

```bash
# Stripe webhook signing secret (from Stripe Dashboard or CLI)
STRIPE_WEBHOOK_SECRET=whsec_...

# Grace period for failed payments (days)
STRIPE_PAYMENT_GRACE_PERIOD_DAYS=3
```

## Local Development with Stripe CLI

### Setup

```bash
# Install Stripe CLI
# macOS: brew install stripe/stripe-cli/stripe
# Linux: see https://docs.stripe.com/stripe-cli

# Login to Stripe
stripe login

# Forward webhooks to local server
stripe listen --forward-to localhost:8000/webhooks/stripe
```

The CLI will output a webhook signing secret (`whsec_...`). Set it as `STRIPE_WEBHOOK_SECRET` in your `.env`.

### Testing Events

```bash
# Trigger a subscription created event
stripe trigger customer.subscription.created

# Trigger payment failure
stripe trigger invoice.payment_failed

# Trigger subscription cancellation
stripe trigger customer.subscription.deleted
```

### Manual Testing

```bash
# Create a checkout session via API
curl -X POST http://localhost:8000/license/upgrade/pro \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"billing_interval": "monthly"}'

# Check license status after webhook
curl http://localhost:8000/license/status \
  -H "Authorization: Bearer <token>"
```

## Idempotency

The webhook handler implements idempotency to safely handle duplicate deliveries:

1. **Redis (primary)**: Event IDs are stored with a 48-hour TTL at `webhook:processed:{event_id}`
2. **In-memory fallback**: If Redis is unavailable, an `OrderedDict` (max 10K events) is used with LRU-style eviction of oldest 2K entries at capacity

Duplicate events return `200 OK` with `{"status": "already_processed", "duplicate": true}`.

## Event Processing Flow

```
Stripe sends event
        |
        v
  Verify signature (STRIPE_WEBHOOK_SECRET)
        |
        v
  Check idempotency (Redis -> in-memory fallback)
        |
   [duplicate?] --yes--> Return 200 (skip)
        |
        no
        |
        v
  Route by event type:
    - subscription.created  -> activate license, set tier + billing interval
    - subscription.updated  -> update tier/status, handle cancellation
    - subscription.deleted  -> downgrade to free
    - payment_succeeded     -> extend validity period
    - payment_failed        -> set past_due, start grace period
        |
        v
  Store event ID for idempotency
        |
        v
  Return 200
```

## Grace Period & Dunning

When `invoice.payment_failed` fires:

1. License status set to `past_due`
2. `valid_until` set to `now + STRIPE_PAYMENT_GRACE_PERIOD_DAYS`
3. User retains access during grace period
4. If payment succeeds during grace: status restored to `active`
5. If grace period expires: `check_grace_period_expiration()` downgrades to free tier

## Monitoring

Webhook processing is tracked via Prometheus metrics:

- `http_requests_total{method="POST", path="/webhooks/stripe"}` - Total webhook calls
- `http_request_duration_seconds{path="/webhooks/stripe"}` - Processing latency

Check webhook health:
```bash
curl http://localhost:8000/health | jq '.components.stripe'
```
