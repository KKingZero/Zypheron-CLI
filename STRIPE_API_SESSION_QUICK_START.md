# ⚡ Stripe API Session Quick Start Guide

> **TL;DR:** Use the `/api/billing/checkout` endpoint instead of direct Stripe payment links to prevent duplicate subscriptions and ensure proper user tracking.

---

## 🎯 Why Use API Sessions?

| Direct Payment Links | API-Generated Sessions |
|---------------------|----------------------|
| ❌ No user tracking | ✅ Automatic user ID linking |
| ❌ Creates duplicate customers | ✅ Reuses existing customers |
| ❌ No duplicate prevention | ✅ Prevents duplicate subscriptions |
| ❌ Hard to debug | ✅ Full logging & monitoring |
| ❌ Fixed configuration | ✅ Dynamic configuration |

---

## 🚀 Quick Implementation

### Frontend (React/TypeScript)

```typescript
import { useState } from 'react'
import toast from 'react-hot-toast'

const SubscribeButton = ({ priceId, planName }) => {
  const [loading, setLoading] = useState(false)
  const { user } = useAuth() // Your auth context

  const handleSubscribe = async () => {
    if (!user) {
      toast.error('Please log in first')
      return
    }

    setLoading(true)

    try {
      const response = await fetch('/api/billing/checkout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${user.access_token}`
        },
        body: JSON.stringify({ priceId })
      })

      const data = await response.json()

      if (response.ok && data.url) {
        // Redirect to Stripe Checkout
        window.location.href = data.url
      } else {
        toast.error(data.error || 'Failed to start checkout')
      }
    } catch (error) {
      toast.error('Failed to connect to server')
    } finally {
      setLoading(false)
    }
  }

  return (
    <button 
      onClick={handleSubscribe}
      disabled={loading}
    >
      {loading ? 'Processing...' : `Get ${planName} Plan`}
    </button>
  )
}
```

---

## 📋 API Reference

### Create Checkout Session

**Endpoint:** `POST /api/billing/checkout`

**Authentication:** Required (Bearer token)

**Request:**
```json
{
  "priceId": "price_1RmQkXABd1WNp9IUjNCzVd6q"
}
```

**Success Response (200):**
```json
{
  "sessionId": "cs_test_a1b2c3d4...",
  "url": "https://checkout.stripe.com/pay/cs_test_..."
}
```

**Error Response (400) - Duplicate Subscription:**
```json
{
  "error": "You already have an active subscription...",
  "existingSubscriptions": ["sub_1ABC123"]
}
```

**Error Response (400) - Missing Price:**
```json
{
  "error": "Price ID is required"
}
```

**Error Response (503) - Stripe Not Configured:**
```json
{
  "error": "Billing is not configured"
}
```

---

## 🔑 Price IDs

```javascript
const STRIPE_PRICES = {
  // Light Plan - $29.99/month
  light: 'price_1RmQkXABd1WNp9IUjNCzVd6q',
  
  // Pro Plan - $149.99/month
  pro: 'price_1RmQZfABd1WNp9IU3BI5HpAN',
  
  // Enterprise Plan - $999.99/month
  enterprise: 'price_1RmQQBABd1WNp9IUa8RSXQ9R'
}
```

---

## ✅ Complete Example with Error Handling

```typescript
import { useState } from 'react'
import toast from 'react-hot-toast'
import { useAuth } from './contexts/AuthContext'
import { useNavigate } from 'react-router-dom'

interface SubscribeProps {
  priceId: string
  planName: string
}

export const useSubscribe = () => {
  const [subscribing, setSubscribing] = useState<string | null>(null)
  const { user } = useAuth()
  const navigate = useNavigate()

  const subscribe = async ({ priceId, planName }: SubscribeProps) => {
    // Check authentication
    if (!user) {
      toast.error('Please log in to subscribe')
      navigate('/login')
      return
    }

    // Prevent duplicate clicks
    if (subscribing) {
      toast.warning('Please wait, processing...')
      return
    }

    setSubscribing(planName)

    try {
      const response = await fetch('/api/billing/checkout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${user.access_token}`
        },
        body: JSON.stringify({ priceId })
      })

      const data = await response.json()

      if (response.ok && data.url) {
        toast.success(`Redirecting to checkout for ${planName} plan...`)
        
        // Delay to show toast
        setTimeout(() => {
          window.location.href = data.url
        }, 500)
      } else {
        // Handle specific errors
        if (data.existingSubscriptions?.length > 0) {
          toast.error(
            'You already have an active subscription. Please manage it from the customer portal.',
            { duration: 5000 }
          )
          navigate('/billing')
        } else if (response.status === 401) {
          toast.error('Session expired. Please log in again.')
          navigate('/login')
        } else {
          toast.error(data.error || 'Failed to create checkout session')
        }
        setSubscribing(null)
      }
    } catch (error) {
      console.error('Checkout error:', error)
      toast.error('Network error. Please check your connection.')
      setSubscribing(null)
    }
  }

  return { subscribe, subscribing }
}

// Usage in component:
function PricingCard({ priceId, planName }) {
  const { subscribe, subscribing } = useSubscribe()

  return (
    <button
      onClick={() => subscribe({ priceId, planName })}
      disabled={subscribing !== null}
    >
      {subscribing === planName ? 'Processing...' : `Get ${planName}`}
    </button>
  )
}
```

---

## 🔄 Webhook Flow

After user completes payment:

1. **Stripe sends webhook** → `POST /api/billing/webhook`
2. **Webhook verifies signature** → Validates Stripe signature
3. **Event processed** → `customer.subscription.created`
4. **User ID extracted** → From metadata or recovered from email
5. **Subscription saved** → To `user_subscriptions` table
6. **User access activated** → Via `activate_user_subscription()` function
7. **User redirected** → Back to app with success message

---

## 🧪 Testing

### Test with Stripe Test Cards

```javascript
// Successful payment
const TEST_CARD_SUCCESS = '4242424242424242'

// Payment requires authentication
const TEST_CARD_3DS = '4000002500003155'

// Card declined
const TEST_CARD_DECLINED = '4000000000000002'
```

### Test Flow

1. Create test user account
2. Click subscription button
3. Use test card number: `4242 4242 4242 4242`
4. Any future expiry date
5. Any 3-digit CVC
6. Complete checkout
7. Verify webhook received (check backend logs)
8. Verify subscription active in database
9. Verify user has access in app

---

## 🐛 Debugging

### Check Backend Logs

Look for these log messages:

```bash
✅ Creating checkout session for user <uuid> (<email>)
   Customer ID: cus_...
   Price ID: price_...
✅ Checkout session created: cs_...
```

### Check Webhook Logs

```bash
✅ Received webhook: customer.subscription.created (evt_...)
🔄 Processing subscription change: sub_... -> Plan: pro, Status: active
✅ Recovered userId: <uuid> for email: <email>
✅ User <uuid> successfully activated with pro plan
```

### Check Database

```sql
-- Check user's subscription
SELECT * FROM user_subscriptions 
WHERE user_id = '<user_uuid>';

-- Check subscription history
SELECT * FROM subscription_history 
WHERE user_id = '<user_uuid>' 
ORDER BY created_at DESC;
```

---

## ⚠️ Common Issues & Solutions

### Issue: "Billing is not configured"

**Solution:** Check environment variables:
```bash
STRIPE_SECRET_KEY=sk_test_... or sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

### Issue: User redirected but no subscription

**Possible causes:**
1. Webhook not received (check Stripe webhook logs)
2. Webhook failed (check backend error logs)
3. User ID not in metadata (check webhook recovery logs)

**Solution:** 
- Verify webhook endpoint is publicly accessible
- Check webhook signature verification
- Manually link subscription to user (see docs)

### Issue: "You already have an active subscription"

**Expected behavior!** The system is preventing duplicate subscriptions.

**Solution:** Direct user to customer portal to manage existing subscription.

---

## 🔐 Security Best Practices

1. **Always verify user authentication** before creating checkout
2. **Use HTTPS** for webhook endpoints
3. **Verify webhook signatures** to prevent fraud
4. **Never expose Stripe secret keys** in frontend
5. **Rate limit** checkout endpoint to prevent abuse
6. **Log all transactions** for audit trail

---

## 📞 Support

If you encounter issues:

1. Check backend logs
2. Check Stripe webhook delivery logs
3. Check database subscription records
4. Review [Full Documentation](./DUPLICATE_SUBSCRIPTION_FIX.md)

---

## 🎓 Learn More

- [Stripe Checkout Documentation](https://stripe.com/docs/payments/checkout)
- [Stripe Webhooks Guide](https://stripe.com/docs/webhooks)
- [Full Fix Documentation](./DUPLICATE_SUBSCRIPTION_FIX.md)

---

**Last Updated:** October 13, 2025  
**Version:** 1.0.0

