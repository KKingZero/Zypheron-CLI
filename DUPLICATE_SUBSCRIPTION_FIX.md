# 🔧 Duplicate Subscription Issue - Fix Implementation

**Date:** October 13, 2025  
**Status:** ✅ Fixed  
**Severity:** Critical

---

## 📋 Problem Summary

Users were experiencing duplicate subscriptions (sometimes 2-3 subscriptions) when signing up for trials or paid plans. The root cause was that the application was using direct Stripe payment links instead of API-generated checkout sessions, which prevented proper user tracking and duplicate prevention.

### Issues Identified:

1. **Missing User Metadata** - Direct payment links don't include user ID in subscription metadata
2. **No Debouncing** - Users could click subscription buttons multiple times
3. **No Duplicate Detection** - No checks for existing active subscriptions
4. **Poor Error Recovery** - Webhooks failed silently when userId was missing
5. **Multiple Customer Creation** - Stripe created new customers each time

---

## ✅ Fixes Implemented

### 1. **API-Generated Checkout Sessions**

**Location:** `frontend/src/pages/Billing.tsx`

Replaced direct Stripe payment links with API calls:

```typescript
// ❌ OLD - Direct payment links
onClick={() => window.location.href = 'https://buy.stripe.com/...'}

// ✅ NEW - API-generated sessions
onClick={() => handleSubscribe('price_1RmQkXABd1WNp9IUjNCzVd6q', 'Light')}
```

**Benefits:**
- User ID properly embedded in subscription metadata
- Consistent customer handling
- Better tracking and analytics
- Proper error handling

---

### 2. **Debouncing & Loading States**

**Location:** `frontend/src/pages/Billing.tsx`

Added state management to prevent multiple simultaneous subscription attempts:

```typescript
const [subscribing, setSubscribing] = useState<string | null>(null)

// In handleSubscribe function:
if (subscribing) {
  toast.warning('Please wait, processing subscription...')
  return
}

// Button implementation:
<button
  disabled={subscribing !== null}
  onClick={() => handleSubscribe(priceId, planName)}
>
  {subscribing === 'Light' ? 'Processing...' : 'Start Free Trial'}
</button>
```

**Benefits:**
- Prevents rapid-fire clicks
- Clear visual feedback
- Prevents duplicate API calls
- Better UX

---

### 3. **Webhook Error Recovery**

**Location:** `backend/src/routes/billing.ts`

Enhanced `handleSubscriptionChange` to recover userId from customer email:

```typescript
if (!userId) {
  console.warn('⚠️ No userId in subscription metadata, attempting recovery...')
  
  const customer = await stripe.customers.retrieve(customerId)
  
  if (customer.email && supabase) {
    // Try users table
    const { data: userData } = await supabase
      .from('users')
      .select('id')
      .eq('email', customer.email)
      .single()
    
    if (userData) {
      userId = userData.id
      
      // Update subscription metadata for future webhooks
      await stripe.subscriptions.update(subscription.id, {
        metadata: { userId: userData.id }
      })
    }
  }
}
```

**Benefits:**
- Recovers from missing metadata
- Fixes subscriptions retroactively
- Updates Stripe records for future events
- Better logging and monitoring

---

### 4. **Duplicate Subscription Detection**

**Location:** `backend/src/routes/billing.ts`

#### A. Webhook Handler Detection

Added check in `handleSubscriptionChange`:

```typescript
// Check for existing active subscriptions
const { data: existingSubscriptions } = await supabase
  .from('user_subscriptions')
  .select('stripe_subscription_id, status')
  .eq('user_id', userId)
  .in('status', ['active', 'trialing'])

if (existingSubscriptions && existingSubscriptions.length > 0) {
  const existingSubIds = existingSubscriptions.map(s => s.stripe_subscription_id)
  
  if (!existingSubIds.includes(subscription.id)) {
    console.warn(`⚠️ User already has ${existingSubscriptions.length} active subscription(s)`)
    
    // Log duplicate for admin review
    await supabase
      .from('subscription_history')
      .insert({
        user_id: userId,
        subscription_status: 'duplicate_detected',
        stripe_subscription_id: subscription.id,
        change_reason: 'Duplicate subscription detected',
        metadata: { existing_subscriptions: existingSubIds }
      })
  }
}
```

#### B. Checkout Endpoint Prevention

Added check in `/api/billing/checkout`:

```typescript
// Check if user already has an active subscription
const { data: existingSubscriptions } = await supabase
  .from('user_subscriptions')
  .select('stripe_subscription_id, status')
  .eq('user_id', user.id)
  .in('status', ['active', 'trialing'])

if (existingSubscriptions && existingSubscriptions.length > 0) {
  return res.status(400).json({ 
    error: 'You already have an active subscription. Please manage your existing subscription from the customer portal.',
    existingSubscriptions: existingSubscriptions.map(s => s.stripe_subscription_id)
  })
}
```

**Benefits:**
- Prevents new subscriptions when one exists
- Logs duplicates for monitoring
- User-friendly error messages
- Directs users to customer portal

---

### 5. **Frontend Error Handling**

**Location:** `frontend/src/pages/Billing.tsx`

Added specific handling for duplicate subscription errors:

```typescript
if (data.existingSubscriptions && data.existingSubscriptions.length > 0) {
  toast.error('You already have an active subscription. Please manage it from the customer portal.', {
    duration: 5000
  })
  // Refresh subscription data
  checkSubscriptionStatus()
}
```

**Benefits:**
- Clear error messages
- Automatic refresh of subscription status
- Guides user to proper action
- Better UX

---

## 🚀 How to Use the Fixed System

### For Users (End Users)

1. **Subscribe to a Plan:**
   - Go to `/billing` page
   - Click on a plan button (Light, Pro, or Enterprise)
   - Wait for "Processing..." message
   - Complete checkout on Stripe's secure page
   - Return to app - subscription will be active

2. **If You See "Already Have Subscription" Error:**
   - Click "Manage Subscription" button
   - Use Stripe Customer Portal to manage your subscription
   - Cancel duplicate subscriptions if any exist

3. **If Payment Succeeds But No Access:**
   - Wait 30-60 seconds for webhook processing
   - Refresh the page
   - If still no access, contact support with email address

### For Developers (Using API)

#### Creating Checkout Sessions

**Endpoint:** `POST /api/billing/checkout`

**Headers:**
```json
{
  "Content-Type": "application/json",
  "Authorization": "Bearer <user_access_token>"
}
```

**Request Body:**
```json
{
  "priceId": "price_1RmQkXABd1WNp9IUjNCzVd6q"
}
```

**Success Response (200):**
```json
{
  "sessionId": "cs_test_...",
  "url": "https://checkout.stripe.com/pay/cs_test_..."
}
```

**Error Response - Duplicate Subscription (400):**
```json
{
  "error": "You already have an active subscription...",
  "existingSubscriptions": ["sub_..."]
}
```

**Error Response - Missing Price ID (400):**
```json
{
  "error": "Price ID is required"
}
```

#### Price IDs

```javascript
const PRICE_IDS = {
  light: 'price_1RmQkXABd1WNp9IUjNCzVd6q',    // $29.99/mo
  pro: 'price_1RmQZfABd1WNp9IU3BI5HpAN',      // $149.99/mo
  enterprise: 'price_1RmQQBABd1WNp9IUa8RSXQ9R' // $999.99/mo
}
```

#### Frontend Implementation Example

```typescript
const handleSubscribe = async (priceId: string, planName: string) => {
  if (!user) {
    toast.error('Please log in to subscribe')
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
      toast.error(data.error || 'Failed to create checkout')
    }
  } catch (error) {
    toast.error('Failed to initiate checkout')
  } finally {
    setLoading(false)
  }
}
```

---

## 🔍 Monitoring & Detection

### Checking for Duplicate Subscriptions

**SQL Query:**
```sql
-- Find users with multiple active subscriptions
SELECT 
  user_id,
  COUNT(*) as subscription_count,
  ARRAY_AGG(stripe_subscription_id) as subscription_ids
FROM user_subscriptions
WHERE status IN ('active', 'trialing')
GROUP BY user_id
HAVING COUNT(*) > 1;
```

### Checking Subscription History Logs

```sql
-- Find duplicate detection logs
SELECT *
FROM subscription_history
WHERE subscription_status = 'duplicate_detected'
ORDER BY created_at DESC
LIMIT 100;
```

### Webhook Logs

Check backend logs for these patterns:

```
✅ Recovered userId: <uuid> for email: <email>
⚠️ User <uuid> already has X active subscription(s)
❌ Could not recover userId for subscription: sub_...
```

---

## 🛠️ Fixing Existing Duplicate Subscriptions

### For the Affected User (dsnkf38uaksdbcvui98243e@proton.me)

1. **Find All Subscriptions in Stripe:**
   ```bash
   # In Stripe Dashboard
   Search: dsnkf38uaksdbcvui98243e@proton.me
   ```

2. **Identify Which to Keep:**
   - Keep the one the user wants to use
   - Cancel the other 2 subscriptions

3. **Cancel Duplicates:**
   ```bash
   # In Stripe Dashboard > Subscriptions
   Click subscription → Cancel subscription → Cancel immediately
   ```

4. **Link Correct Subscription to User Account:**
   ```sql
   -- In Supabase SQL Editor
   -- First, get the user's ID
   SELECT id, email FROM users WHERE email = 'dsnkf38uaksdbcvui98243e@proton.me';
   
   -- Then update their subscription record
   INSERT INTO user_subscriptions (
     user_id,
     stripe_subscription_id,
     stripe_customer_id,
     status,
     current_period_start,
     current_period_end
   ) VALUES (
     '<user_id_from_above>',
     '<correct_stripe_subscription_id>',
     '<stripe_customer_id>',
     'active',
     NOW(),
     NOW() + INTERVAL '1 month'
   )
   ON CONFLICT (user_id) DO UPDATE SET
     stripe_subscription_id = EXCLUDED.stripe_subscription_id,
     stripe_customer_id = EXCLUDED.stripe_customer_id,
     status = EXCLUDED.status,
     updated_at = NOW();
   ```

5. **Issue Refunds:**
   ```bash
   # In Stripe Dashboard > Payments
   Find duplicate charges → Refund
   ```

---

## 📊 Testing the Fix

### Test Scenarios

#### ✅ Test 1: Normal Subscription Flow
1. Log in as a test user with no subscription
2. Click "Get Pro Plan"
3. Should see "Processing..." immediately
4. Should redirect to Stripe Checkout
5. Complete payment
6. Return to app → should have active subscription

#### ✅ Test 2: Prevent Multiple Clicks
1. Log in as a test user with no subscription
2. Click subscription button multiple times rapidly
3. Should see "Please wait, processing subscription..." after first click
4. Button should be disabled during processing

#### ✅ Test 3: Prevent Duplicate Subscriptions
1. Log in as user with existing active subscription
2. Try to click another plan button
3. Should see error: "You already have an active subscription..."
4. Should not redirect to Stripe

#### ✅ Test 4: Webhook Recovery
1. Create subscription with missing userId metadata (simulate old behavior)
2. Webhook should log recovery attempt
3. Should find user by email
4. Should update subscription metadata
5. Should activate subscription in database

---

## 🔐 Security Considerations

### API Endpoint Protection

The `/api/billing/checkout` endpoint is protected by:

1. **Authentication Middleware:** `enhancedAuthMiddleware`
2. **User ID Verification:** Checks `req.user.id`
3. **Duplicate Prevention:** Checks for existing subscriptions
4. **Rate Limiting:** (Should be added if not present)

### Webhook Security

The webhook endpoint uses:

1. **Signature Verification:** `stripe.webhooks.constructEvent`
2. **Idempotency:** Tracks processed event IDs
3. **Error Logging:** Comprehensive error tracking

---

## 📝 Database Schema

### Relevant Tables

```sql
-- user_subscriptions table
CREATE TABLE user_subscriptions (
  id UUID PRIMARY KEY,
  user_id UUID UNIQUE NOT NULL,              -- Prevents duplicates
  stripe_subscription_id TEXT UNIQUE,        -- Prevents duplicates
  stripe_customer_id TEXT,
  status TEXT,                               -- 'active', 'trialing', etc.
  current_period_start TIMESTAMPTZ,
  current_period_end TIMESTAMPTZ,
  created_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ
);

-- subscription_history table (for audit trail)
CREATE TABLE subscription_history (
  id UUID PRIMARY KEY,
  user_id UUID,
  subscription_status TEXT,
  stripe_subscription_id TEXT,
  change_reason TEXT,
  metadata JSONB,
  created_at TIMESTAMPTZ
);
```

---

## 🎯 Success Metrics

After implementing this fix, you should see:

- ✅ Zero duplicate subscriptions created
- ✅ All subscriptions properly linked to user accounts
- ✅ Webhook success rate: 100%
- ✅ User ID recovery rate: >95%
- ✅ Zero failed subscription activations

---

## 📞 Support

If users continue to experience issues:

1. **Check webhook logs** for error messages
2. **Verify Stripe webhook configuration** is pointing to correct endpoint
3. **Check database** for subscription records
4. **Contact Stripe support** if issue is on their end

---

## 🔄 Rollback Plan

If this fix causes issues, you can rollback:

1. **Revert frontend changes:**
   ```bash
   git checkout HEAD~1 -- frontend/src/pages/Billing.tsx
   ```

2. **Revert backend changes:**
   ```bash
   git checkout HEAD~1 -- backend/src/routes/billing.ts
   ```

3. **But note:** Reverting will bring back the duplicate subscription issue!

---

## 📚 Related Documentation

- [Stripe Webhook Setup Guide](./STRIPE_WEBHOOK_SETUP_GUIDE.md)
- [Stripe Integration Setup](./STRIPE_INTEGRATION_SETUP.md)
- [Billing Integration](./BILLING_INTEGRATION_TODO.md)

---

**Last Updated:** October 13, 2025  
**Author:** Cobra AI Development Team  
**Version:** 1.0.0

