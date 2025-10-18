# ✅ Stripe Setup Checklist

Use this checklist to ensure your Stripe integration is properly configured for the fixed checkout system.

---

## 📋 Pre-Setup

- [ ] **Stripe Account Created**
  - Sign up at https://dashboard.stripe.com/register
  - Complete business verification

- [ ] **Node.js & npm Installed**
  - Node.js v16+ required
  - Check: `node --version`

- [ ] **Backend Dependencies Installed**
  ```bash
  cd backend
  npm install
  ```

---

## 🔑 Step 1: API Keys Configuration

### Get Your Keys

- [ ] **Get Test Keys** (for development)
  - Go to: https://dashboard.stripe.com/test/apikeys
  - Copy **Secret key** (starts with `sk_test_`)
  - Copy **Publishable key** (starts with `pk_test_`)

- [ ] **Get Live Keys** (for production - do this later)
  - Go to: https://dashboard.stripe.com/apikeys
  - Copy **Secret key** (starts with `sk_live_`)
  - Copy **Publishable key** (starts with `pk_live_`)

### Configure Backend

- [ ] **Open backend/.env file**
  ```bash
  cd backend
  # File should already exist
  ```

- [ ] **Set STRIPE_SECRET_KEY**
  ```bash
  STRIPE_SECRET_KEY=sk_test_your_actual_key_here
  ```

- [ ] **Set FRONTEND_URL**
  ```bash
  # For local development:
  FRONTEND_URL=http://localhost:5173
  
  # For production:
  # FRONTEND_URL=https://app.cobraai.com
  ```

- [ ] **Verify other required keys are set**
  - SUPABASE_URL
  - SUPABASE_SERVICE_ROLE_KEY
  - OPENAI_API_KEY (or other AI keys)

---

## 🛍️ Step 2: Create Products & Prices

- [ ] **Create Light Plan**
  - Go to: https://dashboard.stripe.com/test/products
  - Click "Add product"
  - Name: `Light Plan`
  - Price: `$29.99` USD, Monthly
  - Click "Save product"
  - **Copy Price ID** (starts with `price_`)
  - Add to backend/.env:
    ```bash
    STRIPE_LITE_PRICE_ID=price_your_light_price_id
    ```

- [ ] **Create Pro Plan**
  - Name: `Pro Plan`
  - Price: `$149.99` USD, Monthly
  - **Copy Price ID**
  - Add to backend/.env:
    ```bash
    STRIPE_PRO_PRICE_ID=price_your_pro_price_id
    ```

- [ ] **Create Enterprise Plan**
  - Name: `Enterprise Plan`
  - Price: `$999.99` USD, Monthly
  - **Copy Price ID**
  - Add to backend/.env:
    ```bash
    STRIPE_ENTERPRISE_PRICE_ID=price_your_enterprise_price_id
    ```

- [ ] **Update price IDs in frontend code (if needed)**
  - Already done in `frontend/src/pages/Billing.tsx`
  - Verify they match your actual Stripe price IDs

---

## 🪝 Step 3: Webhook Setup

### For Local Development

- [ ] **Install Stripe CLI**
  
  **macOS:**
  ```bash
  brew install stripe/stripe-cli/stripe
  ```
  
  **Linux:**
  ```bash
  wget https://github.com/stripe/stripe-cli/releases/download/v1.19.4/stripe_1.19.4_linux_x86_64.tar.gz
  tar -xvf stripe_1.19.4_linux_x86_64.tar.gz
  sudo mv stripe /usr/local/bin/
  ```
  
  **Windows (Scoop):**
  ```powershell
  scoop bucket add stripe https://github.com/stripe/scoop-stripe-cli.git
  scoop install stripe
  ```

- [ ] **Login to Stripe CLI**
  ```bash
  stripe login
  ```

- [ ] **Get Webhook Secret for Local Testing**
  ```bash
  # Run this (or use scripts/test-webhook-locally.sh):
  stripe listen --forward-to localhost:3001/api/billing/webhook
  ```
  
- [ ] **Copy webhook secret from CLI output**
  - Look for: `whsec_...`
  - Add to backend/.env:
    ```bash
    STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret_here
    ```

### For Production

- [ ] **Create Webhook Endpoint**
  - Go to: https://dashboard.stripe.com/webhooks
  - Click "Add endpoint"
  - **Endpoint URL:** `https://api.yourdomain.com/api/billing/webhook`
  - **Description:** `Cobra AI Subscription Webhooks`

- [ ] **Select Events to Listen**
  - ✅ `customer.subscription.created`
  - ✅ `customer.subscription.updated`
  - ✅ `customer.subscription.deleted`
  - ✅ `customer.subscription.trial_will_end`
  - ✅ `checkout.session.completed`
  - ✅ `checkout.session.expired`
  - ✅ `invoice.payment_succeeded`
  - ✅ `invoice.payment_failed`
  - ✅ `payment_intent.succeeded`
  - ✅ `payment_intent.payment_failed`

- [ ] **Save and Get Signing Secret**
  - Click endpoint → Click "Reveal" under "Signing secret"
  - Copy the secret (starts with `whsec_`)
  - Update backend/.env with production webhook secret

---

## 🗄️ Step 4: Database Setup

- [ ] **Supabase Project Created**
  - Sign up at https://supabase.com
  - Create new project

- [ ] **Run Database Schema**
  - Go to Supabase SQL Editor
  - Run: `database/schema-billing.sql`
  - Verify tables created:
    - `subscription_plans`
    - `user_subscriptions`
    - `subscription_history`

- [ ] **Insert Subscription Plans**
  - Already in schema-billing.sql
  - Verify they match your Stripe price IDs

- [ ] **Test Database Connection**
  ```bash
  cd backend
  node -e "require('dotenv').config(); console.log('Supabase URL:', process.env.SUPABASE_URL)"
  ```

---

## ✅ Step 5: Validation

- [ ] **Run Validation Script**
  ```bash
  cd scripts
  node validate-stripe-setup.js
  ```
  - All checks should pass ✅
  - Fix any ❌ errors
  - Review ⚠️ warnings

- [ ] **Test Stripe Connection**
  ```bash
  cd scripts
  node test-stripe-checkout.js
  ```
  - Should create test checkout sessions
  - Verify userId in metadata
  - Check webhook configuration

---

## 🧪 Step 6: Testing

### Start All Services

- [ ] **Start Backend**
  ```bash
  cd backend
  npm run dev
  ```
  - Should start on port 3001
  - Look for: "✅ Stripe initialized successfully"

- [ ] **Start Frontend**
  ```bash
  cd frontend
  npm run dev
  ```
  - Should start on port 5173

- [ ] **Start Webhook Forwarding** (local development only)
  ```bash
  # In new terminal:
  cd scripts
  ./test-webhook-locally.sh
  # OR on Windows:
  # test-webhook-locally.bat
  ```
  - Should show: "Ready! You are using Stripe API Version ..."

### Test Subscription Flow

- [ ] **Navigate to Billing Page**
  - Open: http://localhost:5173/billing
  - Should see three plans: Light, Pro, Enterprise

- [ ] **Test Light Plan Subscription**
  - Click "Start Free Trial" button
  - Button should show "Processing..."
  - Should redirect to Stripe Checkout
  
- [ ] **Complete Test Payment**
  - Use test card: `4242 4242 4242 4242`
  - Expiry: Any future date
  - CVC: Any 3 digits
  - ZIP: Any 5 digits
  - Click "Subscribe"

- [ ] **Verify Redirect Back**
  - Should return to app
  - Should show "Payment successful!"
  - Should show active subscription

- [ ] **Check Webhook Received**
  - Look at Stripe CLI output
  - Should show: `customer.subscription.created`
  - Backend should log: `✅ User ... successfully activated with light plan`

- [ ] **Verify Database**
  - Check Supabase → user_subscriptions table
  - Should have new row with user_id and stripe_subscription_id

- [ ] **Test Duplicate Prevention**
  - Try to click another plan button
  - Should see error: "You already have an active subscription..."
  - Should NOT redirect to Stripe

---

## 🚀 Step 7: Production Deployment

- [ ] **Switch to Live Keys**
  - Update backend/.env with `sk_live_` keys
  - Update FRONTEND_URL to production URL
  - Update STRIPE_WEBHOOK_SECRET with production webhook secret

- [ ] **Update Price IDs**
  - Create live products in Stripe
  - Update all STRIPE_*_PRICE_ID variables

- [ ] **Deploy Backend**
  - Deploy to your hosting service
  - Set environment variables

- [ ] **Deploy Frontend**
  - Deploy to your hosting service
  - Update API endpoint if needed

- [ ] **Test Webhook Endpoint**
  - Go to Stripe Dashboard → Webhooks
  - Click your production webhook
  - Click "Send test webhook"
  - Verify it receives successfully

- [ ] **Test Live Payment Flow**
  - Use a real card (small amount)
  - Verify webhook received
  - Verify subscription created
  - **Cancel test subscription immediately**
  - Issue refund if charged

---

## 📊 Step 8: Monitoring

### Set Up Monitoring

- [ ] **Monitor Stripe Dashboard**
  - Payments: https://dashboard.stripe.com/payments
  - Subscriptions: https://dashboard.stripe.com/subscriptions
  - Webhooks: https://dashboard.stripe.com/webhooks

- [ ] **Monitor Backend Logs**
  - Watch for webhook events
  - Check for errors
  - Monitor userId recovery attempts

- [ ] **Check for Duplicates**
  ```sql
  -- Run in Supabase SQL Editor:
  SELECT 
    user_id,
    COUNT(*) as subscription_count,
    ARRAY_AGG(stripe_subscription_id) as subscription_ids
  FROM user_subscriptions
  WHERE status IN ('active', 'trialing')
  GROUP BY user_id
  HAVING COUNT(*) > 1;
  ```

### Set Up Alerts

- [ ] **Stripe Email Alerts**
  - Go to: https://dashboard.stripe.com/settings/user
  - Enable alerts for:
    - Payment failures
    - Disputed charges
    - Webhook delivery failures

- [ ] **Backend Error Logging**
  - Set up error tracking (Sentry, LogRocket, etc.)
  - Monitor webhook processing errors

---

## 🎉 Completion Checklist

Before marking complete, ensure:

- [x] ✅ Stripe keys configured
- [x] ✅ Products and prices created
- [x] ✅ Webhooks configured
- [x] ✅ Database schema deployed
- [x] ✅ Validation script passes
- [x] ✅ Test checkout successful
- [x] ✅ Webhook received and processed
- [x] ✅ Subscription in database
- [x] ✅ Duplicate prevention working
- [x] ✅ Production deployment ready

---

## 📚 Reference Documents

- **Full Fix Documentation:** `DUPLICATE_SUBSCRIPTION_FIX.md`
- **Quick Start Guide:** `STRIPE_API_SESSION_QUICK_START.md`
- **Implementation Summary:** `IMPLEMENTATION_SUMMARY.md`

---

## 🆘 Troubleshooting

### Issue: Validation script fails

**Solution:**
```bash
# Check .env file exists and has keys
cat backend/.env | grep STRIPE

# Reinstall dependencies
cd backend
npm install stripe --save
```

### Issue: Webhook not received

**Solution:**
1. Check Stripe CLI is running
2. Verify backend is on port 3001
3. Check webhook endpoint in Stripe Dashboard
4. Test webhook: `stripe trigger customer.subscription.created`

### Issue: "Billing is not configured" error

**Solution:**
```bash
# Verify key format
echo $STRIPE_SECRET_KEY | grep "^sk_"

# Restart backend after .env changes
```

### Issue: Payment succeeds but no subscription

**Solution:**
1. Check webhook logs in Stripe Dashboard
2. Check backend logs for errors
3. Verify userId is in subscription metadata
4. Check database for subscription record

---

**Last Updated:** October 13, 2025  
**Version:** 1.0.0

