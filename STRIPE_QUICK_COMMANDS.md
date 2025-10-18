# ⚡ Stripe Quick Commands Reference

Quick reference for common Stripe-related commands and operations.

---

## 🚀 Quick Start Commands

### Initial Setup
```bash
# 1. Install dependencies (if not already done)
cd backend
npm install

# 2. Validate your Stripe setup
npm run validate:stripe

# 3. Test Stripe connection
npm run test:stripe
```

### Development Workflow
```bash
# Terminal 1: Start backend
cd backend
npm run dev

# Terminal 2: Start frontend  
cd frontend
npm run dev

# Terminal 3: Start webhook forwarding (for local testing)
cd backend
npm run webhook:local
# OR
cd scripts
./test-webhook-locally.sh  # Mac/Linux
test-webhook-locally.bat     # Windows
```

---

## 🔧 Validation & Testing

### Validate Configuration
```bash
# Run validation script
cd backend
npm run validate:stripe

# Or run directly
cd scripts
node validate-stripe-setup.js
```

**Expected Output:**
```
✓ STRIPE_SECRET_KEY found (TEST mode)
✓ STRIPE_WEBHOOK_SECRET found
✓ FRONTEND_URL: http://localhost:5173
✓ Stripe SDK initialized successfully!
✅ All critical checks passed!
```

### Test Checkout Sessions
```bash
# Test creating checkout sessions
cd backend
npm run test:stripe

# Or run directly
cd scripts
node test-stripe-checkout.js
```

**What it tests:**
- API connection to Stripe
- Customer creation
- Checkout session creation for all plans
- Metadata verification
- Webhook configuration

---

## 🪝 Webhook Commands

### Local Development

#### Start Webhook Forwarding
```bash
# Option 1: Using npm script
cd backend
npm run webhook:local

# Option 2: Using helper script
cd scripts
./test-webhook-locally.sh  # Mac/Linux
test-webhook-locally.bat     # Windows

# Option 3: Direct stripe CLI command
stripe listen --forward-to localhost:3001/api/billing/webhook
```

**Copy the webhook secret that appears and add to backend/.env:**
```bash
STRIPE_WEBHOOK_SECRET=whsec_abc123...
```

#### Test Webhook Manually
```bash
# Trigger a test subscription.created event
stripe trigger customer.subscription.created

# Trigger test checkout.session.completed event
stripe trigger checkout.session.completed

# View webhook logs
stripe logs tail
```

---

## 💳 Stripe Dashboard Commands

### View in Browser
```bash
# Open Stripe Dashboard
# Test mode: https://dashboard.stripe.com/test
# Live mode: https://dashboard.stripe.com

# Direct links:
open https://dashboard.stripe.com/test/apikeys        # API keys
open https://dashboard.stripe.com/test/products       # Products
open https://dashboard.stripe.com/test/subscriptions  # Subscriptions
open https://dashboard.stripe.com/test/webhooks       # Webhooks
open https://dashboard.stripe.com/test/payments       # Payments
```

### Using Stripe CLI
```bash
# Login to Stripe CLI
stripe login

# List customers
stripe customers list --limit 10

# Get customer details
stripe customers retrieve cus_...

# List subscriptions
stripe subscriptions list --limit 10

# Get subscription details
stripe subscriptions retrieve sub_...

# Cancel a subscription
stripe subscriptions cancel sub_...

# List recent events
stripe events list --limit 10

# Get event details
stripe events retrieve evt_...
```

---

## 🧪 Testing Commands

### Test Cards
```bash
# Success (no authentication)
4242 4242 4242 4242

# Success (requires 3D Secure)
4000 0027 6000 3184

# Declined (generic)
4000 0000 0000 0002

# Declined (insufficient funds)
4000 0000 0000 9995

# Declined (lost card)
4000 0000 0000 9987

# Any future expiry date, any 3-digit CVC
```

### Test Subscription Flow
```bash
# 1. Start all services (3 terminals)
# Terminal 1:
cd backend && npm run dev

# Terminal 2:
cd frontend && npm run dev

# Terminal 3:
cd backend && npm run webhook:local

# 2. Open browser
open http://localhost:5173/billing

# 3. Click a plan, use test card
# Card: 4242 4242 4242 4242
# Expiry: 12/25
# CVC: 123
# ZIP: 12345

# 4. Check webhook received in Terminal 3
# Should see: "customer.subscription.created"

# 5. Check backend logs in Terminal 1
# Should see: "✅ User ... successfully activated with ... plan"
```

---

## 🗄️ Database Commands

### Check Subscriptions
```sql
-- In Supabase SQL Editor:

-- Get all active subscriptions
SELECT * FROM user_subscriptions 
WHERE status IN ('active', 'trialing')
ORDER BY created_at DESC;

-- Get user's subscription
SELECT * FROM user_subscriptions 
WHERE user_id = '<user_uuid>';

-- Find duplicates (should be none!)
SELECT 
  user_id,
  COUNT(*) as count,
  ARRAY_AGG(stripe_subscription_id) as subscription_ids
FROM user_subscriptions
WHERE status IN ('active', 'trialing')
GROUP BY user_id
HAVING COUNT(*) > 1;

-- Check subscription history
SELECT * FROM subscription_history 
WHERE user_id = '<user_uuid>'
ORDER BY created_at DESC
LIMIT 10;

-- Find duplicate detection logs
SELECT * FROM subscription_history
WHERE subscription_status = 'duplicate_detected'
ORDER BY created_at DESC;
```

---

## 🔍 Debugging Commands

### Check Environment Variables
```bash
# View Stripe configuration (hides sensitive data)
cd backend
node -e "require('dotenv').config(); console.log('Secret Key:', process.env.STRIPE_SECRET_KEY?.substring(0,10) + '...'); console.log('Webhook Secret:', process.env.STRIPE_WEBHOOK_SECRET?.substring(0,10) + '...');"

# Check if variables are set
env | grep STRIPE
```

### Check Stripe SDK Version
```bash
cd backend
npm list stripe
```

### Test Stripe API Connection
```bash
# Using node
cd backend
node -e "require('dotenv').config(); const Stripe = require('stripe'); const stripe = new Stripe(process.env.STRIPE_SECRET_KEY); stripe.balance.retrieve().then(b => console.log('✅ Connected! Balance:', b.available[0]?.amount / 100)).catch(e => console.log('❌ Error:', e.message));"
```

### View Backend Logs
```bash
# Tail backend logs (if using pm2)
pm2 logs backend --lines 100

# Or if running with npm run dev
# Logs appear in terminal
```

### Check Webhook Delivery
```bash
# View recent webhook attempts
stripe events list --limit 10

# View specific event
stripe events retrieve evt_...

# Resend webhook event
stripe events resend evt_...
```

---

## 🔄 Common Operations

### Create New Product & Price
```bash
# Create product
stripe products create \
  --name "New Plan" \
  --description "Description of plan"

# Create price
stripe prices create \
  --product prod_... \
  --currency usd \
  --unit-amount 2999 \
  --recurring[interval]=month

# Copy the price ID (price_...) and add to .env
```

### Update Subscription
```bash
# Update subscription to different price
stripe subscriptions update sub_... \
  --items[0][price]=price_new_...

# Cancel subscription
stripe subscriptions cancel sub_...

# Cancel at period end
stripe subscriptions update sub_... \
  --cancel_at_period_end=true
```

### Refund Payment
```bash
# List recent charges
stripe charges list --limit 10

# Refund a charge
stripe refunds create --charge=ch_...

# Partial refund
stripe refunds create --charge=ch_... --amount=1000
```

---

## 📊 Monitoring Commands

### View Metrics
```bash
# Total subscriptions
stripe subscriptions list | grep -c "id"

# Active subscriptions
stripe subscriptions list --status=active | grep -c "id"

# Failed payments today
stripe events list --type=payment_intent.payment_failed --created[gte]=$(date +%s -d "today")
```

### Export Data
```bash
# Export customers to JSON
stripe customers list --limit 100 > customers.json

# Export subscriptions to JSON
stripe subscriptions list --limit 100 > subscriptions.json

# Export events to JSON
stripe events list --limit 100 > events.json
```

---

## 🆘 Emergency Commands

### Pause All Subscriptions (Emergency)
```bash
# Get all active subscription IDs
stripe subscriptions list --status=active --limit 100 | grep "id" > sub_ids.txt

# Update to cancel at period end (safer than immediate cancel)
while read sub_id; do
  stripe subscriptions update $sub_id --cancel_at_period_end=true
done < sub_ids.txt
```

### Check for Failed Webhooks
```bash
# List failed webhook endpoints
stripe webhook_endpoints list

# View failed webhook delivery attempts
stripe events list --delivery_success=false --limit 50
```

### Reset Test Data
```bash
# Delete all test customers
stripe customers list --limit 100 | grep "id" | while read id; do stripe customers delete $id; done

# Delete all test subscriptions (will also delete with customers)
stripe subscriptions list --limit 100 | grep "id" | while read id; do stripe subscriptions cancel $id; done
```

---

## 📝 Helpful Aliases (Add to ~/.bashrc or ~/.zshrc)

```bash
# Stripe validation
alias stripe-validate='cd /path/to/backend && npm run validate:stripe'

# Stripe testing
alias stripe-test='cd /path/to/backend && npm run test:stripe'

# Start webhook forwarding
alias stripe-webhooks='cd /path/to/backend && npm run webhook:local'

# Open Stripe dashboards
alias stripe-dash='open https://dashboard.stripe.com/test'
alias stripe-products='open https://dashboard.stripe.com/test/products'
alias stripe-subs='open https://dashboard.stripe.com/test/subscriptions'
alias stripe-webhooks-dash='open https://dashboard.stripe.com/test/webhooks'
```

---

## 🔗 Quick Links

- **API Keys:** https://dashboard.stripe.com/test/apikeys
- **Products:** https://dashboard.stripe.com/test/products
- **Subscriptions:** https://dashboard.stripe.com/test/subscriptions
- **Webhooks:** https://dashboard.stripe.com/test/webhooks
- **Payments:** https://dashboard.stripe.com/test/payments
- **Customers:** https://dashboard.stripe.com/test/customers
- **Events/Logs:** https://dashboard.stripe.com/test/events
- **CLI Docs:** https://stripe.com/docs/stripe-cli
- **API Docs:** https://stripe.com/docs/api

---

**Pro Tip:** Add these commands to your project's README or keep this file bookmarked for quick reference!

**Last Updated:** October 13, 2025

