# Payment Integration Test Guide

## Overview
This guide outlines how to test the complete payment flow integration for COBRA AI.

## Changes Made

### 1. Frontend Updates
- **Updated pricing**: Pro plan changed from $199.99 to $149.99
- **Added Billing page**: Complete subscription management interface
- **Updated landing page**: Pricing buttons now redirect to billing instead of work-in-progress
- **Login redirect**: Added support for redirecting to billing after login
- **Token limits**: Updated to show total tokens instead of per-model limits

### 2. Backend Updates
- **Stripe product keys**: Added cobraai_light, cobraai_pro, cobraai_super
- **Token tracking**: Implemented consolidated token tracking across all AI models
- **Usage limits**: Updated to use total_tokens instead of separate model limits
- **Auth middleware**: Added to chat routes for usage tracking

### 3. Database Updates
- **Subscription plans**: Updated with correct Stripe price IDs and pricing
- **Token limits**: Added total_tokens field to limits

## Test Steps

### 1. Landing Page Flow
1. Navigate to the root URL (`/`)
2. Verify pricing displays correctly:
   - Lite: $29.99 (100K tokens/month)
   - Pro: $149.99 (1M tokens/month)  
   - Enterprise: $999.99 (Unlimited tokens)
3. Click "Get Started" on Lite or Pro plans
4. Should redirect to login page with redirect parameter
5. After login, should redirect to billing page

### 2. Billing Page
1. Navigate to `/billing` (must be logged in)
2. Verify current subscription status displays
3. Verify available plans show with correct pricing
4. Click "Subscribe" on a plan
5. Should redirect to Stripe Checkout (if backend configured)

### 3. Token Tracking
1. Send chat messages through the interface
2. Verify tokens are tracked in database:
   ```sql
   SELECT * FROM usage_tracking WHERE feature_name = 'total_tokens';
   ```
3. Verify limits are enforced when approaching token limits

### 4. Work in Progress Page
1. Navigate to `/work-in-progress`
2. Verify updated content showing payment integration is available
3. Click "View Pricing & Subscribe" button
4. Should redirect to billing page

## Environment Variables Needed

### Backend (.env)
```env
# Stripe Configuration
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
FRONTEND_URL=http://localhost:5173

# Stripe Product Price IDs
STRIPE_LITE_PRICE_ID=cobraai_light
STRIPE_PRO_PRICE_ID=cobraai_pro
STRIPE_ENTERPRISE_PRICE_ID=cobraai_super
```

## Database Schema Update
Run the updated `database/schema-billing.sql` to ensure subscription plans have correct pricing.

## Expected Results

### Successful Flow
1. User clicks pricing plan on landing page
2. Redirected to login (if not authenticated)
3. After login, redirected to billing page
4. Billing page shows current plan and available options
5. Clicking subscribe opens Stripe Checkout
6. After payment, subscription is activated
7. AI chat respects token limits based on subscription

### Error Handling
1. Token limit exceeded - Shows upgrade message
2. Invalid Stripe configuration - Shows appropriate error
3. Unauthenticated users - Redirected to login

## Stripe Test Cards
For testing Stripe integration:
- Success: `4242 4242 4242 4242`
- Declined: `4000 0000 0000 0002`
- Requires 3D Secure: `4000 0027 6000 3184`

## Notes
- Stripe webhook endpoint: `/api/billing/webhook`
- Customer portal: Available through billing page
- Token estimation: ~1 token per 4 characters
- Free tier: 10,000 tokens by default 