# COBRA AI Subscription Access Guide

## Overview
This guide ensures that users who purchase COBRA AI subscriptions get appropriate access to dashboard features based on their subscription tier.

## Subscription Levels and Access

### 🔵 Light Plan ($29.99/month)
- **Features**: 
  - Stage 1 Security Tools
  - Basic Chat
  - Vulnerability Scanning  
  - AI Analysis
- **Limits**:
  - 100K tokens/month
  - 5K API calls
  - 1K AI requests
  - 100 OSINT queries
- **Dashboard Access**: Basic dashboard + Light tier tools

### 🔴 Pro Plan ($149.99/month)  
- **Features**:
  - Everything in Light
  - Stage 1 & 2 Features
  - Advanced Penetration Testing
  - Premium OSINT Capabilities
  - Automated Exploitation
- **Limits**:
  - 1M tokens/month
  - 50K API calls  
  - 10K AI requests
  - 1K OSINT queries
- **Dashboard Access**: Full dashboard + Pro tier tools

### 🟣 Enterprise Plan ($999.99/month)
- **Features**:
  - Everything in Pro
  - All Features
  - Custom AI Models
  - On-premise Deployment
  - 24/7 Dedicated Support
- **Limits**: Unlimited
- **Dashboard Access**: Full dashboard + Enterprise features

## Technical Implementation

### Database Schema
```sql
-- Subscription plans table stores plan details
subscription_plans (
  name: 'Light' | 'Pro' | 'Enterprise'
  stripe_price_id: Stripe price ID
  features: JSONB of enabled features
  limits: JSONB of usage limits
)

-- User subscriptions table tracks active subscriptions  
user_subscriptions (
  user_id: References profiles(id)
  plan_id: References subscription_plans(id)
  stripe_subscription_id: From Stripe webhook
  status: 'active' | 'trialing' | 'canceled' etc.
)
```

### Stripe Integration
- **Light**: `buy_btn_1RmQkXABd1WNp9IUjNCzVd6q` → `price_1RmQkXABd1WNp9IUjNCzVd6q`
- **Pro**: `buy_btn_1RmQZfABd1WNp9IU3BI5HpAN` → `price_1RmQZfABd1WNp9IU3BI5HpAN`  
- **Enterprise**: `buy_btn_1RmQQBABd1WNp9IUa8RSXQ9R` → `price_1RmQQBABd1WNp9IUa8RSXQ9R`

### Access Control Flow

1. **User purchases subscription** → Stripe webhook fired
2. **Webhook handler** → Updates `user_subscriptions` table
3. **Frontend hook** → `useRBACSubscriptionAccess()` fetches user access
4. **Dashboard components** → Check access with `canAccessFeature()`
5. **Protected routes** → Verify subscription before allowing access

### Key Files

#### Frontend Access Control
- `hooks/useRBACSubscriptionAccess.ts` - Main subscription access hook
- `components/ProtectedRoute.tsx` - Route-level access control
- `components/Layout.tsx` - Feature-level access control in navigation
- `utils/devMode.ts` - Development mode overrides

#### Backend API
- `routes/billing.ts` - Subscription API and webhook handler
- `/api/billing/subscription` - Get user's current access level
- `/api/billing/webhook` - Handle Stripe subscription events

#### Database
- `database/schema-billing.sql` - Complete billing schema
- `get_user_access_level()` - Function to check user access
- `check_feature_access()` - Function to verify specific features

## Verification Steps

### 1. Database Setup
```sql
-- Run this in Supabase SQL Editor
-- Ensure subscription_plans table has correct Stripe price IDs
SELECT name, stripe_price_id FROM subscription_plans;

-- Should show:
-- Light    | price_1RmQkXABd1WNp9IUjNCzVd6q  
-- Pro      | price_1RmQZfABd1WNp9IU3BI5HpAN
-- Enterprise | price_1RmQQBABd1WNp9IUa8RSXQ9R
```

### 2. Stripe Configuration
- Verify webhook endpoint: `your-domain/api/billing/webhook`
- Ensure webhook secret is set in `STRIPE_WEBHOOK_SECRET`
- Confirm price IDs match database entries

### 3. Test Subscription Flow
1. Purchase subscription via Stripe buy button
2. Webhook should update `user_subscriptions` table
3. User refresh should show new access level
4. Dashboard should unlock appropriate features

### 4. Frontend Access Testing
```typescript
// In browser console after login:
// Check current access level
const response = await fetch('/api/billing/subscription', {
  headers: { 'Authorization': `Bearer ${session.access_token}` }
});
const data = await response.json();
console.log('Access Level:', data.accessLevel);
```

## Troubleshooting

### Common Issues

1. **User buys but no access**: 
   - Check webhook logs
   - Verify Stripe price ID matches database
   - Ensure user_id in subscription metadata

2. **Wrong access level**:
   - Check `get_user_access_level()` function
   - Verify subscription status is 'active' or 'trialing'

3. **Features still locked**:
   - Check `canAccessFeature()` logic
   - Verify feature names match between frontend and database

### Debug Commands
```sql
-- Check user's subscription
SELECT * FROM user_subscriptions WHERE user_id = 'USER_UUID';

-- Check user's access level  
SELECT * FROM get_user_access_level('USER_UUID');

-- Check subscription plan features
SELECT sp.name, sp.features FROM subscription_plans sp
JOIN user_subscriptions us ON sp.id = us.plan_id  
WHERE us.user_id = 'USER_UUID';
```

## Development Mode
- Localhost dev mode bypasses subscription checks
- Use DevPlanSelector to test different subscription levels
- Enable via `http://localhost:5174` access

## Security Notes
- All access checks happen server-side via database functions
- Frontend hooks are for UI display only
- Webhook signature verification prevents unauthorized access
- Session tokens required for all subscription API calls
