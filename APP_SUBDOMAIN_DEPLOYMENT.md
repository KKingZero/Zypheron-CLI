# COBRA AI App Subdomain Deployment Guide

This guide covers deploying the dedicated COBRA AI web application to `app.cobraai.com` as part of the full split architecture.

## Architecture Overview

### Split Configuration
- **Marketing Site**: `cobraai.com` (Static Netlify/Vercel deployment)
- **App Site**: `app.cobraai.com` (This application - Railway deployment)

## Deployment Configuration

### Frontend Configuration
- **Vite Config**: Updated for app subdomain deployment
- **Netlify/Railway**: Configured with environment variables for `app.cobraai.com`
- **API Base URL**: Points to `https://app.cobraai.com/api`

### Backend Configuration
- **API Endpoint**: `https://app.cobraai.com/api`
- **Frontend URL**: `https://app.cobraai.com`
- **CORS Origin**: Configured for app subdomain

## Stripe Webhook Configuration

### Required Webhook URL
```
https://app.cobraai.com/api/billing/webhook
```

### Webhook Events to Subscribe To
The following events are handled by the webhook:

**Subscription Events:**
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `customer.subscription.trial_will_end`

**Payment Events:**
- `payment_intent.succeeded`
- `payment_intent.payment_failed`
- `invoice.payment_succeeded`
- `invoice.payment_failed`
- `invoice.payment_action_required`

**Checkout Events:**
- `checkout.session.completed`
- `checkout.session.expired`

**Customer Events:**
- `customer.created`
- `customer.updated`

### Setup Instructions

1. **Stripe Dashboard Configuration:**
   ```
   Dashboard > Webhooks > Add Endpoint
   URL: https://app.cobraai.com/api/billing/webhook
   Events: Select all events listed above
   ```

2. **Environment Variables:**
   ```bash
   STRIPE_SECRET_KEY=sk_live_... # Production key
   STRIPE_WEBHOOK_SECRET=whsec_... # From webhook configuration
   FRONTEND_URL=https://app.cobraai.com
   BACKEND_URL=https://app.cobraai.com/api
   ```

3. **Test Webhook:**
   ```bash
   # Use Stripe CLI to test webhook locally
   stripe listen --forward-to localhost:3001/api/billing/webhook
   ```

## Environment Variables

### Production (.env.production)
```bash
# Core Configuration
NODE_ENV=production
PORT=3001
BACKEND_URL=https://app.cobraai.com/api
FRONTEND_URL=https://app.cobraai.com

# Database
SUPABASE_URL=your_production_supabase_url
SUPABASE_ANON_KEY=your_production_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_production_service_key

# Billing
STRIPE_SECRET_KEY=sk_live_your_production_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret

# Security
JWT_SECRET=your_production_jwt_secret
CORS_ORIGIN=https://app.cobraai.com
```

### Railway Deployment
```bash
# Set via Railway CLI or Dashboard
railway variables set NODE_ENV=production
railway variables set FRONTEND_URL=https://app.cobraai.com
railway variables set BACKEND_URL=https://app.cobraai.com/api
railway variables set STRIPE_SECRET_KEY=sk_live_...
railway variables set STRIPE_WEBHOOK_SECRET=whsec_...
```

## Features Included

### ✅ Web App Features
- Complete authentication system
- Subscription billing & RBAC
- All security tools (Blue Team, Red Team, OSINT, IOC Scanner)
- AI chat interface with multiple models
- Settings and user management
- Stripe payment processing with webhooks

### ❌ Removed Marketing Features
- Landing pages
- Product overview pages  
- Marketing navigation
- Static content pages
- SEO marketing components

## Domain Configuration

### DNS Setup
```
A Record: app.cobraai.com → Railway IP
CNAME: app.cobraai.com → your-railway-app.railway.app
```

### SSL Certificate
Railway automatically handles SSL certificates for custom domains.

## Verification Checklist

- [ ] App loads at `https://app.cobraai.com`
- [ ] Authentication redirects work correctly
- [ ] Stripe checkout flows redirect to app subdomain
- [ ] Webhook endpoint responds at `/api/billing/webhook`
- [ ] All security tools are accessible
- [ ] Settings and billing pages work
- [ ] No marketing pages are accessible
- [ ] Cross-site authentication works (if applicable)

## Troubleshooting

### Common Issues

1. **Webhook 404 Errors:**
   - Verify webhook URL: `https://app.cobraai.com/api/billing/webhook`
   - Check Railway deployment status
   - Confirm environment variables are set

2. **CORS Errors:**
   - Ensure `CORS_ORIGIN=https://app.cobraai.com`
   - Check frontend API base URL configuration

3. **Authentication Issues:**
   - Verify Supabase configuration for production
   - Check JWT secret is set correctly
   - Confirm user redirect URLs in Supabase

4. **Payment Flow Issues:**
   - Verify Stripe keys are production keys
   - Check webhook secret matches Stripe dashboard
   - Test webhook with Stripe CLI

## Support

For deployment issues:
1. Check Railway logs: `railway logs`
2. Monitor Stripe webhook delivery attempts
3. Verify environment variable configuration
4. Test API endpoints directly

## Security Notes

- All production API keys should be different from development
- Regular rotation of JWT secrets and API keys
- Monitor webhook delivery success rates
- Use Railway's built-in security features
- Enable proper logging for audit trails
