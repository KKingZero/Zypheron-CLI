# 🚀 COBRA AI Setup Guide

Complete setup instructions for both local development and production deployment.

## 🔧 Local Development (Instant Setup)

### Quick Start - Zero Configuration
```bash
# 1. Clone the repository
git clone https://github.com/yourusername/cobra-ai.git
cd cobra-ai

# 2. Install dependencies
npm install
cd frontend && npm install
cd ../backend && npm install
cd ..

# 3. Start development servers
npm run dev
```

**🎯 That's it! Localhost automatically provides full access.**

### What You Get Instantly
- ✅ **No Authentication Required** - Direct access to all features
- ✅ **Unlimited Tokens** - No usage limits or restrictions
- ✅ **All Premium Features** - Enterprise-level access
- ✅ **Developer Tools** - Debug information and dev features
- ✅ **Mock User** - Automatic localhost@dev.local user

### Localhost Detection
The app automatically detects these environments:
- `localhost:3000`
- `127.0.0.1:3000` 
- `0.0.0.0:3000`
- `192.168.x.x:3000` (local network)
- Any URL with a port number
- NODE_ENV=development

### Disabling Localhost Access
If you want to test authentication locally:
```typescript
// frontend/src/utils/devMode.ts
export const DEV_MODE_ENABLED = false
```

## 🌐 Production Deployment

### Prerequisites
- Node.js 18+ 
- Supabase account
- Stripe account (for payments)
- API keys for AI services

### Step 1: Database Setup (Supabase)

#### 1.1 Create Supabase Project
1. Go to [supabase.com](https://supabase.com)
2. Create new project
3. Wait for setup completion
4. Note your project URL and API keys

#### 1.2 Run Database Schema
1. Open Supabase Dashboard → SQL Editor
2. Copy entire contents of `database/supabase-setup-fixed.sql`
3. Paste into SQL Editor
4. Click "Run"
5. Verify success messages appear

#### 1.3 Verify Database Setup
```sql
-- Run this to check setup
SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public' 
AND table_name IN ('users', 'subscription_history', 'usage_logs');

-- Check functions
SELECT routine_name FROM information_schema.routines 
WHERE routine_schema = 'public' 
AND routine_name LIKE '%user%';
```

### Step 2: Environment Configuration

#### 2.1 Frontend Environment (.env)
```bash
# Create frontend/.env
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your_anon_key_here
VITE_API_URL=https://your-backend-url.com
```

#### 2.2 Backend Environment (.env)
```bash
# Create backend/.env
PORT=3001
NODE_ENV=production

# Database
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key

# AI API Keys
OPENAI_API_KEY=sk-your-openai-key
ANTHROPIC_API_KEY=sk-ant-your-claude-key
GOOGLE_API_KEY=your-google-ai-key

# Payment
STRIPE_SECRET_KEY=sk_live_your-stripe-key
STRIPE_WEBHOOK_SECRET=whsec_your-webhook-secret

# Security APIs
VIRUSTOTAL_API_KEY=your-virustotal-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
```

### Step 3: API Keys Setup

#### 3.1 AI Services
- **OpenAI**: [platform.openai.com](https://platform.openai.com/api-keys)
- **Anthropic (Claude)**: [console.anthropic.com](https://console.anthropic.com)
- **Google AI**: [ai.google.dev](https://ai.google.dev)

#### 3.2 Security APIs
- **VirusTotal**: [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
- **AbuseIPDB**: [abuseipdb.com/api](https://www.abuseipdb.com/api)

#### 3.3 Stripe (Payment Processing)
1. Create Stripe account
2. Get API keys from Dashboard
3. Create products and pricing
4. Update buy button IDs in `frontend/src/pages/Billing.tsx`

### Step 4: Deployment

#### 4.1 Frontend Deployment (Netlify)
```bash
# Build the frontend
cd frontend
npm run build

# Deploy to Netlify
# 1. Drag and drop dist/ folder to Netlify
# 2. Or connect GitHub repository
# 3. Set build command: npm run build
# 4. Set publish directory: dist
```

#### 4.2 Backend Deployment (Railway)
```bash
# Deploy to Railway
# 1. Connect GitHub repository
# 2. Select backend directory
# 3. Add environment variables
# 4. Deploy automatically
```

#### 4.3 Alternative Deployments
- **Vercel**: Frontend hosting with serverless functions
- **Heroku**: Full-stack deployment
- **DigitalOcean**: VPS deployment
- **AWS**: Complete cloud infrastructure

### Step 5: Configuration & Testing

#### 5.1 Test Developer Access
1. Sign up with `shabblezam@gmail.com`
2. Verify developer access in database:
```sql
SELECT email, developer_access, subscription_status, tokens_limit 
FROM users WHERE email = 'shabblezam@gmail.com';
```

#### 5.2 Test Payment Flow
1. Create test account
2. Go to billing page
3. Test subscription process
4. Verify database updates

#### 5.3 Test Features
- ✅ Authentication flow
- ✅ Subscription checking
- ✅ Token usage tracking
- ✅ All cybersecurity tools
- ✅ Payment processing

## 🔧 Advanced Configuration

### Development Mode Control
```typescript
// frontend/src/utils/devMode.ts
export const DEV_CONFIG = {
  enableLocalhostAccess: true,    // Auto-access on localhost
  enableDeveloperMode: true,      // Developer features
  bypassAuthentication: true,     // Skip login locally
  unlimitedAccess: true          // No limits
}
```

### Adding Developer Emails
```sql
-- In database/supabase-setup-fixed.sql
IF new.email IN (
  'shabblezam@gmail.com',
  'your-email@domain.com',
  'team@company.com'
) THEN
```

### Custom Subscription Plans
```sql
-- Update token limits in database function
CASE new_status
  WHEN 'free' THEN token_limit := 0;
  WHEN 'light' THEN token_limit := 100000;
  WHEN 'pro' THEN token_limit := 1000000;
  WHEN 'enterprise' THEN token_limit := -1;
  WHEN 'custom' THEN token_limit := 5000000; -- New plan
  ELSE token_limit := 0;
END CASE;
```

### Security Hardening
```bash
# 1. Enable HTTPS
# 2. Set up CORS properly
# 3. Use secure headers
# 4. Implement rate limiting
# 5. Monitor API usage
```

## 🐛 Troubleshooting

### Common Issues

#### "Localhost not detected"
- Check browser console for dev mode logs
- Ensure DEV_MODE_ENABLED = true
- Verify URL includes localhost or port

#### "Database connection failed"
- Verify Supabase URL and keys
- Check network connectivity
- Ensure database schema is installed

#### "Payment buttons not working"
- Update Stripe buy button IDs
- Verify Stripe API keys
- Check browser console for errors

#### "Features locked despite subscription"
- Check user record in database
- Verify access level function
- Test with developer email

### Debug Information
```typescript
// Check dev mode status in browser console
import { getDevInfo } from './utils/devMode'
console.log(getDevInfo())
```

### Database Debugging
```sql
-- Check user access
SELECT * FROM get_user_access_level('user-uuid-here');

-- Check subscription status
SELECT email, subscription_status, developer_access, tokens_limit 
FROM users WHERE email = 'user@email.com';

-- Check usage logs
SELECT * FROM usage_logs WHERE user_id = 'user-uuid' ORDER BY created_at DESC;
```

## 📞 Support

- **Documentation**: Check README.md and this guide
- **Issues**: Create GitHub issue with detailed description
- **Community**: Join our Discord/Slack for help
- **Enterprise**: Contact for custom deployment support

## 🔄 Updates & Maintenance

### Keeping Updated
```bash
# Pull latest changes
git pull origin main

# Update dependencies
npm update
cd frontend && npm update
cd ../backend && npm update

# Rebuild and deploy
npm run build
```

### Database Migrations
- Check `database/` folder for new schema updates
- Always backup before running migrations
- Test in development first

---

**🎉 You're all set! Enjoy using COBRA AI for your cybersecurity work!** 