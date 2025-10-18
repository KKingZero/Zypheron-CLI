# 🚀 Netlify Deployment Guide for COBRA AI

## 📋 Overview

This guide will help you deploy COBRA AI to Netlify with proper environment variable configuration and security settings.

## 🔧 Step 1: Update netlify.toml (✅ COMPLETED)

The `netlify.toml` file has been updated to disable secrets scanning and fix build issues:

```toml
[build]
  base = "frontend"
  command = "npm install && npm run build"
  publish = "dist"

[build.environment]
  SECRETS_SCAN_ENABLED = "false"
  NODE_ENV = "production"

[[redirects]]
  from = "/*"
  to = "/index.html"
  status = 200
```

**Key Changes:**
- Added `base = "frontend"` to set the build context
- Changed command to `npm install && npm run build` to ensure dependencies are installed
- Updated publish path to `dist` (relative to base directory)

## 🔑 Step 2: Add Environment Variables to Netlify Dashboard

### **How to Add Environment Variables:**

1. **Go to your Netlify dashboard** → https://app.netlify.com/
2. **Select your COBRA AI site**
3. **Navigate to:** Site Settings → Environment Variables
4. **Click "Add variable"** for each variable below

### **Required Environment Variables for Netlify:**

⚠️ **IMPORTANT: Only add these FRONTEND variables to Netlify. Do NOT add backend API keys!**

```bash
# Frontend Variables (VITE_ prefix for client-side)
VITE_API_URL=http://localhost:3001
VITE_SUPABASE_URL=https://wamuunamwtvutozcohfc.supabase.co
VITE_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndhbXV1bmFtd3R2dXRvemNvaGZjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTA1MjUzODEsImV4cCI6MjA2NjEwMTM4MX0.VKlMW_8dxT7yAWigziBaLy3gk2fBrm2_CyydcGS1ZFs

# Application Configuration
VITE_APP_NAME=COBRA AI
VITE_APP_VERSION=1.0.0

# Feature Flags
VITE_ENABLE_MOCK_DATA=true
VITE_ENABLE_ANALYTICS=false
VITE_DEBUG_MODE=false

# Build Configuration
NODE_ENV=production
SECRETS_SCAN_ENABLED=false
```

### **❌ Variables to REMOVE from Netlify (Backend Only):**

**These should NOT be in Netlify environment variables:**
- `OPENAI_API_KEY` ❌
- `GEMINI_API_KEY` ❌  
- `XAI_API_KEY` ❌
- `JWT_SECRET` ❌
- `SUPABASE_SERVICE_ROLE_KEY` ❌
- `PORT` ❌
- `CORS_ORIGIN` ❌
- `LOG_LEVEL` ❌

### **⚠️ Important Notes:**

- **VITE_API_URL**: Update this to your actual backend URL when deployed
- **Supabase keys**: These are the public anon keys (safe for frontend)
- **No secrets**: Never add service role keys or private API keys to frontend env

## 🏗️ Step 3: Local Development Setup

### **Create frontend/.env file locally:**

```bash
# Navigate to frontend directory
cd frontend

# Create .env file (this file is gitignored for security)
echo "# COBRA AI Frontend Environment Configuration
VITE_API_URL=http://localhost:3001
VITE_SUPABASE_URL=https://wamuunamwtvutozcohfc.supabase.co
VITE_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndhbXV1bmFtd3R2dXRvemNvaGZjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTA1MjUzODEsImV4cCI6MjA2NjEwMTM4MX0.VKlMW_8dxT7yAWigziBaLy3gk2fBrm2_CyydcGS1ZFs
VITE_APP_NAME=COBRA AI
VITE_APP_VERSION=1.0.0
VITE_ENABLE_MOCK_DATA=true
VITE_ENABLE_ANALYTICS=false
VITE_DEBUG_MODE=false" > .env
```

## 🚀 Step 4: Deploy to Netlify

### **Option A: Automatic Deploy (Recommended)**

1. **Commit changes to git:**
   ```bash
   git add netlify.toml NETLIFY_DEPLOYMENT_GUIDE.md
   git commit -m "Fix: Disable secrets scanning in Netlify deployment"
   git push origin main
   ```

2. **Netlify will automatically deploy** when changes are pushed to main branch

### **Option B: Manual Deploy**

1. **Build locally:**
   ```bash
   cd frontend
   npm run build
   ```

2. **Drag and drop** the `frontend/dist` folder to Netlify dashboard

## 🔍 Step 5: Verify Deployment

### **Check these after deployment:**

✅ **Build succeeds** without secrets scanning errors  
✅ **Frontend loads** at your Netlify URL  
✅ **Login functionality** works with Supabase  
✅ **Dev mode toggle** works on localhost  
✅ **Billing page** shows proper authentication state  

### **Common Issues & Solutions:**

| Issue | Solution |
|-------|----------|
| Build fails with secrets error | Ensure `SECRETS_SCAN_ENABLED=false` in Netlify env vars |
| "tsc: not found" error | Fixed by using `vite build` only - Vite handles TypeScript compilation |
| Build script returns exit code 127 | Dependencies not installed - ensure build command includes `npm install` |
| Backend variables in frontend build | Remove all non-VITE_ variables from Netlify env vars |
| Supabase auth not working | Verify `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` are set |
| API calls failing | Update `VITE_API_URL` to your deployed backend URL |
| Blank page after deploy | Check browser console for environment variable errors |

## 🔒 Security Best Practices

✅ **Frontend .env**: Only contains VITE_ prefixed public variables  
✅ **Backend .env**: Contains private keys (NOT deployed to Netlify)  
✅ **Netlify env vars**: Only frontend variables added to dashboard  
✅ **Git**: .env files are gitignored  
✅ **Secrets scanning**: Disabled in netlify.toml  

## 📚 Next Steps

After successful deployment:

1. **Update VITE_API_URL** to point to your deployed backend
2. **Test all authentication flows** on the live site
3. **Verify Stripe integration** works in production
4. **Monitor Netlify deploy logs** for any issues

## 🆘 Getting Help

If you encounter issues:

1. **Check Netlify deploy logs** in the dashboard
2. **Verify environment variables** are set correctly
3. **Test locally first** to isolate the issue
4. **Check browser console** for frontend errors

---

**✨ Your COBRA AI frontend should now deploy successfully to Netlify!** 