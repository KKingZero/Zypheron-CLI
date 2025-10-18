# 🔧 Admin Dev Environment Setup

## 🚨 Critical Security Configuration

### **Add these variables to your `backend/.env` file:**

```env
# ============================================================================
# RBAC & ADMIN DEV SECURITY CONFIGURATION  
# ============================================================================

# CRITICAL: Only these emails can get admin_dev privileges
ADMIN_DEV_EMAILS=shabblezam@gmail.com

# Extended session settings (only applies to authorized emails)
ADMIN_DEV_SESSION_DURATION_HOURS=8760
DEFAULT_SESSION_DURATION_HOURS=24
SESSION_REFRESH_THRESHOLD_HOURS=2

# MFA and session bypass (only applies to authorized emails)
ADMIN_DEV_MFA_BYPASS=true
ADMIN_DEV_EXTENDED_SESSIONS=true

# Security monitoring
ENABLE_SECURITY_AUDIT_LOGS=true
LOG_FAILED_AUTH_ATTEMPTS=true

# JWT Configuration (generate a strong secret)
JWT_SECRET=your_strong_jwt_secret_here_minimum_32_characters
```

### **Generate a Strong JWT Secret:**

```bash
# Run this command to generate a secure JWT secret:
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## 🎯 What This Fixes:

1. **✅ Only your email gets admin_dev privileges**
2. **✅ Environment variables only apply to authorized emails**
3. **✅ Automatic redirect from billing page to dashboard**
4. **✅ Secure bypass loading screens**
5. **✅ Localhost development access**

## 📋 Steps to Apply:

1. **Update your `backend/.env`** with the variables above
2. **Restart your backend server** for environment changes to take effect
3. **Clear browser cache** and reload the frontend
4. **Test login** with your email - should bypass billing and go to dashboard

## 🔍 Testing the Fix:

### **Expected Behavior:**
- **shabblezam@gmail.com** → Redirects to dashboard (no billing page)
- **Other emails** → Goes to billing page normally
- **Localhost** → Bypasses authentication entirely
- **Admin dev banner** shows for your account

### **Debug Output:**
Check browser console for these logs:
```
🔍 Billing bypass check: { userRole: 'admin_dev', isAdminDev: true, ... }
🔧 Admin dev detected, redirecting to dashboard...
```

## 🚨 Security Notes:

- **NEVER commit `.env` files** to version control
- **Only add trusted emails** to `ADMIN_DEV_EMAILS`
- **Use strong JWT secrets** in production
- **Monitor admin_dev access** in audit logs

---

**After applying these changes, your admin dev bypass should work perfectly!** 🎉
