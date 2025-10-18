# 🧪 Subscription Tier Testing Guide

This guide ensures that the Light, Pro, and Enterprise subscription tiers work correctly with the new RBAC system.

## 🎯 Subscription Tiers Overview

### **Free Tier**
- **Price**: $0/month
- **Features**: 
  - ✅ Basic chat only
  - ❌ No penetration testing
  - ❌ No advanced features
- **Limits**: 
  - 0 tokens per month
  - 0 API calls
  - 0 scans

### **Light Tier** 
- **Price**: $29.99/month
- **Features**:
  - ✅ Basic chat
  - ✅ Vulnerability scanning
  - ✅ Basic penetration testing
  - ❌ No advanced pentesting
  - ❌ No premium OSINT
  - ❌ No automated exploitation
- **Limits**:
  - 100,000 tokens per month
  - 5,000 API calls per month  
  - 100 scans per month

### **Pro Tier**
- **Price**: $149.99/month
- **Features**:
  - ✅ All Light features PLUS:
  - ✅ Advanced penetration testing
  - ✅ Premium OSINT tools
  - ✅ Automated exploitation
  - ❌ No custom models
  - ❌ No on-premise deployment
- **Limits**:
  - 1,000,000 tokens per month
  - 50,000 API calls per month
  - 1,000 scans per month

### **Enterprise Tier**
- **Price**: $999.99/month
- **Features**:
  - ✅ ALL features enabled
  - ✅ Custom AI models
  - ✅ On-premise deployment
  - ✅ Priority support
  - ✅ Dedicated support
- **Limits**:
  - ♾️ Unlimited tokens
  - ♾️ Unlimited API calls
  - ♾️ Unlimited scans

### **Admin Dev Role** (RBAC Extension)
- **Price**: N/A (special access)
- **Features**:
  - ✅ ALL Enterprise features PLUS:
  - ✅ MFA bypass capability
  - ✅ Extended sessions (1 year)
  - ✅ Admin panel access
  - ✅ User management
  - ✅ System monitoring
  - ✅ Debug mode
- **Limits**: ♾️ Everything unlimited

## 🧪 Testing Scenarios

### **Test 1: Free User Access**
```sql
-- Create test free user
INSERT INTO auth.users (id, email) VALUES ('test-free-uuid', 'free@test.com');

-- Verify access level
SELECT * FROM public.get_user_access_level('test-free-uuid');
-- Expected: has_access=false, plan_name='Free', basic_chat only
```

**Expected Behavior:**
- ❌ Cannot access paid features
- ✅ Can use basic chat
- ❌ Billing page shows upgrade prompts
- ❌ Locked features show 🔒 icons

### **Test 2: Light Subscription**
```sql
-- Upgrade user to Light
UPDATE public.users 
SET subscription_status = 'light', tokens_limit = 100000 
WHERE email = 'free@test.com';

-- Verify access level
SELECT * FROM public.get_user_access_level(id) FROM public.users WHERE email = 'free@test.com';
-- Expected: has_access=true, plan_name='Light', basic features enabled
```

**Expected Behavior:**
- ✅ Basic chat, vulnerability scanning, basic pentest
- ❌ Advanced pentest locked
- ❌ Premium OSINT locked  
- ❌ Automated exploitation locked
- ✅ Shows Light subscription in billing
- ✅ Usage limits enforced (100K tokens, 5K API calls, 100 scans)

### **Test 3: Pro Subscription**
```sql
-- Upgrade user to Pro
UPDATE public.users 
SET subscription_status = 'pro', tokens_limit = 1000000 
WHERE email = 'free@test.com';

-- Verify access level
SELECT * FROM public.get_user_access_level(id) FROM public.users WHERE email = 'free@test.com';
-- Expected: has_access=true, plan_name='Pro', advanced features enabled
```

**Expected Behavior:**
- ✅ All Light features PLUS advanced pentest, premium OSINT, automated exploitation
- ❌ Custom models locked
- ❌ On-premise locked
- ✅ Shows Pro subscription in billing
- ✅ Higher usage limits (1M tokens, 50K API calls, 1K scans)

### **Test 4: Enterprise Subscription**
```sql
-- Upgrade user to Enterprise
UPDATE public.users 
SET subscription_status = 'enterprise', tokens_limit = -1 
WHERE email = 'free@test.com';

-- Verify access level
SELECT * FROM public.get_user_access_level(id) FROM public.users WHERE email = 'free@test.com';
-- Expected: has_access=true, plan_name='Enterprise', all features enabled
```

**Expected Behavior:**
- ✅ ALL features unlocked
- ✅ Custom models available
- ✅ On-premise deployment options
- ✅ Priority support badge
- ✅ Shows Enterprise subscription in billing
- ✅ Unlimited usage (no rate limits)

### **Test 5: Admin Dev Override**
```sql
-- Grant admin_dev role
UPDATE public.users 
SET role = 'admin_dev', developer_access = true 
WHERE email = 'shabblezam@gmail.com';

-- Verify access level
SELECT * FROM public.get_user_access_level(id) FROM public.users WHERE email = 'shabblezam@gmail.com';
-- Expected: plan_name='Admin Developer', all features + admin features
```

**Expected Behavior:**
- ✅ ALL Enterprise features PLUS admin features
- ✅ Developer bypass banner visible
- ✅ MFA bypass available
- ✅ Extended session options
- ✅ Admin panel access
- ✅ User management capabilities

## 🎮 Frontend Testing Checklist

### **Feature Access Testing**
```typescript
// Test feature access for each tier
const testFeatureAccess = (userTier: string) => {
  const features = {
    basic_chat: true, // All tiers
    vulnerability_scanning: ['light', 'pro', 'enterprise'].includes(userTier),
    basic_pentest: ['light', 'pro', 'enterprise'].includes(userTier),
    advanced_pentest: ['pro', 'enterprise'].includes(userTier),
    premium_osint: ['pro', 'enterprise'].includes(userTier),
    automated_exploitation: ['pro', 'enterprise'].includes(userTier),
    custom_models: ['enterprise'].includes(userTier),
    on_premise: ['enterprise'].includes(userTier)
  }
  
  // Verify each feature is properly enabled/disabled
  Object.entries(features).forEach(([feature, enabled]) => {
    expect(canAccessFeature(feature)).toBe(enabled)
  })
}
```

### **UI Component Testing**
- [ ] **Billing Page**: Shows correct current plan
- [ ] **Feature Buttons**: Disabled for locked features
- [ ] **Usage Indicators**: Show correct limits and usage
- [ ] **Upgrade Prompts**: Appear for locked features
- [ ] **Lock Icons**: Show on disabled features
- [ ] **Plan Badges**: Display correct tier name

### **Payment Flow Testing**
- [ ] **Stripe Integration**: Checkout works for each tier
- [ ] **Webhook Processing**: Subscription updates reflect immediately
- [ ] **Plan Changes**: Upgrading/downgrading works correctly
- [ ] **Cancellation**: Plan cancellation maintains access until period end
- [ ] **Trial Periods**: Free trials work as expected

## 🚨 Common Issues to Test

### **Issue 1: Feature Access Inconsistency**
**Problem**: User has Pro subscription but can't access Pro features
**Check**:
```sql
-- Verify subscription status matches expected features
SELECT subscription_status, role, * FROM public.get_user_access_level(user_id);
```

### **Issue 2: Usage Limit Bypass**
**Problem**: User exceeds limits but can still use features
**Check**:
```sql
-- Verify token consumption tracking
SELECT tokens_used, tokens_limit FROM public.users WHERE id = user_id;
SELECT * FROM public.usage_logs WHERE user_id = user_id ORDER BY created_at DESC LIMIT 10;
```

### **Issue 3: Role vs Subscription Conflicts**
**Problem**: RBAC role conflicts with subscription tier
**Check**:
```sql
-- Ensure RBAC enhances but doesn't conflict with subscription
SELECT role, subscription_status FROM public.users WHERE id = user_id;
SELECT * FROM public.get_user_role_permissions(user_id);
```

## 📊 Automated Testing Commands

### **Backend API Testing**
```bash
# Test subscription endpoint for each tier
curl -H "Authorization: Bearer $TOKEN" http://localhost:3001/api/billing/subscription

# Test feature access endpoints
curl -H "Authorization: Bearer $TOKEN" http://localhost:3001/api/pentest/advanced
curl -H "Authorization: Bearer $TOKEN" http://localhost:3001/api/osint/premium
```

### **Database Testing**
```sql
-- Test subscription tier functions
SELECT public.user_has_subscription_tier('user-uuid', 'pro');
SELECT public.get_subscription_limits('enterprise');

-- Test RBAC integration
SELECT * FROM public.get_user_role_permissions('user-uuid');
SELECT * FROM public.get_user_access_level('user-uuid');
```

## ✅ Success Criteria

### **All Tests Must Pass:**
1. ✅ Free users can only access basic chat
2. ✅ Light users get basic pentesting features
3. ✅ Pro users get advanced features
4. ✅ Enterprise users get all features
5. ✅ Admin dev gets everything + admin features
6. ✅ Usage limits are properly enforced
7. ✅ Billing integration works end-to-end
8. ✅ Feature locks/unlocks work in UI
9. ✅ No unauthorized feature access
10. ✅ Subscription changes reflect immediately

### **Performance Criteria:**
- ⚡ Feature checks respond < 100ms
- ⚡ Billing data loads < 500ms
- ⚡ Plan changes apply < 2 seconds
- ⚡ Database queries optimized with indexes

---

**🎯 Run this testing suite after implementing RBAC to ensure all subscription tiers work exactly as advertised!**
