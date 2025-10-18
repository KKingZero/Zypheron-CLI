# 🔐 COBRA AI RBAC Security Guide

## Overview

This guide documents the implementation of Role-Based Access Control (RBAC) with secure developer bypass functionality in COBRA AI. The system replaces simple metadata flags with a formal role-based security model.

## Role Hierarchy

### User Roles (in order of privilege level)

1. **`user`** (Default)
   - Basic application access
   - Standard authentication required
   - Limited feature set
   - 24-hour session limit

2. **`analyst`** 
   - Extended cybersecurity features
   - Advanced penetration testing tools
   - Threat intelligence access
   - 48-hour session limit

3. **`admin`**
   - User management capabilities
   - Administrative panel access
   - Advanced features
   - 72-hour session limit
   - **Cannot bypass MFA or extend sessions**

4. **`admin_dev`** (Highest Privilege)
   - **All admin capabilities PLUS:**
   - MFA bypass capability
   - Extended sessions (up to 1 year)
   - Unlimited token usage
   - System debugging access
   - Role management for other users
   - Security audit log access

## Security Architecture

### 1. Database Security

#### Row Level Security (RLS)
```sql
-- Users can only see their own data
CREATE POLICY "Users can view own profile" ON public.users
    FOR SELECT USING (auth.uid() = id);

-- admin_dev can view all users
CREATE POLICY "Admin dev can view all users" ON public.users
    FOR SELECT USING (
        auth.uid()::text IN (
            SELECT id::text FROM public.users WHERE role = 'admin_dev'
        )
    );
```

#### Role Assignment Security
- Only `admin_dev` users can modify roles
- Cannot demote the last `admin_dev` user
- All role changes are logged in audit trail
- Email-based auto-assignment only on signup

### 2. Authentication Security

#### Standard Authentication Flow
1. User provides email/password
2. Supabase validates credentials
3. System fetches user role and permissions
4. Standard JWT token issued (24-72 hours)
5. Session established with role-based features

#### Developer Bypass Flow (admin_dev only)
1. User requests extended session during login
2. System validates `admin_dev` role
3. Extended JWT token generated (up to 1 year)
4. Developer bypass banner shown in UI
5. All actions logged for security audit

### 3. Middleware Security Stack

```typescript
// Authentication middleware with RBAC
export const enhancedAuthMiddleware = async (req, res, next) => {
  // 1. Validate JWT token
  // 2. Fetch user role from database
  // 3. Check session expiration
  // 4. Attach role permissions to request
  // 5. Log security events
}

// Role-specific middleware
export const adminDevMiddleware = async (req, res, next) => {
  // Only allows admin_dev role
  // Logs all admin_dev access
  // Rate-limits sensitive operations
}
```

## Security Best Practices

### 1. Role Escalation Prevention

#### Database Level
- **Immutable role assignment function**: Only callable by `admin_dev`
- **RLS policies**: Prevent unauthorized data access
- **Audit logging**: All role changes tracked
- **Last admin protection**: Cannot demote final `admin_dev`

#### Application Level
```typescript
// Secure role checking
const canPerformAction = (userRole: string, requiredRole: string) => {
  const roleHierarchy = ['user', 'analyst', 'admin', 'admin_dev']
  const userLevel = roleHierarchy.indexOf(userRole)
  const requiredLevel = roleHierarchy.indexOf(requiredRole)
  return userLevel >= requiredLevel
}
```

#### API Level
- **JWT validation**: Every request validates token
- **Role verification**: Database lookup on sensitive operations
- **Rate limiting**: Prevents brute force attacks
- **Session monitoring**: Detect suspicious activity

### 2. Developer Bypass Security

#### When Bypass is Active
```typescript
// Environmental controls
ADMIN_DEV_MFA_BYPASS=true          // Enable/disable MFA bypass
ADMIN_DEV_EXTENDED_SESSIONS=true   // Enable/disable long sessions
ADMIN_DEV_EMAILS=user@domain.com   // Auto-assign on signup
```

#### What Gets Bypassed
- ✅ **Multi-Factor Authentication (MFA)**
- ✅ **Standard session duration limits**
- ✅ **Token usage limits**
- ❌ **NOT bypassed: Basic authentication (still need password)**
- ❌ **NOT bypassed: Database-level permissions**
- ❌ **NOT bypassed: Network security**

#### Security Monitoring
```typescript
// All admin_dev actions logged
{
  user_id: "uuid",
  action: "admin_dev_access",
  endpoint: "/api/sensitive-operation",
  timestamp: "2024-01-01T00:00:00Z",
  ip_address: "192.168.1.1",
  user_agent: "..."
}
```

### 3. Production Security Checklist

#### Environment Configuration
- [ ] Change default JWT secrets
- [ ] Set strong database passwords
- [ ] Configure proper CORS origins
- [ ] Enable HTTPS only
- [ ] Set secure cookie flags

#### Role Management
- [ ] Limit admin_dev users to essential personnel only
- [ ] Regular audit of user roles
- [ ] Monitor for unauthorized privilege escalation
- [ ] Implement role change approval workflow (if needed)

#### Monitoring & Alerting
- [ ] Set up failed authentication alerts
- [ ] Monitor admin_dev login events
- [ ] Track unusual session extensions
- [ ] Log all role modifications
- [ ] Monitor API rate limiting violations

### 4. Incident Response

#### Compromised admin_dev Account
1. **Immediate Actions:**
   ```sql
   -- Demote compromised user
   UPDATE public.users SET role = 'user' WHERE email = 'compromised@email.com';
   
   -- Revoke all sessions
   -- (Force re-authentication)
   ```

2. **Investigation:**
   - Review audit logs for unauthorized actions
   - Check for newly created admin accounts
   - Verify no data exfiltration occurred
   - Assess impact of bypassed security controls

3. **Recovery:**
   - Reset all admin passwords
   - Generate new JWT secrets
   - Review and update security policies
   - Conduct security training

#### Unauthorized Role Escalation
1. **Detection:** Monitor for role changes not performed by admin_dev
2. **Response:** Immediately revert unauthorized changes
3. **Investigation:** Review system for vulnerabilities
4. **Prevention:** Enhance database security policies

## Implementation Security Notes

### 1. Database Function Security
```sql
-- Secure role modification function
CREATE OR REPLACE FUNCTION public.set_user_role(
    target_user_uuid UUID,
    new_role TEXT,
    requesting_user_uuid UUID
)
RETURNS BOOLEAN AS $$
DECLARE
    requesting_user_role TEXT;
BEGIN
    -- Verify requester is admin_dev
    SELECT role INTO requesting_user_role 
    FROM public.users 
    WHERE id = requesting_user_uuid;
    
    IF requesting_user_role != 'admin_dev' THEN
        RAISE EXCEPTION 'Access denied: Only admin_dev can modify roles';
    END IF;
    
    -- Additional security checks...
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

### 2. Frontend Security
```typescript
// Secure permission checking
const hasPermission = (feature: string) => {
  return userPermissions?.features?.[feature] === true
}

// Conditional rendering based on role
{userRole === 'admin_dev' && <AdminDevPanel />}
{hasPermission('advanced_pentest') && <AdvancedTools />}
```

### 3. Session Security
```typescript
// Extended session validation
const isExtendedSessionValid = (token: string) => {
  const decoded = jwt.decode(token)
  return (
    decoded.role === 'admin_dev' &&
    decoded.extended_session === true &&
    decoded.exp > Date.now() / 1000
  )
}
```

## Compliance & Auditing

### Audit Trail Requirements
- **User authentication events**
- **Role changes and assignments**
- **Admin_dev privilege usage**
- **Failed authentication attempts**
- **Session extensions and bypasses**

### Regular Security Reviews
- **Monthly:** Review admin_dev access logs
- **Quarterly:** Audit user role assignments
- **Annually:** Penetration test bypass mechanisms
- **As needed:** Review after security incidents

### Documentation Requirements
- Keep this guide updated with any security changes
- Document all admin_dev users and justification
- Maintain incident response procedures
- Record security decisions and rationale

## Emergency Procedures

### Disable All Developer Bypasses
```bash
# In emergency, disable all bypasses
export ADMIN_DEV_MFA_BYPASS=false
export ADMIN_DEV_EXTENDED_SESSIONS=false

# Restart services to apply changes
npm restart
```

### Reset All Admin Sessions
```sql
-- Force all users to re-authenticate
UPDATE auth.sessions SET expires_at = NOW() WHERE user_id IN (
    SELECT id FROM public.users WHERE role IN ('admin', 'admin_dev')
);
```

### Temporarily Lock System
```typescript
// Add to auth middleware for emergency lockdown
if (process.env.EMERGENCY_LOCKDOWN === 'true') {
  return res.status(503).json({ error: 'System temporarily unavailable' })
}
```

---

**⚠️ SECURITY REMINDER:** This bypass system is designed for development and administrative purposes. Regular security audits, monitoring, and adherence to these security practices are essential for maintaining system integrity.
