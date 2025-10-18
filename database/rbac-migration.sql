-- COBRA AI RBAC Migration - Secure Developer Bypass System
-- Execute this in your Supabase SQL Editor to implement role-based access control

-- ============================================================================
-- 1. ADD ROLE COLUMN TO USERS TABLE
-- ============================================================================

-- Add role column to existing users table if it doesn't exist
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'users' AND column_name = 'role' AND table_schema = 'public') THEN
        ALTER TABLE public.users ADD COLUMN role TEXT DEFAULT 'user' 
        CHECK (role IN ('user', 'admin', 'analyst', 'admin_dev'));
    END IF;
END $$;

-- Update existing users to have default 'user' role
UPDATE public.users SET role = 'user' WHERE role IS NULL;

-- Grant admin_dev role to your specific email
UPDATE public.users 
SET role = 'admin_dev',
    developer_access = TRUE,
    subscription_status = 'enterprise',
    tokens_limit = -1  -- Unlimited tokens
WHERE email = 'shabblezam@gmail.com';

-- ============================================================================
-- 2. CREATE ROLE-BASED SECURITY FUNCTIONS
-- ============================================================================

-- Function to check if user has admin_dev role
CREATE OR REPLACE FUNCTION public.is_admin_dev(user_uuid UUID)
RETURNS BOOLEAN AS $$
DECLARE
    user_role TEXT;
BEGIN
    SELECT role INTO user_role FROM public.users WHERE id = user_uuid;
    RETURN COALESCE(user_role = 'admin_dev', FALSE);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get user role and permissions (updated to preserve subscription tiers)
CREATE OR REPLACE FUNCTION public.get_user_role_permissions(user_uuid UUID)
RETURNS TABLE(
    user_role TEXT,
    can_bypass_mfa BOOLEAN,
    can_extend_session BOOLEAN,
    has_unlimited_tokens BOOLEAN,
    max_session_duration_hours INTEGER,
    features JSONB
) AS $$
DECLARE
    user_record RECORD;
BEGIN
    SELECT * INTO user_record FROM public.users WHERE id = user_uuid;
    
    IF NOT FOUND THEN
        -- Return default for unknown user
        RETURN QUERY SELECT 
            'user'::TEXT,
            FALSE,
            FALSE, 
            FALSE,
            24, -- 24 hours default
            '{}'::JSONB;
        RETURN;
    END IF;
    
    -- Admin developer gets all privileges (supersedes subscription)
    IF user_record.role = 'admin_dev' THEN
        RETURN QUERY SELECT 
            'admin_dev'::TEXT,
            TRUE,  -- Can bypass MFA
            TRUE,  -- Can extend session
            TRUE,  -- Unlimited tokens
            8760,  -- 1 year session (365 * 24 hours)
            jsonb_build_object(
                'bypass_mfa', TRUE,
                'extended_sessions', TRUE,
                'unlimited_access', TRUE,
                'all_features', TRUE,
                'admin_panel', TRUE,
                'user_management', TRUE,
                'system_monitoring', TRUE,
                'debug_mode', TRUE,
                -- Include all subscription features
                'basic_chat', TRUE,
                'vulnerability_scanning', TRUE,
                'basic_pentest', TRUE,
                'advanced_pentest', TRUE,
                'premium_osint', TRUE,
                'automated_exploitation', TRUE,
                'custom_models', TRUE,
                'priority_support', TRUE,
                'on_premise', TRUE
            );
        RETURN;
    END IF;
    
    -- Admin role gets elevated privileges + subscription features
    IF user_record.role = 'admin' THEN
        RETURN QUERY SELECT 
            'admin'::TEXT,
            FALSE, -- No MFA bypass
            FALSE, -- No session extension
            user_record.tokens_limit = -1,
            72,    -- 3 days max session
            jsonb_build_object(
                'admin_panel', TRUE,
                'user_management', TRUE,
                'advanced_features', TRUE
            ) || CASE user_record.subscription_status
                WHEN 'light' THEN jsonb_build_object(
                    'basic_chat', TRUE,
                    'vulnerability_scanning', TRUE,
                    'basic_pentest', TRUE
                )
                WHEN 'pro' THEN jsonb_build_object(
                    'basic_chat', TRUE,
                    'vulnerability_scanning', TRUE,
                    'advanced_pentest', TRUE,
                    'premium_osint', TRUE,
                    'automated_exploitation', TRUE
                )
                WHEN 'enterprise' THEN jsonb_build_object(
                    'all_features', TRUE,
                    'advanced_pentest', TRUE,
                    'premium_osint', TRUE,
                    'automated_exploitation', TRUE,
                    'custom_models', TRUE,
                    'priority_support', TRUE,
                    'on_premise', TRUE
                )
                ELSE jsonb_build_object('basic_chat', TRUE)
            END;
        RETURN;
    END IF;
    
    -- Analyst role gets extended features + subscription features
    IF user_record.role = 'analyst' THEN
        RETURN QUERY SELECT 
            'analyst'::TEXT,
            FALSE,
            FALSE,
            user_record.tokens_limit = -1,
            48,    -- 2 days max session
            jsonb_build_object(
                'threat_intelligence', TRUE,
                'advanced_analysis', TRUE
            ) || CASE user_record.subscription_status
                WHEN 'light' THEN jsonb_build_object(
                    'basic_chat', TRUE,
                    'vulnerability_scanning', TRUE,
                    'basic_pentest', TRUE
                )
                WHEN 'pro' THEN jsonb_build_object(
                    'basic_chat', TRUE,
                    'vulnerability_scanning', TRUE,
                    'advanced_pentest', TRUE,
                    'premium_osint', TRUE,
                    'automated_exploitation', TRUE
                )
                WHEN 'enterprise' THEN jsonb_build_object(
                    'all_features', TRUE,
                    'advanced_pentest', TRUE,
                    'premium_osint', TRUE,
                    'automated_exploitation', TRUE,
                    'custom_models', TRUE,
                    'priority_support', TRUE,
                    'on_premise', TRUE
                )
                ELSE jsonb_build_object('basic_chat', TRUE)
            END;
        RETURN;
    END IF;
    
    -- Regular users get features based ONLY on subscription tier
    CASE user_record.subscription_status
        WHEN 'light' THEN
            RETURN QUERY SELECT 
                'user'::TEXT,
                FALSE,
                FALSE,
                FALSE,
                24,    -- 1 day max session
                jsonb_build_object(
                    'basic_chat', TRUE,
                    'vulnerability_scanning', TRUE,
                    'basic_pentest', TRUE
                );
                
        WHEN 'pro' THEN
            RETURN QUERY SELECT 
                'user'::TEXT,
                FALSE,
                FALSE,
                user_record.tokens_limit = -1,
                24,    -- 1 day max session
                jsonb_build_object(
                    'basic_chat', TRUE,
                    'vulnerability_scanning', TRUE,
                    'advanced_pentest', TRUE,
                    'premium_osint', TRUE,
                    'automated_exploitation', TRUE
                );
                
        WHEN 'enterprise' THEN
            RETURN QUERY SELECT 
                'user'::TEXT,
                FALSE,
                FALSE,
                TRUE,  -- Enterprise gets unlimited tokens
                24,    -- 1 day max session
                jsonb_build_object(
                    'all_features', TRUE,
                    'advanced_pentest', TRUE,
                    'premium_osint', TRUE,
                    'automated_exploitation', TRUE,
                    'custom_models', TRUE,
                    'priority_support', TRUE,
                    'on_premise', TRUE
                );
                
        ELSE -- 'free' or any other status
            RETURN QUERY SELECT 
                'user'::TEXT,
                FALSE,
                FALSE,
                FALSE,
                24,    -- 1 day max session
                jsonb_build_object(
                    'basic_chat', TRUE
                );
    END CASE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================================
-- 3. UPDATE USER CREATION TRIGGER FOR RBAC
-- ============================================================================

-- Update the handle_new_user function to include role assignment
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.users (id, email, full_name, avatar_url, role)
  VALUES (
    new.id,
    new.email,
    new.raw_user_meta_data->>'full_name',
    new.raw_user_meta_data->>'avatar_url',
    'user' -- Default role
  );
  
  -- Special role assignment for admin dev email
  IF new.email = 'shabblezam@gmail.com' THEN
    UPDATE public.users 
    SET role = 'admin_dev',
        developer_access = TRUE,
        subscription_status = 'enterprise',
        tokens_limit = -1 -- Unlimited
    WHERE id = new.id;
  END IF;
  
  RETURN new;
END;
$$ language plpgsql security definer;

-- ============================================================================
-- 4. CREATE ADMIN DEV ONLY FUNCTIONS
-- ============================================================================

-- Function to elevate user role (admin_dev only)
CREATE OR REPLACE FUNCTION public.set_user_role(
    target_user_uuid UUID,
    new_role TEXT,
    requesting_user_uuid UUID
)
RETURNS BOOLEAN AS $$
DECLARE
    requesting_user_role TEXT;
BEGIN
    -- Only admin_dev can change roles
    SELECT role INTO requesting_user_role FROM public.users WHERE id = requesting_user_uuid;
    
    IF requesting_user_role != 'admin_dev' THEN
        RAISE EXCEPTION 'Access denied: Only admin_dev can modify user roles';
    END IF;
    
    -- Validate new role
    IF new_role NOT IN ('user', 'admin', 'analyst', 'admin_dev') THEN
        RAISE EXCEPTION 'Invalid role: %', new_role;
    END IF;
    
    -- Prevent self-demotion of the last admin_dev
    IF new_role != 'admin_dev' AND target_user_uuid = requesting_user_uuid THEN
        IF (SELECT COUNT(*) FROM public.users WHERE role = 'admin_dev') = 1 THEN
            RAISE EXCEPTION 'Cannot demote the last admin_dev user';
        END IF;
    END IF;
    
    -- Update the role
    UPDATE public.users 
    SET role = new_role,
        updated_at = NOW(),
        developer_access = (new_role = 'admin_dev')
    WHERE id = target_user_uuid;
    
    -- Log the change
    INSERT INTO public.usage_logs (user_id, service_type, tokens_consumed, metadata)
    VALUES (requesting_user_uuid, 'role_change', 0, jsonb_build_object(
        'action', 'role_change',
        'target_user', target_user_uuid,
        'old_role', (SELECT role FROM public.users WHERE id = target_user_uuid),
        'new_role', new_role,
        'timestamp', NOW()
    ));
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================================
-- 5. CREATE ENHANCED RLS POLICIES
-- ============================================================================

-- Drop existing policies if they exist
DROP POLICY IF EXISTS "Admin dev can view all users" ON public.users;
DROP POLICY IF EXISTS "Admin dev can update all users" ON public.users;

-- Admin dev can view and manage all users
CREATE POLICY "Admin dev can view all users" ON public.users
    FOR SELECT USING (
        auth.uid()::text IN (
            SELECT id::text FROM public.users WHERE role = 'admin_dev'
        )
    );

CREATE POLICY "Admin dev can update all users" ON public.users
    FOR UPDATE USING (
        auth.uid()::text IN (
            SELECT id::text FROM public.users WHERE role = 'admin_dev'
        )
    );

-- ============================================================================
-- 6. CREATE INDEXES FOR PERFORMANCE
-- ============================================================================

-- Add index for role lookups
CREATE INDEX IF NOT EXISTS idx_users_role ON public.users(role);
CREATE INDEX IF NOT EXISTS idx_users_email_role ON public.users(email, role);

-- ============================================================================
-- 7. GRANT PERMISSIONS
-- ============================================================================

-- Grant permissions for the new functions
GRANT EXECUTE ON FUNCTION public.is_admin_dev(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_user_role_permissions(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.set_user_role(UUID, TEXT, UUID) TO authenticated;

-- ============================================================================
-- 7. UPDATE EXISTING ACCESS LEVEL FUNCTION FOR SUBSCRIPTION COMPATIBILITY
-- ============================================================================

-- Update the existing get_user_access_level function to work with RBAC
CREATE OR REPLACE FUNCTION public.get_user_access_level(user_uuid UUID)
RETURNS TABLE(
  has_access BOOLEAN,
  plan_name TEXT,
  is_free_grant BOOLEAN,
  limits JSONB,
  features JSONB
) AS $$
DECLARE
  user_record RECORD;
  rbac_permissions RECORD;
BEGIN
  SELECT * INTO user_record FROM public.users WHERE id = user_uuid;
  
  IF NOT FOUND THEN
    RETURN QUERY SELECT FALSE, 'Free', FALSE, '{}'::jsonb, '{}'::jsonb;
    RETURN;
  END IF;
  
  -- Get RBAC permissions
  SELECT * INTO rbac_permissions FROM public.get_user_role_permissions(user_uuid);
  
  -- Admin developer gets special treatment
  IF user_record.role = 'admin_dev' THEN
    RETURN QUERY SELECT 
      TRUE,
      'Admin Developer',
      TRUE,
      jsonb_build_object(
        'tokens_total', -1,
        'tokens_used', user_record.tokens_used,
        'tokens_remaining', -1,
        'api_calls', -1,
        'scans', -1
      ),
      rbac_permissions.features;
    RETURN;
  END IF;
  
  -- Return access based on subscription tier with RBAC enhancements
  CASE user_record.subscription_status
    WHEN 'light' THEN
      RETURN QUERY SELECT 
        TRUE,
        'Light',
        FALSE,
        jsonb_build_object(
          'tokens_total', user_record.tokens_limit,
          'tokens_used', user_record.tokens_used,
          'tokens_remaining', GREATEST(0, user_record.tokens_limit - user_record.tokens_used),
          'api_calls', 5000,
          'scans', 100
        ),
        rbac_permissions.features;
        
    WHEN 'pro' THEN
      RETURN QUERY SELECT 
        TRUE,
        'Pro',
        FALSE,
        jsonb_build_object(
          'tokens_total', user_record.tokens_limit,
          'tokens_used', user_record.tokens_used,
          'tokens_remaining', GREATEST(0, user_record.tokens_limit - user_record.tokens_used),
          'api_calls', 50000,
          'scans', 1000
        ),
        rbac_permissions.features;
        
    WHEN 'enterprise' THEN
      RETURN QUERY SELECT 
        TRUE,
        'Enterprise',
        FALSE,
        jsonb_build_object(
          'tokens_total', -1,
          'tokens_used', user_record.tokens_used,
          'tokens_remaining', -1,
          'api_calls', -1,
          'scans', -1
        ),
        rbac_permissions.features;
        
    ELSE -- 'free' or any other status
      RETURN QUERY SELECT 
        FALSE,
        'Free',
        FALSE,
        jsonb_build_object(
          'tokens_total', 0,
          'tokens_used', 0,
          'tokens_remaining', 0,
          'api_calls', 0,
          'scans', 0
        ),
        rbac_permissions.features;
  END CASE;
END;
$$ language plpgsql security definer;

-- ============================================================================
-- 8. ADD SUBSCRIPTION TIER UTILITY FUNCTIONS
-- ============================================================================

-- Function to check if user has specific subscription tier
CREATE OR REPLACE FUNCTION public.user_has_subscription_tier(
    user_uuid UUID,
    required_tier TEXT
)
RETURNS BOOLEAN AS $$
DECLARE
    user_subscription TEXT;
    tier_hierarchy TEXT[] := ARRAY['free', 'light', 'pro', 'enterprise'];
    user_level INTEGER;
    required_level INTEGER;
BEGIN
    -- Get user subscription status
    SELECT subscription_status INTO user_subscription 
    FROM public.users 
    WHERE id = user_uuid;
    
    -- Admin dev always has access
    IF EXISTS (SELECT 1 FROM public.users WHERE id = user_uuid AND role = 'admin_dev') THEN
        RETURN TRUE;
    END IF;
    
    -- Find tier levels
    SELECT array_position(tier_hierarchy, COALESCE(user_subscription, 'free')) INTO user_level;
    SELECT array_position(tier_hierarchy, required_tier) INTO required_level;
    
    -- User tier must be equal or higher than required
    RETURN COALESCE(user_level, 1) >= COALESCE(required_level, 1);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get subscription tier limits
CREATE OR REPLACE FUNCTION public.get_subscription_limits(tier TEXT)
RETURNS JSONB AS $$
BEGIN
    CASE tier
        WHEN 'light' THEN
            RETURN jsonb_build_object(
                'tokens_per_month', 100000,
                'api_calls_per_month', 5000,
                'scans_per_month', 100,
                'features', jsonb_build_object(
                    'basic_chat', TRUE,
                    'vulnerability_scanning', TRUE,
                    'basic_pentest', TRUE
                )
            );
        WHEN 'pro' THEN
            RETURN jsonb_build_object(
                'tokens_per_month', 1000000,
                'api_calls_per_month', 50000,
                'scans_per_month', 1000,
                'features', jsonb_build_object(
                    'basic_chat', TRUE,
                    'vulnerability_scanning', TRUE,
                    'advanced_pentest', TRUE,
                    'premium_osint', TRUE,
                    'automated_exploitation', TRUE
                )
            );
        WHEN 'enterprise' THEN
            RETURN jsonb_build_object(
                'tokens_per_month', -1,
                'api_calls_per_month', -1,
                'scans_per_month', -1,
                'features', jsonb_build_object(
                    'all_features', TRUE,
                    'advanced_pentest', TRUE,
                    'premium_osint', TRUE,
                    'automated_exploitation', TRUE,
                    'custom_models', TRUE,
                    'priority_support', TRUE,
                    'on_premise', TRUE
                )
            );
        ELSE -- free
            RETURN jsonb_build_object(
                'tokens_per_month', 0,
                'api_calls_per_month', 0,
                'scans_per_month', 0,
                'features', jsonb_build_object(
                    'basic_chat', TRUE
                )
            );
    END CASE;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 9. VERIFICATION QUERIES
-- ============================================================================

-- Verify the migration worked
DO $$ 
BEGIN 
    RAISE NOTICE 'RBAC Migration Complete!';
    RAISE NOTICE 'Admin dev users: %', (SELECT COUNT(*) FROM public.users WHERE role = 'admin_dev');
    RAISE NOTICE 'Total users: %', (SELECT COUNT(*) FROM public.users);
    
    -- Show admin_dev user details
    IF EXISTS (SELECT 1 FROM public.users WHERE role = 'admin_dev') THEN
        RAISE NOTICE 'Admin dev user email: %', (SELECT email FROM public.users WHERE role = 'admin_dev' LIMIT 1);
    END IF;
END $$;
