-- ========================================
-- COBRA AI - Supabase Database Setup
-- ========================================
-- Run this script in your Supabase SQL Editor
-- Go to: https://app.supabase.com/project/wamuunamwtvutozcohfc/sql

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ========================================
-- SUBSCRIPTION PLANS TABLE
-- ========================================
CREATE TABLE IF NOT EXISTS subscription_plans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL UNIQUE,
    stripe_price_id TEXT UNIQUE,
    price_monthly DECIMAL(10,2),
    price_yearly DECIMAL(10,2),
    features JSONB DEFAULT '{}',
    limits JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default subscription plans
INSERT INTO subscription_plans (name, stripe_price_id, price_monthly, features, limits, is_active) 
VALUES 
    ('light', 'price_1RmQkXABd1WNp9IUjNCzVd6q', 29.00, 
     '{"basic_tools": true, "api_access": true, "email_support": true}',
     '{"api_calls": 1000, "scans": 50, "tokens_total": 50000}', true),
    ('pro', 'price_1RmQZfABd1WNp9IU3BI5HpAN', 79.00, 
     '{"advanced_tools": true, "api_access": true, "priority_support": true, "custom_integrations": true}',
     '{"api_calls": 5000, "scans": 200, "tokens_total": 200000}', true),
    ('enterprise', 'price_1RmQQBABd1WNp9IUa8RSXQ9R', 199.00, 
     '{"all_tools": true, "unlimited_access": true, "premium_support": true, "custom_integrations": true, "admin_panel": true}',
     '{"api_calls": -1, "scans": -1, "tokens_total": -1}', true)
ON CONFLICT (name) DO UPDATE SET
    stripe_price_id = EXCLUDED.stripe_price_id,
    price_monthly = EXCLUDED.price_monthly,
    features = EXCLUDED.features,
    limits = EXCLUDED.limits,
    updated_at = NOW();

-- ========================================
-- USERS TABLE (Extend Supabase auth.users)
-- ========================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    subscription_status TEXT DEFAULT 'inactive',
    subscription_id TEXT,
    customer_id TEXT,
    subscription_start_date TIMESTAMP WITH TIME ZONE,
    subscription_end_date TIMESTAMP WITH TIME ZONE,
    subscription_cancel_at_period_end BOOLEAN DEFAULT false,
    developer_access BOOLEAN DEFAULT false,
    role TEXT DEFAULT 'user',
    tokens_limit INTEGER DEFAULT 0,
    tokens_used INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ========================================
-- USER SUBSCRIPTIONS TABLE
-- ========================================
CREATE TABLE IF NOT EXISTS user_subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    plan_id UUID REFERENCES subscription_plans(id),
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT UNIQUE,
    status TEXT DEFAULT 'inactive',
    current_period_start TIMESTAMP WITH TIME ZONE,
    current_period_end TIMESTAMP WITH TIME ZONE,
    cancel_at_period_end BOOLEAN DEFAULT false,
    trial_end TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ========================================
-- SUBSCRIPTION HISTORY TABLE
-- ========================================
CREATE TABLE IF NOT EXISTS subscription_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    subscription_status TEXT,
    stripe_subscription_id TEXT,
    stripe_customer_id TEXT,
    change_reason TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ========================================
-- USER SETTINGS TABLE
-- ========================================
CREATE TABLE IF NOT EXISTS user_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE UNIQUE,
    preferences JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ========================================
-- DEVELOPER ACCESS GRANT
-- ========================================
-- Grant developer access to shabblezam@gmail.com
INSERT INTO users (id, email, developer_access, subscription_status, role, tokens_limit, is_active)
SELECT 
    auth.users.id,
    'shabblezam@gmail.com',
    true,
    'enterprise',
    'admin_dev',
    -1,
    true
FROM auth.users 
WHERE auth.users.email = 'shabblezam@gmail.com'
ON CONFLICT (id) DO UPDATE SET
    developer_access = true,
    subscription_status = 'enterprise',
    role = 'admin_dev',
    tokens_limit = -1,
    updated_at = NOW();

-- ========================================
-- RPC FUNCTION: get_user_access_level
-- ========================================
CREATE OR REPLACE FUNCTION get_user_access_level(check_user_id UUID)
RETURNS TABLE(
    has_access BOOLEAN,
    plan_name TEXT,
    is_developer BOOLEAN,
    is_admin_dev BOOLEAN,
    is_free_grant BOOLEAN,
    features JSONB,
    limits JSONB,
    role TEXT,
    can_bypass_mfa BOOLEAN,
    can_extend_session BOOLEAN,
    has_unlimited_tokens BOOLEAN,
    max_session_duration_hours INTEGER
) LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    user_record users%ROWTYPE;
    subscription_record user_subscriptions%ROWTYPE;
    plan_record subscription_plans%ROWTYPE;
BEGIN
    -- Get user record
    SELECT * INTO user_record FROM users WHERE id = check_user_id;
    
    -- If user doesn't exist, return no access
    IF user_record.id IS NULL THEN
        RETURN QUERY SELECT 
            false as has_access,
            'none'::TEXT as plan_name,
            false as is_developer,
            false as is_admin_dev,
            false as is_free_grant,
            '{}'::JSONB as features,
            '{"api_calls": 0, "scans": 0, "tokens_total": 0, "tokens_used": 0, "tokens_remaining": 0}'::JSONB as limits,
            'none'::TEXT as role,
            false as can_bypass_mfa,
            false as can_extend_session,
            false as has_unlimited_tokens,
            1 as max_session_duration_hours;
        RETURN;
    END IF;
    
    -- Check if user is admin_dev (developer access)
    IF user_record.role = 'admin_dev' OR user_record.developer_access = true THEN
        RETURN QUERY SELECT 
            true as has_access,
            'enterprise'::TEXT as plan_name,
            true as is_developer,
            true as is_admin_dev,
            true as is_free_grant,
            '{"all_tools": true, "unlimited_access": true, "debug_mode": true, "admin_panel": true, "user_management": true}'::JSONB as features,
            '{"api_calls": -1, "scans": -1, "tokens_total": -1, "tokens_used": 0, "tokens_remaining": -1}'::JSONB as limits,
            'admin_dev'::TEXT as role,
            true as can_bypass_mfa,
            true as can_extend_session,
            true as has_unlimited_tokens,
            8760 as max_session_duration_hours;
        RETURN;
    END IF;
    
    -- Get active subscription
    SELECT * INTO subscription_record 
    FROM user_subscriptions 
    WHERE user_id = check_user_id 
      AND status IN ('active', 'trialing')
    ORDER BY created_at DESC 
    LIMIT 1;
    
    -- If no active subscription, return limited access
    IF subscription_record.id IS NULL THEN
        RETURN QUERY SELECT 
            false as has_access,
            'none'::TEXT as plan_name,
            false as is_developer,
            false as is_admin_dev,
            false as is_free_grant,
            '{}'::JSONB as features,
            '{"api_calls": 0, "scans": 0, "tokens_total": 0, "tokens_used": 0, "tokens_remaining": 0}'::JSONB as limits,
            'user'::TEXT as role,
            false as can_bypass_mfa,
            false as can_extend_session,
            false as has_unlimited_tokens,
            1 as max_session_duration_hours;
        RETURN;
    END IF;
    
    -- Get plan details
    SELECT * INTO plan_record FROM subscription_plans WHERE id = subscription_record.plan_id;
    
    -- Return subscription access
    RETURN QUERY SELECT 
        true as has_access,
        COALESCE(plan_record.name, 'light')::TEXT as plan_name,
        user_record.developer_access as is_developer,
        (user_record.role = 'admin_dev') as is_admin_dev,
        false as is_free_grant,
        COALESCE(plan_record.features, '{}'::JSONB) as features,
        jsonb_build_object(
            'api_calls', COALESCE((plan_record.limits->>'api_calls')::INTEGER, 1000),
            'scans', COALESCE((plan_record.limits->>'scans')::INTEGER, 50),
            'tokens_total', COALESCE((plan_record.limits->>'tokens_total')::INTEGER, 50000),
            'tokens_used', COALESCE(user_record.tokens_used, 0),
            'tokens_remaining', CASE 
                WHEN COALESCE((plan_record.limits->>'tokens_total')::INTEGER, 50000) = -1 THEN -1
                ELSE GREATEST(0, COALESCE((plan_record.limits->>'tokens_total')::INTEGER, 50000) - COALESCE(user_record.tokens_used, 0))
            END
        ) as limits,
        COALESCE(user_record.role, 'user')::TEXT as role,
        false as can_bypass_mfa,
        (plan_record.name IN ('pro', 'enterprise')) as can_extend_session,
        (plan_record.name = 'enterprise') as has_unlimited_tokens,
        CASE 
            WHEN plan_record.name = 'enterprise' THEN 8760
            WHEN plan_record.name = 'pro' THEN 24
            ELSE 8
        END as max_session_duration_hours;
END;
$$;

-- ========================================
-- RPC FUNCTION: activate_user_subscription
-- ========================================
CREATE OR REPLACE FUNCTION activate_user_subscription(
    user_uuid UUID,
    plan_name TEXT,
    stripe_subscription_id TEXT,
    stripe_customer_id TEXT
)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    plan_id UUID;
    result JSONB;
BEGIN
    -- Get plan ID
    SELECT id INTO plan_id FROM subscription_plans WHERE name = plan_name LIMIT 1;
    
    IF plan_id IS NULL THEN
        plan_id := (SELECT id FROM subscription_plans WHERE name = 'light' LIMIT 1);
    END IF;
    
    -- Update or create user record
    INSERT INTO users (id, email, subscription_status, subscription_id, customer_id, updated_at)
    SELECT 
        user_uuid,
        auth.users.email,
        plan_name,
        stripe_subscription_id,
        stripe_customer_id,
        NOW()
    FROM auth.users WHERE auth.users.id = user_uuid
    ON CONFLICT (id) DO UPDATE SET
        subscription_status = plan_name,
        subscription_id = stripe_subscription_id,
        customer_id = stripe_customer_id,
        updated_at = NOW();
    
    -- Create subscription record
    INSERT INTO user_subscriptions (user_id, plan_id, stripe_customer_id, stripe_subscription_id, status, created_at, updated_at)
    VALUES (user_uuid, plan_id, stripe_customer_id, stripe_subscription_id, 'active', NOW(), NOW())
    ON CONFLICT (stripe_subscription_id) DO UPDATE SET
        status = 'active',
        updated_at = NOW();
    
    result := jsonb_build_object(
        'success', true,
        'user_id', user_uuid,
        'plan_name', plan_name,
        'subscription_id', stripe_subscription_id
    );
    
    RETURN result;
END;
$$;

-- ========================================
-- RPC FUNCTION: verify_user_payment_access
-- ========================================
CREATE OR REPLACE FUNCTION verify_user_payment_access(user_email TEXT)
RETURNS TABLE(
    has_access BOOLEAN,
    subscription_status TEXT,
    is_developer BOOLEAN,
    access_level TEXT
) LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    user_id UUID;
    user_record users%ROWTYPE;
BEGIN
    -- Get user ID from email
    SELECT auth.users.id INTO user_id FROM auth.users WHERE auth.users.email = user_email;
    
    IF user_id IS NULL THEN
        RETURN QUERY SELECT false, 'none'::TEXT, false, 'none'::TEXT;
        RETURN;
    END IF;
    
    -- Get user record
    SELECT * INTO user_record FROM users WHERE id = user_id;
    
    -- Return access information
    RETURN QUERY SELECT 
        CASE 
            WHEN user_record.developer_access = true THEN true
            WHEN user_record.subscription_status IN ('light', 'pro', 'enterprise', 'active') THEN true
            ELSE false
        END as has_access,
        COALESCE(user_record.subscription_status, 'none')::TEXT as subscription_status,
        COALESCE(user_record.developer_access, false) as is_developer,
        CASE 
            WHEN user_record.developer_access = true THEN 'enterprise'
            ELSE COALESCE(user_record.subscription_status, 'none')
        END::TEXT as access_level;
END;
$$;

-- ========================================
-- TRIGGERS FOR AUTOMATIC TIMESTAMPS
-- ========================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply triggers
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_user_subscriptions_updated_at ON user_subscriptions;
CREATE TRIGGER update_user_subscriptions_updated_at BEFORE UPDATE ON user_subscriptions FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_user_settings_updated_at ON user_settings;
CREATE TRIGGER update_user_settings_updated_at BEFORE UPDATE ON user_settings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ========================================
-- ROW LEVEL SECURITY (RLS)
-- ========================================
-- Enable RLS on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscription_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscription_plans ENABLE ROW LEVEL SECURITY;

-- Users can only see their own data
CREATE POLICY "Users can view own data" ON users FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Users can update own data" ON users FOR UPDATE USING (auth.uid() = id);

-- Subscription data policies
CREATE POLICY "Users can view own subscriptions" ON user_subscriptions FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can view own subscription history" ON subscription_history FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can view own settings" ON user_settings FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can update own settings" ON user_settings FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "Users can insert own settings" ON user_settings FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Public read access to subscription plans
CREATE POLICY "Anyone can view subscription plans" ON subscription_plans FOR SELECT TO public USING (is_active = true);

-- ========================================
-- COMPLETION MESSAGE
-- ========================================
DO $$ 
BEGIN 
    RAISE NOTICE 'COBRA AI Database Setup Complete!';
    RAISE NOTICE 'Developer access granted to: shabblezam@gmail.com';
    RAISE NOTICE 'Subscription plans configured: light, pro, enterprise';
    RAISE NOTICE 'All RPC functions created successfully';
END $$;
