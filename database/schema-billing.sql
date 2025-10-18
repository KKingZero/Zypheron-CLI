-- COBRA AI Billing Database Schema
-- Execute this in your Supabase SQL Editor after the main schema

-- Subscription plans table
CREATE TABLE IF NOT EXISTS public.subscription_plans (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    stripe_price_id TEXT UNIQUE,
    price_monthly DECIMAL(10,2),
    price_yearly DECIMAL(10,2),
    features JSONB DEFAULT '{}',
    limits JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User subscriptions table
CREATE TABLE IF NOT EXISTS public.user_subscriptions (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL UNIQUE,
    plan_id UUID REFERENCES public.subscription_plans(id),
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT UNIQUE,
    status TEXT CHECK (status IN ('trialing', 'active', 'canceled', 'incomplete', 'incomplete_expired', 'past_due', 'unpaid')) DEFAULT 'incomplete',
    current_period_start TIMESTAMP WITH TIME ZONE,
    current_period_end TIMESTAMP WITH TIME ZONE,
    cancel_at_period_end BOOLEAN DEFAULT FALSE,
    trial_end TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Free access grants table (for giving certain users free access)
CREATE TABLE IF NOT EXISTS public.free_access_grants (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL UNIQUE,
    granted_by UUID REFERENCES public.profiles(id) NOT NULL,
    reason TEXT,
    features_granted JSONB DEFAULT '{}',
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Usage tracking table
CREATE TABLE IF NOT EXISTS public.usage_tracking (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    feature_name TEXT NOT NULL,
    count INTEGER DEFAULT 1,
    date DATE DEFAULT CURRENT_DATE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, feature_name, date)
);

-- Add billing columns to profiles table if they don't exist
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'profiles' AND column_name = 'subscription_status') THEN
        ALTER TABLE public.profiles ADD COLUMN subscription_status TEXT DEFAULT 'none';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'profiles' AND column_name = 'is_free_access') THEN
        ALTER TABLE public.profiles ADD COLUMN is_free_access BOOLEAN DEFAULT FALSE;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'profiles' AND column_name = 'role') THEN
        ALTER TABLE public.profiles ADD COLUMN role TEXT DEFAULT 'user' CHECK (role IN ('user', 'admin', 'analyst'));
    END IF;
END $$;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_user_id ON public.user_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_status ON public.user_subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_free_access_grants_user_id ON public.free_access_grants(user_id);
CREATE INDEX IF NOT EXISTS idx_free_access_grants_active ON public.free_access_grants(is_active);
CREATE INDEX IF NOT EXISTS idx_usage_tracking_user_date ON public.usage_tracking(user_id, date);
CREATE INDEX IF NOT EXISTS idx_usage_tracking_feature ON public.usage_tracking(feature_name, date);

-- Insert default subscription plans
INSERT INTO public.subscription_plans (name, stripe_price_id, price_monthly, price_yearly, features, limits) 
VALUES 
    ('Light', 'price_1RmQkXABd1WNp9IUjNCzVd6q', 29.99, 299.90, 
     '{"stage_1": true, "basic_chat": true, "vulnerability_scanning": true, "ai_analysis": true}',
     '{"total_tokens": 100000, "api_calls": 5000, "ai_requests": 1000, "osint_queries": 100}'
    ),
    ('Pro', 'price_1RmQZfABd1WNp9IU3BI5HpAN', 149.99, 1499.90,
     '{"stage_1": true, "stage_2": true, "advanced_chat": true, "penetration_testing": true, "osint_advanced": true, "automated_exploitation": true}',
     '{"total_tokens": 1000000, "api_calls": 50000, "ai_requests": 10000, "osint_queries": 1000}'
    ),
    ('Enterprise', 'price_1RmQQBABd1WNp9IUa8RSXQ9R', 999.99, 9999.90,
     '{"stage_1": true, "stage_2": true, "stage_3": true, "custom_models": true, "on_premise": true, "dedicated_support": true}',
     '{"total_tokens": -1, "api_calls": -1, "ai_requests": -1, "osint_queries": -1}'
    )
ON CONFLICT (name) DO NOTHING;

-- Function to get user access level
CREATE OR REPLACE FUNCTION public.get_user_access_level(check_user_id UUID)
RETURNS TABLE (
    has_access BOOLEAN,
    plan_name TEXT,
    is_free_grant BOOLEAN,
    limits JSONB,
    features JSONB
) 
LANGUAGE plpgsql SECURITY DEFINER
AS $$
BEGIN
    -- Check for free access grant first
    IF EXISTS (
        SELECT 1 FROM public.free_access_grants 
        WHERE user_id = check_user_id 
        AND is_active = TRUE 
        AND (expires_at IS NULL OR expires_at > NOW())
    ) THEN
        RETURN QUERY SELECT 
            TRUE as has_access,
            'Free Grant' as plan_name,
            TRUE as is_free_grant,
            '{"api_calls": -1, "ai_requests": -1, "osint_queries": -1}'::jsonb as limits,
            '{"stage_1": true, "stage_2": true, "stage_3": true, "unlimited": true}'::jsonb as features;
        RETURN;
    END IF;

    -- Check for active subscription
    IF EXISTS (
        SELECT 1 FROM public.user_subscriptions us
        JOIN public.subscription_plans sp ON us.plan_id = sp.id
        WHERE us.user_id = check_user_id 
        AND us.status IN ('active', 'trialing')
        AND (us.current_period_end IS NULL OR us.current_period_end > NOW())
    ) THEN
        RETURN QUERY SELECT 
            TRUE as has_access,
            sp.name as plan_name,
            FALSE as is_free_grant,
            sp.limits,
            sp.features
        FROM public.user_subscriptions us
        JOIN public.subscription_plans sp ON us.plan_id = sp.id
        WHERE us.user_id = check_user_id 
        AND us.status IN ('active', 'trialing')
        AND (us.current_period_end IS NULL OR us.current_period_end > NOW())
        ORDER BY us.created_at DESC
        LIMIT 1;
        RETURN;
    END IF;

    -- Default free tier access
    RETURN QUERY SELECT 
        TRUE as has_access,
        'Free' as plan_name,
        FALSE as is_free_grant,
        '{"api_calls": 100, "ai_requests": 50, "osint_queries": 10}'::jsonb as limits,
        '{"basic_chat": true, "local_llm": true, "stage_1": true}'::jsonb as features;
END;
$$;

-- Function to check if user can access a specific feature
CREATE OR REPLACE FUNCTION public.check_feature_access(check_user_id UUID, feature_name TEXT)
RETURNS BOOLEAN 
LANGUAGE plpgsql SECURITY DEFINER
AS $$
DECLARE
    user_features JSONB;
BEGIN
    -- Get user's features
    SELECT features INTO user_features 
    FROM public.get_user_access_level(check_user_id) 
    LIMIT 1;

    -- Check if feature is available
    RETURN COALESCE((user_features ->> feature_name)::boolean, FALSE);
END;
$$;

-- Function to get daily usage for a user and feature
CREATE OR REPLACE FUNCTION public.get_daily_usage(check_user_id UUID, feature_name TEXT, check_date DATE DEFAULT CURRENT_DATE)
RETURNS INTEGER 
LANGUAGE plpgsql SECURITY DEFINER
AS $$
DECLARE
    usage_count INTEGER;
BEGIN
    SELECT COALESCE(SUM(count), 0) INTO usage_count
    FROM public.usage_tracking
    WHERE user_id = check_user_id 
    AND feature_name = get_daily_usage.feature_name
    AND date = check_date;

    RETURN usage_count;
END;
$$;

-- RLS (Row Level Security) Policies
ALTER TABLE public.subscription_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.free_access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.usage_tracking ENABLE ROW LEVEL SECURITY;

-- Subscription plans are public
CREATE POLICY "Subscription plans are viewable by everyone" ON public.subscription_plans
    FOR SELECT USING (true);

-- Users can only see their own subscription data
CREATE POLICY "Users can view own subscription" ON public.user_subscriptions
    FOR SELECT USING (auth.uid() = user_id);

-- Only admins can manage subscriptions (admin operations handled by service role)
CREATE POLICY "Service role can manage subscriptions" ON public.user_subscriptions
    USING (auth.role() = 'service_role');

-- Free access grants policies
CREATE POLICY "Users can view own free access grants" ON public.free_access_grants
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Admins can manage free access grants" ON public.free_access_grants
    USING (EXISTS (
        SELECT 1 FROM public.profiles 
        WHERE id = auth.uid() AND role = 'admin'
    ));

-- Usage tracking policies
CREATE POLICY "Users can view own usage" ON public.usage_tracking
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "System can insert usage data" ON public.usage_tracking
    FOR INSERT WITH CHECK (true);

-- Triggers for updated_at
CREATE OR REPLACE FUNCTION public.handle_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_updated_at_user_subscriptions
    BEFORE UPDATE ON public.user_subscriptions
    FOR EACH ROW EXECUTE FUNCTION public.handle_updated_at(); 