-- COBRA AI Complete Database Setup for Supabase (FIXED VERSION)
-- Copy and paste this entire file into your Supabase SQL Editor and run it

-- ============================================================================
-- CLEANUP EXISTING FUNCTIONS (if any)
-- ============================================================================

-- Drop existing functions to avoid conflicts
DROP FUNCTION IF EXISTS public.get_user_access_level(uuid);
DROP FUNCTION IF EXISTS public.handle_new_user();
DROP FUNCTION IF EXISTS public.update_user_subscription(uuid, text, text, text, integer);
DROP FUNCTION IF EXISTS public.consume_tokens(uuid, integer, text, text, jsonb);

-- Drop trigger to recreate it
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;

-- ============================================================================
-- USERS TABLE WITH SUBSCRIPTION MANAGEMENT
-- ============================================================================

-- Users table with subscription management and developer access
CREATE TABLE IF NOT EXISTS public.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  full_name TEXT,
  avatar_url TEXT,
  
  -- Subscription fields
  subscription_status TEXT DEFAULT 'free' CHECK (subscription_status IN ('free', 'light', 'pro', 'enterprise')),
  subscription_id TEXT, -- Stripe subscription ID
  customer_id TEXT, -- Stripe customer ID
  subscription_start_date TIMESTAMPTZ,
  subscription_end_date TIMESTAMPTZ,
  subscription_cancel_at_period_end BOOLEAN DEFAULT FALSE,
  
  -- Access control
  developer_access BOOLEAN DEFAULT FALSE,
  is_active BOOLEAN DEFAULT TRUE,
  
  -- Usage tracking
  tokens_used INTEGER DEFAULT 0,
  tokens_limit INTEGER DEFAULT 0,
  last_token_reset TIMESTAMPTZ DEFAULT NOW(),
  
  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- SUBSCRIPTION HISTORY TABLE
-- ============================================================================

-- Subscription history table
CREATE TABLE IF NOT EXISTS public.subscription_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
  subscription_status TEXT NOT NULL,
  stripe_subscription_id TEXT,
  stripe_customer_id TEXT,
  change_reason TEXT,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- USAGE LOGS TABLE
-- ============================================================================

-- Usage tracking table
CREATE TABLE IF NOT EXISTS public.usage_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
  service_type TEXT NOT NULL, -- 'chat', 'pentest', 'bruteforce', etc.
  tokens_consumed INTEGER DEFAULT 0,
  session_id TEXT,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================================

-- Enable RLS
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscription_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.usage_logs ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if they exist
DROP POLICY IF EXISTS "Users can view own profile" ON public.users;
DROP POLICY IF EXISTS "Users can update own profile" ON public.users;
DROP POLICY IF EXISTS "Users can insert own profile" ON public.users;
DROP POLICY IF EXISTS "Users can view own subscription history" ON public.subscription_history;
DROP POLICY IF EXISTS "Users can view own usage logs" ON public.usage_logs;
DROP POLICY IF EXISTS "Service can insert usage logs" ON public.usage_logs;

-- Create policies
CREATE POLICY "Users can view own profile" ON public.users
  FOR SELECT USING (auth.uid()::text = id::text);

CREATE POLICY "Users can update own profile" ON public.users
  FOR UPDATE USING (auth.uid()::text = id::text);

CREATE POLICY "Users can insert own profile" ON public.users
  FOR INSERT WITH CHECK (auth.uid()::text = id::text);

CREATE POLICY "Users can view own subscription history" ON public.subscription_history
  FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "Users can view own usage logs" ON public.usage_logs
  FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "Service can insert usage logs" ON public.usage_logs
  FOR INSERT WITH CHECK (true);

-- ============================================================================
-- DATABASE FUNCTIONS
-- ============================================================================

-- Function to automatically create user profile on signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.users (id, email, full_name, avatar_url)
  VALUES (
    new.id,
    new.email,
    new.raw_user_meta_data->>'full_name',
    new.raw_user_meta_data->>'avatar_url'
  );
  
  -- Grant developer access to specific email
  IF new.email = 'shabblezam@gmail.com' THEN
    UPDATE public.users 
    SET developer_access = TRUE,
        subscription_status = 'enterprise',
        tokens_limit = -1 -- Unlimited
    WHERE id = new.id;
  END IF;
  
  RETURN new;
END;
$$ language plpgsql security definer;

-- Create the trigger
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();

-- Function to update user subscription
CREATE OR REPLACE FUNCTION public.update_user_subscription(
  user_uuid UUID,
  new_status TEXT,
  stripe_sub_id TEXT DEFAULT NULL,
  stripe_cust_id TEXT DEFAULT NULL,
  tokens_limit_override INTEGER DEFAULT NULL
)
RETURNS void AS $$
DECLARE
  token_limit INTEGER;
BEGIN
  -- Set token limits based on subscription
  CASE new_status
    WHEN 'free' THEN token_limit := 0;
    WHEN 'light' THEN token_limit := 100000;
    WHEN 'pro' THEN token_limit := 1000000;
    WHEN 'enterprise' THEN token_limit := -1; -- Unlimited
    ELSE token_limit := 0;
  END CASE;
  
  -- Use override if provided
  IF tokens_limit_override IS NOT NULL THEN
    token_limit := tokens_limit_override;
  END IF;
  
  -- Update user subscription
  UPDATE public.users SET
    subscription_status = new_status,
    subscription_id = COALESCE(stripe_sub_id, subscription_id),
    customer_id = COALESCE(stripe_cust_id, customer_id),
    tokens_limit = token_limit,
    tokens_used = 0, -- Reset usage on plan change
    last_token_reset = NOW(),
    updated_at = NOW()
  WHERE id = user_uuid;
  
  -- Log the change
  INSERT INTO public.subscription_history (
    user_id, 
    subscription_status, 
    stripe_subscription_id, 
    stripe_customer_id,
    change_reason,
    metadata
  ) VALUES (
    user_uuid,
    new_status,
    stripe_sub_id,
    stripe_cust_id,
    'Subscription updated',
    jsonb_build_object('updated_at', NOW())
  );
END;
$$ language plpgsql security definer;

-- Function to track token usage
CREATE OR REPLACE FUNCTION public.consume_tokens(
  user_uuid UUID,
  tokens INTEGER,
  service TEXT DEFAULT 'chat',
  session_uuid TEXT DEFAULT NULL,
  extra_metadata JSONB DEFAULT '{}'
)
RETURNS boolean AS $$
DECLARE
  current_usage INTEGER;
  token_limit INTEGER;
  dev_access BOOLEAN;
BEGIN
  -- Get current usage and limits
  SELECT tokens_used, tokens_limit, developer_access 
  INTO current_usage, token_limit, dev_access
  FROM public.users 
  WHERE id = user_uuid;
  
  -- Developer access bypasses limits
  IF dev_access = TRUE OR token_limit = -1 THEN
    -- Log usage but don't enforce limits
    INSERT INTO public.usage_logs (user_id, service_type, tokens_consumed, session_id, metadata)
    VALUES (user_uuid, service, tokens, session_uuid, extra_metadata);
    
    RETURN TRUE;
  END IF;
  
  -- Check if user has enough tokens
  IF current_usage + tokens > token_limit THEN
    RETURN FALSE;
  END IF;
  
  -- Update usage
  UPDATE public.users SET
    tokens_used = tokens_used + tokens,
    updated_at = NOW()
  WHERE id = user_uuid;
  
  -- Log the usage
  INSERT INTO public.usage_logs (user_id, service_type, tokens_consumed, session_id, metadata)
  VALUES (user_uuid, service, tokens, session_uuid, extra_metadata);
  
  RETURN TRUE;
END;
$$ language plpgsql security definer;

-- Function to get user access level (for API)
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
BEGIN
  SELECT * INTO user_record FROM public.users WHERE id = user_uuid;
  
  IF NOT FOUND THEN
    RETURN QUERY SELECT FALSE, 'Free', FALSE, '{}'::jsonb, '{}'::jsonb;
    RETURN;
  END IF;
  
  -- Developer access gets everything
  IF user_record.developer_access = TRUE THEN
    RETURN QUERY SELECT 
      TRUE,
      'Developer Mode',
      TRUE,
      jsonb_build_object(
        'tokens_total', -1,
        'tokens_used', user_record.tokens_used,
        'tokens_remaining', -1
      ),
      jsonb_build_object(
        'all_features', TRUE,
        'advanced_pentest', TRUE,
        'premium_osint', TRUE,
        'automated_exploitation', TRUE,
        'custom_models', TRUE,
        'priority_support', TRUE
      );
    RETURN;
  END IF;
  
  -- Return access based on subscription
  CASE user_record.subscription_status
    WHEN 'light' THEN
      RETURN QUERY SELECT 
        TRUE,
        'Light',
        FALSE,
        jsonb_build_object(
          'tokens_total', user_record.tokens_limit,
          'tokens_used', user_record.tokens_used,
          'tokens_remaining', GREATEST(0, user_record.tokens_limit - user_record.tokens_used)
        ),
        jsonb_build_object(
          'basic_chat', TRUE,
          'vulnerability_scanning', TRUE,
          'basic_pentest', TRUE
        );
        
    WHEN 'pro' THEN
      RETURN QUERY SELECT 
        TRUE,
        'Pro',
        FALSE,
        jsonb_build_object(
          'tokens_total', user_record.tokens_limit,
          'tokens_used', user_record.tokens_used,
          'tokens_remaining', GREATEST(0, user_record.tokens_limit - user_record.tokens_used)
        ),
        jsonb_build_object(
          'basic_chat', TRUE,
          'vulnerability_scanning', TRUE,
          'advanced_pentest', TRUE,
          'premium_osint', TRUE,
          'automated_exploitation', TRUE
        );
        
    WHEN 'enterprise' THEN
      RETURN QUERY SELECT 
        TRUE,
        'Enterprise',
        FALSE,
        jsonb_build_object(
          'tokens_total', -1,
          'tokens_used', user_record.tokens_used,
          'tokens_remaining', -1
        ),
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
        FALSE,
        'Free',
        FALSE,
        jsonb_build_object(
          'tokens_total', 0,
          'tokens_used', 0,
          'tokens_remaining', 0
        ),
        jsonb_build_object(
          'view_only', TRUE
        );
  END CASE;
END;
$$ language plpgsql security definer;

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users(email);
CREATE INDEX IF NOT EXISTS idx_users_subscription_status ON public.users(subscription_status);
CREATE INDEX IF NOT EXISTS idx_users_developer_access ON public.users(developer_access);
CREATE INDEX IF NOT EXISTS idx_subscription_history_user_id ON public.subscription_history(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_logs_user_id ON public.usage_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_logs_created_at ON public.usage_logs(created_at);

-- ============================================================================
-- PERMISSIONS
-- ============================================================================

-- Grant necessary permissions
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.users TO authenticated;
GRANT SELECT, INSERT ON public.subscription_history TO authenticated;
GRANT SELECT, INSERT ON public.usage_logs TO authenticated;

-- Allow service role to manage subscriptions
GRANT ALL ON public.users TO service_role;
GRANT ALL ON public.subscription_history TO service_role;
GRANT ALL ON public.usage_logs TO service_role;

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Test the function with a dummy UUID
SELECT 'Testing get_user_access_level function' as test_status;
SELECT * FROM public.get_user_access_level('00000000-0000-0000-0000-000000000000'::uuid);

-- Show available functions
SELECT 'Available functions created:' as info;
SELECT routine_name 
FROM information_schema.routines 
WHERE routine_schema = 'public' 
AND routine_name IN ('handle_new_user', 'get_user_access_level', 'consume_tokens', 'update_user_subscription')
ORDER BY routine_name;

-- Verify tables
SELECT 'Tables created:' as tables_info;
SELECT table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
AND table_name IN ('users', 'subscription_history', 'usage_logs')
ORDER BY table_name;

-- Final success message
SELECT '🎉 COBRA AI Database Setup Complete! 🎉' as result,
       'Ready for shabblezam@gmail.com to get developer access on signup!' as next_step; 