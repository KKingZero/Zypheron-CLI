-- COBRA AI Waitlist Database Schema
-- Execute this in your Supabase SQL Editor to set up the waitlist system

-- ============================================================================
-- WAITLIST TABLE
-- ============================================================================

-- Waitlist table for collecting user emails before full registration
CREATE TABLE IF NOT EXISTS public.waitlist (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  full_name TEXT,
  source TEXT DEFAULT 'signup_form', -- How they found the app
  interest_level TEXT DEFAULT 'high' CHECK (interest_level IN ('low', 'medium', 'high')),
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'invited', 'registered', 'declined')),
  metadata JSONB DEFAULT '{}', -- Store additional data like user agent, referrer, etc.
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- USER REGISTRATIONS TABLE 
-- ============================================================================

-- Enhanced users table to track registration details for the waitlist system
CREATE TABLE IF NOT EXISTS public.user_registrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID, -- Will reference auth.users(id) when they actually sign up
  email TEXT UNIQUE NOT NULL,
  full_name TEXT,
  
  -- Registration source and details
  registration_source TEXT DEFAULT 'direct', -- direct, waitlist, invite, etc.
  referrer_url TEXT,
  user_agent TEXT,
  ip_address INET,
  
  -- Account status
  account_status TEXT DEFAULT 'pending' CHECK (account_status IN ('pending', 'active', 'suspended', 'deleted')),
  email_verified BOOLEAN DEFAULT FALSE,
  terms_accepted BOOLEAN DEFAULT FALSE,
  privacy_accepted BOOLEAN DEFAULT FALSE,
  
  -- Subscription intent (for waitlist validation)
  intended_plan TEXT DEFAULT 'free' CHECK (intended_plan IN ('free', 'light', 'pro', 'enterprise')),
  expected_usage TEXT, -- What they plan to use COBRA AI for
  
  -- Timestamps
  registered_at TIMESTAMPTZ DEFAULT NOW(),
  activated_at TIMESTAMPTZ,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_waitlist_email ON public.waitlist(email);
CREATE INDEX IF NOT EXISTS idx_waitlist_status ON public.waitlist(status);
CREATE INDEX IF NOT EXISTS idx_waitlist_created_at ON public.waitlist(created_at);

CREATE INDEX IF NOT EXISTS idx_user_registrations_email ON public.user_registrations(email);
CREATE INDEX IF NOT EXISTS idx_user_registrations_user_id ON public.user_registrations(user_id);
CREATE INDEX IF NOT EXISTS idx_user_registrations_status ON public.user_registrations(account_status);
CREATE INDEX IF NOT EXISTS idx_user_registrations_source ON public.user_registrations(registration_source);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

-- Enable RLS on waitlist table
ALTER TABLE public.waitlist ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only view their own waitlist entry
CREATE POLICY "Users can view their own waitlist entry" ON public.waitlist
  FOR SELECT USING (auth.email() = email);

-- Policy: Anyone can insert to waitlist (for signup)
CREATE POLICY "Anyone can join waitlist" ON public.waitlist
  FOR INSERT WITH CHECK (true);

-- Policy: Only authenticated users can update their own waitlist entry
CREATE POLICY "Users can update their own waitlist entry" ON public.waitlist
  FOR UPDATE USING (auth.email() = email);

-- Enable RLS on user registrations table
ALTER TABLE public.user_registrations ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only view their own registration
CREATE POLICY "Users can view their own registration" ON public.user_registrations
  FOR SELECT USING (auth.uid() = user_id OR auth.email() = email);

-- Policy: Anyone can insert registration (for signup)
CREATE POLICY "Anyone can register" ON public.user_registrations
  FOR INSERT WITH CHECK (true);

-- Policy: Users can update their own registration
CREATE POLICY "Users can update their own registration" ON public.user_registrations
  FOR UPDATE USING (auth.uid() = user_id OR auth.email() = email);

-- ============================================================================
-- FUNCTIONS FOR AUTOMATION
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers to automatically update updated_at
CREATE TRIGGER update_waitlist_updated_at BEFORE UPDATE ON public.waitlist
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_registrations_updated_at BEFORE UPDATE ON public.user_registrations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to move user from waitlist to registered status
CREATE OR REPLACE FUNCTION promote_waitlist_user(user_email TEXT, user_id_param UUID)
RETURNS void AS $$
BEGIN
    -- Update waitlist status
    UPDATE public.waitlist 
    SET status = 'registered', updated_at = NOW()
    WHERE email = user_email;
    
    -- Update user registration with actual user_id
    UPDATE public.user_registrations 
    SET user_id = user_id_param, 
        account_status = 'active',
        activated_at = NOW(),
        updated_at = NOW()
    WHERE email = user_email;
END;
$$ language 'plpgsql';

-- Function to get waitlist stats (admin use)
CREATE OR REPLACE FUNCTION get_waitlist_stats()
RETURNS TABLE(
    total_waitlist BIGINT,
    pending_count BIGINT,
    registered_count BIGINT,
    total_registrations BIGINT,
    active_users BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        (SELECT COUNT(*) FROM public.waitlist) as total_waitlist,
        (SELECT COUNT(*) FROM public.waitlist WHERE status = 'pending') as pending_count,
        (SELECT COUNT(*) FROM public.waitlist WHERE status = 'registered') as registered_count,
        (SELECT COUNT(*) FROM public.user_registrations) as total_registrations,
        (SELECT COUNT(*) FROM public.user_registrations WHERE account_status = 'active') as active_users;
END;
$$ language 'plpgsql';

-- ============================================================================
-- INITIAL DATA (OPTIONAL)
-- ============================================================================

-- Insert some example data (remove in production)
-- INSERT INTO public.waitlist (email, full_name, source, interest_level) VALUES
-- ('demo@example.com', 'Demo User', 'landing_page', 'high'),
-- ('test@example.com', 'Test User', 'referral', 'medium');

-- Success message
DO $$ 
BEGIN 
    RAISE NOTICE 'COBRA AI Waitlist Database Setup Complete!';
    RAISE NOTICE 'Tables created: waitlist, user_registrations';
    RAISE NOTICE 'RLS policies configured for security';
    RAISE NOTICE 'Helper functions available: promote_waitlist_user(), get_waitlist_stats()';
END $$; 