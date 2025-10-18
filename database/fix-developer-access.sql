-- Fix Developer Access and Account Verification
-- This script addresses the issues mentioned in Discord messages where
-- users cannot access the dashboard after payment, particularly for shabblezam@gmail.com

-- ============================================================================
-- 1. ENSURE PROPER TRIGGER SETUP FOR NEW USER ACCOUNTS
-- ============================================================================

-- Drop existing trigger if it exists (to avoid conflicts)
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS handle_new_user() CASCADE;

-- Create the improved handle_new_user function
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
    user_email TEXT;
    subscription_tier TEXT;
    token_limit INTEGER;
    dev_access BOOLEAN := FALSE;
    user_role TEXT := 'user';
BEGIN
    user_email := NEW.email;
    
    -- Check if this is a developer/admin email
    IF user_email IN (
        'shabblezam@gmail.com'
        -- Add more developer emails here as needed
    ) THEN
        dev_access := TRUE;
        user_role := 'admin_dev';
        subscription_tier := 'enterprise';
        token_limit := -1; -- Unlimited
    ELSE
        dev_access := FALSE;
        user_role := 'user';
        subscription_tier := 'free';
        token_limit := 0;
    END IF;

    -- Insert into public.users table
    INSERT INTO public.users (
        id,
        email,
        full_name,
        avatar_url,
        subscription_status,
        developer_access,
        role,
        tokens_limit,
        is_active,
        created_at,
        updated_at
    ) VALUES (
        NEW.id,
        user_email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', split_part(user_email, '@', 1)),
        NEW.raw_user_meta_data->>'avatar_url',
        subscription_tier,
        dev_access,
        user_role,
        token_limit,
        TRUE,
        NOW(),
        NOW()
    ) ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        full_name = EXCLUDED.full_name,
        avatar_url = EXCLUDED.avatar_url,
        subscription_status = EXCLUDED.subscription_status,
        developer_access = EXCLUDED.developer_access,
        role = EXCLUDED.role,
        tokens_limit = EXCLUDED.tokens_limit,
        updated_at = NOW();

    -- Also create a profiles entry if it doesn't exist
    INSERT INTO public.profiles (
        id,
        email,
        full_name,
        avatar_url,
        subscription_status,
        updated_at
    ) VALUES (
        NEW.id,
        user_email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', split_part(user_email, '@', 1)),
        NEW.raw_user_meta_data->>'avatar_url',
        subscription_tier,
        NOW()
    ) ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        full_name = EXCLUDED.full_name,
        avatar_url = EXCLUDED.avatar_url,
        subscription_status = EXCLUDED.subscription_status,
        updated_at = NOW();

    -- Log the user creation
    INSERT INTO public.subscription_history (
        user_id,
        subscription_status,
        change_reason,
        metadata,
        created_at
    ) VALUES (
        NEW.id,
        subscription_tier,
        'User account created',
        jsonb_build_object(
            'email', user_email,
            'developer_access', dev_access,
            'role', user_role,
            'auto_granted', dev_access
        ),
        NOW()
    );

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Recreate the trigger
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION handle_new_user();

-- ============================================================================
-- 2. FIX EXISTING shabblezam@gmail.com ACCOUNT
-- ============================================================================

-- Update shabblezam@gmail.com account if it exists
UPDATE public.users 
SET role = 'admin_dev',
    developer_access = TRUE,
    subscription_status = 'enterprise',
    tokens_limit = -1,  -- Unlimited tokens
    is_active = TRUE,
    updated_at = NOW()
WHERE email = 'shabblezam@gmail.com';

-- Also update profiles table
UPDATE public.profiles 
SET subscription_status = 'enterprise',
    updated_at = NOW()
WHERE email = 'shabblezam@gmail.com';

-- If the user doesn't exist in the users table yet, create the record
INSERT INTO public.users (id, email, role, developer_access, subscription_status, tokens_limit, is_active)
SELECT 
    auth.users.id,
    'shabblezam@gmail.com',
    'admin_dev',
    TRUE,
    'enterprise',
    -1,
    TRUE
FROM auth.users 
WHERE auth.users.email = 'shabblezam@gmail.com'
  AND NOT EXISTS (SELECT 1 FROM public.users WHERE email = 'shabblezam@gmail.com');

-- ============================================================================
-- 3. CREATE FUNCTION TO VERIFY USER ACCESS AFTER PAYMENT
-- ============================================================================

CREATE OR REPLACE FUNCTION public.verify_user_payment_access(user_email TEXT)
RETURNS TABLE(
    user_id UUID,
    has_access BOOLEAN,
    subscription_status TEXT,
    is_developer BOOLEAN,
    access_level TEXT
) AS $$
DECLARE
    user_record RECORD;
BEGIN
    -- Get user information
    SELECT u.id, u.subscription_status, u.developer_access, u.role,
           COALESCE(us.status, 'none') as stripe_status
    INTO user_record
    FROM public.users u
    LEFT JOIN public.user_subscriptions us ON u.id = us.user_id
    WHERE u.email = user_email;

    IF user_record IS NULL THEN
        -- User not found
        RETURN QUERY SELECT 
            NULL::UUID,
            FALSE,
            'not_found'::TEXT,
            FALSE,
            'no_access'::TEXT;
        RETURN;
    END IF;

    -- Determine access level
    IF user_record.role = 'admin_dev' OR user_record.developer_access THEN
        -- Developer access
        RETURN QUERY SELECT 
            user_record.id,
            TRUE,
            user_record.subscription_status,
            TRUE,
            'developer'::TEXT;
    ELSIF user_record.stripe_status IN ('active', 'trialing') THEN
        -- Active subscription
        RETURN QUERY SELECT 
            user_record.id,
            TRUE,
            user_record.subscription_status,
            FALSE,
            'subscription'::TEXT;
    ELSIF user_record.subscription_status != 'free' THEN
        -- Has a plan but might be processing
        RETURN QUERY SELECT 
            user_record.id,
            TRUE,
            user_record.subscription_status,
            FALSE,
            'processing'::TEXT;
    ELSE
        -- Free user
        RETURN QUERY SELECT 
            user_record.id,
            FALSE,
            user_record.subscription_status,
            FALSE,
            'free'::TEXT;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================================
-- 4. IMPROVE WEBHOOK HANDLING FOR USER ACCESS
-- ============================================================================

-- Function to handle successful payment and ensure user access
CREATE OR REPLACE FUNCTION public.activate_user_subscription(
    user_uuid UUID,
    plan_name TEXT,
    stripe_subscription_id TEXT DEFAULT NULL,
    stripe_customer_id TEXT DEFAULT NULL
)
RETURNS BOOLEAN AS $$
DECLARE
    token_limit INTEGER;
    success BOOLEAN := FALSE;
BEGIN
    -- Determine token limit based on plan
    CASE LOWER(plan_name)
        WHEN 'light' THEN token_limit := 100000;
        WHEN 'pro' THEN token_limit := 1000000;
        WHEN 'enterprise' THEN token_limit := -1;
        ELSE token_limit := 100000; -- Default to light
    END CASE;

    -- Update user subscription status
    UPDATE public.users 
    SET subscription_status = LOWER(plan_name),
        tokens_limit = token_limit,
        updated_at = NOW()
    WHERE id = user_uuid;

    -- Update profiles table
    UPDATE public.profiles 
    SET subscription_status = LOWER(plan_name),
        updated_at = NOW()
    WHERE id = user_uuid;

    -- Create or update subscription record
    INSERT INTO public.user_subscriptions (
        user_id,
        stripe_subscription_id,
        stripe_customer_id,
        status,
        updated_at
    ) VALUES (
        user_uuid,
        stripe_subscription_id,
        stripe_customer_id,
        'active',
        NOW()
    ) ON CONFLICT (user_id) DO UPDATE SET
        stripe_subscription_id = EXCLUDED.stripe_subscription_id,
        stripe_customer_id = EXCLUDED.stripe_customer_id,
        status = 'active',
        updated_at = NOW();

    -- Log the subscription activation
    INSERT INTO public.subscription_history (
        user_id,
        subscription_status,
        change_reason,
        metadata,
        created_at
    ) VALUES (
        user_uuid,
        LOWER(plan_name),
        'Payment successful - subscription activated',
        jsonb_build_object(
            'stripe_subscription_id', stripe_subscription_id,
            'stripe_customer_id', stripe_customer_id,
            'plan_name', plan_name,
            'token_limit', token_limit
        ),
        NOW()
    );

    GET DIAGNOSTICS success = ROW_COUNT;
    RETURN success > 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================================
-- 5. VERIFY THE SETUP
-- ============================================================================

-- Check if shabblezam@gmail.com has proper access
SELECT 
    email, 
    role, 
    developer_access, 
    subscription_status, 
    tokens_limit,
    is_active
FROM public.users 
WHERE email = 'shabblezam@gmail.com';

-- Test the verification function
SELECT * FROM public.verify_user_payment_access('shabblezam@gmail.com');

-- Test RBAC functions if they exist
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'get_user_access_level') THEN
        PERFORM public.get_user_access_level(
            (SELECT id FROM public.users WHERE email = 'shabblezam@gmail.com')
        );
    END IF;
END $$;

-- ============================================================================
-- 6. GRANT NECESSARY PERMISSIONS
-- ============================================================================

-- Grant permissions for the service role to use these functions
GRANT EXECUTE ON FUNCTION public.verify_user_payment_access(TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.activate_user_subscription(UUID, TEXT, TEXT, TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION handle_new_user() TO service_role;

-- Grant permissions for authenticated users to verify their own access
GRANT EXECUTE ON FUNCTION public.verify_user_payment_access(TEXT) TO authenticated;

-- Success message
SELECT 'Developer access and account verification system has been updated successfully!' as status;
