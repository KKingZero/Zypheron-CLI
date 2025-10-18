-- Quick SQL script to grant admin_dev access to shabblezam@gmail.com
-- Execute this in your Supabase SQL Editor

-- First, make sure the role column exists
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'users' AND column_name = 'role' AND table_schema = 'public') THEN
        ALTER TABLE public.users ADD COLUMN role TEXT DEFAULT 'user' 
        CHECK (role IN ('user', 'admin', 'analyst', 'admin_dev'));
    END IF;
END $$;

-- Update shabblezam@gmail.com to admin_dev if user exists
UPDATE public.users 
SET role = 'admin_dev',
    developer_access = TRUE,
    subscription_status = 'enterprise',
    tokens_limit = -1  -- Unlimited tokens
WHERE email = 'shabblezam@gmail.com';

-- If the user doesn't exist in the users table yet, create the record
INSERT INTO public.users (id, email, role, developer_access, subscription_status, tokens_limit)
SELECT 
    auth.users.id,
    'shabblezam@gmail.com',
    'admin_dev',
    TRUE,
    'enterprise',
    -1
FROM auth.users 
WHERE auth.users.email = 'shabblezam@gmail.com'
  AND NOT EXISTS (SELECT 1 FROM public.users WHERE email = 'shabblezam@gmail.com');

-- Verify the update
SELECT email, role, developer_access, subscription_status, tokens_limit 
FROM public.users 
WHERE email = 'shabblezam@gmail.com';

-- Test the RBAC functions
SELECT * FROM public.get_user_role_permissions(
    (SELECT id FROM public.users WHERE email = 'shabblezam@gmail.com')
);

SELECT * FROM public.get_user_access_level(
    (SELECT id FROM public.users WHERE email = 'shabblezam@gmail.com')
);
