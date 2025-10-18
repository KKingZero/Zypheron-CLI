-- Database setup script for COBRA AI
-- Run this in your Supabase SQL Editor
-- Note: Copy and paste the contents of database/schema-users.sql here first, then run this verification

-- Verify the setup
SELECT 'Users table created' as status WHERE EXISTS (
  SELECT 1 FROM information_schema.tables 
  WHERE table_schema = 'public' AND table_name = 'users'
);

SELECT 'Subscription history table created' as status WHERE EXISTS (
  SELECT 1 FROM information_schema.tables 
  WHERE table_schema = 'public' AND table_name = 'subscription_history'
);

SELECT 'Usage logs table created' as status WHERE EXISTS (
  SELECT 1 FROM information_schema.tables 
  WHERE table_schema = 'public' AND table_name = 'usage_logs'
);

-- Test the access level function
SELECT 'Testing get_user_access_level function' as test;
SELECT * FROM public.get_user_access_level('00000000-0000-0000-0000-000000000000'::uuid);

-- Show available functions
SELECT routine_name, routine_type 
FROM information_schema.routines 
WHERE routine_schema = 'public' 
AND routine_name LIKE '%user%'
ORDER BY routine_name; 