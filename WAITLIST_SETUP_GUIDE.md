# CobraAI Waitlist & User Registration Setup Guide

## Overview

CobraAI now includes a comprehensive **waitlist and user registration system** that automatically saves user data to Supabase when they create accounts. This allows you to:

- **Track user signups** and validate demand before full feature development
- **Collect user emails** for marketing and product announcements  
- **Monitor user engagement** with detailed registration and login tracking
- **Understand user intent** with data on expected usage and subscription plans

## ✅ What's Been Implemented

### Database Schema
- **`waitlist`** table - Collects emails before users sign up
- **`user_registrations`** table - Tracks full user registration details
- **Helper functions** - Automated user promotion and statistics
- **Row Level Security (RLS)** - Secure access policies

### Backend Services
- **`UserRegistrationService`** - Handles all database operations
- **API endpoints** - `/api/user/*` routes for registration, login tracking, and stats
- **Automatic tracking** - Users saved to database on signup/login

### Frontend Integration
- **Enhanced AuthContext** - Automatic database saving on signup/login
- **No UI changes** - Existing interface preserved exactly as before
- **Demo mode support** - Works with or without Supabase configuration

## 🛠️ Setup Instructions

### Step 1: Database Setup

1. **Open your Supabase SQL Editor**
2. **Copy and paste** the contents of `database/waitlist-schema.sql`
3. **Run the script** to create tables and functions
4. **Verify creation** by checking the Tables section in Supabase

```sql
-- The script creates:
-- ✅ waitlist table
-- ✅ user_registrations table  
-- ✅ Indexes for performance
-- ✅ RLS policies for security
-- ✅ Helper functions
```

### Step 2: Environment Configuration

Your existing Supabase configuration will work automatically:

```env
# backend/.env (already configured)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key_here
```

**No additional environment variables needed!**

### Step 3: Verify Integration

1. **Start CobraAI**:
   ```bash
   npm run dev
   ```

2. **Test user registration**:
   - Go to the login page
   - Create a new account with any email
   - Check Supabase tables to see the user data

3. **Check logs**:
   ```
   ✅ User registration saved to database
   🔄 Login tracked in database
   ```

## 📊 Database Tables Structure

### `waitlist` Table
Collects emails before users actually sign up:

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `email` | TEXT | User email (unique) |
| `full_name` | TEXT | Optional full name |
| `source` | TEXT | How they found the app |
| `interest_level` | TEXT | low/medium/high |
| `status` | TEXT | pending/invited/registered/declined |
| `metadata` | JSONB | Additional data (user agent, referrer, etc.) |
| `created_at` | TIMESTAMPTZ | When added to waitlist |
| `updated_at` | TIMESTAMPTZ | Last updated |

### `user_registrations` Table
Tracks full user registration and activity:

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `user_id` | UUID | References auth.users(id) |
| `email` | TEXT | User email (unique) |
| `full_name` | TEXT | Full name if provided |
| `registration_source` | TEXT | How they registered |
| `referrer_url` | TEXT | Where they came from |
| `user_agent` | TEXT | Browser/device info |
| `ip_address` | INET | IP address |
| `account_status` | TEXT | pending/active/suspended/deleted |
| `email_verified` | BOOLEAN | Email verification status |
| `terms_accepted` | BOOLEAN | Terms of service accepted |
| `privacy_accepted` | BOOLEAN | Privacy policy accepted |
| `intended_plan` | TEXT | free/light/pro/enterprise |
| `expected_usage` | TEXT | What they plan to use COBRA for |
| `registered_at` | TIMESTAMPTZ | Registration timestamp |
| `activated_at` | TIMESTAMPTZ | Account activation time |
| `last_login_at` | TIMESTAMPTZ | Last login time |

## 🔍 API Endpoints

### Registration Endpoints

```http
# Save user to database after signup
POST /api/user/register
{
  "userId": "user-uuid-here", 
  "email": "user@example.com",
  "fullName": "John Doe",
  "intendedPlan": "free"
}
```

```http
# Track user login
POST /api/user/login  
{
  "userId": "user-uuid-here",
  "email": "user@example.com"
}
```

### Waitlist Endpoints

```http
# Add to waitlist (for future use)
POST /api/user/waitlist
{
  "email": "user@example.com",
  "fullName": "John Doe", 
  "source": "landing_page",
  "interestLevel": "high"
}
```

### Admin Endpoints

```http
# Get waitlist statistics
GET /api/user/admin/waitlist-stats
# Returns: total_waitlist, pending_count, registered_count, etc.

# Get user registration data  
GET /api/user/registration/:userId

# Health check
GET /api/user/health
```

## 📈 How It Works

### User Signup Flow
1. User creates account through normal signup form
2. **AuthContext** automatically calls `/api/user/register`
3. **UserRegistrationService** saves data to `user_registrations` table
4. If user was on waitlist, status updated to "registered"
5. All happens transparently without affecting UI

### User Login Flow  
1. User logs in through normal login form
2. **AuthContext** automatically calls `/api/user/login`
3. **UserRegistrationService** updates `last_login_at` timestamp
4. Login activity tracked for engagement analysis

### Data Collection
Automatically collected on registration:
- ✅ **Email and name** from signup form
- ✅ **Referrer URL** (where they came from)
- ✅ **User agent** (browser/device info)
- ✅ **IP address** for analytics
- ✅ **Registration source** (signup_form, api, etc.)
- ✅ **Intended plan** (defaults to 'free')

## 🔒 Security & Privacy

### Row Level Security (RLS)
- Users can only access their own data
- Admin functions require proper authentication
- Secure policies prevent data leaks

### Data Protection
- No sensitive passwords stored in custom tables
- All authentication handled by Supabase Auth
- IP addresses stored securely with proper types
- Optional fields for privacy compliance

### Graceful Degradation
- Works without Supabase configuration (demo mode)
- Failed database saves don't block user signup/login
- Clear error logging without exposing sensitive data

## 📊 Analytics & Insights

### Helper Functions Available

```sql
-- Get comprehensive waitlist statistics
SELECT * FROM get_waitlist_stats();

-- Promote user from waitlist to registered
SELECT promote_waitlist_user('user@example.com', 'user-uuid');
```

### Query Examples

```sql
-- Daily signups in last 30 days
SELECT DATE(registered_at) as signup_date, 
       COUNT(*) as signups
FROM user_registrations 
WHERE registered_at >= NOW() - INTERVAL '30 days'
GROUP BY DATE(registered_at)
ORDER BY signup_date;

-- Users by intended plan
SELECT intended_plan, 
       COUNT(*) as user_count,
       ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 2) as percentage
FROM user_registrations 
GROUP BY intended_plan;

-- Registration sources  
SELECT registration_source,
       COUNT(*) as registrations
FROM user_registrations
GROUP BY registration_source
ORDER BY registrations DESC;

-- Active users (logged in last 7 days)
SELECT COUNT(*) as active_users
FROM user_registrations
WHERE last_login_at >= NOW() - INTERVAL '7 days';
```

## 🎯 Benefits

### For Product Validation
- ✅ **Real signup data** to validate demand
- ✅ **User intent tracking** with intended plans
- ✅ **Source attribution** to see what marketing works
- ✅ **Engagement metrics** with login frequency

### For Business Intelligence  
- ✅ **Conversion funnels** from waitlist to signup to usage
- ✅ **User segmentation** by plan intent and usage
- ✅ **Retention analysis** with login patterns
- ✅ **Growth metrics** for investors and stakeholders

### For User Experience
- ✅ **No UI changes** - existing interface preserved
- ✅ **Transparent operation** - users don't see database saves
- ✅ **Fast performance** - async operations don't slow signup
- ✅ **Reliable fallbacks** - works even if database is down

## 🚀 Future Enhancements

This foundation enables:
- **Email marketing campaigns** to registered users
- **User onboarding sequences** based on intended plans  
- **Feature usage tracking** when you add new capabilities
- **Subscription conversion** with existing user data
- **A/B testing** with user segmentation
- **Referral programs** with source tracking

## 🛠️ Troubleshooting

### Common Issues

1. **Users not appearing in database**
   ```bash
   # Check backend logs for registration API calls
   npm run dev
   # Look for: "✅ User registration saved to database"
   ```

2. **Database connection issues**
   ```bash
   # Verify Supabase environment variables
   cat backend/.env | grep SUPABASE
   
   # Test health endpoint
   curl http://localhost:3001/api/user/health
   ```

3. **RLS policy errors**
   ```sql
   -- Temporarily disable RLS for testing
   ALTER TABLE user_registrations DISABLE ROW LEVEL SECURITY;
   
   -- Re-enable after fixing policies
   ALTER TABLE user_registrations ENABLE ROW LEVEL SECURITY;
   ```

### Debug Steps

1. **Check API endpoints**:
   ```bash
   curl -X POST http://localhost:3001/api/user/register \
     -H "Content-Type: application/json" \
     -d '{"userId":"test","email":"test@example.com"}'
   ```

2. **Monitor database**:
   - Open Supabase dashboard
   - Go to Table Editor
   - Watch `user_registrations` table during signups

3. **Review logs**:
   ```bash
   # Backend logs show registration attempts
   # Browser console shows any frontend errors
   ```

---

**🎉 Congratulations!** Your CobraAI now has a complete waitlist and user registration system that automatically validates demand and tracks user engagement. The existing UI remains unchanged while you gather valuable business intelligence in the background.

**Next Steps:**
1. Run the database setup script
2. Test user registration
3. Check your Supabase tables
4. Start analyzing user data to validate your cybersecurity SaaS concept! 