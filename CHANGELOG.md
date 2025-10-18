# Changelog

All notable changes to COBRA AI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added - Latest Updates 🚀
- **Localhost Development Mode** with automatic full access
  - Auto-detection of localhost/development environment
  - Bypass authentication when running locally
  - Unlimited access to all features in development
  - Simple variable switch to enable/disable dev mode
  - Mock developer user for localhost testing
- **Comprehensive User Database** with Supabase integration
  - Complete user management with subscription tracking
  - Automatic developer access for shabblezam@gmail.com
  - Token usage tracking and limits enforcement
  - Subscription history and usage logs
  - Row Level Security (RLS) for data protection
- **Enhanced Access Control System**
  - Real-time subscription checking with developer mode bypass
  - Visual indicators for locked features (🔒)
  - Smart redirection to billing for non-subscribers
  - Back-to-home button on billing page
  - Login-required payment flow for better user management

### Added
- **Professional Landing Page** with pricing tiers and marketing content
  - Lite plan ($29.99/month) - Stage 1 features only
  - Pro plan ($199.99/month) - Stages 1 & 2 features
  - Enterprise plan (custom pricing) - All features
  - Free trial option leading to login page
- **Complete Stripe Billing Integration**
  - Customer creation and management
  - Checkout session handling
  - Subscription management
  - Webhook processing for payment events
  - Customer portal access
- **Free Access Management System**
  - Admin ability to grant unlimited free access to specific users
  - Database-driven access control that overrides paid subscriptions
  - Comprehensive user management for administrators
- **Usage Tracking Service**
  - API call monitoring and limits enforcement
  - Feature-based access control
  - Daily usage tracking per user
- **Admin Management System**
  - User role management (user, admin, analyst)
  - Subscription oversight and statistics
  - Free access grants administration
- **Database Schema Enhancements**
  - Subscription plans table with feature definitions
  - User subscriptions with Stripe integration
  - Free access grants tracking
  - Usage monitoring tables
  - Row Level Security (RLS) policies

### Changed
- **Updated App Routing** - Landing page is now the default route (`/`)
- **Enhanced Authentication** - Proper Supabase token validation in middleware
- **Improved Type Safety** - Fixed all TypeScript compilation errors
- **Updated Dependencies** - Added Stripe SDK and updated API versions

### Fixed
- TypeScript compilation errors in middleware and routes
- Async function return types and error handling
- Stripe API version compatibility
- SVG background pattern parsing in landing page
- Unused import cleanup

### Security
- Enhanced authentication middleware with proper error handling
- Row Level Security policies for billing data
- Admin-only access controls for sensitive operations
- Secure API key handling for Stripe integration

## [Previous Versions]
- AI-powered cybersecurity chat interface
- Multiple LLM provider support (OpenAI, xAI, DeepSeek)
- OSINT capabilities and threat analysis
- Penetration testing tools
- Blue team security scanning
- IOC (Indicators of Compromise) scanner
- Real-time website monitoring
- Attack simulation and brute force testing 