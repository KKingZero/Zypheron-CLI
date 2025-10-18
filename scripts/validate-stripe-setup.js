#!/usr/bin/env node

/**
 * Stripe Setup Validation Script
 * Validates that Stripe is properly configured for the fixed checkout system
 */

require('dotenv').config({ path: require('path').join(__dirname, '../backend/.env') });

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function checkmark() {
  return `${colors.green}✓${colors.reset}`;
}

function crossmark() {
  return `${colors.red}✗${colors.reset}`;
}

function warning() {
  return `${colors.yellow}⚠${colors.reset}`;
}

async function validateStripeSetup() {
  log('\n' + '='.repeat(60), colors.cyan);
  log('  🔍 STRIPE SETUP VALIDATION', colors.cyan);
  log('='.repeat(60) + '\n', colors.cyan);

  let allValid = true;
  const issues = [];
  const warnings = [];

  // Check 1: Stripe Secret Key
  log('1. Checking STRIPE_SECRET_KEY...', colors.blue);
  const stripeSecretKey = process.env.STRIPE_SECRET_KEY;
  
  if (!stripeSecretKey) {
    log(`   ${crossmark()} STRIPE_SECRET_KEY is missing!`, colors.red);
    issues.push('STRIPE_SECRET_KEY environment variable is not set');
    allValid = false;
  } else if (stripeSecretKey === 'your_stripe_secret_key_here') {
    log(`   ${crossmark()} STRIPE_SECRET_KEY is still the placeholder value!`, colors.red);
    issues.push('Replace STRIPE_SECRET_KEY with your actual Stripe secret key');
    allValid = false;
  } else if (stripeSecretKey.startsWith('sk_test_')) {
    log(`   ${checkmark()} STRIPE_SECRET_KEY found (TEST mode)`, colors.green);
    warnings.push('Using TEST mode Stripe key - switch to sk_live_ for production');
  } else if (stripeSecretKey.startsWith('sk_live_')) {
    log(`   ${checkmark()} STRIPE_SECRET_KEY found (LIVE mode)`, colors.green);
  } else {
    log(`   ${warning()} STRIPE_SECRET_KEY format looks unusual`, colors.yellow);
    warnings.push('Stripe secret key should start with sk_test_ or sk_live_');
  }

  // Check 2: Stripe Webhook Secret
  log('\n2. Checking STRIPE_WEBHOOK_SECRET...', colors.blue);
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  
  if (!webhookSecret) {
    log(`   ${crossmark()} STRIPE_WEBHOOK_SECRET is missing!`, colors.red);
    issues.push('STRIPE_WEBHOOK_SECRET environment variable is not set');
    allValid = false;
  } else if (webhookSecret === 'your_stripe_webhook_secret_here') {
    log(`   ${crossmark()} STRIPE_WEBHOOK_SECRET is still the placeholder value!`, colors.red);
    issues.push('Replace STRIPE_WEBHOOK_SECRET with your actual webhook secret');
    allValid = false;
  } else if (webhookSecret.startsWith('whsec_')) {
    log(`   ${checkmark()} STRIPE_WEBHOOK_SECRET found`, colors.green);
  } else {
    log(`   ${warning()} STRIPE_WEBHOOK_SECRET format looks unusual`, colors.yellow);
    warnings.push('Stripe webhook secret should start with whsec_');
  }

  // Check 3: Frontend URL
  log('\n3. Checking FRONTEND_URL...', colors.blue);
  const frontendUrl = process.env.FRONTEND_URL;
  
  if (!frontendUrl) {
    log(`   ${warning()} FRONTEND_URL is missing (will use default)`, colors.yellow);
    warnings.push('Set FRONTEND_URL for proper checkout redirects');
  } else {
    log(`   ${checkmark()} FRONTEND_URL: ${frontendUrl}`, colors.green);
    if (frontendUrl.includes('localhost')) {
      warnings.push('FRONTEND_URL points to localhost - update for production');
    }
  }

  // Check 4: Price IDs
  log('\n4. Checking Stripe Price IDs...', colors.blue);
  const priceIds = {
    'Light Plan': process.env.STRIPE_LITE_PRICE_ID,
    'Pro Plan': process.env.STRIPE_PRO_PRICE_ID,
    'Enterprise Plan': process.env.STRIPE_ENTERPRISE_PRICE_ID
  };

  let priceIdsValid = true;
  for (const [planName, priceId] of Object.entries(priceIds)) {
    if (!priceId) {
      log(`   ${warning()} ${planName}: Not configured`, colors.yellow);
      warnings.push(`Set STRIPE_${planName.toUpperCase().replace(' ', '_')}_PRICE_ID`);
      priceIdsValid = false;
    } else if (priceId.startsWith('cobraai_')) {
      log(`   ${warning()} ${planName}: Still using placeholder (${priceId})`, colors.yellow);
      warnings.push(`Replace ${planName} price ID with actual Stripe price ID`);
      priceIdsValid = false;
    } else if (priceId.startsWith('price_')) {
      log(`   ${checkmark()} ${planName}: ${priceId}`, colors.green);
    } else {
      log(`   ${warning()} ${planName}: Unusual format (${priceId})`, colors.yellow);
      warnings.push(`${planName} price ID should start with price_`);
    }
  }

  // Check 5: Try to initialize Stripe
  log('\n5. Testing Stripe SDK initialization...', colors.blue);
  try {
    const Stripe = require('stripe');
    const stripe = new Stripe(stripeSecretKey, {
      apiVersion: '2025-06-30.basil'
    });
    
    // Try a simple API call
    await stripe.balance.retrieve();
    log(`   ${checkmark()} Stripe SDK initialized successfully!`, colors.green);
    log(`   ${checkmark()} Successfully connected to Stripe API`, colors.green);
  } catch (error) {
    log(`   ${crossmark()} Failed to initialize Stripe SDK`, colors.red);
    log(`   Error: ${error.message}`, colors.red);
    issues.push(`Stripe SDK error: ${error.message}`);
    allValid = false;
  }

  // Check 6: Database configuration
  log('\n6. Checking Supabase configuration...', colors.blue);
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  
  if (!supabaseUrl || !supabaseKey) {
    log(`   ${warning()} Supabase not fully configured`, colors.yellow);
    warnings.push('Supabase is required for subscription management');
  } else {
    log(`   ${checkmark()} Supabase configuration found`, colors.green);
  }

  // Print Summary
  log('\n' + '='.repeat(60), colors.cyan);
  log('  📊 VALIDATION SUMMARY', colors.cyan);
  log('='.repeat(60) + '\n', colors.cyan);

  if (allValid && issues.length === 0) {
    log(`${checkmark()} All critical checks passed!`, colors.green);
    log('✨ Your Stripe integration is properly configured!\n', colors.green);
  } else {
    log(`${crossmark()} Setup has ${issues.length} critical issue(s):\n`, colors.red);
    issues.forEach((issue, i) => {
      log(`   ${i + 1}. ${issue}`, colors.red);
    });
    log('');
  }

  if (warnings.length > 0) {
    log(`${warning()} ${warnings.length} warning(s):\n`, colors.yellow);
    warnings.forEach((warn, i) => {
      log(`   ${i + 1}. ${warn}`, colors.yellow);
    });
    log('');
  }

  // Next Steps
  if (!allValid || warnings.length > 0) {
    log('📝 NEXT STEPS:', colors.blue);
    log('');
    log('1. Fix critical issues first (marked with ✗)', colors.reset);
    log('2. Get your Stripe keys from: https://dashboard.stripe.com/apikeys', colors.reset);
    log('3. Set up webhooks: https://dashboard.stripe.com/webhooks', colors.reset);
    log('4. For local testing, run: stripe listen --forward-to localhost:3001/api/billing/webhook', colors.reset);
    log('5. Update backend/.env with the correct values', colors.reset);
    log('6. Run this script again to verify', colors.reset);
    log('');
  } else {
    log('🚀 READY TO TEST:', colors.blue);
    log('');
    log('1. Start backend: cd backend && npm run dev', colors.reset);
    log('2. Start frontend: cd frontend && npm run dev', colors.reset);
    log('3. For local testing: stripe listen --forward-to localhost:3001/api/billing/webhook', colors.reset);
    log('4. Test subscription flow at: http://localhost:5173/billing', colors.reset);
    log('5. Use test card: 4242 4242 4242 4242', colors.reset);
    log('');
  }

  log('📚 Documentation:', colors.blue);
  log('   - Full setup guide: DUPLICATE_SUBSCRIPTION_FIX.md', colors.reset);
  log('   - Quick start: STRIPE_API_SESSION_QUICK_START.md', colors.reset);
  log('');

  process.exit(allValid && issues.length === 0 ? 0 : 1);
}

// Run validation
validateStripeSetup().catch(error => {
  log(`\n${crossmark()} Validation failed with error:`, colors.red);
  console.error(error);
  process.exit(1);
});

