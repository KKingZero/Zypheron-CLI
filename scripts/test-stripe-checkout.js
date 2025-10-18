#!/usr/bin/env node

/**
 * Stripe Checkout Testing Script
 * Tests the API-generated checkout session flow
 */

require('dotenv').config({ path: require('path').join(__dirname, '../backend/.env') });
const Stripe = require('stripe');

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m'
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

const TEST_USER = {
  email: 'test@example.com',
  userId: 'test-user-123',
  name: 'Test User'
};

const PRICE_IDS = {
  light: process.env.STRIPE_LITE_PRICE_ID || 'price_1RmQkXABd1WNp9IUjNCzVd6q',
  pro: process.env.STRIPE_PRO_PRICE_ID || 'price_1RmQZfABd1WNp9IU3BI5HpAN',
  enterprise: process.env.STRIPE_ENTERPRISE_PRICE_ID || 'price_1RmQQBABd1WNp9IUa8RSXQ9R'
};

async function testStripeCheckout() {
  log('\n' + '='.repeat(70), colors.cyan);
  log('  🧪 STRIPE CHECKOUT SESSION TEST', colors.cyan);
  log('='.repeat(70) + '\n', colors.cyan);

  const stripeSecretKey = process.env.STRIPE_SECRET_KEY;
  
  if (!stripeSecretKey || stripeSecretKey === 'your_stripe_secret_key_here') {
    log('❌ STRIPE_SECRET_KEY not configured!', colors.red);
    log('Please set your Stripe secret key in backend/.env', colors.yellow);
    process.exit(1);
  }

  const stripe = new Stripe(stripeSecretKey, {
    apiVersion: '2025-06-30.basil'
  });

  try {
    // Test 1: Check Stripe Connection
    log('1️⃣  Testing Stripe API connection...', colors.blue);
    const balance = await stripe.balance.retrieve();
    log(`   ✅ Connected to Stripe successfully!`, colors.green);
    log(`   💰 Account balance: $${(balance.available[0]?.amount || 0) / 100}`, colors.green);

    // Test 2: Create or Get Test Customer
    log('\n2️⃣  Creating/retrieving test customer...', colors.blue);
    
    // Check if customer exists
    const existingCustomers = await stripe.customers.list({
      email: TEST_USER.email,
      limit: 1
    });

    let customer;
    if (existingCustomers.data.length > 0) {
      customer = existingCustomers.data[0];
      log(`   ✅ Found existing customer: ${customer.id}`, colors.green);
    } else {
      customer = await stripe.customers.create({
        email: TEST_USER.email,
        name: TEST_USER.name,
        metadata: {
          userId: TEST_USER.userId
        }
      });
      log(`   ✅ Created new customer: ${customer.id}`, colors.green);
    }

    // Test 3: Create Checkout Session for Each Plan
    log('\n3️⃣  Creating checkout sessions for each plan...', colors.blue);

    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    const plans = [
      { name: 'Light', priceId: PRICE_IDS.light, price: '$29.99' },
      { name: 'Pro', priceId: PRICE_IDS.pro, price: '$149.99' },
      { name: 'Enterprise', priceId: PRICE_IDS.enterprise, price: '$999.99' }
    ];

    const sessions = [];

    for (const plan of plans) {
      try {
        const session = await stripe.checkout.sessions.create({
          customer: customer.id,
          payment_method_types: ['card'],
          line_items: [
            {
              price: plan.priceId,
              quantity: 1
            }
          ],
          mode: 'subscription',
          success_url: `${frontendUrl}/billing?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${frontendUrl}/billing?cancelled=true`,
          client_reference_id: TEST_USER.userId,
          metadata: {
            userId: TEST_USER.userId
          },
          subscription_data: {
            metadata: {
              userId: TEST_USER.userId
            }
          },
          allow_promotion_codes: true,
          billing_address_collection: 'auto'
        });

        sessions.push({ plan: plan.name, session });
        log(`   ✅ ${plan.name} Plan (${plan.price}):`, colors.green);
        log(`      Session ID: ${session.id}`, colors.reset);
        log(`      URL: ${session.url}`, colors.cyan);
        log(`      Expires: ${new Date(session.expires_at * 1000).toLocaleString()}`, colors.reset);
      } catch (error) {
        log(`   ❌ ${plan.name} Plan failed: ${error.message}`, colors.red);
      }
    }

    // Test 4: Verify Metadata
    log('\n4️⃣  Verifying userId in metadata...', colors.blue);
    let allHaveUserId = true;
    
    for (const { plan, session } of sessions) {
      const hasUserId = session.metadata?.userId === TEST_USER.userId;
      const hasClientRef = session.client_reference_id === TEST_USER.userId;
      
      if (hasUserId && hasClientRef) {
        log(`   ✅ ${plan}: userId in both metadata and client_reference_id`, colors.green);
      } else if (hasUserId || hasClientRef) {
        log(`   ⚠️  ${plan}: userId only in ${hasUserId ? 'metadata' : 'client_reference_id'}`, colors.yellow);
      } else {
        log(`   ❌ ${plan}: userId missing!`, colors.red);
        allHaveUserId = false;
      }
    }

    // Test 5: Check Webhook Configuration
    log('\n5️⃣  Checking webhook endpoints...', colors.blue);
    const webhooks = await stripe.webhookEndpoints.list({ limit: 10 });
    
    if (webhooks.data.length === 0) {
      log(`   ⚠️  No webhook endpoints configured`, colors.yellow);
      log(`   📝 Set up webhook at: https://dashboard.stripe.com/webhooks`, colors.yellow);
    } else {
      log(`   ✅ Found ${webhooks.data.length} webhook endpoint(s):`, colors.green);
      webhooks.data.forEach((webhook, i) => {
        log(`      ${i + 1}. ${webhook.url}`, colors.reset);
        log(`         Status: ${webhook.status}`, colors.reset);
        log(`         Events: ${webhook.enabled_events.length}`, colors.reset);
      });
    }

    // Summary
    log('\n' + '='.repeat(70), colors.cyan);
    log('  📊 TEST SUMMARY', colors.cyan);
    log('='.repeat(70) + '\n', colors.cyan);

    if (sessions.length === 3 && allHaveUserId) {
      log('✅ All tests passed!', colors.green);
      log('', colors.reset);
      log('Your Stripe checkout integration is working correctly!', colors.green);
      log('', colors.reset);
      log('🧪 TO TEST THE FULL FLOW:', colors.blue);
      log('', colors.reset);
      log('1. Start your backend: cd backend && npm run dev', colors.reset);
      log('2. Start your frontend: cd frontend && npm run dev', colors.reset);
      log('3. For local webhooks: stripe listen --forward-to localhost:3001/api/billing/webhook', colors.reset);
      log('4. Open: http://localhost:5173/billing', colors.reset);
      log('5. Click a plan button', colors.reset);
      log('6. Use test card: 4242 4242 4242 4242', colors.reset);
      log('7. Any future expiry, any CVC', colors.reset);
      log('', colors.reset);
      log('📝 TEST CARDS:', colors.blue);
      log('   Success: 4242 4242 4242 4242', colors.green);
      log('   3D Secure: 4000 0027 6000 3184', colors.yellow);
      log('   Declined: 4000 0000 0000 0002', colors.red);
      log('', colors.reset);
    } else {
      log('⚠️  Some tests had issues', colors.yellow);
      log('Please check the logs above for details', colors.yellow);
    }

    log('📚 More info:', colors.blue);
    log('   - Full documentation: STRIPE_API_SESSION_QUICK_START.md', colors.reset);
    log('   - Fix details: DUPLICATE_SUBSCRIPTION_FIX.md', colors.reset);
    log('', colors.reset);

  } catch (error) {
    log('\n❌ Test failed with error:', colors.red);
    console.error(error);
    log('\n💡 Common issues:', colors.yellow);
    log('   1. Invalid Stripe secret key', colors.reset);
    log('   2. Network connection issues', colors.reset);
    log('   3. Invalid price IDs', colors.reset);
    log('', colors.reset);
    process.exit(1);
  }
}

// Run tests
testStripeCheckout().catch(error => {
  console.error('Test failed:', error);
  process.exit(1);
});

