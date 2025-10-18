import express from 'express'
import { supabase } from '../server'
import { billingService, stripe } from '../services/stripe'
import { enhancedAuthMiddleware } from '../middleware/rbac'
import { emailService } from '../services/email'

const router = express.Router()

// GET /api/billing/plans - Get available subscription plans
router.get('/plans', async (req: express.Request, res: express.Response) => {
  try {
    if (!supabase) {
      return res.json({ plans: [] })
    }
    const { data: plans, error } = await supabase
      .from('subscription_plans')
      .select('*')
      .eq('is_active', true)
      .order('price_monthly', { ascending: true })

    if (error) throw error

    return res.json({ plans })
  } catch (error) {
    console.error('Get Plans Error:', error)
    return res.status(500).json({
      error: 'Failed to fetch subscription plans'
    })
  }
})

// GET /api/billing/subscription - Get user's current subscription
router.get('/subscription', enhancedAuthMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    const userId = req.user?.id
    const userEmail = req.user?.email
    const userRole = req.userRole

    if (!supabase) {
      return res.json({
        subscription: null,
        accessLevel: {
          has_access: true,
          plan_name: 'Developer',
          is_developer: true,
          is_free_grant: true,
          features: { all_tools: true },
          limits: { api_calls: -1, scans: -1, tokens_total: -1, tokens_used: 0, tokens_remaining: -1 }
        }
      })
    }

    // Admin dev gets full access
    if (userRole?.role === 'admin_dev') {
      return res.json({
        subscription: {
          id: userId,
          user_id: userId,
          status: 'active',
          subscription_id: 'admin-dev-override',
          customer_id: 'admin-dev-customer',
          plan_name: 'Admin Developer'
        },
        accessLevel: {
          has_access: true,
          plan_name: 'Admin Developer',
          is_developer: true,
          is_admin_dev: true,
          is_free_grant: false,
          features: { 
            all_tools: true, 
            unlimited_access: true,
            debug_mode: true,
            priority_support: true,
            custom_integrations: true,
            admin_panel: true,
            user_management: true,
            security_bypass: true,
            extended_sessions: true
          },
          limits: { 
            api_calls: -1, 
            scans: -1,
            tokens_total: -1,
            tokens_used: 0,
            tokens_remaining: -1
          }
        }
      });
    }

    // Get user access level from our RBAC function
    const { data: accessData, error: accessError } = await supabase
      .rpc('get_user_access_level', { user_uuid: userId })

    if (accessError) throw accessError

    // Get user details from the users table
    const { data: userDetails, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('id', userId)
      .single()

    if (userError) throw userError

    // Convert RBAC permissions to billing access level format
    const rbacAccess = accessData?.[0]
    const accessLevel = {
      has_access: rbacAccess?.has_access || false,
      plan_name: rbacAccess?.plan_name || 'Free',
      is_developer: userDetails?.developer_access || false,
      is_admin_dev: userRole?.role === 'admin_dev',
      is_free_grant: rbacAccess?.is_free_grant || false,
      features: {
        ...rbacAccess?.features,
        // Map RBAC features to billing features
        all_tools: rbacAccess?.features?.all_features || false,
        unlimited_access: userRole?.has_unlimited_tokens || false,
        debug_mode: rbacAccess?.features?.debug_mode || false,
        priority_support: rbacAccess?.features?.priority_support || false,
        admin_panel: rbacAccess?.features?.admin_panel || false,
        user_management: rbacAccess?.features?.user_management || false,
        advanced_pentest: rbacAccess?.features?.advanced_pentest || false,
        premium_osint: rbacAccess?.features?.premium_osint || false
      },
      limits: {
        api_calls: userRole?.has_unlimited_tokens ? -1 : 1000,
        scans: userRole?.has_unlimited_tokens ? -1 : 100,
        tokens_total: rbacAccess?.limits?.tokens_total || 0,
        tokens_used: rbacAccess?.limits?.tokens_used || 0,
        tokens_remaining: rbacAccess?.limits?.tokens_remaining || 0
      },
      // Include RBAC specific data
      rbac_role: userRole?.role,
      can_bypass_mfa: userRole?.can_bypass_mfa,
      can_extend_session: userRole?.can_extend_session,
      max_session_hours: userRole?.max_session_duration_hours
    }

    // Format subscription data for frontend compatibility
    const subscription = userDetails ? {
      id: userDetails.id,
      user_id: userDetails.id,
      status: userDetails.subscription_status,
      subscription_id: userDetails.subscription_id,
      customer_id: userDetails.customer_id,
      subscription_start_date: userDetails.subscription_start_date,
      subscription_end_date: userDetails.subscription_end_date,
      cancel_at_period_end: userDetails.subscription_cancel_at_period_end,
      created_at: userDetails.created_at,
      updated_at: userDetails.updated_at,
      plan_name: accessLevel.plan_name
    } : null

    return res.json({
      subscription,
      accessLevel
    })
  } catch (error) {
    console.error('Get Subscription Error:', error)
    return res.status(500).json({
      error: 'Failed to fetch subscription'
    })
  }
})

// POST /api/billing/checkout - Create checkout session
router.post('/checkout', enhancedAuthMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    if (!billingService || !stripe) {
      return res.status(503).json({ error: 'Billing is not configured' })
    }
    const { priceId } = req.body
    const user = req.user

    if (!priceId) {
      return res.status(400).json({ error: 'Price ID is required' })
    }

    // Check if user already has an active subscription to prevent duplicates
    if (supabase && user?.id) {
      const { data: existingSubscriptions } = await supabase
        .from('user_subscriptions')
        .select('stripe_subscription_id, status')
        .eq('user_id', user.id)
        .in('status', ['active', 'trialing'])
      
      if (existingSubscriptions && existingSubscriptions.length > 0) {
        console.warn(`⚠️ User ${user.id} (${user.email}) attempted to create duplicate subscription`)
        console.warn(`   Existing subscriptions: ${existingSubscriptions.map(s => s.stripe_subscription_id).join(', ')}`)
        
        return res.status(400).json({ 
          error: 'You already have an active subscription. Please manage your existing subscription from the customer portal.',
          existingSubscriptions: existingSubscriptions.map(s => s.stripe_subscription_id)
        })
      }
    }

    // Create or get Stripe customer
    const customer = await billingService.createOrGetCustomer(
      user?.email || '',
      user?.id || '',
      user?.user_metadata?.full_name
    )

    if (!customer) {
      return res.status(500).json({ error: 'Failed to create customer' })
    }

    console.log(`✅ Creating checkout session for user ${user?.id} (${user?.email})`)
    console.log(`   Customer ID: ${customer.id}`)
    console.log(`   Price ID: ${priceId}`)

    // Create checkout session
    const session = await billingService.createCheckoutSession(
      customer.id,
      priceId,
      `${process.env.FRONTEND_URL || 'http://localhost:5173'}/billing?session_id={CHECKOUT_SESSION_ID}`,
      `${process.env.FRONTEND_URL || 'http://localhost:5173'}/billing?cancelled=true`,
      user?.id || ''
    )

    console.log(`✅ Checkout session created: ${session.id}`)

    return res.json({ sessionId: session.id, url: session.url })
  } catch (error) {
    console.error('Checkout Error:', error)
    return res.status(500).json({
      error: 'Failed to create checkout session'
    })
  }
})

// POST /api/billing/portal - Create customer portal session
router.post('/portal', enhancedAuthMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    if (!supabase || !billingService || !stripe) {
      return res.status(503).json({ error: 'Billing is not configured' })
    }
    const userId = req.user?.id

    // Get user's Stripe customer ID
    const { data: subscription } = await supabase
      .from('user_subscriptions')
      .select('stripe_customer_id')
      .eq('user_id', userId)
      .limit(1)
      .maybeSingle()

    if (!subscription?.stripe_customer_id) {
      return res.status(400).json({ error: 'No subscription found' })
    }

    const session = await billingService.createPortalSession(
      subscription.stripe_customer_id,
      `${process.env.FRONTEND_URL}/billing`
    )

    return res.json({ url: session.url })
  } catch (error) {
    console.error('Portal Error:', error)
    return res.status(500).json({
      error: 'Failed to create portal session'
    })
  }
})

// POST /api/billing/cancel-subscription - Cancel user's subscription
router.post('/cancel-subscription', enhancedAuthMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    if (!supabase || !billingService || !stripe) {
      return res.status(503).json({ error: 'Billing is not configured' })
    }

    const userId = req.user?.id
    const { subscriptionId } = req.body

    if (!subscriptionId) {
      return res.status(400).json({ error: 'Subscription ID is required' })
    }

    // Verify this subscription belongs to the user
    const { data: subscription } = await supabase
      .from('user_subscriptions')
      .select('*')
      .eq('user_id', userId)
      .eq('stripe_subscription_id', subscriptionId)
      .single()

    if (!subscription) {
      return res.status(404).json({ error: 'Subscription not found' })
    }

    // Cancel subscription in Stripe (cancel at period end)
    const cancelledSubscription = await billingService.cancelSubscription(subscriptionId)

    // Update subscription in database
    await supabase
      .from('user_subscriptions')
      .update({ 
        cancel_at_period_end: true,
        updated_at: new Date().toISOString()
      })
      .eq('stripe_subscription_id', subscriptionId)

    console.log(`✅ Subscription ${subscriptionId} cancelled for user ${userId}`)

    return res.json({ 
      success: true, 
      subscription: cancelledSubscription,
      message: 'Subscription cancelled successfully. You will have access until the end of your billing period.'
    })

  } catch (error) {
    console.error('Cancel subscription error:', error)
    return res.status(500).json({
      error: 'Failed to cancel subscription'
    })
  }
})

// GET /api/billing/success - Handle successful checkout session
router.get('/success', async (req: express.Request, res: express.Response) => {
  try {
    const sessionId = req.query.session_id as string
    
    if (!sessionId) {
      return res.redirect(`${process.env.FRONTEND_URL}/billing?error=missing_session`)
    }

    if (!stripe) {
      return res.redirect(`${process.env.FRONTEND_URL}/billing?error=stripe_not_configured`)
    }

    // Retrieve the checkout session
    const session = await stripe.checkout.sessions.retrieve(sessionId)
    
    if (!session) {
      return res.redirect(`${process.env.FRONTEND_URL}/billing?error=session_not_found`)
    }

    // Get customer and subscription details
    const customerId = session.customer as string
    const subscriptionId = session.subscription as string
    
    // Log successful checkout
    console.log(`✅ Checkout success: Session ${sessionId}, Customer ${customerId}, Subscription ${subscriptionId}`)

    // Redirect to billing page with success message
    const redirectUrl = `${process.env.FRONTEND_URL}/billing?success=true&session_id=${sessionId}`
    res.redirect(redirectUrl)
    
  } catch (error) {
    console.error('Checkout success error:', error)
    res.redirect(`${process.env.FRONTEND_URL}/billing?error=checkout_error`)
  }
})

// GET /api/billing/cancel - Handle cancelled checkout session
router.get('/cancel', async (req: express.Request, res: express.Response) => {
  try {
    const sessionId = req.query.session_id as string
    
    // Log cancelled checkout
    console.log(`❌ Checkout cancelled: Session ${sessionId}`)

    // Redirect to billing page with cancel message
    const redirectUrl = `${process.env.FRONTEND_URL}/billing?cancelled=true`
    res.redirect(redirectUrl)
    
  } catch (error) {
    console.error('Checkout cancel error:', error)
    res.redirect(`${process.env.FRONTEND_URL}/billing?error=cancel_error`)
  }
})

// POST /api/billing/verify-access - Verify user access after signup/payment
router.post('/verify-access', enhancedAuthMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    if (!supabase) {
      return res.status(503).json({ error: 'Database not configured' })
    }

    const userId = req.user?.id
    const userEmail = req.user?.email

    if (!userId || !userEmail) {
      return res.status(401).json({ error: 'User not authenticated' })
    }

    // Verify user access using the database function
    const { data: accessVerification, error: verificationError } = await supabase
      .rpc('verify_user_payment_access', { user_email: userEmail })

    if (verificationError) {
      console.error('Access verification error:', verificationError)
      return res.status(500).json({ error: 'Failed to verify access' })
    }

    // Get detailed user information
    const { data: userDetails, error: userError } = await supabase
      .from('users')
      .select(`
        id,
        email,
        subscription_status,
        developer_access,
        role,
        tokens_limit,
        tokens_used,
        is_active
      `)
      .eq('id', userId)
      .single()

    if (userError) {
      console.error('Failed to fetch user details:', userError)
      return res.status(500).json({ error: 'Failed to fetch user details' })
    }

    // Get subscription details if available
    const { data: subscriptionDetails } = await supabase
      .from('user_subscriptions')
      .select('*')
      .eq('user_id', userId)
      .single()

    const accessResult = accessVerification?.[0] || {}
    
    console.log(`🔍 Access verification for ${userEmail}:`, {
      hasAccess: accessResult.has_access,
      subscriptionStatus: accessResult.subscription_status,
      isDeveloper: accessResult.is_developer,
      accessLevel: accessResult.access_level
    })

    return res.json({
      success: true,
      verification: accessResult,
      userDetails,
      subscriptionDetails,
      message: accessResult.has_access 
        ? 'User has valid access' 
        : 'User needs to subscribe for access'
    })

  } catch (error) {
    console.error('Verify access error:', error)
    return res.status(500).json({
      error: 'Internal server error during access verification'
    })
  }
})

// POST /api/billing/webhook - Stripe webhook handler
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature']
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET

  if (!sig || !webhookSecret || !stripe) {
    console.error('Webhook signature verification failed - missing signature or secret')
    res.status(400).send('Webhook signature verification failed.')
    return
  }

  let event: any

  try {
    // Verify the webhook signature
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret)
    console.log(`✅ Received webhook: ${event.type} (${event.id})`)
  } catch (error) {
    console.error(`❌ Webhook signature verification failed:`, error)
    return res.status(400).send(`Webhook Error: ${error}`)
  }

  // Handle idempotency - check if we've already processed this event
  const processedEvents = await getProcessedEvents()
  if (processedEvents.has(event.id)) {
    console.log(`⚠️ Event ${event.id} already processed, returning success`)
    return res.json({ received: true })
  }

  try {
    // Process the event based on type
    switch (event.type) {
      // Subscription events
      case 'customer.subscription.created':
        console.log('📝 Processing subscription created')
        await handleSubscriptionChange(event.data.object as any)
        await logSubscriptionHistory(event.data.object, 'created')
        break
        
      case 'customer.subscription.updated':
        console.log('📝 Processing subscription updated')
        await handleSubscriptionChange(event.data.object as any)
        await logSubscriptionHistory(event.data.object, 'updated')
        break
      
      case 'customer.subscription.deleted':
        console.log('📝 Processing subscription deleted')
        await handleSubscriptionCanceled(event.data.object as any)
        await logSubscriptionHistory(event.data.object, 'deleted')
        break

      // Payment events (for one-time payments and subscription renewals)
      case 'payment_intent.succeeded':
        console.log('💳 Processing payment intent succeeded')
        await handlePaymentSucceeded(event.data.object as any)
        break

      case 'payment_intent.payment_failed':
        console.log('❌ Processing payment intent failed')
        await handlePaymentIntentFailed(event.data.object as any)
        break

      // Checkout session events (for buy button flows)
      case 'checkout.session.completed':
        console.log('🛒 Processing checkout session completed')
        await handleCheckoutCompleted(event.data.object as any)
        break

      case 'checkout.session.expired':
        console.log('⏰ Processing checkout session expired')
        await handleCheckoutExpired(event.data.object as any)
        break

      // Invoice events
      case 'invoice.payment_succeeded':
        console.log('💰 Processing invoice payment succeeded')
        await handleInvoicePaymentSucceeded(event.data.object as any)
        break
        
      case 'invoice.payment_failed':
        console.log('❌ Processing invoice payment failed')
        await handlePaymentFailed(event.data.object as any)
        break

      case 'invoice.payment_action_required':
        console.log('⚠️ Processing invoice payment action required')
        await handlePaymentActionRequired(event.data.object as any)
        break

      // Customer events
      case 'customer.created':
        console.log('👤 Processing customer created')
        await handleCustomerCreated(event.data.object as any)
        break

      case 'customer.updated':
        console.log('👤 Processing customer updated')
        await handleCustomerUpdated(event.data.object as any)
        break

      // Trial events
      case 'customer.subscription.trial_will_end':
        console.log('⏰ Processing trial will end')
        await handleTrialWillEnd(event.data.object as any)
        break

      default:
        console.log(`ℹ️ Unhandled event type: ${event.type}`)
        // Still return success for unhandled events to prevent retries
    }

    // Mark event as processed
    await markEventProcessed(event.id)
    
    // Return success response
    console.log(`✅ Successfully processed webhook: ${event.type} (${event.id})`)
    res.json({ received: true, event_id: event.id, event_type: event.type })

  } catch (error) {
    console.error(`❌ Error processing webhook ${event.type} (${event.id}):`, error)
    
    // Log the error for monitoring
    await logWebhookError(event.id, event.type, error)
    
    // Return error status to trigger Stripe's retry mechanism
    res.status(500).send(`Webhook processing error: ${error}`)
  }
})

// Webhook handlers
async function handleSubscriptionChange(subscription: any) {
  const customerId = subscription.customer as string
  let userId = subscription.metadata?.userId

  if (!userId) {
    console.warn('⚠️ No userId in subscription metadata, attempting recovery...')
    
    try {
      // Try to recover userId from customer email
      if (!stripe) {
        console.error('Stripe not initialized')
        return
      }
      
      const customer = await stripe.customers.retrieve(customerId) as any
      
      if (customer.email && supabase) {
        console.log(`🔍 Looking up user by email: ${customer.email}`)
        
        // Try to find user in users table
        const { data: userData, error: userError } = await supabase
          .from('users')
          .select('id')
          .eq('email', customer.email)
          .single()
        
        if (userData && !userError) {
          userId = userData.id
          console.log(`✅ Recovered userId: ${userId} for email: ${customer.email}`)
          
          // Update subscription metadata in Stripe for future webhooks
          await stripe.subscriptions.update(subscription.id, {
            metadata: { userId: userData.id }
          })
          console.log(`✅ Updated subscription metadata with userId`)
        } else {
          // Try profiles table as fallback
          const { data: profileData } = await supabase
            .from('profiles')
            .select('id')
            .eq('email', customer.email)
            .single()
          
          if (profileData) {
            userId = profileData.id
            console.log(`✅ Recovered userId from profiles: ${userId}`)
            
            await stripe.subscriptions.update(subscription.id, {
              metadata: { userId: profileData.id }
            })
          }
        }
      }
    } catch (recoveryError) {
      console.error('❌ Failed to recover userId:', recoveryError)
    }
    
    if (!userId) {
      console.error('❌ Could not recover userId for subscription:', subscription.id)
      console.error('   Customer ID:', customerId)
      console.error('   Subscription will not be activated in database')
      // Log to admin monitoring system
      await logWebhookError(subscription.id, 'subscription.created', new Error('Missing userId and recovery failed'))
      return
    }
  }

  // Check for existing active subscriptions to prevent duplicates
  if (supabase) {
    const { data: existingSubscriptions } = await supabase
      .from('user_subscriptions')
      .select('stripe_subscription_id, status')
      .eq('user_id', userId)
      .in('status', ['active', 'trialing'])
    
    if (existingSubscriptions && existingSubscriptions.length > 0) {
      const existingSubIds = existingSubscriptions.map(s => s.stripe_subscription_id)
      
      // If this subscription is not in the existing list and user already has active subs
      if (!existingSubIds.includes(subscription.id)) {
        console.warn(`⚠️ User ${userId} already has ${existingSubscriptions.length} active subscription(s)`)
        console.warn(`   Existing: ${existingSubIds.join(', ')}`)
        console.warn(`   New: ${subscription.id}`)
        console.warn(`   This may be a duplicate subscription!`)
        
        // Log duplicate subscription attempt
        await supabase
          .from('subscription_history')
          .insert({
            user_id: userId,
            subscription_status: 'duplicate_detected',
            stripe_subscription_id: subscription.id,
            change_reason: 'Duplicate subscription detected',
            metadata: {
              existing_subscriptions: existingSubIds,
              new_subscription: subscription.id,
              timestamp: new Date().toISOString()
            }
          })
      }
    }
  }

  // Get plan details from Stripe price
  const priceId = subscription.items.data[0]?.price.id
  
  // Map Stripe price IDs to plan names
  // Light: https://buy.stripe.com/bJebJ0chi0hlf1JdO2dAk02
  // Pro: https://buy.stripe.com/28EbJ02GId47bPx9xMdAk01  
  // Enterprise/Super: https://buy.stripe.com/4gMdR8epq9RVdXFaBQdAk00
  const planMapping: Record<string, string> = {
    'price_1RmQkXABd1WNp9IUjNCzVd6q': 'light',
    'price_1RmQZfABd1WNp9IU3BI5HpAN': 'pro', 
    'price_1RmQQBABd1WNp9IUa8RSXQ9R': 'enterprise',
    // Add support for super plan (alias for enterprise)
    'price_super': 'super'
  }
  
  const planName = planMapping[priceId] || 'light'
  
  console.log(`🔄 Processing subscription change: ${subscription.id} -> Plan: ${planName}, Status: ${subscription.status}`)

  // Get plan details from database
  const { data: plan } = await supabase
    .from('subscription_plans')
    .select('*')
    .eq('stripe_price_id', priceId)
    .single()

  // Upsert subscription (will update if user_id already exists due to UNIQUE constraint)
  await supabase
    .from('user_subscriptions')
    .upsert({
      user_id: userId,
      plan_id: plan?.id,
      stripe_customer_id: customerId,
      stripe_subscription_id: subscription.id,
      status: subscription.status,
      current_period_start: new Date(subscription.current_period_start * 1000).toISOString(),
      current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
      cancel_at_period_end: subscription.cancel_at_period_end,
      trial_end: subscription.trial_end ? new Date(subscription.trial_end * 1000).toISOString() : null
    }, {
      onConflict: 'user_id'
    })

  // Use the new activation function for better user access handling
  if (subscription.status === 'active' || subscription.status === 'trialing') {
    const { data: activationResult, error: activationError } = await supabase
      .rpc('activate_user_subscription', {
        user_uuid: userId,
        plan_name: planName,
        stripe_subscription_id: subscription.id,
        stripe_customer_id: customerId
      })

    if (activationError) {
      console.error('❌ Failed to activate user subscription:', activationError)
    } else {
      console.log(`✅ User ${userId} successfully activated with ${planName} plan`)
    }
  }

  // Update profile subscription status
  await supabase
    .from('profiles')
    .update({ subscription_status: subscription.status })
    .eq('id', userId)
}

async function handleSubscriptionCanceled(subscription: any) {
  await supabase
    .from('user_subscriptions')
    .update({ 
      status: 'canceled',
      cancel_at_period_end: true
    })
    .eq('stripe_subscription_id', subscription.id)

  // Update profile
  const userId = subscription.metadata.userId
  if (userId) {
    await supabase
      .from('profiles')
      .update({ subscription_status: 'canceled' })
      .eq('id', userId)
  }
}

async function handlePaymentFailed(invoice: any) {
  const subscriptionId = invoice.subscription as string
  
  await supabase
    .from('user_subscriptions')
    .update({ status: 'past_due' })
    .eq('stripe_subscription_id', subscriptionId)
}

// New webhook handlers for comprehensive payment processing

// Handle successful payment intents (one-time payments)
async function handlePaymentSucceeded(paymentIntent: any) {
  try {
    console.log(`💳 Payment succeeded: ${paymentIntent.id}`)
    
    // Extract user/order info from metadata
    const userId = paymentIntent.metadata?.user_id
    const orderId = paymentIntent.metadata?.order_id
    const planName = paymentIntent.metadata?.plan_name
    
    if (!userId) {
      console.warn('No user_id in payment intent metadata')
      return
    }

    // Update user payment status if this is for a subscription
    if (planName) {
      await supabase
        .from('users')
        .update({
          subscription_status: planName.toLowerCase(),
          subscription_start_date: new Date().toISOString(),
          customer_id: paymentIntent.customer
        })
        .eq('id', userId)
    }

    // Log payment success
    await logPaymentEvent(userId, paymentIntent.id, 'payment_succeeded', {
      amount: paymentIntent.amount,
      currency: paymentIntent.currency,
      payment_method: paymentIntent.payment_method,
      plan_name: planName
    })

    // Send confirmation email
    await emailService.sendPaymentConfirmation(userId, paymentIntent)
    
    console.log(`✅ Payment processing completed for user ${userId}`)
    
  } catch (error) {
    console.error('Error processing payment success:', error)
    throw error
  }
}

// Handle failed payment intents
async function handlePaymentIntentFailed(paymentIntent: any) {
  try {
    console.log(`❌ Payment failed: ${paymentIntent.id}`)
    
    const userId = paymentIntent.metadata?.user_id
    
    if (userId) {
      await logPaymentEvent(userId, paymentIntent.id, 'payment_failed', {
        amount: paymentIntent.amount,
        currency: paymentIntent.currency,
        last_payment_error: paymentIntent.last_payment_error
      })

      // Send payment failure notification
      await emailService.sendPaymentFailure(userId, paymentIntent)
    }
    
  } catch (error) {
    console.error('Error processing payment failure:', error)
    throw error
  }
}

// Handle completed checkout sessions (buy button flows)
async function handleCheckoutCompleted(session: any) {
  try {
    console.log(`🛒 Checkout completed: ${session.id}`)
    
    const customerId = session.customer
    const userId = session.metadata?.userId || session.client_reference_id
    
    if (!userId) {
      console.warn('No userId in checkout session metadata')
      return
    }

    // Get user email for verification
    const { data: userData } = await supabase
      .from('users')
      .select('email')
      .eq('id', userId)
      .single()

    console.log(`👤 Processing checkout for user: ${userData?.email || 'unknown'} (${userId})`)

    // Get subscription if this was a subscription checkout
    if (session.mode === 'subscription' && session.subscription) {
      const subscription = await stripe?.subscriptions.retrieve(session.subscription as string)
      if (subscription) {
        console.log(`📋 Processing subscription: ${subscription.id} with status: ${subscription.status}`)
        await handleSubscriptionChange(subscription)
        
        // Additional verification for successful subscriptions
        if (subscription.status === 'active' || subscription.status === 'trialing') {
          console.log(`✅ Subscription active, verifying user access for ${userData?.email}`)
          
          // Verify the user has proper access
          if (userData?.email) {
            const { data: accessVerification } = await supabase
              .rpc('verify_user_payment_access', { user_email: userData.email })
              
            console.log(`🔍 Access verification result:`, accessVerification)
          }
        }
      }
    }

    // Update customer info
    await supabase
      .from('users')
      .update({
        customer_id: customerId,
        updated_at: new Date().toISOString()
      })
      .eq('id', userId)

    // Log checkout completion with enhanced data
    await logPaymentEvent(userId, session.id, 'checkout_completed', {
      amount_total: session.amount_total,
      currency: session.currency,
      payment_status: session.payment_status,
      mode: session.mode,
      customer_id: customerId,
      user_email: userData?.email,
      subscription_id: session.subscription,
      checkout_session_url: session.url
    })

    console.log(`✅ Checkout processing completed for user ${userId} (${userData?.email})`)
    
  } catch (error) {
    console.error('Error processing checkout completion:', error)
    throw error
  }
}

// Handle expired checkout sessions
async function handleCheckoutExpired(session: any) {
  try {
    console.log(`⏰ Checkout expired: ${session.id}`)
    
    const userId = session.metadata?.userId || session.client_reference_id
    
    if (userId) {
      await logPaymentEvent(userId, session.id, 'checkout_expired', {
        amount_total: session.amount_total,
        currency: session.currency
      })
    }
    
  } catch (error) {
    console.error('Error processing checkout expiration:', error)
    throw error
  }
}

// Handle successful invoice payments
async function handleInvoicePaymentSucceeded(invoice: any) {
  try {
    console.log(`💰 Invoice payment succeeded: ${invoice.id}`)
    
    const subscriptionId = invoice.subscription
    const customerId = invoice.customer
    
    // Update subscription status if needed
    if (subscriptionId) {
      await supabase
        .from('user_subscriptions')
        .update({ 
          status: 'active',
          updated_at: new Date().toISOString()
        })
        .eq('stripe_subscription_id', subscriptionId)
    }

    // Log invoice payment
    const { data: userSub } = await supabase
      .from('user_subscriptions')
      .select('user_id')
      .eq('stripe_customer_id', customerId)
      .single()

    if (userSub?.user_id) {
      await logPaymentEvent(userSub.user_id, invoice.id, 'invoice_payment_succeeded', {
        amount_paid: invoice.amount_paid,
        currency: invoice.currency,
        subscription_id: subscriptionId
      })
    }
    
  } catch (error) {
    console.error('Error processing invoice payment success:', error)
    throw error
  }
}

// Handle payment action required
async function handlePaymentActionRequired(invoice: any) {
  try {
    console.log(`⚠️ Payment action required: ${invoice.id}`)
    
    const subscriptionId = invoice.subscription
    const customerId = invoice.customer
    
    // Get user info
    const { data: userSub } = await supabase
      .from('user_subscriptions')
      .select('user_id')
      .eq('stripe_customer_id', customerId)
      .single()

    if (userSub?.user_id) {
      await logPaymentEvent(userSub.user_id, invoice.id, 'payment_action_required', {
        amount_due: invoice.amount_due,
        currency: invoice.currency,
        hosted_invoice_url: invoice.hosted_invoice_url
      })

      // Send action required email
      await emailService.sendPaymentActionRequired(userSub.user_id, invoice)
    }
    
  } catch (error) {
    console.error('Error processing payment action required:', error)
    throw error
  }
}

// Handle customer created
async function handleCustomerCreated(customer: any) {
  try {
    console.log(`👤 Customer created: ${customer.id}`)
    
    const userId = customer.metadata?.userId
    
    if (userId) {
      await supabase
        .from('users')
        .update({
          customer_id: customer.id
        })
        .eq('id', userId)
    }
    
  } catch (error) {
    console.error('Error processing customer creation:', error)
    throw error
  }
}

// Handle customer updated
async function handleCustomerUpdated(customer: any) {
  try {
    console.log(`👤 Customer updated: ${customer.id}`)
    
    // Update customer information if needed
    const userId = customer.metadata?.userId
    
    if (userId) {
      // Update any customer-specific data
      await supabase
        .from('users')
        .update({
          updated_at: new Date().toISOString()
        })
        .eq('customer_id', customer.id)
    }
    
  } catch (error) {
    console.error('Error processing customer update:', error)
    throw error
  }
}

// Handle trial will end
async function handleTrialWillEnd(subscription: any) {
  try {
    console.log(`⏰ Trial will end: ${subscription.id}`)
    
    const userId = subscription.metadata?.userId
    
    if (userId) {
      await logPaymentEvent(userId, subscription.id, 'trial_will_end', {
        trial_end: new Date(subscription.trial_end * 1000).toISOString(),
        plan_id: subscription.items.data[0]?.price.id
      })

      // Send trial ending email
      await emailService.sendTrialEnding(userId, subscription)
    }
    
  } catch (error) {
    console.error('Error processing trial will end:', error)
    throw error
  }
}

// Helper functions for webhook processing

// In-memory cache for processed events (in production, use Redis or database)
const processedEventsCache = new Set<string>()

async function getProcessedEvents(): Promise<Set<string>> {
  // In production, this should query a database or Redis
  // For now, using in-memory cache
  return processedEventsCache
}

async function markEventProcessed(eventId: string): Promise<void> {
  // In production, this should store in database or Redis
  processedEventsCache.add(eventId)
  
  // Optional: Clean up old events periodically
  if (processedEventsCache.size > 10000) {
    // Keep only the most recent 5000 events
    const events = Array.from(processedEventsCache)
    processedEventsCache.clear()
    events.slice(-5000).forEach(id => processedEventsCache.add(id))
  }
}

// Log subscription history
async function logSubscriptionHistory(subscription: any, action: string) {
  try {
    const userId = subscription.metadata?.userId
    
    if (!userId || !supabase) return
    
    await supabase
      .from('subscription_history')
      .insert({
        user_id: userId,
        subscription_status: subscription.status,
        stripe_subscription_id: subscription.id,
        stripe_customer_id: subscription.customer,
        change_reason: action,
        metadata: {
          action,
          current_period_start: subscription.current_period_start,
          current_period_end: subscription.current_period_end,
          trial_end: subscription.trial_end,
          cancel_at_period_end: subscription.cancel_at_period_end
        }
      })
  } catch (error) {
    console.error('Error logging subscription history:', error)
  }
}

// Log payment events
async function logPaymentEvent(userId: string, eventId: string, eventType: string, metadata: any) {
  try {
    if (!supabase) return
    
    // Using subscription_history table for all payment events
    await supabase
      .from('subscription_history')
      .insert({
        user_id: userId,
        subscription_status: eventType,
        stripe_subscription_id: eventId,
        change_reason: eventType,
        metadata: {
          event_type: eventType,
          ...metadata
        }
      })
  } catch (error) {
    console.error('Error logging payment event:', error)
  }
}

// Log webhook errors
async function logWebhookError(eventId: string, eventType: string, error: any) {
  try {
    console.error(`Webhook Error Log - Event: ${eventId} (${eventType})`, error)
    
    // In production, send to error monitoring service (Sentry, etc.)
    // Or store in database for analysis
    
  } catch (logError) {
    console.error('Error logging webhook error:', logError)
  }
}

// Email notifications are now handled by the EmailService

export default router 