import Stripe from 'stripe'
import { getSecureApiKey } from './encryption'

const STRIPE_SECRET_KEY = getSecureApiKey('STRIPE_SECRET_KEY')
if (!STRIPE_SECRET_KEY) {
  console.warn('STRIPE_SECRET_KEY not found. Billing features will be unavailable.')
}

export const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY, {
  apiVersion: '2025-06-30.basil'
}) : null

export class BillingService {
  
  // Create or retrieve Stripe customer
  async createOrGetCustomer(email: string, userId: string, name?: string) {
    if (!stripe) throw new Error('Stripe not initialized')

    // Check if customer already exists
    const existingCustomers = await stripe.customers.list({
      email,
      limit: 1
    })

    if (existingCustomers.data.length > 0) {
      return existingCustomers.data[0]
    }

    // Create new customer
    return await stripe.customers.create({
      email,
      name,
      metadata: {
        userId
      }
    })
  }

  // Create checkout session
  async createCheckoutSession(
    customerId: string, 
    priceId: string, 
    successUrl: string, 
    cancelUrl: string,
    userId: string
  ) {
    if (!stripe) throw new Error('Stripe not initialized')

    return await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [
        {
          price: priceId,
          quantity: 1
        }
      ],
      mode: 'subscription',
      success_url: successUrl,
      cancel_url: cancelUrl,
      client_reference_id: userId, // Alternative to metadata for checkout sessions
      metadata: {
        userId
      },
      subscription_data: {
        metadata: {
          userId // Ensure metadata is passed to the subscription
        }
      },
      allow_promotion_codes: true,
      billing_address_collection: 'auto',
      automatic_tax: {
        enabled: false // Can be enabled if tax calculation is needed
      }
    })
  }

  // Create customer portal session
  async createPortalSession(customerId: string, returnUrl: string) {
    if (!stripe) throw new Error('Stripe not initialized')

    return await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: returnUrl
    })
  }

  // Get subscription details
  async getSubscription(subscriptionId: string) {
    if (!stripe) throw new Error('Stripe not initialized')
    
    return await stripe.subscriptions.retrieve(subscriptionId)
  }

  // Cancel subscription
  async cancelSubscription(subscriptionId: string) {
    if (!stripe) throw new Error('Stripe not initialized')
    
    return await stripe.subscriptions.update(subscriptionId, {
      cancel_at_period_end: true
    })
  }

  // Get pricing information for a product
  async getProductPricing(productId: string) {
    if (!stripe) throw new Error('Stripe not initialized')
    
    const prices = await stripe.prices.list({
      product: productId,
      active: true
    })
    
    return prices.data
  }
}

export const billingService = new BillingService() 