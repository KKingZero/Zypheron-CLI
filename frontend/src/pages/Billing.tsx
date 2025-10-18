import React, { useState, useEffect } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { ArrowLeft, CreditCard, CheckCircle, ExternalLink, Shield, LogOut, Home } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { isDevModeEnabled } from '../utils/devMode'
import toast from 'react-hot-toast'

interface SubscriptionData {
  hasSubscription: boolean;
  planName: string | null;
  planType: string | null;
  subscriptionInfo: any;
}

const Billing: React.FC = () => {
  const navigate = useNavigate()
  const { user, signOut, loading: authLoading } = useAuth()
  const [searchParams] = useSearchParams()
  
  const [loading, setLoading] = useState(true)
  const [subscriptionData, setSubscriptionData] = useState<SubscriptionData | null>(null)
  const [checkingPayment, setCheckingPayment] = useState(false)
  const [subscribing, setSubscribing] = useState<string | null>(null) // Track which plan is being subscribed to

  // Dev mode bypass - allow access regardless of authentication
  const devModeBypass = isDevModeEnabled()
  
  // Only redirect to login if not in dev mode and not authenticated
  useEffect(() => {
    if (!authLoading && !user && !devModeBypass) {
      toast.error('Please log in to access billing')
      navigate('/login')
    }
  }, [user, authLoading, navigate, devModeBypass])

  // Check subscription status on load
  useEffect(() => {
    if (user) {
      checkSubscriptionStatus()
    } else if (devModeBypass) {
      // In dev mode without user, just set loading to false to show the page
      setLoading(false)
      console.log('🔧 DEV MODE: Billing page accessible without authentication')
    }
  }, [user, devModeBypass])

  // Handle payment success from URL parameters
  useEffect(() => {
    const success = searchParams.get('success')
    const planName = searchParams.get('plan_name')

    if (success === 'true' && user) {
      setCheckingPayment(true)
      toast.success(`Payment successful! ${planName ? `Welcome to ${planName}!` : ''}`)
      
      // Give webhook time to process, then check subscription
      setTimeout(() => {
        checkSubscriptionStatus()
        setCheckingPayment(false)
        // Clean up URL
        window.history.replaceState({}, '', '/billing')
      }, 3000)
    }
  }, [searchParams, user])

  const checkSubscriptionStatus = async () => {
    if (!user && !devModeBypass) return

    try {
      setLoading(true)
      const response = await fetch('/api/billing/subscription', {
        headers: {
          'Authorization': `Bearer ${(user as any)?.access_token || ''}`
        }
      })

      if (response.ok) {
        const data = await response.json()
        const planName = data?.accessLevel?.plan_name?.toLowerCase()
        
        setSubscriptionData({
          hasSubscription: planName && ['light', 'pro', 'enterprise', 'super'].includes(planName),
          planName: planName || null,
          planType: planName || null,
          subscriptionInfo: data
        })

        // If user has subscription, redirect to dashboard after a moment
        if (planName && ['light', 'pro', 'enterprise', 'super'].includes(planName)) {
          toast.success(`You have access to ${planName} features!`)
          setTimeout(() => {
            navigate('/dashboard')
          }, 2000)
        }
      }
    } catch (error) {
      console.error('Failed to check subscription:', error)
      toast.error('Failed to check subscription status')
    } finally {
      setLoading(false)
    }
  }

  const handleManageSubscription = async () => {
    if (!user && !devModeBypass) {
      toast.error('Please log in to manage subscription')
      return
    }
    
    if (devModeBypass) {
      toast.success('🔧 DEV MODE: Subscription management simulated')
      return
    }

    try {
      const response = await fetch('/api/billing/portal', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${(user as any)?.access_token || ''}`
        }
      })

      const data = await response.json()

      if (response.ok && data.url) {
        window.open(data.url, '_blank')
      } else {
        toast.error(data.error || 'Failed to open customer portal')
      }
    } catch (error) {
      console.error('Portal error:', error)
      toast.error('Failed to open customer portal')
    }
  }

  const handleLogout = async () => {
    if (devModeBypass) {
      toast.success('🔧 DEV MODE: Logout simulated')
      return
    }
    
    try {
      await signOut()
      toast.success('Logged out successfully')
      navigate('/login')
    } catch (error) {
      toast.error('Logout failed')
    }
  }

  // Handle subscription purchase with API-generated checkout session
  const handleSubscribe = async (priceId: string, planName: string) => {
    if (!user && !devModeBypass) {
      toast.error('Please log in to subscribe')
      navigate('/login')
      return
    }

    if (devModeBypass) {
      toast.success(`🔧 DEV MODE: ${planName} subscription simulated`)
      return
    }

    // Prevent multiple simultaneous subscription attempts
    if (subscribing) {
      toast.warning('Please wait, processing subscription...')
      return
    }

    setSubscribing(planName)
    
    try {
      const response = await fetch('/api/billing/checkout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${(user as any)?.access_token || ''}`
        },
        body: JSON.stringify({ priceId })
      })

      const data = await response.json()

      if (response.ok && data.url) {
        // Show success message and redirect
        toast.success(`Redirecting to secure checkout for ${planName} plan...`)
        // Small delay to show the toast
        setTimeout(() => {
          window.location.href = data.url
        }, 500)
      } else {
        // Handle specific error cases
        if (data.existingSubscriptions && data.existingSubscriptions.length > 0) {
          toast.error('You already have an active subscription. Please manage it from the customer portal.', {
            duration: 5000
          })
          // Refresh subscription data to show current subscription
          checkSubscriptionStatus()
        } else {
          toast.error(data.error || 'Failed to create checkout session')
        }
        setSubscribing(null)
      }
    } catch (error) {
      console.error('Checkout error:', error)
      toast.error('Failed to initiate checkout. Please try again.')
      setSubscribing(null)
    }
  }

  // Show loading while checking auth or subscription
  if (authLoading || loading || checkingPayment) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-800 text-white flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-zypheron-500 mx-auto mb-4"></div>
          <p className="text-xl">
            {checkingPayment ? 'Processing your payment...' : 'Loading billing information...'}
          </p>
        </div>
      </div>
    )
  }

  // Allow rendering in dev mode even without user
  if (!user && !devModeBypass) {
    return null // Will redirect to login
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-800 text-white overflow-x-hidden">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-4 sm:py-8">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6 sm:mb-8 space-y-4 sm:space-y-0">
          <div className="flex flex-col sm:flex-row items-start sm:items-center space-y-2 sm:space-y-0 sm:space-x-4">
            <button
              onClick={() => navigate('/dashboard')}
              className="flex items-center space-x-2 text-gray-400 hover:text-white transition-colors text-sm sm:text-base"
            >
              <ArrowLeft className="w-4 h-4 sm:w-5 sm:h-5" />
              <span className="hidden sm:inline">Back to Dashboard</span>
              <span className="sm:hidden">Dashboard</span>
            </button>
            
            <button
              onClick={() => window.location.href = 'https://cobraai.dev/'}
              className="flex items-center space-x-2 text-gray-400 hover:text-white transition-colors text-sm sm:text-base"
            >
              <Home className="w-4 h-4 sm:w-5 sm:h-5" />
              <span className="hidden sm:inline">Marketing Site</span>
              <span className="sm:hidden">Home</span>
            </button>
          </div>
          
          <h1 className="text-2xl sm:text-3xl font-bold font-orbitron break-words">Billing & Subscriptions</h1>
          
          <div className="flex items-center space-x-4">
            <button
              onClick={handleLogout}
              className="flex items-center space-x-2 px-4 py-2 bg-zypheron-600 hover:bg-zypheron-700 rounded-lg font-medium transition-colors"
            >
              <LogOut className="w-4 h-4" />
              <span className="hidden sm:inline">Logout</span>
            </button>
          </div>
        </div>

        {/* Current Subscription Status */}
        {subscriptionData?.hasSubscription && (
          <div className="bg-gray-800 rounded-lg p-4 sm:p-6 mb-6 sm:mb-8 border border-gray-700">
            <h2 className="text-xl sm:text-2xl font-semibold mb-4 flex items-center space-x-2">
              <Shield className="w-5 h-5 sm:w-6 sm:h-6 text-green-500" />
              <span>Active Subscription</span>
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
              <div>
                <div className="text-2xl sm:text-3xl font-bold text-green-500 mb-4 capitalize">
                  {subscriptionData.planName} Plan
                </div>
                <p className="text-gray-300 mb-4">
                  🎉 You have full access to all {subscriptionData.planName} features!
                </p>
                <button
                  onClick={() => navigate('/dashboard')}
                  className="bg-green-600 hover:bg-green-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors"
                >
                  Access Dashboard
                </button>
              </div>
              <div>
                                <button
                  onClick={handleManageSubscription}
                  className="flex items-center space-x-2 px-4 py-3 bg-zypheron-600 hover:bg-zypheron-700 rounded-lg transition-colors"
                >
                  <ExternalLink className="w-4 h-4" />
                  <span>Manage Subscription</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Upgrade Plans (only show if no subscription) */}
        {!subscriptionData?.hasSubscription && (
          <div className="mb-6 sm:mb-8">
            <h2 className="text-xl sm:text-2xl font-semibold mb-4 sm:mb-6 flex items-center space-x-2">
              <CreditCard className="w-5 h-5 sm:w-6 sm:h-6 text-zypheron-500" />
              <span>Choose Your Plan</span>
            </h2>
            <p className="text-gray-400 mb-6 text-center">
              Select a plan to unlock Zypheron's cybersecurity features
            </p>

            <div className="grid gap-4 sm:gap-6 grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
              {/* Light Plan */}
              <div className="bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-700 hover:border-zypheron-500/50 transition-all">
                <div className="text-center mb-4 sm:mb-6">
                  <h3 className="text-lg sm:text-xl font-bold mb-2">Light</h3>
                  <div className="text-2xl sm:text-3xl font-bold text-zypheron-500 mb-1">$29.99</div>
                  <div className="text-gray-400 text-sm">per month</div>
                  <div className="bg-blue-500 text-white px-3 py-1 rounded-full text-xs font-semibold mt-2 inline-block">
                    FREE TRIAL
                  </div>
                </div>

                <div className="mb-6">
                  <h4 className="font-semibold mb-3">Features:</h4>
                  <ul className="space-y-2 text-sm">
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span>Basic Security Tools</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span>AI Chat Assistant</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span>Vulnerability Scanning</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span>Basic OSINT Tools</span>
                    </li>
                  </ul>
                </div>

                <div className="text-center">
                  <button
                    onClick={() => handleSubscribe('price_1RmQkXABd1WNp9IUjNCzVd6q', 'Light')}
                    disabled={subscribing !== null}
                    className="w-full bg-zypheron-600 hover:bg-zypheron-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {subscribing === 'Light' ? 'Processing...' : 'Start Free Trial'}
                  </button>
                  <p className="text-xs text-gray-400 mt-2">
                    14 days free, then $29.99/month
                  </p>
                </div>
              </div>

              {/* Pro Plan */}
              <div className="bg-gray-800 rounded-lg p-6 border-2 border-zypheron-500 relative">
                <div className="absolute -top-3 left-1/2 transform -translate-x-1/2">
                  <div className="bg-zypheron-500 text-white px-3 py-1 rounded-full text-xs font-semibold">
                    POPULAR
                  </div>
                </div>
                
                <div className="text-center mb-6">
                  <h3 className="text-xl font-bold text-white mb-4">Pro</h3>
                  <div className="text-3xl font-bold text-zypheron-500 mb-1">$149.99</div>
                  <div className="text-gray-400 text-sm">per month</div>
                </div>

                <div className="mb-6">
                  <h4 className="font-semibold text-white mb-3">Features:</h4>
                  <ul className="space-y-2 text-sm">
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span className="text-gray-300">Everything in Light</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span className="text-gray-300">Stage 1 & 2 Features</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span className="text-gray-300">Advanced Penetration Testing</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span className="text-gray-300">Premium OSINT Capabilities</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span className="text-gray-300">Automated Exploitation</span>
                    </li>
                  </ul>
                </div>

                <div className="mb-6">
                  <h4 className="font-semibold text-white mb-3">Limits:</h4>
                  <div className="text-sm text-gray-300">
                    <div className="flex justify-between">
                      <span>Total Tokens:</span>
                      <span>1M</span>
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => handleSubscribe('price_1RmQZfABd1WNp9IU3BI5HpAN', 'Pro')}
                  disabled={subscribing !== null}
                  className="w-full bg-zypheron-600 hover:bg-zypheron-700 text-white font-semibold py-3 rounded-lg transition-colors mb-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {subscribing === 'Pro' ? 'Processing...' : 'Get Pro Plan'}
                </button>
                <div className="flex items-center justify-center text-xs text-gray-400">
                  <Shield className="w-3 h-3 mr-1" />
                  <span>Secure payment processing by Stripe</span>
                </div>
              </div>

              {/* Enterprise Plan */}
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <div className="text-center mb-6">
                  <h3 className="text-xl font-bold text-white mb-4">Enterprise</h3>
                  <div className="text-3xl font-bold text-zypheron-500 mb-1">$999.99</div>
                  <div className="text-gray-400 text-sm">per month</div>
                </div>

                <div className="mb-6">
                  <h4 className="font-semibold text-white mb-3">Features:</h4>
                  <ul className="space-y-2 text-sm">
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span className="text-gray-300">Everything in Pro</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span className="text-gray-300">All Features</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span className="text-gray-300">Custom AI Models</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span className="text-gray-300">On-premise Deployment</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span className="text-gray-300">24/7 Dedicated Support</span>
                    </li>
                  </ul>
                </div>

                <div className="mb-6">
                  <h4 className="font-semibold text-white mb-3">Limits:</h4>
                  <div className="text-sm text-gray-300">
                    <div className="flex justify-between">
                      <span>Total Tokens:</span>
                      <span>Unlimited</span>
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => handleSubscribe('price_1RmQQBABd1WNp9IUa8RSXQ9R', 'Enterprise')}
                  disabled={subscribing !== null}
                  className="w-full bg-zypheron-600 hover:bg-zypheron-700 text-white font-semibold py-3 rounded-lg transition-colors mb-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {subscribing === 'Enterprise' ? 'Processing...' : 'Get Enterprise Plan'}
                </button>
                <div className="flex items-center justify-center text-xs text-gray-400">
                  <Shield className="w-3 h-3 mr-1" />
                  <span>Secure payment processing by Stripe</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Billing Information */}
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h3 className="text-lg font-semibold text-white mb-6">Billing Information</h3>
          <div className="grid md:grid-cols-2 gap-8">
            <div>
              <h4 className="font-semibold text-white mb-4">Payment Security</h4>
              <ul className="space-y-2 text-sm text-gray-300">
                <li>• All payments processed securely by Stripe</li>
                <li>• SSL encryption for all transactions</li>
                <li>• No card details stored on our servers</li>
                <li>• PCI DSS compliant payment processing</li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold text-white mb-4">Subscription Details</h4>
              <ul className="space-y-2 text-sm text-gray-300">
                <li>• Monthly billing on subscription date</li>
                <li>• Cancel anytime from customer portal</li>
                <li>• Immediate access upon payment</li>
                <li>• Email notifications for billing events</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Billing