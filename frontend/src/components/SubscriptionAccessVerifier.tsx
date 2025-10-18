import React, { useState, useEffect } from 'react'
import { Shield, CheckCircle, XCircle, AlertTriangle, RefreshCw } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { useRBACSubscriptionAccess } from '../hooks/useRBACSubscriptionAccess'

interface AccessVerificationResult {
  hasAccess: boolean
  planName: string
  isTrialing: boolean
  features: Record<string, boolean>
  limits: Record<string, number>
  subscriptionStatus: string
  lastUpdated: string
}

const SubscriptionAccessVerifier: React.FC = () => {
  const { user, session } = useAuth()
  const { 
    hasAccess, 
    planName, 
    isTrialing, 
    subscriptionStatus,
    subscriptionData,
    canAccessFeature,
    refresh: refreshSubscription
  } = useRBACSubscriptionAccess()
  
  const [verificationResult, setVerificationResult] = useState<AccessVerificationResult | null>(null)
  const [isVerifying, setIsVerifying] = useState(false)
  const [showDetails, setShowDetails] = useState(false)

  const runVerification = async () => {
    if (!user || !session) return

    setIsVerifying(true)
    try {
      // Refresh subscription data
      await refreshSubscription()
      
      // Get fresh data from the API
      const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:3001'
      const response = await fetch(`${baseUrl}/api/billing/subscription`, {
        headers: {
          'Authorization': `Bearer ${session.access_token}`
        }
      })

      if (response.ok) {
        const data = await response.json()
        setVerificationResult({
          hasAccess: data.accessLevel?.has_access || false,
          planName: data.accessLevel?.plan_name || 'Free',
          isTrialing: data.subscription?.status === 'trialing',
          features: data.accessLevel?.features || {},
          limits: data.accessLevel?.limits || {},
          subscriptionStatus: data.subscription?.status || 'none',
          lastUpdated: new Date().toISOString()
        })
      }
    } catch (error) {
      console.error('Verification failed:', error)
    } finally {
      setIsVerifying(false)
    }
  }

  useEffect(() => {
    if (user && session) {
      runVerification()
    }
  }, [user, session])

  const featureTests = [
    { key: 'stage_1', name: 'Stage 1 Security Tools', requiredPlan: 'Light+' },
    { key: 'basic_chat', name: 'Basic Chat', requiredPlan: 'Light+' },
    { key: 'vulnerability_scanning', name: 'Vulnerability Scanning', requiredPlan: 'Light+' },
    { key: 'stage_2', name: 'Stage 2 Features', requiredPlan: 'Pro+' },
    { key: 'penetration_testing', name: 'Penetration Testing', requiredPlan: 'Pro+' },
    { key: 'osint_advanced', name: 'Advanced OSINT', requiredPlan: 'Pro+' },
    { key: 'custom_models', name: 'Custom AI Models', requiredPlan: 'Enterprise' },
    { key: 'on_premise', name: 'On-premise Deployment', requiredPlan: 'Enterprise' }
  ]

  if (!user) {
    return (
      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center space-x-2 text-gray-400">
          <Shield className="w-5 h-5" />
          <span>Login required to verify subscription access</span>
        </div>
      </div>
    )
  }

  return (
    <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-2">
          <Shield className="w-5 h-5 text-blue-500" />
          <h3 className="text-lg font-semibold">Subscription Access Verification</h3>
        </div>
        <button
          onClick={runVerification}
          disabled={isVerifying}
          className="flex items-center space-x-2 px-3 py-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 rounded-lg text-sm transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${isVerifying ? 'animate-spin' : ''}`} />
          <span>{isVerifying ? 'Verifying...' : 'Refresh'}</span>
        </button>
      </div>

      {/* Current Status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-gray-700 rounded-lg p-4">
          <div className="flex items-center space-x-2 mb-2">
            {hasAccess ? (
              <CheckCircle className="w-5 h-5 text-green-500" />
            ) : (
              <XCircle className="w-5 h-5 text-red-500" />
            )}
            <span className="font-semibold">Access Status</span>
          </div>
          <p className="text-sm text-gray-300">
            {hasAccess ? 'Active' : 'No Access'}
          </p>
        </div>

        <div className="bg-gray-700 rounded-lg p-4">
          <div className="flex items-center space-x-2 mb-2">
            <Shield className="w-5 h-5 text-blue-500" />
            <span className="font-semibold">Plan</span>
          </div>
          <p className="text-sm text-gray-300">{planName}</p>
          {isTrialing && (
            <p className="text-xs text-yellow-400 mt-1">Trial Active</p>
          )}
        </div>

        <div className="bg-gray-700 rounded-lg p-4">
          <div className="flex items-center space-x-2 mb-2">
            <AlertTriangle className="w-5 h-5 text-orange-500" />
            <span className="font-semibold">Status</span>
          </div>
          <p className="text-sm text-gray-300 capitalize">{subscriptionStatus}</p>
        </div>
      </div>

      {/* Feature Access Test */}
      <div className="mb-6">
        <button
          onClick={() => setShowDetails(!showDetails)}
          className="flex items-center space-x-2 text-sm text-blue-400 hover:text-blue-300 mb-3"
        >
          <span>{showDetails ? 'Hide' : 'Show'} Feature Access Details</span>
        </button>

        {showDetails && verificationResult && (
          <div className="bg-gray-700 rounded-lg p-4">
            <h4 className="font-semibold mb-3">Feature Access Test</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {featureTests.map((feature) => {
                const hasFeature = canAccessFeature(feature.key)
                return (
                  <div key={feature.key} className="flex items-center justify-between py-1">
                    <span className="text-sm">{feature.name}</span>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs text-gray-400">{feature.requiredPlan}</span>
                      {hasFeature ? (
                        <CheckCircle className="w-4 h-4 text-green-500" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-500" />
                      )}
                    </div>
                  </div>
                )
              })}
            </div>

            {/* Limits Display */}
            <div className="mt-4 pt-4 border-t border-gray-600">
              <h5 className="font-medium mb-2">Usage Limits</h5>
              <div className="grid grid-cols-2 gap-2 text-sm">
                {Object.entries(verificationResult.limits).map(([key, value]) => (
                  <div key={key} className="flex justify-between">
                    <span className="text-gray-400 capitalize">{key.replace('_', ' ')}</span>
                    <span>{value === -1 ? 'Unlimited' : value.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Raw Data */}
            <details className="mt-4">
              <summary className="text-sm text-gray-400 cursor-pointer">Raw Subscription Data</summary>
              <pre className="mt-2 p-2 bg-gray-800 rounded text-xs overflow-auto">
                {JSON.stringify(verificationResult, null, 2)}
              </pre>
            </details>
          </div>
        )}
      </div>

      {/* Troubleshooting */}
      {!hasAccess && (
        <div className="bg-yellow-900/20 border border-yellow-500/30 rounded-lg p-4">
          <div className="flex items-center space-x-2 mb-2">
            <AlertTriangle className="w-5 h-5 text-yellow-500" />
            <span className="font-semibold text-yellow-400">No Subscription Access</span>
          </div>
          <div className="text-sm text-yellow-200 space-y-1">
            <p>If you recently purchased a subscription:</p>
            <ul className="list-disc list-inside ml-4 space-y-1">
              <li>Wait a few minutes for Stripe webhook processing</li>
              <li>Click the "Refresh" button above</li>
              <li>Try logging out and back in</li>
              <li>Contact support if the issue persists</li>
            </ul>
          </div>
        </div>
      )}

      {/* Success Message */}
      {hasAccess && (
        <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-4">
          <div className="flex items-center space-x-2">
            <CheckCircle className="w-5 h-5 text-green-500" />
            <span className="font-semibold text-green-400">
              Subscription Active - Dashboard Access Enabled
            </span>
          </div>
          <p className="text-sm text-green-200 mt-1">
            You have full access to {planName} features and can use the dashboard.
          </p>
        </div>
      )}
    </div>
  )
}

export default SubscriptionAccessVerifier
