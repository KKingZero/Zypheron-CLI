import { useState, useEffect } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { 
  isDevModeEnabled, 
  hasLocalhostAccess, 
  shouldBypassAuth, 
  getMockAccessLevel, 
  getSelectedDevPlan,
  isLocalhost 
} from '../utils/devMode'

interface SubscriptionData {
  subscription: any
  accessLevel: {
    has_access: boolean
    plan_name: string
    is_developer: boolean
    is_admin_dev: boolean
    is_free_grant: boolean
    features: Record<string, boolean>
    limits: Record<string, number>
    rbac_role: string
    can_bypass_mfa: boolean
    can_extend_session: boolean
    max_session_hours: number
  }
}

export const useRBACSubscriptionAccess = () => {
  const { user } = useAuth()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [subscriptionData, setSubscriptionData] = useState<SubscriptionData | null>(null)

  // Fetch subscription data from API or use dev mode mock data
  const fetchSubscriptionData = async () => {
    // Check if we're in dev mode and should use mock data
    if (isDevModeEnabled()) {
      console.log('🔧 DEV MODE: Using mock subscription data')
      setLoading(true)
      setError(null)
      
      // Simulate API delay for realism
      await new Promise(resolve => setTimeout(resolve, 500))
      
      const mockAccessLevel = getMockAccessLevel()
      const selectedPlan = getSelectedDevPlan()
      
      const mockData: SubscriptionData = {
        subscription: { status: 'active' },
        accessLevel: {
          has_access: true,
          plan_name: selectedPlan,
          is_developer: true,
          is_admin_dev: selectedPlan === 'enterprise',
          is_free_grant: false,
          features: mockAccessLevel?.features || {},
          limits: mockAccessLevel?.limits || {
            api_calls: -1,
            scans: -1,
            tokens_total: -1,
            tokens_used: 0,
            tokens_remaining: -1
          },
          rbac_role: selectedPlan === 'enterprise' ? 'admin_dev' : 'user',
          can_bypass_mfa: selectedPlan === 'enterprise',
          can_extend_session: selectedPlan !== 'light',
          max_session_hours: selectedPlan === 'enterprise' ? -1 : (selectedPlan === 'pro' ? 24 : 8)
        }
      }
      
      setSubscriptionData(mockData)
      setLoading(false)
      return
    }

    // Production mode - fetch real data from API
    if (!user) {
      setLoading(false)
      return
    }

    try {
      setLoading(true)
      setError(null)
      
      const response = await fetch('/api/billing/subscription', {
        headers: {
          'Authorization': `Bearer ${(user as any)?.access_token || ''}`
        }
      })

      if (response.ok) {
        const data = await response.json()
        const planName = data?.accessLevel?.plan_name?.toLowerCase()
        
        // Map the response to our interface
        const mappedData: SubscriptionData = {
          subscription: data.subscription || { status: 'inactive' },
          accessLevel: {
            has_access: Boolean(planName && ['light', 'pro', 'enterprise', 'super'].includes(planName)),
            plan_name: planName || 'none',
            is_developer: data?.accessLevel?.is_developer || false,
            is_admin_dev: data?.accessLevel?.is_admin_dev || false,
            is_free_grant: data?.accessLevel?.is_free_grant || false,
            features: data?.accessLevel?.features || {},
            limits: data?.accessLevel?.limits || {
              api_calls: 0,
              scans: 0,
              tokens_total: 0,
              tokens_used: 0,
              tokens_remaining: 0
            },
            rbac_role: data?.accessLevel?.rbac_role || 'none',
            can_bypass_mfa: data?.accessLevel?.can_bypass_mfa || false,
            can_extend_session: data?.accessLevel?.can_extend_session || false,
            max_session_hours: data?.accessLevel?.max_session_hours || 1
          }
        }
        
        setSubscriptionData(mappedData)
      } else {
        // No subscription or error
        setSubscriptionData({
          subscription: { status: 'inactive' },
          accessLevel: {
            has_access: false,
            plan_name: 'none',
            is_developer: false,
            is_admin_dev: false,
            is_free_grant: false,
            features: {},
            limits: {
              api_calls: 0,
              scans: 0,
              tokens_total: 0,
              tokens_used: 0,
              tokens_remaining: 0
            },
            rbac_role: 'none',
            can_bypass_mfa: false,
            can_extend_session: false,
            max_session_hours: 1
          }
        })
      }
    } catch (err) {
      console.error('Failed to fetch subscription data:', err)
      setError('Failed to load subscription information')
      
      // Set no access on error
      setSubscriptionData({
        subscription: { status: 'error' },
        accessLevel: {
          has_access: false,
          plan_name: 'none',
          is_developer: false,
          is_admin_dev: false,
          is_free_grant: false,
          features: {},
          limits: {
            api_calls: 0,
            scans: 0,
            tokens_total: 0,
            tokens_used: 0,
            tokens_remaining: 0
          },
          rbac_role: 'none',
          can_bypass_mfa: false,
          can_extend_session: false,
          max_session_hours: 1
        }
      })
    } finally {
      setLoading(false)
    }
  }

  // Fetch subscription data on mount and when user changes
  // Also re-fetch when dev plan changes in dev mode
  useEffect(() => {
    fetchSubscriptionData()
  }, [user])

  // Listen for dev plan changes if in dev mode
  useEffect(() => {
    if (!isDevModeEnabled()) return

    const handleDevPlanChange = () => {
      console.log('🔧 DEV MODE: Plan changed, refetching subscription data')
      fetchSubscriptionData()
    }

    // Listen for storage changes (dev plan selector)
    window.addEventListener('storage', handleDevPlanChange)
    
    // Listen for custom events (from dev plan selector)
    window.addEventListener('devPlanChanged', handleDevPlanChange)

    return () => {
      window.removeEventListener('storage', handleDevPlanChange)
      window.removeEventListener('devPlanChanged', handleDevPlanChange)
    }
  }, [])

  // Watch for dev mode toggle changes
  useEffect(() => {
    if (!isLocalhost()) return

    const handleDevModeToggle = () => {
      console.log('🔧 DEV MODE: Dev mode toggled, refetching subscription data')
      fetchSubscriptionData()
    }

    window.addEventListener('devModeToggled', handleDevModeToggle)
    return () => window.removeEventListener('devModeToggled', handleDevModeToggle)
  }, [])

  // Computed values based on real subscription data
  const hasAccess = subscriptionData?.accessLevel?.has_access || false
  const hasUnlimitedAccess = subscriptionData?.accessLevel?.plan_name === 'enterprise' || subscriptionData?.accessLevel?.plan_name === 'super'
  const isDeveloper = subscriptionData?.accessLevel?.is_developer || false
  const isAdminDev = subscriptionData?.accessLevel?.is_admin_dev || false
  const isFreeGrant = subscriptionData?.accessLevel?.is_free_grant || false

  // Feature access based on real data
  const canAccessFeature = (feature: string): boolean => {
    return subscriptionData?.accessLevel?.features?.[feature] || false
  }

  // Plan information
  const planName = subscriptionData?.accessLevel?.plan_name || 'none'
  const isFreePlan = planName === 'none' || planName === 'free'
  const isPaidPlan = ['light', 'pro', 'enterprise', 'super'].includes(planName)
  
  // Usage limits from real data
  const limits = subscriptionData?.accessLevel?.limits || {
    api_calls: 0,
    scans: 0,
    tokens_total: 0,
    tokens_used: 0,
    tokens_remaining: 0
  }
  
  const hasHitLimit = (limitType: string): boolean => {
    const limit = limits[limitType as keyof typeof limits]
    const used = limits[`${limitType}_used` as keyof typeof limits]
    return limit > 0 && used >= limit
  }

  // Trial status (simplified for now)
  const isTrialing = false
  const trialEndsAt = null
  const trialDaysLeft = 0

  // Subscription status based on real data
  const subscriptionStatus = subscriptionData?.subscription?.status || 'inactive'
  const isActiveSubscription = hasAccess && ['active', 'trialing'].includes(subscriptionStatus)
  const needsUpgrade = !hasAccess || subscriptionStatus === 'inactive'

  // RBAC data from real subscription
  const rbacRole = subscriptionData?.accessLevel?.rbac_role || 'none'
  const canBypassMFA = subscriptionData?.accessLevel?.can_bypass_mfa || false
  const canExtendSession = subscriptionData?.accessLevel?.can_extend_session || false
  const maxSessionHours = subscriptionData?.accessLevel?.max_session_hours || 1

  return {
    // Data
    subscriptionData,
    loading,
    error,
    
    // Basic access
    hasAccess,
    hasUnlimitedAccess,
    isDeveloper,
    isAdminDev,
    isFreeGrant,
    
    // Plan info
    planName,
    isFreePlan,
    isPaidPlan,
    
    // Trial info
    isTrialing,
    trialDaysLeft,
    
    // Subscription status
    subscriptionStatus,
    isActiveSubscription,
    needsUpgrade,
    
    // Feature access
    canAccessFeature,
    hasHitLimit,
    
    // Usage limits
    limits,
    
    // RBAC data
    rbacRole,
    canBypassMFA,
    canExtendSession,
    maxSessionHours,
    
    // Actions
    refresh: fetchSubscriptionData
  }
}
