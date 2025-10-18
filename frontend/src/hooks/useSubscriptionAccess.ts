import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { hasLocalhostAccess, getMockAccessLevel } from '../utils/devMode'

// Helper function to get upgrade messages
const getUpgradeMessageForFeature = (feature: keyof FeatureAccess, currentPlan: string): string => {
  const messages = {
    stage2: 'Stage 2 Features require Pro or Enterprise plan. Upgrade to access advanced attack vectors.',
    redTeamOps: 'Red Team Operations require Pro or Enterprise plan. Upgrade for full penetration testing capabilities.',
    premiumModels: 'Premium AI models (GPT-5, Claude Opus, Grok 4) require Pro or Enterprise plan. Upgrade for access to cutting-edge AI models.'
  }
  return messages[feature]
}

// Helper function to determine plan features
const getPlanFeatures = (planName: string, isDeveloper: boolean): FeatureAccess => {
  if (isDeveloper) {
    return {
      stage2: true,
      redTeamOps: true,
      blueTeamPatching: true,
      premiumModels: true
    }
  }

  const plan = planName.toLowerCase()
  
  if (plan.includes('enterprise')) {
    return {
      stage2: true,
      redTeamOps: true,
      blueTeamPatching: true,
      premiumModels: true
    }
  }
  
  if (plan.includes('pro')) {
    return {
      stage2: true,
      redTeamOps: true,
      blueTeamPatching: true,
      premiumModels: true
    }
  }
  
  if (plan.includes('light')) {
    return {
      stage2: false,
      redTeamOps: false,
      blueTeamPatching: false,
      premiumModels: false
    }
  }
  
  // Free plan
  return {
    stage2: false,
    redTeamOps: false,
    blueTeamPatching: false,
    premiumModels: false
  }
}

interface AccessLevel {
  has_access: boolean
  plan_name: string
  is_free_grant: boolean
  limits: Record<string, number>
  features: Record<string, boolean>
}

interface FeatureAccess {
  stage2: boolean
  redTeamOps: boolean
  blueTeamPatching: boolean
  premiumModels: boolean
}

interface SubscriptionAccess {
  hasAccess: boolean
  isDeveloper: boolean
  planName: string
  loading: boolean
  error: string | null
  isLightMode: boolean
  isProMode: boolean
  isEnterpriseMode: boolean
  features: FeatureAccess
  canAccessFeature: (feature: keyof FeatureAccess) => boolean
  getUpgradeMessage: (feature: keyof FeatureAccess) => string
}

export const useSubscriptionAccess = (): SubscriptionAccess => {
  const { session } = useAuth()
  const [access, setAccess] = useState<SubscriptionAccess>({
    hasAccess: false,
    isDeveloper: false,
    planName: 'Free',
    loading: true,
    error: null,
    isLightMode: false,
    isProMode: false,
    isEnterpriseMode: false,
    features: {
      stage2: false,
      redTeamOps: false,
      blueTeamPatching: false,
      premiumModels: false
    },
    canAccessFeature: () => false,
    getUpgradeMessage: () => ''
  })

  // Create stable callback functions to prevent infinite re-renders
  const canAccessFeature = useCallback((feature: keyof FeatureAccess) => {
    return access.features[feature]
  }, [access.features])

  const getUpgradeMessage = useCallback((feature: keyof FeatureAccess) => {
    return getUpgradeMessageForFeature(feature, access.planName)
  }, [access.planName])

  useEffect(() => {
    const checkAccess = async () => {
      // Check for localhost access first
      if (hasLocalhostAccess()) {
        const mockAccess = getMockAccessLevel()
        setAccess({
          hasAccess: true,
          isDeveloper: true,
          planName: mockAccess?.plan_name || 'Localhost Developer',
          loading: false,
          error: null,
          isLightMode: false,
          isProMode: false,
          isEnterpriseMode: false,
          features: {
            stage2: true,
            redTeamOps: true,
            blueTeamPatching: true,
            premiumModels: true
          },
          canAccessFeature: () => true,
          getUpgradeMessage: () => ''
        })
        return
      }

      if (!session?.access_token) {
        setAccess({
          hasAccess: false,
          isDeveloper: false,
          planName: 'Free',
          loading: false,
          error: null,
          isLightMode: false,
          isProMode: false,
          isEnterpriseMode: false,
          features: {
            stage2: false,
            redTeamOps: false,
            blueTeamPatching: false,
            premiumModels: false
          },
          canAccessFeature: () => false,
          getUpgradeMessage: (feature) => getUpgradeMessageForFeature(feature, 'Free')
        })
        return
      }

      try {
        const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:3001'
        const response = await fetch(`${baseUrl}/api/billing/subscription`, {
          headers: {
            'Authorization': `Bearer ${session.access_token}`
          }
        })

        if (response.ok) {
          const data = await response.json()
          const accessLevel: AccessLevel = data.accessLevel

          const isDeveloper = accessLevel?.plan_name?.toLowerCase().includes('developer') || false
          const planName = accessLevel?.plan_name || 'Free'
          const hasSubscription = accessLevel?.plan_name?.toLowerCase().includes('light') ||
                                 accessLevel?.plan_name?.toLowerCase().includes('pro') ||
                                 accessLevel?.plan_name?.toLowerCase().includes('enterprise') ||
                                 isDeveloper

          const planLower = planName.toLowerCase()
          const isLightMode = planLower.includes('light')
          const isProMode = planLower.includes('pro')
          const isEnterpriseMode = planLower.includes('enterprise')

          const features = getPlanFeatures(planName, isDeveloper)

          setAccess({
            hasAccess: hasSubscription,
            isDeveloper,
            planName,
            loading: false,
            error: null,
            isLightMode,
            isProMode,
            isEnterpriseMode,
            features,
            canAccessFeature: (feature: keyof FeatureAccess) => features[feature],
            getUpgradeMessage: (feature: keyof FeatureAccess) => getUpgradeMessageForFeature(feature, planName)
          })
        } else {
          setAccess({
            hasAccess: false,
            isDeveloper: false,
            planName: 'Free',
            loading: false,
            error: 'Failed to check subscription status',
            isLightMode: false,
            isProMode: false,
            isEnterpriseMode: false,
            features: {
              stage2: false,
              redTeamOps: false,
              blueTeamPatching: false,
              premiumModels: false
            },
            canAccessFeature: () => false,
            getUpgradeMessage: (feature) => getUpgradeMessageForFeature(feature, 'Free')
          })
        }
      } catch (error) {
        console.error('Error checking subscription access:', error)
        setAccess({
          hasAccess: false,
          isDeveloper: false,
          planName: 'Free',
          loading: false,
          error: 'Network error checking subscription',
          isLightMode: false,
          isProMode: false,
          isEnterpriseMode: false,
          features: {
            stage2: false,
            redTeamOps: false,
            blueTeamPatching: false,
            premiumModels: false
          },
          canAccessFeature: () => false,
          getUpgradeMessage: (feature) => getUpgradeMessageForFeature(feature, 'Free')
        })
      }
    }

    checkAccess()
  }, [session?.access_token])

  return {
    ...access,
    canAccessFeature,
    getUpgradeMessage
  }
} 