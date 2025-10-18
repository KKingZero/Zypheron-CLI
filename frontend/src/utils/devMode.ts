// Development Mode Configuration
// Simple variable to enable/disable full access on localhost

interface DevConfig {
  enableLocalhostAccess: boolean
  enableDeveloperMode: boolean
  bypassAuthentication: boolean
  unlimitedAccess: boolean
}

// 🔧 MAIN DEV MODE SWITCH - Change this to enable/disable dev features
export const DEV_MODE_ENABLED = true

// 🚀 FULL BYPASS MODE - When enabled, dev mode bypasses ALL restrictions
export const DEV_MODE_FULL_BYPASS = true

// Development configuration
export const DEV_CONFIG: DevConfig = {
  // Enable localhost access in development by default
  enableLocalhostAccess: true,
  enableDeveloperMode: DEV_MODE_ENABLED,
  // Bypass authentication in development so demo mode works out of the box
  bypassAuthentication: DEV_MODE_FULL_BYPASS,
  // Grant unlimited access in full bypass mode
  unlimitedAccess: DEV_MODE_FULL_BYPASS
}

// Localhost detection
export const isLocalhost = (): boolean => {
  if (typeof window === 'undefined') return false
  
  const hostname = window.location.hostname
  const port = window.location.port
  
  const isLocal = (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '0.0.0.0' ||
    hostname.startsWith('192.168.') ||
    hostname.startsWith('10.') ||
    hostname.includes('local') ||
    port !== ''
  )
  
  // Debug logging for localhost detection
  console.log('🔍 Localhost Detection Debug:', {
    hostname,
    port,
    isLocal,
    url: window.location.href
  })
  
  return isLocal
}

// Check if we're in development environment
export const isDevelopmentMode = (): boolean => {
  return DEV_CONFIG.enableDeveloperMode && (
    process.env.NODE_ENV === 'development' ||
    isLocalhost() ||
    window.location.href.includes('localhost') ||
    window.location.href.includes('127.0.0.1')
  )
}

// Check if user should have full access (localhost + dev mode enabled)
export const hasLocalhostAccess = (): boolean => {
  // Must be on localhost AND have dev mode explicitly enabled by toggle
  return isDevModeEnabled()
}

// Legacy function for backward compatibility
export const hasLocalhostAccessOld = (): boolean => {
  // Check for runtime override
  const runtimeOverride = (window as any).COBRA_DEV_MODE
  if (typeof runtimeOverride === 'boolean') {
    return runtimeOverride && isLocalhost()
  }
  return DEV_CONFIG.enableLocalhostAccess && isLocalhost()
}

// Check if authentication should be bypassed
export const shouldBypassAuth = (): boolean => {
  // Only bypass auth when dev mode is explicitly enabled by user toggle
  return isDevModeEnabled()
}

// Check if user should have unlimited access
export const hasUnlimitedAccess = (): boolean => {
  // Only grant unlimited access when dev mode is explicitly enabled by user toggle
  return isDevModeEnabled()
}

// Get mock developer user for localhost (only when dev mode is enabled)
export const getMockDevUser = () => {
  if (!isDevModeEnabled()) return null
  
  return {
    id: 'localhost-dev-user',
    email: 'localhost@dev.local',
    user_metadata: {
      full_name: 'Localhost Developer',
      avatar_url: null
    },
    aud: 'authenticated',
    role: 'authenticated'
  }
}

// Get selected dev plan
export const getSelectedDevPlan = (): 'light' | 'pro' | 'enterprise' => {
  if (typeof window === 'undefined') return 'light'
  
  // Check window global first, then localStorage
  const windowPlan = (window as any).COBRA_DEV_PLAN
  if (windowPlan && ['light', 'pro', 'enterprise'].includes(windowPlan)) {
    return windowPlan
  }
  
  const savedPlan = localStorage.getItem('COBRA_DEV_PLAN')
  if (savedPlan && ['light', 'pro', 'enterprise'].includes(savedPlan)) {
    return savedPlan as 'light' | 'pro' | 'enterprise'
  }
  
  return 'light' // Default to light plan
}

// Get mock access level for localhost based on selected dev plan (only when dev mode is enabled)
export const getMockAccessLevel = () => {
  if (!isDevModeEnabled()) return null
  
  const selectedPlan = getSelectedDevPlan()
  
  switch (selectedPlan) {
    case 'light':
      return {
        has_access: true,
        plan_name: 'Light',
        is_free_grant: false,
        limits: {
          tokens_total: 100000,
          tokens_used: Math.floor(Math.random() * 25000), // Random usage for demo
          tokens_remaining: 75000,
          api_calls: 1000,
          api_calls_used: Math.floor(Math.random() * 250),
          scans: 100,
          scans_used: Math.floor(Math.random() * 25),
          ai_requests: 500,
          ai_requests_used: Math.floor(Math.random() * 125),
          osint_queries: 200,
          osint_queries_used: Math.floor(Math.random() * 50)
        },
        features: {
          basic_chat: true,
          vulnerability_scanning: true,
          basic_osint: true,
          pdf_reports: true,
          email_support: true,
          localhost_access: true,
          // Advanced features disabled
          advanced_chat: false,
          stage_2_tools: false,
          advanced_pentest: false,
          premium_osint: false,
          automated_exploitation: false,
          custom_models: false,
          priority_support: false
        }
      }
    
    case 'pro':
      return {
        has_access: true,
        plan_name: 'Pro',
        is_free_grant: false,
        limits: {
          tokens_total: 1000000,
          tokens_used: Math.floor(Math.random() * 250000), // Random usage for demo
          tokens_remaining: 750000,
          api_calls: 10000,
          api_calls_used: Math.floor(Math.random() * 2500),
          scans: 1000,
          scans_used: Math.floor(Math.random() * 250),
          ai_requests: 5000,
          ai_requests_used: Math.floor(Math.random() * 1250),
          osint_queries: 2000,
          osint_queries_used: Math.floor(Math.random() * 500)
        },
        features: {
          // All Light features
          basic_chat: true,
          vulnerability_scanning: true,
          basic_osint: true,
          pdf_reports: true,
          email_support: true,
          localhost_access: true,
          // Pro-specific features
          advanced_chat: true,
          stage_1_tools: true,
          stage_2_tools: true,
          advanced_pentest: true,
          premium_osint: true,
          automated_exploitation: true,
          api_access: true,
          bulk_operations: true,
          priority_support: true,
          // Enterprise features disabled
          custom_models: false,
          on_premise_deployment: false,
          dedicated_support: false,
          white_labeling: false
        }
      }
    
    case 'enterprise':
      return {
        has_access: true,
        plan_name: 'Enterprise',
        is_free_grant: false,
        limits: {
          tokens_total: -1, // Unlimited
          tokens_used: Math.floor(Math.random() * 500000), // Random usage for demo
          tokens_remaining: -1, // Unlimited
          api_calls: -1, // Unlimited
          api_calls_used: Math.floor(Math.random() * 5000),
          scans: -1, // Unlimited
          scans_used: Math.floor(Math.random() * 500),
          ai_requests: -1, // Unlimited
          ai_requests_used: Math.floor(Math.random() * 2500),
          osint_queries: -1, // Unlimited
          osint_queries_used: Math.floor(Math.random() * 1000)
        },
        features: {
          // All Light and Pro features
          basic_chat: true,
          vulnerability_scanning: true,
          basic_osint: true,
          pdf_reports: true,
          email_support: true,
          localhost_access: true,
          advanced_chat: true,
          stage_1_tools: true,
          stage_2_tools: true,
          advanced_pentest: true,
          premium_osint: true,
          automated_exploitation: true,
          api_access: true,
          bulk_operations: true,
          priority_support: true,
          // Enterprise-exclusive features
          all_features: true,
          custom_models: true,
          on_premise_deployment: true,
          dedicated_support: true,
          white_labeling: true,
          sso_integration: true,
          advanced_analytics: true,
          custom_integrations: true,
          regulatory_compliance: true,
          advanced_security: true,
          audit_logs: true
        }
      }
    
    default:
      return {
        has_access: true,
        plan_name: 'Light',
        is_free_grant: false,
        limits: {
          tokens_total: 100000,
          tokens_used: Math.floor(Math.random() * 25000),
          tokens_remaining: 75000,
          api_calls: 1000,
          api_calls_used: Math.floor(Math.random() * 250),
          scans: 100,
          scans_used: Math.floor(Math.random() * 25)
        },
        features: {
          basic_chat: true,
          vulnerability_scanning: true,
          basic_osint: true,
          pdf_reports: true,
          email_support: true,
          localhost_access: true
        }
      }
  }
}

// Development info for debugging
export const getDevInfo = () => {
  return {
    isLocalhost: isLocalhost(),
    isDevelopmentMode: isDevelopmentMode(),
    hasLocalhostAccess: hasLocalhostAccess(),
    shouldBypassAuth: shouldBypassAuth(),
    hasUnlimitedAccess: hasUnlimitedAccess(),
    runtimeOverride: typeof window !== 'undefined' ? (window as any).COBRA_DEV_MODE : 'undefined',
    hostname: typeof window !== 'undefined' ? window.location.hostname : 'unknown',
    port: typeof window !== 'undefined' ? window.location.port : 'unknown',
    url: typeof window !== 'undefined' ? window.location.href : 'unknown',
    nodeEnv: process.env.NODE_ENV,
    devConfig: DEV_CONFIG
  }
}

// Initialize runtime override if on localhost and not set
if (typeof window !== 'undefined' && isLocalhost()) {
  if (typeof (window as any).COBRA_DEV_MODE === 'undefined') {
    // Check localStorage for persisted dev mode state
    const savedDevMode = localStorage.getItem('COBRA_DEV_MODE')
    if (savedDevMode !== null) {
      (window as any).COBRA_DEV_MODE = savedDevMode === 'true'
      console.log('🔧 Restored dev mode from localStorage:', savedDevMode === 'true')
    } else {
      // AUTO-ENABLE dev mode on localhost for better UX
      (window as any).COBRA_DEV_MODE = true
      localStorage.setItem('COBRA_DEV_MODE', 'true')
      console.log('🔧 Auto-enabled dev mode on localhost (first visit)')
    }
  }
}

// Function to manually set dev mode (for testing)
export const setDevMode = (enabled: boolean) => {
  if (typeof window !== 'undefined') {
    (window as any).COBRA_DEV_MODE = enabled
    localStorage.setItem('COBRA_DEV_MODE', enabled.toString())
    console.log(`🔧 Dev Mode ${enabled ? 'ENABLED' : 'DISABLED'} manually`)
  }
}

// Function to reset dev mode (for testing)
export const resetDevMode = () => {
  if (typeof window !== 'undefined') {
    localStorage.removeItem('COBRA_DEV_MODE')
    delete (window as any).COBRA_DEV_MODE
    console.log('🔄 Dev Mode reset - refresh page to see default state')
  }
}

// Check if dev mode is explicitly enabled (secure check)
export const isDevModeEnabled = (): boolean => {
  if (typeof window === 'undefined') return false
  
  // Must be on localhost AND have dev mode explicitly enabled by user toggle
  const devModeEnabled = (window as any).COBRA_DEV_MODE === true
  const onLocalhost = isLocalhost()
  
  return onLocalhost && devModeEnabled
}

// Check if admin dev features should be available (most secure check)
export const canShowAdminDevFeatures = (): boolean => {
  if (!isDevModeEnabled()) return false
  
  // Additional security: check if user is on the right hostname
  if (typeof window !== 'undefined') {
    const hostname = window.location.hostname
    // Only allow on localhost, not any random domain
    return hostname === 'localhost' || hostname === '127.0.0.1'
  }
  
  return false
}

// Console log dev status (only in development)
if (isDevelopmentMode()) {
  console.log('🔧 Zypheron Development Mode:', getDevInfo())
} 