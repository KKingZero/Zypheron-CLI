/**
 * Centralized API Configuration
 * All API endpoints and URLs should reference this file
 */

// Get environment variables with fallbacks
const getEnvVar = (key: string, fallback: string): string => {
  return import.meta.env[key] || fallback
}

// API Base URLs
export const API_CONFIG = {
  // Primary backend API
  BASE_URL: getEnvVar('VITE_API_URL', 'http://localhost:3001'),
  
  // Supabase configuration
  SUPABASE_URL: getEnvVar('VITE_SUPABASE_URL', ''),
  SUPABASE_ANON_KEY: getEnvVar('VITE_SUPABASE_ANON_KEY', ''),
  
  // Local AI providers
  LM_STUDIO_URL: getEnvVar('VITE_LM_STUDIO_URL', 'http://localhost:1234/v1'),
  OLLAMA_URL: getEnvVar('VITE_OLLAMA_URL', 'http://localhost:11434'),
  DOCKER_OLLAMA_URL: getEnvVar('VITE_DOCKER_OLLAMA_URL', 'http://localhost:11434/api'),
  
  // WebSocket endpoints
  WS_BASE_URL: getEnvVar('VITE_WS_URL', 'ws://localhost:3001'),
  
  // Feature flags
  ENABLE_DEV_MODE: getEnvVar('VITE_ENABLE_DEV_MODE', 'false') === 'true',
  ENABLE_LOCALHOST_BYPASS: getEnvVar('VITE_ALLOW_LOCALHOST_DEV', 'false') === 'true',
} as const

// API Endpoints - centralized endpoint definitions
export const API_ENDPOINTS = {
  // Authentication
  AUTH: {
    LOGIN: '/api/auth/login',
    LOGOUT: '/api/auth/logout',
    REFRESH: '/api/auth/refresh',
  },
  
  // Chat
  CHAT: {
    SEND: '/api/chat',
    SESSIONS: '/api/chat/sessions',
    HISTORY: '/api/chat/history',
  },
  
  // Pentest
  PENTEST: {
    SCAN: '/api/pentest/scan',
    RESULTS: '/api/pentest/results',
  },
  
  // Red Team Operations
  RED_TEAM: {
    AGENT: {
      ANALYZE: '/api/agent/analyze-assessment',
      REASONING: '/api/agent/reasoning',
      PATCH: '/api/agent/patch',
    },
    TOOLS: {
      EXECUTE: '/api/tools/execute',
    },
  },
  
  // Threat Intelligence
  THREAT: {
    ANALYZE: '/api/threat/analyze',
  },
  
  // Brute Force
  BRUTE_FORCE: {
    NATIVE: '/api/bruteforce/native/attack',
    HYDRA: '/api/bruteforce/hydra/attack',
  },
  
  // Advanced Pentest
  ADVANCED_PENTEST: {
    POST_EXPLOIT: {
      ESCALATE: '/api/advanced-pentest/post-exploit/escalate',
      HARVEST_CREDS: '/api/advanced-pentest/post-exploit/harvest-credentials',
      LATERAL_MOVEMENT: '/api/advanced-pentest/post-exploit/lateral-movement',
      PERSISTENCE: '/api/advanced-pentest/post-exploit/establish-persistence',
    },
    WEB_SECURITY: {
      TEST_GRAPHQL: '/api/advanced-pentest/web-security/test-graphql',
      INTELLIGENT_FUZZ: '/api/advanced-pentest/web-security/intelligent-fuzzing',
      TEST_BUSINESS_LOGIC: '/api/advanced-pentest/web-security/test-business-logic',
      TEST_JWT: '/api/advanced-pentest/web-security/test-jwt',
      TEST_CORS: '/api/advanced-pentest/web-security/test-cors',
    },
    CLOUD_SECURITY: {
      ASSESS_AWS: '/api/advanced-pentest/cloud-security/assess-aws',
      ASSESS_AZURE: '/api/advanced-pentest/cloud-security/assess-azure',
      ASSESS_GCP: '/api/advanced-pentest/cloud-security/assess-gcp',
    },
    EVASION: {
      EVADE_IDS: '/api/advanced-pentest/evasion/evade-ids',
      EVADE_AV: '/api/advanced-pentest/evasion/evade-av',
      BYPASS_WAF: '/api/advanced-pentest/evasion/bypass-waf',
    },
    SESSIONS: {
      LIST: '/api/advanced-pentest/sessions/list',
      REGISTER: '/api/advanced-pentest/sessions/register',
      GET: '/api/advanced-pentest/sessions/:id',
    },
    WORKFLOWS: {
      AUTO_POST_EXPLOIT: '/api/advanced-pentest/workflows/auto-post-exploit',
      AUTO_WEB_ASSESSMENT: '/api/advanced-pentest/workflows/auto-web-assessment',
      AUTO_CLOUD_ASSESSMENT: '/api/advanced-pentest/workflows/auto-cloud-assessment',
    },
  },
} as const

/**
 * Get full API URL
 * @param endpoint - Endpoint path (with or without leading slash)
 */
export const getApiUrl = (endpoint: string): string => {
  const baseUrl = API_CONFIG.BASE_URL.replace(/\/$/, '') // Remove trailing slash
  const path = endpoint.startsWith('/') ? endpoint : `/${endpoint}`
  return `${baseUrl}${path}`
}

/**
 * Get WebSocket URL
 * @param endpoint - Endpoint path (with or without leading slash)
 */
export const getWsUrl = (endpoint: string = ''): string => {
  const baseUrl = API_CONFIG.WS_BASE_URL.replace(/\/$/, '')
  const path = endpoint.startsWith('/') ? endpoint : `/${endpoint}`
  return `${baseUrl}${path}`
}

/**
 * Check if running in development mode
 */
export const isDevelopment = (): boolean => {
  return import.meta.env.DEV || import.meta.env.MODE === 'development'
}

/**
 * Check if localhost bypass is enabled
 */
export const isLocalhostBypassEnabled = (): boolean => {
  if (!isDevelopment()) return false
  
  try {
    if (typeof window !== 'undefined') {
      const isLocal = window.location.hostname === 'localhost' || 
                     window.location.hostname === '127.0.0.1'
      return isLocal && API_CONFIG.ENABLE_LOCALHOST_BYPASS
    }
  } catch {}
  
  return false
}

/**
 * Get common headers for API requests
 */
export const getCommonHeaders = (includeAuth: boolean = false, token?: string): Record<string, string> => {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  
  // Add auth header if provided
  if (includeAuth && token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  
  // Add dev bypass header in development
  if (isLocalhostBypassEnabled()) {
    headers['x-dev-bypass'] = 'true'
  }
  
  return headers
}

// Export for backward compatibility
export default API_CONFIG

