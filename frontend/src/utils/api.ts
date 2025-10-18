import { Session } from '@supabase/supabase-js'
import { getApiUrl, getCommonHeaders } from '../config/api.config'

interface ApiRequestOptions {
  method?: string
  headers?: Record<string, string>
  body?: any
  session?: Session | null
}

/**
 * Make an authenticated API request to the backend
 */
export const makeAuthenticatedRequest = async (
  endpoint: string, 
  options: ApiRequestOptions = {}
): Promise<Response> => {
  // Use centralized API URL construction
  const url = getApiUrl(endpoint.startsWith('/api') ? endpoint : `/api${endpoint}`)
  
  // Get common headers with auth
  const token = options.session?.access_token
  const baseHeaders = getCommonHeaders(!!token, token)
  
  // Merge with custom headers
  const headers: Record<string, string> = {
    ...baseHeaders,
    ...options.headers
  }
  
  // Prepare fetch options
  const fetchOptions: RequestInit = {
    method: options.method || 'GET',
    headers,
  }
  
  // Add body if provided
  if (options.body) {
    fetchOptions.body = typeof options.body === 'string' 
      ? options.body 
      : JSON.stringify(options.body)
  }
  
  return fetch(url, fetchOptions)
}

/**
 * Make an authenticated API request and parse JSON response
 */
export const makeAuthenticatedJsonRequest = async <T = any>(
  endpoint: string, 
  options: ApiRequestOptions = {}
): Promise<T> => {
  const response = await makeAuthenticatedRequest(endpoint, options)
  
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ message: 'Unknown error' }))
    throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`)
  }
  
  return response.json()
}

/**
 * Common API endpoints
 */
export const API_ENDPOINTS = {
  PENTEST_SCAN: '/pentest/scan',
  PENTEST_ANALYZE: '/chat/analyze-pentest',
  ATTACK_PAYLOAD: '/attack/generate-payload',
  CHAT_MESSAGE: '/chat/message',
  THREAT_ANALYZE: '/threat/analyze',
  THREAT_SECURITY_SCAN: '/threat/security-scan',
} as const 