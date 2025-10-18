/**
 * API Response Validation Utility
 * Validates API responses to prevent crashes from malformed data
 * 
 * Fixes: HIGH PRIORITY #4 - Unvalidated API Responses
 */

import { z, ZodSchema } from 'zod'

/**
 * Common response schemas
 */
export const MessageResponseSchema = z.object({
  message: z.string(),
  metadata: z.object({
    threatLevel: z.enum(['high', 'medium', 'low', 'unknown']).optional(),
    tool: z.string().optional(),
    command: z.string().optional(),
  }).optional(),
})

export const PentestResponseSchema = z.object({
  target: z.string(),
  timestamp: z.string(),
  tests_performed: z.array(z.string()),
  results: z.record(z.any()),
  summary: z.object({
    risk_level: z.string(),
    total_issues: z.number(),
    security_score: z.number().optional(),
    recommendations: z.array(z.string()).optional(),
  }).optional(),
})

export const AttackPayloadResponseSchema = z.object({
  payload: z.object({
    name: z.string(),
    description: z.string(),
    target: z.string(),
    type: z.string(),
    attack_vectors: z.array(z.any()),
    detection_signatures: z.array(z.string()).optional(),
    mitigation_strategies: z.array(z.string()).optional(),
  }),
})

export const AgentRecommendationsSchema = z.object({
  recommendations: z.object({
    tools: z.array(z.object({
      name: z.string(),
      description: z.string(),
      usage: z.string(),
    })),
    techniques: z.array(z.object({
      name: z.string(),
      description: z.string(),
      steps: z.array(z.string()),
    })),
    nextSteps: z.array(z.string()),
    contextualInfo: z.string().optional(),
  }),
})

/**
 * Generic API response wrapper
 */
export interface ApiResponse<T> {
  success: boolean
  data?: T
  error?: string
  status?: number
}

/**
 * Validate API response against a schema
 */
export const validateResponse = <T>(
  data: unknown,
  schema: ZodSchema<T>
): ApiResponse<T> => {
  try {
    const validated = schema.parse(data)
    return {
      success: true,
      data: validated,
    }
  } catch (error) {
    console.error('API Response validation failed:', error)
    
    if (error instanceof z.ZodError) {
      const issues = error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join(', ')
      return {
        success: false,
        error: `Invalid response format: ${issues}`,
      }
    }
    
    return {
      success: false,
      error: 'Failed to validate API response',
    }
  }
}

/**
 * Safe fetch wrapper with response validation
 */
export const safeFetch = async <T>(
  url: string,
  options: RequestInit,
  schema: ZodSchema<T>
): Promise<ApiResponse<T>> => {
  try {
    const response = await fetch(url, options)
    
    // Check HTTP status
    if (!response.ok) {
      let errorMessage = `HTTP ${response.status}: ${response.statusText}`
      
      // Try to parse error message from response body
      try {
        const errorData = await response.json()
        if (errorData.message) {
          errorMessage = errorData.message
        } else if (errorData.error) {
          errorMessage = errorData.error
        }
      } catch (e) {
        // Couldn't parse error body, use default message
      }
      
      return {
        success: false,
        error: errorMessage,
        status: response.status,
      }
    }
    
    // Parse JSON response
    let data: unknown
    try {
      data = await response.json()
    } catch (error) {
      return {
        success: false,
        error: 'Failed to parse JSON response',
        status: response.status,
      }
    }
    
    // Validate against schema
    return validateResponse(data, schema)
    
  } catch (error) {
    console.error('Fetch error:', error)
    
    // Network or other errors
    if (error instanceof TypeError && error.message.includes('Failed to fetch')) {
      return {
        success: false,
        error: 'Network error: Unable to connect to server. Please check your internet connection.',
      }
    }
    
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
    }
  }
}

/**
 * Partial validation - validates what's present but allows missing fields
 */
export const validatePartial = <T>(
  data: unknown,
  schema: ZodSchema<T>
): ApiResponse<Partial<T>> => {
  try {
    const partialSchema = schema.partial()
    const validated = partialSchema.parse(data)
    return {
      success: true,
      data: validated,
    }
  } catch (error) {
    console.error('Partial validation failed:', error)
    return {
      success: false,
      error: 'Failed to validate response',
    }
  }
}

/**
 * Sanitize user input to prevent XSS
 */
export const sanitizeInput = (input: string): string => {
  // Basic HTML entity encoding
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
}

/**
 * Validate URL format
 */
export const isValidUrl = (url: string): boolean => {
  try {
    new URL(url)
    return true
  } catch {
    return false
  }
}

/**
 * Validate email format
 */
export const isValidEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

/**
 * Rate limiting helper
 */
class RateLimiter {
  private requests: Map<string, number[]> = new Map()
  
  constructor(
    private maxRequests: number,
    private windowMs: number
  ) {}
  
  /**
   * Check if request should be allowed
   */
  canMakeRequest(key: string): boolean {
    const now = Date.now()
    const timestamps = this.requests.get(key) || []
    
    // Remove timestamps outside the window
    const validTimestamps = timestamps.filter(ts => now - ts < this.windowMs)
    
    if (validTimestamps.length >= this.maxRequests) {
      return false
    }
    
    validTimestamps.push(now)
    this.requests.set(key, validTimestamps)
    return true
  }
  
  /**
   * Get time until next request is allowed (in ms)
   */
  getTimeUntilNextRequest(key: string): number {
    const timestamps = this.requests.get(key) || []
    if (timestamps.length < this.maxRequests) {
      return 0
    }
    
    const oldestTimestamp = timestamps[0]
    const timeUntilExpiry = this.windowMs - (Date.now() - oldestTimestamp)
    return Math.max(0, timeUntilExpiry)
  }
  
  /**
   * Reset rate limit for a key
   */
  reset(key: string): void {
    this.requests.delete(key)
  }
}

// Export a default rate limiter (10 requests per minute)
export const defaultRateLimiter = new RateLimiter(10, 60000)

/**
 * Retry logic with exponential backoff
 */
export const retryWithBackoff = async <T>(
  fn: () => Promise<T>,
  maxRetries: number = 3,
  baseDelay: number = 1000
): Promise<T> => {
  let lastError: Error | undefined
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn()
    } catch (error) {
      lastError = error instanceof Error ? error : new Error('Unknown error')
      
      if (attempt < maxRetries) {
        const delay = baseDelay * Math.pow(2, attempt)
        console.log(`Retry attempt ${attempt + 1}/${maxRetries} after ${delay}ms`)
        await new Promise(resolve => setTimeout(resolve, delay))
      }
    }
  }
  
  throw lastError
}

