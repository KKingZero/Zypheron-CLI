/**
 * AI Rate Limiter
 * Prevents API quota exhaustion with intelligent throttling
 */

import { EventEmitter } from 'events'

export interface RateLimitConfig {
  provider: string
  requestsPerMinute: number
  requestsPerHour: number
  requestsPerDay: number
  tokensPerMinute?: number
  costPerRequest?: number
  maxDailyCost?: number
}

export interface RateLimitStatus {
  provider: string
  requestsThisMinute: number
  requestsThisHour: number
  requestsThisDay: number
  tokensThisMinute: number
  costToday: number
  isThrottled: boolean
  resetTimes: {
    minute: Date
    hour: Date
    day: Date
  }
}

export class AIRateLimiter extends EventEmitter {
  private limits: Map<string, RateLimitConfig> = new Map()
  private usage: Map<string, RateLimitStatus> = new Map()
  private requestQueue: Map<string, Array<() => void>> = new Map()

  constructor() {
    super()
    this.initializeDefaultLimits()
    this.startResetTimers()
  }

  /**
   * Initialize default rate limits for AI providers
   */
  private initializeDefaultLimits() {
    // OpenAI GPT-4
    this.setRateLimit('openai-gpt4', {
      provider: 'openai-gpt4',
      requestsPerMinute: 500,
      requestsPerHour: 10000,
      requestsPerDay: 100000,
      tokensPerMinute: 150000,
      costPerRequest: 0.03,
      maxDailyCost: 100
    })

    // OpenAI GPT-3.5
    this.setRateLimit('openai-gpt3.5', {
      provider: 'openai-gpt3.5',
      requestsPerMinute: 3000,
      requestsPerHour: 50000,
      requestsPerDay: 500000,
      tokensPerMinute: 90000,
      costPerRequest: 0.002,
      maxDailyCost: 50
    })

    // Claude
    this.setRateLimit('anthropic-claude', {
      provider: 'anthropic-claude',
      requestsPerMinute: 1000,
      requestsPerHour: 20000,
      requestsPerDay: 200000,
      tokensPerMinute: 100000,
      costPerRequest: 0.008,
      maxDailyCost: 75
    })

    // Gemini
    this.setRateLimit('google-gemini', {
      provider: 'google-gemini',
      requestsPerMinute: 60,
      requestsPerHour: 1000,
      requestsPerDay: 10000,
      tokensPerMinute: 32000,
      costPerRequest: 0.001,
      maxDailyCost: 25
    })

    // Local Ollama (no limits)
    this.setRateLimit('ollama', {
      provider: 'ollama',
      requestsPerMinute: 10000,
      requestsPerHour: 100000,
      requestsPerDay: 1000000,
      costPerRequest: 0,
      maxDailyCost: 0
    })
  }

  /**
   * Set rate limit for a provider
   */
  setRateLimit(provider: string, config: RateLimitConfig): void {
    this.limits.set(provider, config)
    
    if (!this.usage.has(provider)) {
      this.usage.set(provider, {
        provider,
        requestsThisMinute: 0,
        requestsThisHour: 0,
        requestsThisDay: 0,
        tokensThisMinute: 0,
        costToday: 0,
        isThrottled: false,
        resetTimes: {
          minute: new Date(Date.now() + 60000),
          hour: new Date(Date.now() + 3600000),
          day: new Date(Date.now() + 86400000)
        }
      })
    }
  }

  /**
   * Check if request can proceed
   */
  async checkLimit(provider: string, estimatedTokens: number = 1000): Promise<boolean> {
    const limit = this.limits.get(provider)
    const usage = this.usage.get(provider)

    if (!limit || !usage) {
      console.warn(`No rate limit configured for ${provider}`)
      return true
    }

    // Check all limits
    if (usage.requestsThisMinute >= limit.requestsPerMinute) {
      usage.isThrottled = true
      this.emit('rate-limit-exceeded', { provider, window: 'minute' })
      return false
    }

    if (usage.requestsThisHour >= limit.requestsPerHour) {
      usage.isThrottled = true
      this.emit('rate-limit-exceeded', { provider, window: 'hour' })
      return false
    }

    if (usage.requestsThisDay >= limit.requestsPerDay) {
      usage.isThrottled = true
      this.emit('rate-limit-exceeded', { provider, window: 'day' })
      return false
    }

    // Check token limit
    if (limit.tokensPerMinute && usage.tokensThisMinute + estimatedTokens > limit.tokensPerMinute) {
      usage.isThrottled = true
      this.emit('token-limit-exceeded', { provider, tokens: estimatedTokens })
      return false
    }

    // Check cost limit
    if (limit.maxDailyCost && usage.costToday + (limit.costPerRequest || 0) > limit.maxDailyCost) {
      usage.isThrottled = true
      this.emit('cost-limit-exceeded', { provider, cost: usage.costToday })
      return false
    }

    return true
  }

  /**
   * Wait for rate limit to allow request
   */
  async waitForLimit(provider: string, estimatedTokens: number = 1000): Promise<void> {
    const canProceed = await this.checkLimit(provider, estimatedTokens)
    
    if (canProceed) {
      return
    }

    // Calculate wait time
    const usage = this.usage.get(provider)
    if (!usage) return

    const now = Date.now()
    const minuteWait = usage.resetTimes.minute.getTime() - now
    const hourWait = usage.resetTimes.hour.getTime() - now
    const dayWait = usage.resetTimes.day.getTime() - now

    const waitTime = Math.min(
      minuteWait > 0 ? minuteWait : Infinity,
      hourWait > 0 ? hourWait : Infinity,
      dayWait > 0 ? dayWait : Infinity
    )

    if (waitTime < Infinity) {
      console.log(`⏳ Rate limited for ${provider}, waiting ${waitTime}ms...`)
      await new Promise(resolve => setTimeout(resolve, waitTime))
      
      // Retry
      return this.waitForLimit(provider, estimatedTokens)
    }
  }

  /**
   * Record request
   */
  recordRequest(provider: string, tokens: number = 1000, cost?: number): void {
    const usage = this.usage.get(provider)
    const limit = this.limits.get(provider)
    
    if (!usage || !limit) return

    usage.requestsThisMinute++
    usage.requestsThisHour++
    usage.requestsThisDay++
    usage.tokensThisMinute += tokens
    usage.costToday += cost || limit.costPerRequest || 0

    // Check if approaching limits
    if (usage.requestsThisMinute > limit.requestsPerMinute * 0.8) {
      this.emit('approaching-limit', { provider, window: 'minute', percentage: 80 })
    }

    if (usage.requestsThisHour > limit.requestsPerHour * 0.8) {
      this.emit('approaching-limit', { provider, window: 'hour', percentage: 80 })
    }

    if (usage.costToday > (limit.maxDailyCost || 0) * 0.8) {
      this.emit('approaching-cost-limit', { provider, percentage: 80 })
    }
  }

  /**
   * Get rate limit status
   */
  getStatus(provider: string): RateLimitStatus | null {
    return this.usage.get(provider) || null
  }

  /**
   * Get all statuses
   */
  getAllStatuses(): Map<string, RateLimitStatus> {
    return new Map(this.usage)
  }

  /**
   * Start reset timers
   */
  private startResetTimers(): void {
    // Reset per-minute counters
    setInterval(() => {
      this.usage.forEach(usage => {
        usage.requestsThisMinute = 0
        usage.tokensThisMinute = 0
        usage.resetTimes.minute = new Date(Date.now() + 60000)
        usage.isThrottled = false
      })
    }, 60000)

    // Reset per-hour counters
    setInterval(() => {
      this.usage.forEach(usage => {
        usage.requestsThisHour = 0
        usage.resetTimes.hour = new Date(Date.now() + 3600000)
      })
    }, 3600000)

    // Reset per-day counters
    setInterval(() => {
      this.usage.forEach(usage => {
        usage.requestsThisDay = 0
        usage.costToday = 0
        usage.resetTimes.day = new Date(Date.now() + 86400000)
      })
      this.emit('daily-reset')
    }, 86400000)
  }

  /**
   * Get recommended provider based on limits
   */
  getRecommendedProvider(providers: string[]): string | null {
    let bestProvider: string | null = null
    let bestScore = -Infinity

    for (const provider of providers) {
      const usage = this.usage.get(provider)
      const limit = this.limits.get(provider)

      if (!usage || !limit) continue

      // Calculate availability score (0-1)
      const minuteAvailability = 1 - (usage.requestsThisMinute / limit.requestsPerMinute)
      const hourAvailability = 1 - (usage.requestsThisHour / limit.requestsPerHour)
      const costAvailability = limit.maxDailyCost 
        ? 1 - (usage.costToday / limit.maxDailyCost)
        : 1

      const score = (minuteAvailability + hourAvailability + costAvailability) / 3

      if (score > bestScore) {
        bestScore = score
        bestProvider = provider
      }
    }

    return bestProvider
  }

  /**
   * Reset specific provider
   */
  resetProvider(provider: string): void {
    const usage = this.usage.get(provider)
    if (usage) {
      usage.requestsThisMinute = 0
      usage.requestsThisHour = 0
      usage.requestsThisDay = 0
      usage.tokensThisMinute = 0
      usage.costToday = 0
      usage.isThrottled = false
    }
  }

  /**
   * Reset all providers
   */
  resetAll(): void {
    this.usage.forEach((_, provider) => {
      this.resetProvider(provider)
    })
  }
}

// Singleton instance
let rateLimiterInstance: AIRateLimiter | null = null

export function getAIRateLimiter(): AIRateLimiter {
  if (!rateLimiterInstance) {
    rateLimiterInstance = new AIRateLimiter()
  }
  return rateLimiterInstance
}

