import { supabase } from '../server'

interface AccessLevel {
  has_access: boolean
  plan_name: string
  is_free_grant: boolean
  limits: Record<string, number>
  features: Record<string, boolean>
}

// Developer email for unlimited access
const DEVELOPER_EMAIL = 'shabblezam@gmail.com'

export class UsageService {
  // In-memory token tracking per provider for development/non-Supabase runs
  private static providerTokenUsage: Map<string, { [provider: string]: { used: number, periodStart: number } }> = new Map()

  static getProviderForModel(model: string): string {
    const id = model.toLowerCase()
    if (id.startsWith('gpt-')) return 'openai'
    if (id.startsWith('gpt5') || id.startsWith('gpt-5')) return 'openai'
    if (id.startsWith('gemini')) return 'google'
    if (id.startsWith('grok')) return 'xai'
    if (id.startsWith('claude')) return 'anthropic'
    if (id.startsWith('moonshot') || id.startsWith('kimi')) return 'moonshot'
    return 'unknown'
  }

  static isModelAllowedForPlan(planName: string, model: string): boolean {
    const plan = (planName || '').toLowerCase()
    const id = model.toLowerCase()

    // Dev and enterprise allow everything
    if (plan.includes('developer') || plan.includes('enterprise')) return true

    // Free trial: Kimi K2 only
    if (plan.includes('trial') || plan.includes('free trial') || plan.includes('14-day')) {
      return id.startsWith('moonshot') || id.startsWith('kimi')
    }

    // Light: all except grok-4, gpt-5, claude-4-opus
    if (plan.includes('light')) {
      const disallowed = [
        'grok-4',
        'gpt-5',
        'claude-4-opus'
      ]
      return !disallowed.some(d => id.startsWith(d))
    }

    // Pro: all
    if (plan.includes('pro')) return true

    // Default: be conservative
    return false
  }

  private static getProviderLimitForPlan(planName: string, provider: string): number | -1 {
    const plan = (planName || '').toLowerCase()
    if (plan.includes('developer') || plan.includes('enterprise')) return -1
    if (plan.includes('pro')) return 2_000_000 // 2M per provider
    if (plan.includes('light')) return 1_000_000 // 1M total; enforce per provider for simplicity
    if (plan.includes('trial')) return 100_000 // small cap for trial
    return 0
  }

  private static addProviderTokensDev(userId: string, provider: string, tokens: number) {
    const now = Date.now()
    const periodMs = 1000 * 60 * 60 * 24 * 30 // roughly monthly
    const record = this.providerTokenUsage.get(userId) || {}
    const prov = record[provider] || { used: 0, periodStart: now }
    if (now - prov.periodStart > periodMs) {
      prov.used = 0
      prov.periodStart = now
    }
    prov.used += tokens
    record[provider] = prov
    this.providerTokenUsage.set(userId, record)
  }

  private static getProviderUsedDev(userId: string, provider: string): number {
    const record = this.providerTokenUsage.get(userId)
    return record?.[provider]?.used || 0
  }

  static async validateModelAccess(userId: string, model: string, estimatedTokens: number): Promise<{ allowed: boolean, reason?: string, plan?: string, provider: string }>{
    const provider = this.getProviderForModel(model)
    // Dev user: allow
    if (userId === 'dev-user' || process.env.NODE_ENV === 'development' || !supabase) {
      // Track dev usage in-memory only
      this.addProviderTokensDev(userId, provider, 0)
      return { allowed: true, provider, plan: 'Developer Mode' }
    }

    const access = await this.getUserAccessLevel(userId)
    if (!access?.has_access) {
      return { allowed: false, reason: 'No access', provider, plan: access?.plan_name }
    }

    if (!this.isModelAllowedForPlan(access.plan_name, model)) {
      return { allowed: false, reason: `Model '${model}' not allowed for plan ${access.plan_name}`, provider, plan: access.plan_name }
    }

    const limit = this.getProviderLimitForPlan(access.plan_name, provider)
    if (limit === -1) return { allowed: true, provider, plan: access.plan_name }

    // For Supabase-enabled paths we do not have per-provider counters; approximate by dev map
    const used = this.getProviderUsedDev(userId, provider)
    if (used + estimatedTokens > limit) {
      return { allowed: false, reason: `Token limit exceeded for ${provider}: ${used}/${limit}`, provider, plan: access.plan_name }
    }
    return { allowed: true, provider, plan: access.plan_name }
  }
  
  // Track API usage
  static async trackUsage(userId: string, featureName: string, count: number = 1) {
    try {
      const today = new Date().toISOString().split('T')[0]
      
      const { error } = await supabase
        .from('usage_tracking')
        .upsert({
          user_id: userId,
          feature_name: featureName,
          count,
          date: today
        }, {
          onConflict: 'user_id,feature_name,date'
        })

      if (error) console.error('Usage tracking error:', error)
    } catch (error) {
      console.error('Usage tracking failed:', error)
    }
  }

  // Track token usage for AI models using new database function
  static async trackTokens(userId: string, tokens: number, serviceType: string = 'chat', sessionId?: string, metadata?: any) {
    try {
      // Track dev usage per provider in-memory too
      if (!supabase || userId === 'dev-user' || process.env.NODE_ENV === 'development') {
        const provider = metadata?.provider
        if (provider) this.addProviderTokensDev(userId, provider, tokens)
      }
      const { data, error } = await supabase
        .rpc('consume_tokens', {
          user_uuid: userId,
          tokens: tokens,
          service: serviceType,
          session_uuid: sessionId,
          extra_metadata: metadata || {}
        })

      if (error) {
        console.error('Token consumption error:', error)
        return false
      }

      return data // Returns boolean indicating if tokens were consumed successfully
    } catch (error) {
      console.error('Token tracking failed:', error)
      return false
    }
  }

  // Check if user has access to feature
  static async checkAccess(userId: string, featureName: string): Promise<boolean> {
    try {
      const accessLevel = await this.getUserAccessLevel(userId)

      if (!accessLevel) return false

      // Developer mode - unlimited access
      if (accessLevel.plan_name === 'Developer Mode' || accessLevel.features?.all_features) {
        return true
      }

      // Check if user has subscription access
      if (!accessLevel.has_access) {
        return false
      }

      // Check specific feature access based on plan
      if (accessLevel.features?.[featureName]) {
        return true
      }

      // For token-based features, check if user has tokens remaining
      if (featureName === 'tokens' || featureName === 'chat' || featureName === 'ai_requests') {
        const tokenLimit = accessLevel.limits?.tokens_total || 0
        const tokensUsed = accessLevel.limits?.tokens_used || 0
        
        // Unlimited tokens (-1) or has remaining tokens
        return tokenLimit === -1 || tokensUsed < tokenLimit
      }

      return accessLevel.has_access
    } catch (error) {
      console.error('Access check failed:', error)
      return false
    }
  }

  // Get user's current usage for a feature
  static async getCurrentUsage(userId: string, featureName: string): Promise<number> {
    try {
      const today = new Date().toISOString().split('T')[0]
      const { data: usage } = await supabase
        .from('usage_tracking')
        .select('count')
        .eq('user_id', userId)
        .eq('feature_name', featureName)
        .eq('date', today)
        .single()

      return usage?.count || 0
    } catch (error) {
      console.error('Failed to get current usage:', error)
      return 0
    }
  }

  // Get user's access level and limits
  static async getUserAccessLevel(userId: string): Promise<AccessLevel> {
    try {
      // Developer bypass for localhost/dev user
      if (userId === 'dev-user' || process.env.NODE_ENV === 'development') {
        return {
          has_access: true,
          plan_name: 'Developer Mode',
          is_free_grant: true,
          limits: { tokens_total: -1, tokens_used: 0, tokens_remaining: -1 },
          features: { all_features: true, unlimited_tokens: true }
        }
      }
      // If Supabase is not configured (development mode), return developer access
      if (!supabase) {
        console.warn("  Supabase not configured - granting developer access for development mode")
        return {
          has_access: true,
          plan_name: "Developer Mode",
          is_free_grant: true,
          limits: { tokens_total: -1, tokens_used: 0, tokens_remaining: -1 },
          features: { all_features: true, unlimited_tokens: true }
        }
      }

      // Use our new database function to get access level
      const { data: accessData, error } = await supabase
        .rpc('get_user_access_level', { user_uuid: userId })

      if (error) {
        console.error('Access level error:', error)
        throw error
      }

      // Return the first row (should only be one)
      return (accessData?.[0] as AccessLevel) || {
        has_access: false,
        plan_name: 'Free',
        is_free_grant: false,
        limits: { tokens_total: 0, tokens_used: 0, tokens_remaining: 0 },
        features: { view_only: true }
      }
    } catch (error) {
      console.error('Failed to get user access level:', error)
      return {
        has_access: false,
        plan_name: 'Unknown',
        is_free_grant: false,
        limits: { tokens_total: 0, tokens_used: 0, tokens_remaining: 0 },
        features: {}
      }
    }
  }

  // Check if user has stage access
  static async hasStageAccess(userId: string, stage: 1 | 2 | 3): Promise<boolean> {
    try {
      const accessLevel = await this.getUserAccessLevel(userId)
      
      // Developer access has all stages
      if (accessLevel.plan_name === 'Developer Mode' || accessLevel.features?.all_features) {
        return true
      }

      // Check specific stage access based on plan
      switch (stage) {
        case 1:
          return accessLevel.has_access && (
            accessLevel.features?.basic_chat || 
            accessLevel.features?.vulnerability_scanning ||
            accessLevel.plan_name !== 'Free'
          )
        case 2:
          return accessLevel.has_access && (
            accessLevel.features?.advanced_pentest ||
            accessLevel.features?.premium_osint ||
            ['Pro', 'Enterprise'].includes(accessLevel.plan_name)
          )
        case 3:
          return accessLevel.has_access && (
            accessLevel.features?.automated_exploitation ||
            accessLevel.features?.custom_models ||
            accessLevel.plan_name === 'Enterprise'
          )
        default:
          return false
      }
    } catch (error) {
      console.error('Stage access check failed:', error)
      return false
    }
  }

  // Check if user can use tokens (before AI model calls)
  static async canUseTokens(userId: string, estimatedTokens: number): Promise<boolean> {
    try {
      const accessLevel = await this.getUserAccessLevel(userId)
      
      // Check for unlimited access (developer mode or enterprise)
      if (accessLevel.plan_name === 'Developer Mode' || 
          accessLevel.features?.all_features ||
          accessLevel.limits?.tokens_total === -1) {
        return true
      }

      // Check if user has access at all
      if (!accessLevel.has_access) {
        return false
      }

      // Check current token usage
      const tokensRemaining = accessLevel.limits?.tokens_remaining || 0
      
      return estimatedTokens <= tokensRemaining
    } catch (error) {
      console.error('Token access check failed:', error)
      return false
    }
  }

  // Get usage summary for dashboard
  static async getUsageSummary(userId: string) {
    try {
      const today = new Date().toISOString().split('T')[0]
      const accessLevel = await this.getUserAccessLevel(userId)

      const { data: usageData } = await supabase
        .from('usage_tracking')
        .select('feature_name, count')
        .eq('user_id', userId)
        .eq('date', today)

      const usage = {
        api_calls: 0,
        ai_requests: 0,
        osint_queries: 0,
        total_tokens: 0
      }

      usageData?.forEach(item => {
        if (item.feature_name in usage) {
          usage[item.feature_name as keyof typeof usage] = item.count
        }
      })

      return {
        usage,
        limits: accessLevel.limits,
        plan_name: accessLevel.plan_name,
        is_free_grant: accessLevel.is_free_grant,
        features: accessLevel.features
      }
    } catch (error) {
      console.error('Failed to get usage summary:', error)
      return {
        usage: { api_calls: 0, ai_requests: 0, osint_queries: 0, total_tokens: 0 },
        limits: {},
        plan_name: 'Unknown',
        is_free_grant: false,
        features: {}
      }
    }
  }
} 

