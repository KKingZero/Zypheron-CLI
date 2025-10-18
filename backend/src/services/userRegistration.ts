import { createClient } from '@supabase/supabase-js'

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY

if (!supabaseUrl || !supabaseServiceKey) {
  console.warn('Supabase configuration missing. User registration will not be saved to database.')
}

const supabase = (supabaseUrl && supabaseServiceKey && supabaseUrl !== 'your_supabase_project_url_here')
  ? createClient(supabaseUrl, supabaseServiceKey)
  : null

export interface UserRegistrationData {
  email: string
  fullName?: string
  registrationSource?: string
  referrerUrl?: string
  userAgent?: string
  ipAddress?: string
  intendedPlan?: 'free' | 'light' | 'pro' | 'enterprise'
  expectedUsage?: string
  termsAccepted?: boolean
  privacyAccepted?: boolean
}

export interface WaitlistData {
  email: string
  fullName?: string
  source?: string
  interestLevel?: 'low' | 'medium' | 'high'
  metadata?: Record<string, any>
}

export class UserRegistrationService {
  
  /**
   * Add user to waitlist (before they actually sign up)
   */
  async addToWaitlist(data: WaitlistData): Promise<{ success: boolean; error?: string }> {
    if (!supabase) {
      console.warn('Supabase not configured - skipping waitlist save')
      return { success: true } // Don't fail in demo mode
    }

    try {
      const { error } = await supabase
        .from('waitlist')
        .insert({
          email: data.email,
          full_name: data.fullName,
          source: data.source || 'signup_form',
          interest_level: data.interestLevel || 'high',
          metadata: data.metadata || {}
        })

      if (error) {
        // Handle duplicate email gracefully
        if (error.code === '23505') {
          console.log(`Email ${data.email} already on waitlist`)
          return { success: true } // Don't treat as error
        }
        throw error
      }

      console.log(`✅ Added ${data.email} to waitlist`)
      return { success: true }
    } catch (error: any) {
      console.error('Failed to add to waitlist:', error)
      return { success: false, error: error.message }
    }
  }

  /**
   * Register new user when they create an account
   */
  async registerUser(userId: string, data: UserRegistrationData): Promise<{ success: boolean; error?: string }> {
    if (!supabase) {
      console.warn('Supabase not configured - skipping user registration save')
      return { success: true } // Don't fail in demo mode
    }

    try {
      // First, insert user registration data
      const { error: regError } = await supabase
        .from('user_registrations')
        .insert({
          user_id: userId,
          email: data.email,
          full_name: data.fullName,
          registration_source: data.registrationSource || 'direct',
          referrer_url: data.referrerUrl,
          user_agent: data.userAgent,
          ip_address: data.ipAddress,
          account_status: 'active',
          email_verified: false, // Will be updated by Supabase auth
          terms_accepted: data.termsAccepted || false,
          privacy_accepted: data.privacyAccepted || false,
          intended_plan: data.intendedPlan || 'free',
          expected_usage: data.expectedUsage,
          activated_at: new Date().toISOString()
        })

      if (regError) {
        // Handle duplicate email gracefully
        if (regError.code === '23505') {
          console.log(`User ${data.email} already registered`)
          // Update existing registration with new user_id
          const { error: updateError } = await supabase
            .from('user_registrations')
            .update({
              user_id: userId,
              account_status: 'active',
              activated_at: new Date().toISOString()
            })
            .eq('email', data.email)

          if (updateError) {
            console.error('Failed to update existing registration:', updateError)
            return { success: false, error: updateError.message }
          }
        } else {
          throw regError
        }
      }

      // If user was on waitlist, promote them to registered
      await this.promoteWaitlistUser(data.email, userId)

      console.log(`✅ Registered user ${data.email} (${userId})`)
      return { success: true }
    } catch (error: any) {
      console.error('Failed to register user:', error)
      return { success: false, error: error.message }
    }
  }

  /**
   * Promote user from waitlist to registered status
   */
  async promoteWaitlistUser(email: string, userId: string): Promise<void> {
    if (!supabase) return

    try {
      // Update waitlist status if user exists
      await supabase
        .from('waitlist')
        .update({ 
          status: 'registered',
          updated_at: new Date().toISOString()
        })
        .eq('email', email)

      console.log(`📈 Promoted ${email} from waitlist to registered`)
    } catch (error) {
      console.error('Failed to promote waitlist user:', error)
      // Don't throw error as this is not critical
    }
  }

  /**
   * Update user's last login time
   */
  async updateLastLogin(userId: string, email: string): Promise<void> {
    if (!supabase) return

    try {
      await supabase
        .from('user_registrations')
        .update({ 
          last_login_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq('user_id', userId)

      console.log(`🔄 Updated last login for ${email}`)
    } catch (error) {
      console.error('Failed to update last login:', error)
      // Don't throw error as this is not critical
    }
  }

  /**
   * Get user registration data
   */
  async getUserRegistration(userId: string): Promise<any | null> {
    if (!supabase) return null

    try {
      const { data, error } = await supabase
        .from('user_registrations')
        .select('*')
        .eq('user_id', userId)
        .single()

      if (error) {
        console.error('Failed to get user registration:', error)
        return null
      }

      return data
    } catch (error) {
      console.error('Failed to get user registration:', error)
      return null
    }
  }

  /**
   * Get waitlist stats (for admin dashboard)
   */
  async getWaitlistStats(): Promise<any | null> {
    if (!supabase) return null

    try {
      const { data, error } = await supabase
        .rpc('get_waitlist_stats')

      if (error) {
        console.error('Failed to get waitlist stats:', error)
        return null
      }

      return data?.[0] || null
    } catch (error) {
      console.error('Failed to get waitlist stats:', error)
      return null
    }
  }

  /**
   * Check if Supabase is configured
   */
  isConfigured(): boolean {
    return supabase !== null
  }
}

// Export singleton instance
export const userRegistrationService = new UserRegistrationService() 