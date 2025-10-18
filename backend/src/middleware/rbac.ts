import { Request, Response, NextFunction } from 'express'
import { supabase } from '../server'
import jwt from 'jsonwebtoken'

// User role interface
export interface UserRole {
  role: string
  can_bypass_mfa: boolean
  can_extend_session: boolean
  has_unlimited_tokens: boolean
  max_session_duration_hours: number
  features: Record<string, boolean>
}

// Extend Request interface to include user role
declare global {
  namespace Express {
    interface Request {
      user?: any
      userRole?: UserRole
    }
  }
}

/**
 * Enhanced authentication middleware with RBAC support
 */
export const enhancedAuthMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    // Skip authentication if Supabase is not configured (development mode)
    if (!supabase) {
      console.warn('⚠️  Auth middleware: Supabase not configured, allowing request in development mode')
      req.user = { id: 'dev-user', email: 'dev@cobraai.com', role: 'admin_dev' }
      req.userRole = {
        role: 'admin_dev',
        can_bypass_mfa: true,
        can_extend_session: true,
        has_unlimited_tokens: true,
        max_session_duration_hours: 8760,
        features: { all_features: true, debug_mode: true }
      }
      next()
      return
    }

    // Development bypass: allow admin_dev tokens
    const isLocalhost = req.headers.host?.includes('localhost') || req.headers.host?.includes('127.0.0.1')
    const isDevelopment = process.env.NODE_ENV !== 'production'
    const hasDevBypass = process.env.ALLOW_LOCALHOST_DEV === 'true'
    
    if (isDevelopment || hasDevBypass || isLocalhost) {
      const devBypassHeader = req.headers['x-dev-bypass']
      const authHeaderDev = req.headers.authorization || ''
      
      if (devBypassHeader === 'true' || authHeaderDev.includes('localhost-dev-token')) {
        console.warn('⚠️  Enhanced Auth middleware: Dev bypass active, accepting localhost token')
        console.warn(`   - NODE_ENV: ${process.env.NODE_ENV}`)
        console.warn(`   - isDevelopment: ${isDevelopment}`)
        console.warn(`   - isLocalhost: ${isLocalhost}`)
        req.user = { id: 'dev-user', email: 'dev@cobraai.com', role: 'admin_dev' }
        req.userRole = {
          role: 'admin_dev',
          can_bypass_mfa: true,
          can_extend_session: true,
          has_unlimited_tokens: true,
          max_session_duration_hours: 8760,
          features: { all_features: true, debug_mode: true }
        }
        next()
        return
      }
    }

    const authHeader = req.headers.authorization
    if (!authHeader) {
      res.status(401).json({ error: 'No authorization header' })
      return
    }

    const token = authHeader.replace('Bearer ', '')
    
    // Get user from Supabase
    const supabaseClient = supabase as NonNullable<typeof supabase>
    const { data, error } = await supabaseClient.auth.getUser(token)

    if (error || !data.user) {
      res.status(401).json({ error: 'Invalid token' })
      return
    }

    // Get user role and permissions from database
    const { data: roleData, error: roleError } = await supabaseClient
      .rpc('get_user_access_level', { check_user_id: data.user.id })

    if (roleError) {
      console.error('Failed to get user role:', roleError)
      res.status(500).json({ error: 'Failed to verify user permissions' })
      return
    }

    const userRole: UserRole = roleData?.[0] || {
      role: 'user',
      can_bypass_mfa: false,
      can_extend_session: false,
      has_unlimited_tokens: false,
      max_session_duration_hours: 24,
      features: {}
    }

    // Check if token needs refresh for admin_dev users with extended sessions
    if (userRole.role === 'admin_dev' && userRole.can_extend_session) {
      const tokenInfo = jwt.decode(token) as any
      if (tokenInfo?.exp) {
        const expiresAt = new Date(tokenInfo.exp * 1000)
        const now = new Date()
        const hoursUntilExpiry = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60)
        
        // If token expires in less than threshold, suggest refresh
        const refreshThreshold = parseInt(process.env.SESSION_REFRESH_THRESHOLD_HOURS || '2')
        if (hoursUntilExpiry < refreshThreshold) {
          res.setHeader('X-Token-Refresh-Suggested', 'true')
          res.setHeader('X-Token-Expires-In-Hours', hoursUntilExpiry.toFixed(2))
        }
      }
    }

    req.user = { ...data.user, role: userRole.role }
    req.userRole = userRole
    next()
  } catch (error) {
    console.error('Authentication error:', error)
    res.status(401).json({ error: 'Authentication failed' })
  }
}

/**
 * Middleware to check for admin_dev role
 */
export const adminDevMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    if (!req.userRole) {
      res.status(401).json({ error: 'User not authenticated' })
      return
    }

    if (req.userRole.role !== 'admin_dev') {
      res.status(403).json({ 
        error: 'Admin developer access required',
        required_role: 'admin_dev',
        current_role: req.userRole.role
      })
      return
    }

    // Log admin_dev access for security auditing
    if (process.env.ENABLE_SECURITY_AUDIT_LOGS === 'true') {
      console.log(`🔐 Admin dev access: ${req.user?.email} - ${req.method} ${req.path}`)
    }

    next()
  } catch (error) {
    res.status(403).json({ error: 'Admin developer verification failed' })
  }
}

/**
 * Middleware to check for any admin role (admin or admin_dev)
 */
export const adminMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    if (!req.userRole) {
      res.status(401).json({ error: 'User not authenticated' })
      return
    }

    if (!['admin', 'admin_dev'].includes(req.userRole.role)) {
      res.status(403).json({ 
        error: 'Admin access required',
        required_role: 'admin or admin_dev',
        current_role: req.userRole.role
      })
      return
    }

    next()
  } catch (error) {
    res.status(403).json({ error: 'Admin verification failed' })
  }
}

/**
 * Middleware to check for elevated access (analyst, admin, or admin_dev)
 */
export const elevatedAccessMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    if (!req.userRole) {
      res.status(401).json({ error: 'User not authenticated' })
      return
    }

    if (!['analyst', 'admin', 'admin_dev'].includes(req.userRole.role)) {
      res.status(403).json({ 
        error: 'Elevated access required',
        required_role: 'analyst, admin, or admin_dev',
        current_role: req.userRole.role
      })
      return
    }

    next()
  } catch (error) {
    res.status(403).json({ error: 'Access verification failed' })
  }
}

/**
 * Generate extended session token for admin_dev users
 */
export const generateExtendedToken = async (userId: string, email: string): Promise<string> => {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET not configured')
  }

  const sessionDuration = parseInt(process.env.ADMIN_DEV_SESSION_DURATION_HOURS || '8760') // Default 1 year

  const payload = {
    sub: userId,
    email,
    role: 'admin_dev',
    aud: 'authenticated',
    exp: Math.floor(Date.now() / 1000) + (sessionDuration * 60 * 60),
    iat: Math.floor(Date.now() / 1000),
    extended_session: true
  }

  return jwt.sign(payload, process.env.JWT_SECRET as string)
}

/**
 * Check if user can bypass MFA
 */
export const canBypassMFA = (userRole: UserRole): boolean => {
  return userRole.role === 'admin_dev' && 
         userRole.can_bypass_mfa && 
         process.env.ADMIN_DEV_MFA_BYPASS === 'true'
}

/**
 * Check if user can have extended sessions
 */
export const canExtendSession = (userRole: UserRole): boolean => {
  return userRole.role === 'admin_dev' && 
         userRole.can_extend_session && 
         process.env.ADMIN_DEV_EXTENDED_SESSIONS === 'true'
}

/**
 * Utility function to get user permissions
 */
export const getUserPermissions = (userRole: UserRole) => {
  return {
    role: userRole.role,
    features: userRole.features,
    canBypassMFA: canBypassMFA(userRole),
    canExtendSession: canExtendSession(userRole),
    hasUnlimitedTokens: userRole.has_unlimited_tokens,
    maxSessionHours: userRole.max_session_duration_hours
  }
}
