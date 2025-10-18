import { Request, Response, NextFunction } from 'express'
import { supabase } from '../server'

// Extend Request interface to include user
declare global {
  namespace Express {
    interface Request {
      user?: any
    }
  }
}

export const authMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    // Skip authentication if Supabase is not configured (development mode)
    if (!supabase) {
      console.warn('⚠️  Auth middleware: Supabase not configured, allowing request in development mode')
      req.user = { id: 'dev-user', email: 'dev@cobraai.com' }
      next()
      return
    }

    // Development bypass: allow a special token or header when not in production
    if (process.env.NODE_ENV !== 'production') {
      const devBypassHeader = req.headers['x-dev-bypass']
      const authHeaderDev = req.headers.authorization || ''
      if (devBypassHeader === 'true' || authHeaderDev.includes('localhost-dev-token')) {
        console.warn('⚠️  Auth middleware: Dev bypass active, accepting localhost token')
        req.user = { id: 'dev-user', email: 'dev@cobraai.com', role: 'admin_dev' }
        next()
        return
      }
    }

    // Dev bypass (explicit opt-in). Accept localhost-dev-token OR x-dev-bypass when enabled.
    if (process.env.ALLOW_LOCALHOST_DEV === 'true') {
      const devBypassHeader = req.headers['x-dev-bypass']
      const authHeaderDevMode = (req.headers.authorization || '') as string
      if (devBypassHeader === 'true' || authHeaderDevMode.includes('localhost-dev-token')) {
        console.warn('⚠️  Auth middleware: Dev bypass active')
        req.user = { id: 'dev-user', email: 'dev@cobraai.com', role: 'admin_dev' }
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
    
    // TypeScript assertion since we've already checked supabase is not null above
    const supabaseClient = supabase as NonNullable<typeof supabase>
    const { data, error } = await supabaseClient.auth.getUser(token)

    if (error || !data.user) {
      res.status(401).json({ error: 'Invalid token' })
      return
    }

    req.user = data.user
    next()
  } catch (error) {
    res.status(401).json({ error: 'Authentication failed' })
  }
}

export const adminMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    // Allow admin routes in development when Supabase isn't configured
    if (!supabase) {
      console.warn('⚠️  Admin middleware: Supabase not configured, allowing admin access in development mode')
      next()
      return
    }

    const userId = req.user?.id

    if (!userId) {
      res.status(401).json({ error: 'User not authenticated' })
      return
    }

    const { data: profile, error } = await supabase
      .from('profiles')
      .select('role')
      .eq('id', userId)
      .single()

    if (error || profile?.role !== 'admin') {
      res.status(403).json({ error: 'Admin access required' })
      return
    }

    next()
  } catch (error) {
    res.status(403).json({ error: 'Admin verification failed' })
  }
} 