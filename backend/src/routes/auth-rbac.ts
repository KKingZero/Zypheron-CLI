import express from 'express'
import { enhancedAuthMiddleware, adminDevMiddleware } from '../middleware/rbac'

const router = express.Router()

// GET /api/auth/me - Get current user permissions
router.get('/me', enhancedAuthMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    const userRole = (req as any).userRole
    
    if (!userRole) {
      return res.status(401).json({ error: 'No user role found' })
    }

    res.json({
      role: userRole.role,
      features: userRole.features || {},
      canBypassMFA: userRole.can_bypass_mfa || false,
      canExtendSession: userRole.can_extend_session || false,
      hasUnlimitedTokens: userRole.has_unlimited_tokens || false,
      maxSessionHours: userRole.max_session_hours || 24
    })
  } catch (error) {
    console.error('Get user permissions error:', error)
    res.status(500).json({ error: 'Failed to get user permissions' })
  }
})

// POST /api/auth/extend-session - Extend session for admin_dev users
router.post('/extend-session', enhancedAuthMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    const userRole = (req as any).userRole
    
    if (!userRole || userRole.role !== 'admin_dev') {
      return res.status(403).json({ error: 'Insufficient permissions' })
    }

    // For now, return success - actual session extension would be handled by Supabase
    res.json({ 
      success: true, 
      message: 'Session extended for admin_dev user',
      expiresIn: '1 year'
    })
  } catch (error) {
    console.error('Extend session error:', error)
    res.status(500).json({ error: 'Failed to extend session' })
  }
})

// GET /api/auth/admin-dev/users - List users (admin_dev only)
router.get('/admin-dev/users', adminDevMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    // This would fetch users from the database
    // For now, return a placeholder response
    res.json({ 
      users: [],
      message: 'Admin dev endpoint working' 
    })
  } catch (error) {
    console.error('Admin users list error:', error)
    res.status(500).json({ error: 'Failed to fetch users' })
  }
})

// POST /api/auth/admin-dev/set-role - Set user role (admin_dev only)
router.post('/admin-dev/set-role', adminDevMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    const { userId, role } = req.body
    
    if (!userId || !role) {
      return res.status(400).json({ error: 'User ID and role are required' })
    }

    // This would update the user role in the database
    // For now, return a placeholder response
    res.json({ 
      success: true,
      message: `User role would be updated to ${role}`,
      userId,
      role
    })
  } catch (error) {
    console.error('Set user role error:', error)
    res.status(500).json({ error: 'Failed to set user role' })
  }
})

export default router
