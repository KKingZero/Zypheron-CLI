import express from 'express'
import { supabase } from '../src/server'
import { enhancedAuthMiddleware, adminDevMiddleware, generateExtendedToken, getUserPermissions } from '../src/middleware/rbac'

const router = express.Router()

/**
 * POST /api/auth/login-extended - Login with extended session for admin_dev users
 */
router.post('/login-extended', async (req: express.Request, res: express.Response) => {
  try {
    const { email, password, requestExtendedSession } = req.body

    if (!email || !password) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Email and password are required'
      })
    }

    if (!supabase) {
      return res.status(500).json({
        error: 'Configuration Error',
        message: 'Authentication service not available'
      })
    }

    // Authenticate user with Supabase
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    })

    if (error) {
      return res.status(401).json({
        error: 'Authentication Error',
        message: error.message
      })
    }

    if (!data.user) {
      return res.status(401).json({
        error: 'Authentication Error',
        message: 'Login failed'
      })
    }

    // Get user role and permissions
    const { data: roleData, error: roleError } = await supabase
      .rpc('get_user_role_permissions', { user_uuid: data.user.id })

    if (roleError) {
      console.error('Failed to get user role:', roleError)
      return res.status(500).json({
        error: 'Permission Error',
        message: 'Failed to verify user permissions'
      })
    }

    const userRole = roleData?.[0]
    const permissions = getUserPermissions(userRole)

    // Check if user can have extended session
    let sessionToken = data.session?.access_token
    let sessionInfo: any = {
      standard_session: true,
      extended_session: false
    }

    if (requestExtendedSession && userRole?.role === 'admin_dev' && permissions.canExtendSession) {
      try {
        sessionToken = await generateExtendedToken(data.user.id, data.user.email!)
        sessionInfo = {
          standard_session: false,
          extended_session: true,
          duration_hours: userRole.max_session_duration_hours,
          bypass_enabled: permissions.canBypassMFA
        }
        
        console.log(`🔐 Extended session granted to admin_dev: ${email}`)
      } catch (error) {
        console.error('Failed to generate extended token:', error)
        // Fallback to standard session
      }
    }

    return res.json({
      message: 'Login successful',
      user: {
        id: data.user.id,
        email: data.user.email,
        role: userRole?.role || 'user'
      },
      session: {
        access_token: sessionToken,
        user: data.user,
        ...sessionInfo
      },
      permissions,
      developer_bypass_active: userRole?.role === 'admin_dev'
    })

  } catch (error) {
    console.error('Extended login error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to process login'
    })
  }
})

/**
 * GET /api/auth/me - Get current user info with role and permissions
 */
router.get('/me', enhancedAuthMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    if (!req.user || !req.userRole) {
      return res.status(401).json({ error: 'User not authenticated' })
    }

    const permissions = getUserPermissions(req.userRole)

    return res.json({
      user: {
        id: req.user.id,
        email: req.user.email,
        role: req.userRole.role
      },
      permissions,
      developer_bypass_active: req.userRole.role === 'admin_dev',
      session_info: {
        max_duration_hours: req.userRole.max_session_duration_hours,
        can_extend: req.userRole.can_extend_session
      }
    })
  } catch (error) {
    console.error('Get user info error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to get user information'
    })
  }
})

/**
 * POST /api/auth/extend-session - Extend session for admin_dev users
 */
router.post('/extend-session', enhancedAuthMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    if (!req.user || !req.userRole) {
      return res.status(401).json({ error: 'User not authenticated' })
    }

    if (req.userRole.role !== 'admin_dev' || !req.userRole.can_extend_session) {
      return res.status(403).json({
        error: 'Access Denied',
        message: 'Extended sessions only available for admin_dev users'
      })
    }

    const newToken = await generateExtendedToken(req.user.id, req.user.email)

    console.log(`🔐 Session extended for admin_dev: ${req.user.email}`)

    return res.json({
      message: 'Session extended successfully',
      session: {
        access_token: newToken,
        extended_session: true,
        duration_hours: req.userRole.max_session_duration_hours
      }
    })
  } catch (error) {
    console.error('Extend session error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to extend session'
    })
  }
})

/**
 * GET /api/auth/admin-dev/users - List all users (admin_dev only)
 */
router.get('/admin-dev/users', enhancedAuthMiddleware, adminDevMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    if (!supabase) {
      return res.status(500).json({ error: 'Database not available' })
    }

    const { data: users, error } = await supabase
      .from('users')
      .select('id, email, role, subscription_status, developer_access, created_at, last_token_reset')
      .order('created_at', { ascending: false })

    if (error) {
      console.error('Failed to fetch users:', error)
      return res.status(500).json({ error: 'Failed to fetch users' })
    }

    return res.json({
      users: users || [],
      total_count: users?.length || 0
    })
  } catch (error) {
    console.error('List users error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to list users'
    })
  }
})

/**
 * POST /api/auth/admin-dev/set-role - Change user role (admin_dev only)
 */
router.post('/admin-dev/set-role', enhancedAuthMiddleware, adminDevMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    const { userId, newRole } = req.body

    if (!userId || !newRole) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'userId and newRole are required'
      })
    }

    const validRoles = ['user', 'admin', 'analyst', 'admin_dev']
    if (!validRoles.includes(newRole)) {
      return res.status(400).json({
        error: 'Validation Error',
        message: `Invalid role. Must be one of: ${validRoles.join(', ')}`
      })
    }

    if (!supabase) {
      return res.status(500).json({ error: 'Database not available' })
    }

    // Use the secure function to set role
    const { data, error } = await supabase
      .rpc('set_user_role', {
        target_user_uuid: userId,
        new_role: newRole,
        requesting_user_uuid: req.user.id
      })

    if (error) {
      console.error('Failed to set user role:', error)
      return res.status(400).json({
        error: 'Role Change Failed',
        message: error.message
      })
    }

    console.log(`🔐 Role changed: ${req.user.email} set ${userId} to ${newRole}`)

    return res.json({
      message: 'User role updated successfully',
      success: true
    })
  } catch (error) {
    console.error('Set role error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to update user role'
    })
  }
})

/**
 * GET /api/auth/admin-dev/audit-logs - Get security audit logs (admin_dev only)
 */
router.get('/admin-dev/audit-logs', enhancedAuthMiddleware, adminDevMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    if (!supabase) {
      return res.status(500).json({ error: 'Database not available' })
    }

    const { limit = 100, offset = 0 } = req.query

    const { data: logs, error } = await supabase
      .from('usage_logs')
      .select('*')
      .in('service_type', ['role_change', 'admin_access', 'security_event'])
      .order('created_at', { ascending: false })
      .range(parseInt(offset as string), parseInt(offset as string) + parseInt(limit as string) - 1)

    if (error) {
      console.error('Failed to fetch audit logs:', error)
      return res.status(500).json({ error: 'Failed to fetch audit logs' })
    }

    return res.json({
      logs: logs || [],
      pagination: {
        limit: parseInt(limit as string),
        offset: parseInt(offset as string),
        total: logs?.length || 0
      }
    })
  } catch (error) {
    console.error('Audit logs error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch audit logs'
    })
  }
})

export default router
