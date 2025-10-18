import express from 'express'
import { supabase } from '../server'
import { authMiddleware, adminMiddleware } from '../middleware/auth'

const router = express.Router()

// POST /api/admin/free-access - Grant free access to a user
router.post('/free-access', authMiddleware, adminMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    const { userEmail, reason, features, expiresAt } = req.body
    const adminId = req.user?.id

    if (!userEmail) {
      return res.status(400).json({ error: 'User email is required' })
    }

    // Find user by email
    const { data: userData, error: userError } = await supabase
      .from('profiles')
      .select('id, email')
      .eq('email', userEmail)
      .single()

    if (userError || !userData) {
      return res.status(404).json({ error: 'User not found' })
    }

    // Grant free access
    const { data, error } = await supabase
      .from('free_access_grants')
      .upsert({
        user_id: userData.id,
        granted_by: adminId,
        reason: reason || 'Admin granted access',
        features_granted: features || { unlimited: true },
        expires_at: expiresAt || null,
        is_active: true
      }, {
        onConflict: 'user_id'
      })
      .select()

    if (error) throw error

    // Update profile flag
    await supabase
      .from('profiles')
      .update({ is_free_access: true })
      .eq('id', userData.id)

    return res.json({
      message: 'Free access granted successfully',
      grant: data[0]
    })
  } catch (error) {
    console.error('Grant Free Access Error:', error)
    return res.status(500).json({
      error: 'Failed to grant free access'
    })
  }
})

// DELETE /api/admin/free-access/:userId - Revoke free access
router.delete('/free-access/:userId', authMiddleware, adminMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    const { userId } = req.params

    // Revoke free access
    const { error } = await supabase
      .from('free_access_grants')
      .update({ is_active: false })
      .eq('user_id', userId)

    if (error) throw error

    // Update profile flag
    await supabase
      .from('profiles')
      .update({ is_free_access: false })
      .eq('id', userId)

    return res.json({ message: 'Free access revoked successfully' })
  } catch (error) {
    console.error('Revoke Free Access Error:', error)
    return res.status(500).json({
      error: 'Failed to revoke free access'
    })
  }
})

// GET /api/admin/free-access - List all free access grants
router.get('/free-access', authMiddleware, adminMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    const { data, error } = await supabase
      .from('free_access_grants')
      .select(`
        *,
        profiles!user_id (email, full_name),
        granted_by_profile:profiles!granted_by (email, full_name)
      `)
      .eq('is_active', true)
      .order('created_at', { ascending: false })

    if (error) throw error

    return res.json({ grants: data })
  } catch (error) {
    console.error('List Free Access Error:', error)
    return res.status(500).json({
      error: 'Failed to fetch free access grants'
    })
  }
})

// GET /api/admin/users - List all users with subscription info
router.get('/users', authMiddleware, adminMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    const { data, error } = await supabase
      .from('profiles')
      .select(`
        *,
        user_subscriptions (
          *,
          subscription_plans (name, price_monthly)
        ),
        free_access_grants (
          is_active,
          reason,
          expires_at
        )
      `)
      .order('created_at', { ascending: false })

    if (error) throw error

    return res.json({ users: data })
  } catch (error) {
    console.error('List Users Error:', error)
    return res.status(500).json({
      error: 'Failed to fetch users'
    })
  }
})

// GET /api/admin/stats - Get subscription and usage statistics
router.get('/stats', authMiddleware, adminMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    // Get subscription counts by plan
    const { data: subscriptionStats, error: subError } = await supabase
      .from('user_subscriptions')
      .select(`
        status,
        subscription_plans (name)
      `)
      .eq('status', 'active')

    if (subError) throw subError

    // Get total user count
    const { count: totalUsers, error: userError } = await supabase
      .from('profiles')
      .select('*', { count: 'exact', head: true })

    if (userError) throw userError

    // Get free access grants count
    const { count: freeAccessCount, error: freeError } = await supabase
      .from('free_access_grants')
      .select('*', { count: 'exact', head: true })
      .eq('is_active', true)

    if (freeError) throw freeError

    // Process subscription stats
    const planStats = subscriptionStats?.reduce((acc: any, sub: any) => {
      const planName = sub.subscription_plans?.name || 'Unknown'
      acc[planName] = (acc[planName] || 0) + 1
      return acc
    }, {}) || {}

    return res.json({
      totalUsers,
      freeAccessCount,
      planStats,
      activeSubscriptions: subscriptionStats?.length || 0
    })
  } catch (error) {
    console.error('Get Stats Error:', error)
    return res.status(500).json({
      error: 'Failed to fetch statistics'
    })
  }
})

// POST /api/admin/users/:userId/role - Update user role
router.post('/users/:userId/role', authMiddleware, adminMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    const { userId } = req.params
    const { role } = req.body

    if (!['user', 'admin', 'analyst'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' })
    }

    const { error } = await supabase
      .from('profiles')
      .update({ role })
      .eq('id', userId)

    if (error) throw error

    return res.json({ message: 'User role updated successfully' })
  } catch (error) {
    console.error('Update User Role Error:', error)
    return res.status(500).json({
      error: 'Failed to update user role'
    })
  }
})

export default router 