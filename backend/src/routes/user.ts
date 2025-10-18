import express from 'express'
import Joi from 'joi'
import { userRegistrationService, UserRegistrationData, WaitlistData } from '../services/userRegistration'

const router = express.Router()

// Validation schemas
const waitlistSchema = Joi.object({
  email: Joi.string().email().required(),
  fullName: Joi.string().min(1).max(100).optional(),
  source: Joi.string().max(50).optional(),
  interestLevel: Joi.string().valid('low', 'medium', 'high').optional(),
  metadata: Joi.object().optional()
})

const registrationSchema = Joi.object({
  userId: Joi.string().required(),
  email: Joi.string().email().required(),
  fullName: Joi.string().min(1).max(100).optional(),
  registrationSource: Joi.string().max(50).optional(),
  referrerUrl: Joi.string().uri().optional(),
  userAgent: Joi.string().max(500).optional(),
  ipAddress: Joi.string().ip().optional(),
  intendedPlan: Joi.string().valid('free', 'light', 'pro', 'enterprise').optional(),
  expectedUsage: Joi.string().max(500).optional(),
  termsAccepted: Joi.boolean().optional(),
  privacyAccepted: Joi.boolean().optional()
})

// Add to waitlist endpoint
router.post('/waitlist', async (req: express.Request, res: express.Response) => {
  try {
    const { error, value } = waitlistSchema.validate(req.body)
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        message: error.details?.[0]?.message || 'Invalid request data'
      })
    }

    const waitlistData: WaitlistData = {
      email: value.email,
      fullName: value.fullName,
      source: value.source || 'api',
      interestLevel: value.interestLevel || 'high',
      metadata: {
        ...(value.metadata || {}),
        userAgent: req.get('User-Agent'),
        referrer: req.get('Referrer'),
        ip: req.ip,
        timestamp: new Date().toISOString()
      }
    }

    const result = await userRegistrationService.addToWaitlist(waitlistData)

    if (!result.success) {
      return res.status(500).json({
        error: 'Database Error',
        message: result.error || 'Failed to add to waitlist'
      })
    }

    res.json({
      success: true,
      message: 'Successfully added to waitlist',
      email: waitlistData.email
    })
  } catch (error: any) {
    console.error('Waitlist endpoint error:', error)
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to process waitlist request'
    })
  }
})

// Register user endpoint (called after successful auth signup)
router.post('/register', async (req: express.Request, res: express.Response) => {
  try {
    const { error, value } = registrationSchema.validate(req.body)
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        message: error.details?.[0]?.message || 'Invalid request data'
      })
    }

    const registrationData: UserRegistrationData = {
      email: value.email,
      fullName: value.fullName,
      registrationSource: value.registrationSource || 'direct',
      referrerUrl: value.referrerUrl || req.get('Referrer'),
      userAgent: value.userAgent || req.get('User-Agent'),
      ipAddress: value.ipAddress || req.ip,
      intendedPlan: value.intendedPlan || 'free',
      expectedUsage: value.expectedUsage,
      termsAccepted: value.termsAccepted || false,
      privacyAccepted: value.privacyAccepted || false
    }

    const result = await userRegistrationService.registerUser(value.userId, registrationData)

    if (!result.success) {
      return res.status(500).json({
        error: 'Database Error',
        message: result.error || 'Failed to register user'
      })
    }

    res.json({
      success: true,
      message: 'User registered successfully',
      userId: value.userId,
      email: registrationData.email
    })
  } catch (error: any) {
    console.error('Registration endpoint error:', error)
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to process registration'
    })
  }
})

// Update last login endpoint
router.post('/login', async (req: express.Request, res: express.Response) => {
  try {
    const { userId, email } = req.body

    if (!userId || !email) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'userId and email are required'
      })
    }

    await userRegistrationService.updateLastLogin(userId, email)

    res.json({
      success: true,
      message: 'Login recorded successfully'
    })
  } catch (error: any) {
    console.error('Login update endpoint error:', error)
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to record login'
    })
  }
})

// Get user registration data endpoint
router.get('/registration/:userId', async (req: express.Request, res: express.Response) => {
  try {
    const { userId } = req.params

    if (!userId) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'userId is required'
      })
    }

    const registrationData = await userRegistrationService.getUserRegistration(userId)

    if (!registrationData) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'User registration data not found'
      })
    }

    res.json({
      success: true,
      data: registrationData
    })
  } catch (error: any) {
    console.error('Get registration endpoint error:', error)
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to get registration data'
    })
  }
})

// Get waitlist stats endpoint (for admin use)
router.get('/admin/waitlist-stats', async (req: express.Request, res: express.Response) => {
  try {
    const stats = await userRegistrationService.getWaitlistStats()

    if (!stats) {
      return res.status(500).json({
        error: 'Database Error',
        message: 'Failed to get waitlist stats'
      })
    }

    res.json({
      success: true,
      data: stats
    })
  } catch (error: any) {
    console.error('Waitlist stats endpoint error:', error)
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to get waitlist stats'
    })
  }
})

// Health check endpoint
router.get('/health', async (req: express.Request, res: express.Response) => {
  try {
    const isConfigured = userRegistrationService.isConfigured()
    
    res.json({
      success: true,
      message: 'User registration service is running',
      supabaseConfigured: isConfigured,
      timestamp: new Date().toISOString()
    })
  } catch (error: any) {
    console.error('Health check error:', error)
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Health check failed'
    })
  }
})

export default router 