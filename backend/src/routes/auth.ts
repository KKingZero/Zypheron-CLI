import express from 'express'
import { supabase } from '../server'

const router = express.Router()

// POST /api/auth/register - Register new user
router.post('/register', async (req: express.Request, res: express.Response) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Email and password are required'
      })
    }

    const { data, error } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true
    })

    if (error) {
      return res.status(400).json({
        error: 'Registration Error',
        message: error.message
      })
    }

    return res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: data.user?.id,
        email: data.user?.email
      }
    })

  } catch (error) {
    console.error('Registration Error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to register user'
    })
  }
})

// POST /api/auth/login - Login user
router.post('/login', async (req: express.Request, res: express.Response) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Email and password are required'
      })
    }

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

    return res.json({
      message: 'Login successful',
      user: {
        id: data.user?.id,
        email: data.user?.email
      },
      session: data.session
    })

  } catch (error) {
    console.error('Login Error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to login user'
    })
  }
})

// POST /api/auth/logout - Logout user
router.post('/logout', async (req: express.Request, res: express.Response) => {
  try {
    const authHeader = req.headers.authorization
    if (!authHeader) {
      return res.status(401).json({
        error: 'Authentication Error',
        message: 'No authorization header provided'
      })
    }

    const token = authHeader.replace('Bearer ', '')
    
    const { error } = await supabase.auth.admin.signOut(token)

    if (error) {
      return res.status(400).json({
        error: 'Logout Error',
        message: error.message
      })
    }

    return res.json({
      message: 'Logout successful'
    })

  } catch (error) {
    console.error('Logout Error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to logout user'
    })
  }
})

// GET /api/auth/profile - Get user profile
router.get('/profile', async (req: express.Request, res: express.Response) => {
  try {
    const authHeader = req.headers.authorization
    if (!authHeader) {
      return res.status(401).json({
        error: 'Authentication Error',
        message: 'No authorization header provided'
      })
    }

    const token = authHeader.replace('Bearer ', '')
    
    const { data, error } = await supabase.auth.getUser(token)

    if (error || !data.user) {
      return res.status(401).json({
        error: 'Authentication Error',
        message: 'Invalid or expired token'
      })
    }

    return res.json({
      user: {
        id: data.user.id,
        email: data.user.email,
        created_at: data.user.created_at,
        last_sign_in_at: data.user.last_sign_in_at
      }
    })

  } catch (error) {
    console.error('Profile Error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to get user profile'
    })
  }
})

export default router 